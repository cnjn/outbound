package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/cert"
	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"github.com/daeuniverse/outbound/pool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// https://github.com/v2fly/v2ray-core/blob/v5.0.6/transport/internet/grpc/dial.go
type clientConnMeta struct {
	cc *grpc.ClientConn
}

var (
	globalCCMap    map[string]*clientConnMeta
	globalCCAccess sync.Mutex
)

func grpcClientCacheKey(scope, serverName, address string, allowInsecure bool, somark uint32, mptcp bool) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%t\x00%d\x00%t", scope, serverName, address, allowInsecure, somark, mptcp)
}

func scopedCachePrefix(scope string) string {
	return scope + "\x00"
}

func CleanGlobalClientConnectionCache() {
	globalCCAccess.Lock()
	cached := make([]*grpc.ClientConn, 0, len(globalCCMap))
	for _, meta := range globalCCMap {
		if meta != nil && meta.cc != nil {
			cached = append(cached, meta.cc)
		}
	}
	globalCCMap = make(map[string]*clientConnMeta)
	globalCCAccess.Unlock()

	for _, cc := range cached {
		_ = cc.Close()
	}
}

func CleanScopedClientConnectionCache(scope string) {
	if scope == "" {
		return
	}
	prefix := scopedCachePrefix(scope)
	globalCCAccess.Lock()
	var cached []*grpc.ClientConn
	for key, meta := range globalCCMap {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if meta != nil && meta.cc != nil {
			cached = append(cached, meta.cc)
		}
		delete(globalCCMap, key)
	}
	globalCCAccess.Unlock()

	for _, cc := range cached {
		_ = cc.Close()
	}
}

type ccCanceller func()

// ClientConn is a gRPC tunnel that carries hunk-framed bytes.
//
// Deadline semantics, because they are asymmetric and the asymmetry is part of
// the contract:
//
//   - A read deadline is transient: an expired read deadline makes the current
//     Read return os.ErrDeadlineExceeded without touching the stream, and a
//     later Read with a fresh deadline resumes normally. The receive pump
//     keeps ownership of the hunk in flight.
//   - A write deadline is terminal: a wedged Send cannot be aborted, and a
//     second Send must not overtake it (that would reorder stream data), so
//     the only way to unblock writers is to cancel the stream context. Once a
//     write deadline fires, this ClientConn is permanently unusable.
//
// recvErr is sticky: once the receive pump has observed a stream error, every
// subsequent Read returns it rather than reporting a clean EOF.
type ClientConn struct {
	tun       proto.GunService_TunClient
	closer    context.CancelFunc
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	buf       []byte
	offset    int

	// recvCh is fed by a single lazily-started receive pump so an abandoned
	// deadline-expired Read cannot lose a received hunk (a per-Read Recv
	// goroutine whose buffered(1) result channel nobody drains anymore).
	recvCh   chan RecvResp
	pumpOnce sync.Once
	recvErr  error

	// sendCh feeds a single lazily-started sender goroutine that owns every
	// tun.Send, replacing the per-Write goroutine + result channel (one
	// goroutine, one channel and one proto.Hunk allocated per chunk).
	// muWriting serializes writers to at most one request in flight, which
	// is what makes the pooled request below safe to recycle.
	sendCh     chan *sendRequest
	senderOnce sync.Once

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer

	ctxRead     context.Context
	cancelRead  func()
	ctxWrite    context.Context
	cancelWrite func()
	ctx         context.Context
	cancel      func()
}

// readCtx snapshots the current read-deadline context under deadlineMu: the
// Set*Deadline methods replace ctxRead/ctxWrite concurrently, and selecting
// on the field without the lock is a data race.
func (c *ClientConn) readCtx() context.Context {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.ctxRead
}

func (c *ClientConn) writeCtx() context.Context {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.ctxWrite
}

// ensureRecvPump starts the single receive pump goroutine. It exits when the
// stream context is done or Recv reports a terminal error.
func (c *ClientConn) ensureRecvPump() {
	c.pumpOnce.Do(func() {
		c.recvCh = make(chan RecvResp, 1)
		go func() {
			for {
				recv, e := c.tun.Recv()
				select {
				case c.recvCh <- RecvResp{hunk: recv, err: e}:
				case <-c.ctx.Done():
					return
				}
				if e != nil {
					return
				}
			}
		}()
	})
}

// sendRequest carries one Write's payload through the sender goroutine.
// Requests are pooled; each one owns a buffered(1) done channel so the
// sender never blocks delivering the result of a Send whose writer already
// returned at a write deadline (deadline expiry is terminal; see Write).
type sendRequest struct {
	hunk proto.Hunk
	done chan error
}

var sendReqPool = sync.Pool{
	New: func() any { return &sendRequest{done: make(chan error, 1)} },
}

// ensureSender starts the single sender goroutine. It exits once the conn
// context is done (Close); a Send wedged inside the sender is unwedged by
// c.closer cancelling the stream context, the same mechanism the write
// deadline path relies on.
func (c *ClientConn) ensureSender() {
	c.senderOnce.Do(func() {
		go func() {
			for {
				select {
				case req := <-c.sendCh:
					// grpc-go v1.57 marshals the message synchronously
					// inside SendMsg (prepareMsg -> codec.Marshal, before
					// the transport write) and never retains it afterwards,
					// so the pooled hunk can be recycled as soon as Send
					// returns. done is buffered: this cannot block on a
					// writer that already abandoned the request.
					req.done <- c.tun.Send(&req.hunk)
					sendReqPool.Put(req)
				case <-c.ctx.Done():
					return
				}
			}
		}()
	})
}

func NewClientConn(tun proto.GunService_TunClient, closer context.CancelFunc) *ClientConn {
	ctx, cancel := context.WithCancel(context.Background())
	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxWrite, cancelWrite := context.WithCancel(context.Background())
	return &ClientConn{
		tun:         tun,
		closer:      closer,
		sendCh:      make(chan *sendRequest, 1),
		ctx:         ctx,
		cancel:      cancel,
		ctxRead:     ctxRead,
		cancelRead:  cancelRead,
		ctxWrite:    ctxWrite,
		cancelWrite: cancelWrite,
	}
}

type RecvResp struct {
	hunk *proto.Hunk
	err  error
}

func (c *ClientConn) Read(p []byte) (n int, err error) {
	c.ensureRecvPump()
	ctxRead := c.readCtx()
	select {
	case <-ctxRead.Done():
		// Deadline expiry is NOT terminal: the pending Recv keeps running in
		// the pump and its result stays queued in recvCh for the next Read
		// after the caller clears or extends the deadline.
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muReading.Lock()
	defer c.muReading.Unlock()
	if c.recvErr != nil {
		return 0, c.recvErr
	}
	// Refresh after acquiring the read lock so deadline changes made while
	// this operation waited for another reader apply to the pending I/O.
	ctxRead = c.readCtx()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	select {
	case <-ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case recvResp := <-c.recvCh:
		err = recvResp.err
		if err != nil {
			if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
				err = io.EOF
			}
			c.recvErr = err
			return 0, err
		}
		n = copy(p, recvResp.hunk.Data)
		if rest := len(recvResp.hunk.Data) - n; rest > 0 {
			// A zero-length remainder must not be stored: an empty
			// non-nil buf made the next Read return (0, nil), one
			// spurious iteration per fully-consumed hunk.
			c.buf = pool.Get(rest)
			copy(c.buf, recvResp.hunk.Data[n:])
			c.offset = 0
		}
		return n, nil
	}
}

func (c *ClientConn) Write(p []byte) (n int, err error) {
	ctxWrite := c.writeCtx()
	select {
	case <-ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	// Refresh after acquiring the write lock so deadline changes made while
	// this operation waited for another writer apply to the pending I/O.
	ctxWrite = c.writeCtx()
	c.ensureSender()

	req := sendReqPool.Get().(*sendRequest)
	// A previous writer may have abandoned this recycled request at a write
	// deadline, leaving the aborted Send's error queued; drop it.
	select {
	case <-req.done:
	default:
	}
	// Whole-struct assignment, not a field write: it also resets the legacy
	// proto XXX_ cache fields, so a recycled hunk marshals like a fresh one.
	req.hunk = proto.Hunk{Data: p}
	select {
	case c.sendCh <- req:
		// The sender dequeues a request before calling Send, and muWriting
		// admits one writer at a time, so this handoff only blocks while an
		// earlier wedged Send (already released by c.closer below or by
		// Close) is still draining; the deadline/close arms keep that wait
		// interruptible.
	case <-ctxWrite.Done():
		c.closer()
		sendReqPool.Put(req)
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		sendReqPool.Put(req)
		return 0, io.EOF
	}
	select {
	case <-ctxWrite.Done():
		// A wedged gRPC Send cannot be aborted or bypassed, and a second
		// Send must not overtake it (that would reorder stream data), so
		// cancelling the stream is the only way to unblock writers. Write
		// deadlines are therefore terminal for this conn, unlike read
		// deadlines above. The sender goroutine stays alive: it reports the
		// aborted Send's error into req.done (buffered, never blocking) and
		// recycles the request for later writers.
		c.closer() // Cancel stream context so the wedged Send can return
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case err = <-req.done:
		if err != nil {
			// A gRPC hunk is atomic at the message level: either the whole
			// Hunk was accepted by the stream or none of it was, so there is
			// no such thing as a partial send to report. Claiming len(p) on
			// error contradicts the short-write contract and lets a caller
			// treat a dropped chunk as delivered.
			if code := status.Code(err); code == codes.Unavailable || code == codes.OutOfRange {
				err = io.EOF
			}
			return 0, err
		}
		return len(p), nil
	}
}

// setDeadlineLocked updates one direction while preserving the context used by
// pending I/O. Only an expired context needs replacing. Caller holds deadlineMu.
func (c *ClientConn) setDeadlineLocked(slot **time.Timer, ctx *context.Context, cancel *func(), t time.Time) {
	if *slot != nil {
		(*slot).Stop()
		*slot = nil
	}
	if !t.IsZero() && !t.After(time.Now()) {
		(*cancel)()
		return
	}
	if (*ctx).Err() != nil {
		*ctx, *cancel = context.WithCancel(context.Background())
	}
	if t.IsZero() {
		return
	}
	cancelDeadline := *cancel
	var timer *time.Timer
	timer = time.AfterFunc(time.Until(t), func() {
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()
		// Stop does not wait for a callback already blocked on deadlineMu.
		// The slot identity prevents that old epoch from cancelling new I/O.
		if *slot == timer {
			cancelDeadline()
		}
	})
	*slot = timer
}

func (c *ClientConn) Close() error {
	c.deadlineMu.Lock()
	if c.readDeadline != nil {
		c.readDeadline.Stop()
		c.readDeadline = nil
	}
	if c.writeDeadline != nil {
		c.writeDeadline.Stop()
		c.writeDeadline = nil
	}
	c.deadlineMu.Unlock()
	select {
	case <-c.ctx.Done():
	default:
		c.cancel()
	}
	c.closer()
	return nil
}

func (c *ClientConn) CloseWrite() error {
	return c.tun.CloseSend()
}

func (c *ClientConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.setDeadlineLocked(&c.readDeadline, &c.ctxRead, &c.cancelRead, t)
	c.setDeadlineLocked(&c.writeDeadline, &c.ctxWrite, &c.cancelWrite, t)
	return nil
}

func (c *ClientConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.setDeadlineLocked(&c.readDeadline, &c.ctxRead, &c.cancelRead, t)
	return nil
}

func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.setDeadlineLocked(&c.writeDeadline, &c.ctxWrite, &c.cancelWrite, t)
	return nil
}

type Dialer struct {
	NextDialer    netproxy.Dialer
	ServiceName   string
	ServerName    string
	AllowInsecure bool
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.NextDialer
}

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	meta, cancel, err := getGrpcClientConn(ctx, d.NextDialer, d.ServerName, address, d.AllowInsecure, magicNetwork.Mark, magicNetwork.Mptcp)
	if err != nil {
		cancel()
		return nil, err
	}
	client := proto.NewGunServiceClient(meta.cc)

	clientX := client.(proto.GunServiceClientX)
	serviceName := d.ServiceName
	if serviceName == "" {
		serviceName = "GunService"
	}
	// Stream lifetime is independent of the dial ctx (dae cancels dial ctx
	// after Dial returns). Honor the caller ctx only while Tun is opening.
	ctxStream, streamCloser := context.WithCancel(context.Background())
	stopWatch := context.AfterFunc(ctx, streamCloser)
	tun, err := clientX.TunCustomName(ctxStream, serviceName)
	if err != nil {
		_ = stopWatch()
		streamCloser()
		return nil, err
	}
	if !stopWatch() {
		streamCloser()
		_ = tun.CloseSend()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, context.Canceled
	}
	return NewClientConn(tun, streamCloser), nil
}

// systemCertPoolCached resolves the system pool once: GetSystemCertPool is
// not free and previously ran on every dial, even on cache-hit paths.
var (
	systemCertPoolMu  sync.Mutex
	systemCertPool    *x509.CertPool
	systemCertPoolErr error
)

// Success is memoized; a failure (e.g. CA bundle briefly missing at cold
// start) must stay retryable or every gRPC dial fails until restart.
func systemCertPoolCached() (*x509.CertPool, error) {
	systemCertPoolMu.Lock()
	defer systemCertPoolMu.Unlock()
	if systemCertPool != nil {
		return systemCertPool, nil
	}
	systemCertPool, systemCertPoolErr = cert.GetSystemCertPool()
	return systemCertPool, systemCertPoolErr
}

func getGrpcClientConn(ctx context.Context, tcpDialer netproxy.Dialer, serverName string, address string, allowInsecure bool, somark uint32, mptcp bool) (*clientConnMeta, ccCanceller, error) {
	scope := netproxy.TransportCacheNamespace(tcpDialer)
	cacheKey := grpcClientCacheKey(scope, serverName, address, allowInsecure, somark, mptcp)
	// allowInsecure?
	roots, err := systemCertPoolCached()
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to get system certificate pool: %w", err)
	}
	certOption := grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{ServerName: serverName, RootCAs: roots, InsecureSkipVerify: allowInsecure}))

	// Hold the cache lock across lookup, dial and store: grpc.DialContext is
	// lazy (it does not wait for the connection), and doing the dial outside
	// the lock let two concurrent dials for the same key both miss, both
	// connect, and orphan the loser's connection.
	globalCCAccess.Lock()
	defer globalCCAccess.Unlock()
	if globalCCMap == nil {
		globalCCMap = make(map[string]*clientConnMeta)
	}

	var meta *clientConnMeta
	// Fresh-dial canceller: close the conn only while this dial still owns
	// the cache entry (or never published it, e.g. DialContext failed). A
	// conn that another dialer adopted from the cache is no longer ours to
	// close.
	canceller := func() {
		globalCCAccess.Lock()
		current, ok := globalCCMap[cacheKey]
		owned := !ok || current == meta
		if ok && current == meta {
			delete(globalCCMap, cacheKey)
		}
		globalCCAccess.Unlock()
		if owned && meta != nil && meta.cc != nil {
			_ = meta.cc.Close()
		}
	}

	// TODO Should support chain proxy to the same destination
	if cached, found := globalCCMap[cacheKey]; found && cached.cc.GetState() != connectivity.Shutdown {
		// Cache hits return a no-op canceller: the shared ClientConn must
		// outlive any single borrower.
		return cached, func() {}, nil
	}
	meta = &clientConnMeta{
		cc: nil,
	}
	meta.cc, err = grpc.DialContext(ctx, address,
		certOption,
		grpc.WithContextDialer(func(ctxGrpc context.Context, s string) (net.Conn, error) {
			tcpNetwork := netproxy.MagicNetwork{
				Network: "tcp",
				Mark:    somark,
				Mptcp:   mptcp,
			}.Encode()
			c, err := tcpDialer.DialContext(ctxGrpc, tcpNetwork, s)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{
				Conn:  c,
				LAddr: nil,
				RAddr: nil,
			}, nil
		}), grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}), grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, canceller, err
	}
	globalCCMap[cacheKey] = meta
	return meta, canceller, err
}
