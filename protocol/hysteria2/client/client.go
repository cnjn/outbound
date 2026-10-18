package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/hysteria2/obfs"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"

	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
)

const (
	closeErrCodeOK            = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client interface {
	TCP(addr string, ctx context.Context) (netproxy.Conn, error)
	UDP(addr string, ctx context.Context) (netproxy.Conn, error)
	Close() error
}

func NewClient(config *Config) (Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &clientImpl{
		config: config,
	}
	return c, nil
}

// TODO: How to handle quic conn for the same dialer with different marks?

type clientImpl struct {
	config *Config

	pktConn net.PacketConn
	conn    quic.Connection

	udpSM *udpSessionManager

	m      sync.Mutex
	closed bool
}

// closeExistingLocked closes the old QUIC connection, packet conn, and UDP
// session manager before establishing a new connection. Must be called with
// c.m held.
func (c *clientImpl) closeExistingLocked() {
	// Close the session manager first: this closes m.done so routeDemux can
	// unblock from a full worker queue instead of waiting for ReceiveMessage
	// to fail after the QUIC connection is already gone.
	if c.udpSM != nil {
		c.udpSM.Close()
		c.udpSM = nil
	}
	if c.conn != nil {
		_ = c.conn.CloseWithError(closeErrCodeOK, "reconnecting")
	}
	if c.pktConn != nil {
		_ = c.pktConn.Close()
	}
	c.conn = nil
	c.pktConn = nil
}

func (c *clientImpl) connect(ctx context.Context) error {
	if c.closed {
		return coreErrs.ClosedError{}
	}

	// Close old resources before creating new ones to prevent goroutine and
	// socket leaks (especially important for UDPHopPacketConn which spawns
	// recvLoop + hopLoop goroutines).
	c.closeExistingLocked()

	pktConn, err := c.config.ConnFactory.New(ctx)
	if err != nil {
		return err
	}
	if c.config.ObfsPassword != "" {
		// Salamander obfuscation: wrap the packet conn so every QUIC packet
		// becomes indistinguishable random bytes on the wire.
		pktConn, err = obfs.WrapPacketConnSalamander(pktConn, []byte(c.config.ObfsPassword))
		if err != nil {
			_ = pktConn.Close()
			return err
		}
	}
	serverAddr := quicRemoteAddr(pktConn, c.config.ServerAddr)
	// Convert config to TLS config & QUIC config
	tlsConfig := c.config.TLSConfig.toTLSConfig()
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     c.config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         c.config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: c.config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     c.config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 c.config.QUICConfig.MaxIdleTimeout,
		KeepAlivePeriod:                c.config.QUICConfig.KeepAlivePeriod,
		DisablePathMTUDiscovery:        c.config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
	}
	// Prepare Transport
	var conn quic.EarlyConnection
	rt := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, pktConn, serverAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	u := &url.URL{
		Scheme: "https",
		Host:   protocol.URLHost,
		Path:   protocol.URLPath,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header = make(http.Header)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return coreErrs.ConnectError{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != protocol.StatusAuthOK {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return coreErrs.AuthError{StatusCode: resp.StatusCode}
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	// resolveCongestion preserves the pre-override behavior when CCOverride is
	// empty, and fails the connection on an unsupported override instead of
	// silently falling back to BBR.
	ccName, actualTx, err := resolveCongestion(
		c.config.CCOverride,
		authResp.RxAuto,
		authResp.Rx,
		c.config.BandwidthConfig.MaxTx,
	)
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(closeErrCodeProtocolError, "")
		}
		_ = pktConn.Close()
		return coreErrs.ConnectError{Err: err}
	}
	switch ccName {
	case ccBrutal:
		congestion.UseBrutal(conn, actualTx)
	case ccBbr3:
		// actualTx carries the access-link ceiling hint in bytes per second;
		// zero leaves the sender purely probing.
		congestion.UseBbr3(conn, actualTx)
	default:
		congestion.UseBBR(conn)
	}
	c.pktConn = pktConn
	c.conn = conn
	if authResp.UDPEnabled {
		c.udpSM = newUDPSessionManager(&udpIOImpl{Conn: conn})
	}
	return nil
}

func quicRemoteAddr(pktConn net.PacketConn, fallback net.Addr) net.Addr {
	type remoteAddrConn interface {
		RemoteAddr() net.Addr
	}
	if c, ok := pktConn.(remoteAddrConn); ok {
		if addr := c.RemoteAddr(); addr != nil {
			return addr
		}
	}
	return fallback
}

func (c *clientImpl) active() bool {
	if c.conn == nil {
		return false
	}
	select {
	case <-c.conn.Context().Done():
		return false
	default:
		return true
	}
}

func (c *clientImpl) Close() error {
	c.m.Lock()
	if c.closed {
		c.m.Unlock()
		return nil
	}
	c.closed = true
	udpSM := c.udpSM
	if udpSM != nil && !udpSM.closeWhenIdle(c.closeExistingWhenDrained) {
		c.m.Unlock()
		return nil
	}
	c.closeExistingLocked()
	c.m.Unlock()
	return nil
}

// closeExistingWhenDrained is the udpSessionManager drain callback. It can
// fire from call stacks that already hold c.m (e.g.
// handleIfConnectionClosed -> closeExistingLocked -> udpSM.Close ->
// closeCleanup invoking onIdle), so it must not take c.m synchronously or it
// self-deadlocks; decoupling with a goroutine lets the holder release first.
func (c *clientImpl) closeExistingWhenDrained() {
	go c.closeExisting()
}

func (c *clientImpl) closeExisting() {
	c.m.Lock()
	defer c.m.Unlock()
	c.closeExistingLocked()
}

// openStream wraps the stream with QStream, which handles Close() properly.
func (c *clientImpl) openStream(conn quic.Connection) (*utils.QStream, error) {
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &utils.QStream{Stream: stream}, nil
}

func (c *clientImpl) TCP(addr string, ctx context.Context) (netproxy.Conn, error) {
	c.m.Lock()
	select {
	case <-ctx.Done():
		c.m.Unlock()
		return nil, ctx.Err()
	default:
	}
	if c.closed {
		c.m.Unlock()
		return nil, coreErrs.ClosedError{}
	}
	if !c.active() {
		err := c.connect(ctx)
		if err != nil {
			c.m.Unlock()
			return nil, err
		}
	}
	// Snapshot the connection BEFORE releasing the lock so that
	// handleIfConnectionClosed can compare against the exact instance
	// that was active when this call started.
	connSnapshot := c.conn
	c.m.Unlock()

	stream, err := c.openStream(connSnapshot)
	if err != nil {
		c.handleIfConnectionClosed(err, connSnapshot)
		return nil, err
	}
	var dialDeadline time.Time
	if deadline, ok := ctx.Deadline(); ok {
		dialDeadline = deadline
		_ = stream.SetDeadline(deadline)
		if !c.config.FastOpen {
			defer func() { _ = stream.SetDeadline(time.Time{}) }()
		}
	}
	// Send request
	err = protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		_ = stream.Close()
		c.handleIfConnectionClosed(err, connSnapshot)
		return nil, err
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call. Keep the dial deadline armed until
		// the response is consumed, independently of caller deadlines.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  connSnapshot.LocalAddr(),
			PseudoRemoteAddr: connSnapshot.RemoteAddr(),
			Established:      false,
			dialDeadline:     dialDeadline,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		_ = stream.Close()
		c.handleIfConnectionClosed(err, connSnapshot)
		return nil, err
	}
	if !ok {
		_ = stream.Close()
		return nil, coreErrs.DialError{Message: "from remote: " + msg}
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  connSnapshot.LocalAddr(),
		PseudoRemoteAddr: connSnapshot.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *clientImpl) UDP(addr string, ctx context.Context) (netproxy.Conn, error) {
	c.m.Lock()
	select {
	case <-ctx.Done():
		c.m.Unlock()
		return nil, ctx.Err()
	default:
	}
	if c.closed {
		c.m.Unlock()
		return nil, coreErrs.ClosedError{}
	}
	if !c.active() {
		err := c.connect(ctx)
		if err != nil {
			c.m.Unlock()
			return nil, err
		}
	}
	// Snapshot the connection BEFORE releasing the lock so that
	// handleIfConnectionClosed can compare against the exact instance
	// that was active when this call started.
	connSnapshot := c.conn
	udpSMSnapshot := c.udpSM
	c.m.Unlock()

	// Local input validation: a malformed target address must surface as a
	// dial error without ever reaching the tunnel-fatal classification (and
	// without tearing down the shared connection).
	if _, err := netip.ParseAddrPort(addr); err != nil {
		return nil, err
	}
	if udpSMSnapshot == nil {
		return nil, coreErrs.DialError{Message: "UDP not enabled"}
	}
	conn, err := udpSMSnapshot.NewUDP(addr)
	c.handleIfConnectionClosed(err, connSnapshot)
	return conn, err
}

// wrapIfConnectionClosed checks if the error returned by quic-go
// indicates that the QUIC connection has been permanently closed,
// and if so, wraps the error with coreErrs.ClosedError.
// PITFALL: sometimes quic-go has "internal errors" that are not net.Error,
// but we still need to treat them as ClosedError.
func (c *clientImpl) handleIfConnectionClosed(err error, originConn quic.Connection) {
	if !tunnelFatalError(err) {
		return
	}
	// Hold the mutex to avoid racing with connect() which may have
	// already replaced c.conn/c.pktConn with new instances.
	c.m.Lock()
	defer c.m.Unlock()
	// Only close if the connection is still the one that errored.
	// If connect() already ran, c.conn is a new instance and must not
	// be closed — doing so would kill the fresh QUIC session.
	if c.conn == originConn {
		c.closeExistingLocked()
	}
}

// tunnelFatalError reports whether err means the shared QUIC tunnel itself is
// dead and should be torn down. Stream-, caller- and input-scoped errors must
// return false: tearing the tunnel down for them kills healthy streams and
// forces a full re-handshake for everyone.
func tunnelFatalError(err error) bool {
	if err == nil {
		return false
	}

	// Stream-scoped failures must not tear down the shared tunnel: a RESET
	// on one stream (quic.StreamError), a refused stream-limit probe, or a
	// temporary/datagram-backpressure error only affects that attempt,
	// while other streams on the connection stay healthy.
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return false
	}
	if outbounderrors.IsStreamExhausted(err) || outbounderrors.IsTemporaryError(err) {
		return false
	}

	var closedErr coreErrs.ClosedError
	if errors.As(err, &closedErr) {
		return true
	}
	// A server FIN without a response (protocol.ReadTCPResponse surfaces it
	// as io.EOF) is a per-stream condition, not a tunnel death.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	// Caller-scoped abort: the dial context died, the tunnel did not.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Local input validation (e.g. a malformed target address) must not
	// kill the shared connection.
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() { // nolint:staticcheck
		return false
	}
	return true
}

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool

	// deadlineMu serializes caller deadline changes with handshake cleanup.
	// Until the response is consumed, the dial deadline caps both directions.
	deadlineMu    sync.Mutex
	dialDeadline  time.Time
	readDeadline  time.Time
	writeDeadline time.Time

	// Fast-open mode defers the response read to the first Read. The once
	// guarantees exactly one ReadTCPResponse even if callers race the first
	// reads, so every reader observes the same handshake outcome.
	establishOnce sync.Once
	respErr       error
}

func (c *tcpConn) readFastOpenResponse() error {
	c.establishOnce.Do(func() {
		defer func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			if !c.dialDeadline.IsZero() {
				c.dialDeadline = time.Time{}
				_ = c.Orig.SetReadDeadline(c.readDeadline)
				_ = c.Orig.SetWriteDeadline(c.writeDeadline)
			}
		}()
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			c.respErr = err
			return
		}
		if !ok {
			c.respErr = coreErrs.DialError{Message: "from remote: " + msg}
		}
	})
	return c.respErr
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if !c.Established {
		// Read response
		if err = c.readFastOpenResponse(); err != nil {
			return 0, err
		}
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

func (c *tcpConn) CloseWrite() error {
	// quic-go's default close only closes the write side
	// for more info, see comments in utils.QStream struct
	return c.Orig.Stream.Close()
}

func (c *tcpConn) CloseRead() error {
	c.Orig.Stream.CancelRead(0)
	return nil
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

// handshakeDeadline returns the earlier nonzero deadline. Caller deadlines
// cannot extend or disable the dial timeout while the response is pending.
func (c *tcpConn) handshakeDeadline(t time.Time) time.Time {
	if !c.dialDeadline.IsZero() && (t.IsZero() || c.dialDeadline.Before(t)) {
		return c.dialDeadline
	}
	return t
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline, c.writeDeadline = t, t
	return c.Orig.SetDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	return c.Orig.SetReadDeadline(c.handshakeDeadline(t))
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = t
	return c.Orig.SetWriteDeadline(c.handshakeDeadline(t))
}

type udpIOImpl struct {
	Conn quic.Connection
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		buf, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			if !outbounderrors.IsTemporaryError(err) {
				return nil, err
			}
			// Some temporary errors (notably stateless reset) are delivered
			// after the datagram queue is already closed, so Receive returns
			// immediately from then on. Exit via the connection context
			// instead of spinning in a tight loop.
			if ctxErr := io.Conn.Context().Err(); ctxErr != nil {
				return nil, ctxErr
			}
			continue
		}
		udpMsg, err := protocol.ParseUDPMessage(buf)
		if err != nil {
			// Invalid message - return the pooled buffer before waiting for
			// the next datagram.
			io.Conn.ReleaseDatagram(buf)
			continue
		}
		// Attach the buffer release so the consumer can return storage to
		// the quic-go pool once it is done with Data (which aliases buf).
		udpMsg.Release = func() { io.Conn.ReleaseDatagram(buf) }
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		return &quic.DatagramTooLargeError{MaxDataLen: int64(len(buf))}
	}
	return io.Conn.SendDatagram(buf[:msgN])
}

// ReadBuffered reports immediately-readable stream bytes from the QUIC
// receive path. Until the deferred handshake response is consumed the
// signal reports the stream only, never the pending response bytes, so it
// stays conservative during fast open. It backs write-batching copy loops
// that must not issue speculative reads or arm deadlines on streams.
func (c *tcpConn) ReadBuffered() int {
	if rb, ok := c.Orig.Stream.(interface{ ReadBuffered() int }); ok {
		return rb.ReadBuffered()
	}
	return 0
}
