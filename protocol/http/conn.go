package http

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/http2"
)

var httpRequestLinePattern = regexp.MustCompile(`^\S+ \S+ HTTP/[\d.]+$`)

var httpMethods = [][]byte{
	[]byte("GET"),
	[]byte("HEAD"),
	[]byte("POST"),
	[]byte("PUT"),
	[]byte("DELETE"),
	[]byte("CONNECT"),
	[]byte("OPTIONS"),
	[]byte("TRACE"),
	[]byte("PATCH"),
	[]byte("PRI"),
}

const (
	connLifeIdle int32 = iota
	connLifeHandshaking
	connLifeReady
	connLifeClosed
)

// maxPendingFirstWriteSize bounds the plain-HTTP request sniffing buffer.
// The buffered bytes come from the proxied client, so without a cap a client
// streaming bytes without a request terminator grows memory without limit and
// re-parses the whole buffer on every Write (quadratic CPU). 64 KiB is well
// above any realistic client request header budget.
const maxPendingFirstWriteSize = 64 * 1024

type publishResult int

const (
	publishOK publishResult = iota
	publishRejected
	publishStolen
)

type publishedConn struct {
	conn netproxy.Conn
	h2   bool
}

type handshakeCancel struct {
	cancel context.CancelFunc
}

type Conn struct {
	nextDialer netproxy.Dialer

	proxy        *HttpProxy
	magicNetwork string
	tgt          string
	// handshakeDeadline preserves the original dial budget for the lazy
	// proxy handshake that starts on the first Read/Write.
	handshakeDeadline time.Time

	ctxShakeFinished    context.Context
	cancelShakeFinished func()
	closeCtx            context.Context
	closeCancel         context.CancelFunc

	// life is a monotonic lifecycle: idle -> handshaking -> ready -> closed.
	life      atomic.Int32
	published atomic.Pointer[publishedConn]
	hsCancel  atomic.Pointer[handshakeCancel]

	muShake            sync.Mutex
	muFinishShakeFuncs sync.Mutex
	finishShakeFuncs   []func(conn netproxy.Conn)
	// finishShakeFuncsApplied is set (under muFinishShakeFuncs) when the
	// queued closures have been applied. It closes the window between
	// applyFinishShakeFuncs returning and ctxShakeFinished firing, in which
	// a concurrent SetXDeadline would otherwise queue a closure that nobody
	// ever runs while still reporting success.
	finishShakeFuncsApplied bool

	closeOnce sync.Once

	pendingFirstWrite bytes.Buffer
}

// setDeadlineDuringShake applies a deadline change while a lazy handshake may
// still be pending. When the inner conn is already there it applies the
// deadline immediately (io.EOF when the conn is gone, a no-op on the
// multiplexed h2 session); otherwise it queues a closure that replays the
// deadline on the conn the handshake ends up with.
func (c *Conn) setDeadlineDuringShake(t time.Time, apply func(conn netproxy.Conn, t time.Time) error) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	if c.finishShakeFuncsApplied {
		conn, h2 := c.currentConn()
		if conn == nil {
			return io.EOF
		}
		if h2 {
			return nil
		}
		return apply(conn, t)
	}
	select {
	case <-c.ctxShakeFinished.Done():
		conn, h2 := c.currentConn()
		if conn == nil {
			return io.EOF
		}
		if h2 {
			return nil
		}
		return apply(conn, t)
	default:
	}
	c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn netproxy.Conn) {
		if _, h2 := c.currentConn(); h2 {
			return
		}
		_ = apply(conn, t)
	})
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.setDeadlineDuringShake(t, netproxy.Conn.SetDeadline)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.setDeadlineDuringShake(t, netproxy.Conn.SetReadDeadline)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the current inner conn. This type overrides
// SetWriteDeadline (the deadline may target a different inner conn after a
// handshake retry), so the optional declaration must be forwarded explicitly or
// a session-closing inner conn becomes invisible to deadline-arming callers.
func (c *Conn) WriteDeadlineClosesSession() bool {
	conn, h2 := c.currentConn()
	if conn == nil {
		return false
	}
	if h2 {
		// The HTTP/2 transport multiplexes every flow onto one session, so it
		// exposes no destructive per-flow write deadline.
		return false
	}
	return netproxy.WriteDeadlineClosesSession(conn)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadlineDuringShake(t, netproxy.Conn.SetWriteDeadline)
}

func NewConn(ctx context.Context, nextDialer netproxy.Dialer, proxy *HttpProxy, addr string, network string) *Conn {
	ctxShakeFinished, cancelShakeFinished := context.WithCancel(context.Background())
	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &Conn{
		nextDialer:          nextDialer,
		proxy:               proxy,
		tgt:                 addr,
		magicNetwork:        network,
		handshakeDeadline:   netproxy.CaptureDeadline(ctx),
		ctxShakeFinished:    ctxShakeFinished,
		cancelShakeFinished: cancelShakeFinished,
		closeCtx:            closeCtx,
		closeCancel:         closeCancel,
	}
}

func (c *Conn) newHandshakeContext() (context.Context, context.CancelFunc) {
	base, cancelBase := netproxy.NewDialTimeoutContextWithCapturedDeadline(c.handshakeDeadline)
	ctx, cancelLinked := context.WithCancel(c.closeCtx)
	if deadline, ok := base.Deadline(); ok {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithDeadline(ctx, deadline)
		cancel := func() {
			cancelDeadline()
			cancelLinked()
			cancelBase()
		}
		c.storeHandshakeCancel(cancel)
		return ctx, cancel
	}
	cancel := func() {
		cancelLinked()
		cancelBase()
	}
	c.storeHandshakeCancel(cancel)
	return ctx, cancel
}

func (c *Conn) storeHandshakeCancel(cancel context.CancelFunc) {
	c.hsCancel.Store(&handshakeCancel{cancel: cancel})
	if c.closed() {
		cancel()
	}
}

func (c *Conn) currentConn() (netproxy.Conn, bool) {
	if published := c.published.Load(); published != nil {
		return published.conn, published.h2
	}
	return nil, false
}

func (c *Conn) closed() bool {
	return c.life.Load() == connLifeClosed
}

// publishConn installs a locally-owned candidate after a closed-check.
// The candidate stays off the published slot until this returns publishOK
// so a racing Close cannot miss it and a late ignored-ctx Dial cannot
// publish after Close.
func (c *Conn) publishConn(conn netproxy.Conn, h2 bool) publishResult {
	if conn == nil || c.closed() {
		return publishRejected
	}
	published := &publishedConn{conn: conn, h2: h2}
	if !c.published.CompareAndSwap(nil, published) {
		return publishRejected
	}
	c.life.CompareAndSwap(connLifeHandshaking, connLifeReady)
	if !c.closed() {
		return publishOK
	}
	// Close raced the publication. Taking the slot back means Write still
	// owns the candidate; a failed take-back means Close already closed it.
	if c.published.CompareAndSwap(published, nil) {
		return publishRejected
	}
	return publishStolen
}

func watchConnCancel(ctx context.Context, conn netproxy.Conn) func() {
	if ctx == nil || conn == nil {
		return func() {}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return func() { stop() }
}

func (c *Conn) discardCandidate(conn netproxy.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Close()
}

func (c *Conn) applyFinishShakeFuncs(conn netproxy.Conn) {
	if conn == nil {
		return
	}
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	c.finishShakeFuncsApplied = true
	for _, f := range c.finishShakeFuncs {
		f(conn)
	}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if published := c.published.Load(); published != nil && published.conn != nil {
		return published.conn.Write(b)
	}
	if c.closed() {
		return 0, io.EOF
	}

	c.muShake.Lock()
	defer c.muShake.Unlock()

	if published := c.published.Load(); published != nil && published.conn != nil {
		return published.conn.Write(b)
	}
	if c.closed() {
		return 0, io.EOF
	}
	select {
	case <-c.ctxShakeFinished.Done():
		conn, _ := c.currentConn()
		if conn == nil {
			return 0, io.EOF
		}
		return conn.Write(b)
	default:
		// Handshake
		handshakeInput := b
		hadPendingFirstWrite := c.pendingFirstWrite.Len() > 0
		if hadPendingFirstWrite {
			_, _ = c.pendingFirstWrite.Write(b)
			handshakeInput = c.pendingFirstWrite.Bytes()
		}

		firstLine, hasFirstLine := readHTTPFirstLine(handshakeInput)
		// The sniffing buffer is attacker-influenced (any proxied client can
		// stream bytes without a terminator), so it must be bounded: without
		// a cap, memory grows without limit and every Write re-parses the
		// whole buffer (quadratic CPU). A request that cannot be recognized
		// within the budget fails the conn instead.
		if !c.proxy.https && !hasFirstLine && len(handshakeInput) > maxPendingFirstWriteSize {
			c.pendingFirstWrite.Reset()
			return 0, fmt.Errorf("http: request line exceeds %d bytes", maxPendingFirstWriteSize)
		}
		if !c.proxy.https && !hasFirstLine && isPossibleHTTPRequestLinePrefix(handshakeInput) {
			if !hadPendingFirstWrite {
				_, _ = c.pendingFirstWrite.Write(handshakeInput)
			}
			return len(b), nil
		}
		isHttpReq := !c.proxy.https && httpRequestLinePattern.Match(firstLine)
		payload := b
		bufferedPrefixLen := 0
		if hadPendingFirstWrite && !isHttpReq {
			payload = bytes.Clone(handshakeInput)
			bufferedPrefixLen = len(payload) - len(b)
		}

		var req *http.Request
		if isHttpReq && !c.proxy.https {
			// HTTP Request

			req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(handshakeInput)))
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					// handshakeInput includes the current write. Check it before
					// retaining the bytes so a large first write cannot bypass the
					// pending buffer budget.
					if len(handshakeInput) <= maxPendingFirstWriteSize {
						if c.pendingFirstWrite.Len() == 0 {
							_, _ = c.pendingFirstWrite.Write(handshakeInput)
						}
						return len(b), nil
					}
					c.pendingFirstWrite.Reset()
					err = fmt.Errorf("http: request header exceeds %d bytes: %w", maxPendingFirstWriteSize, err)
				}
				// Error
				return 0, err
			}

			req.URL.Scheme = "http"
			req.URL.Host = c.tgt
			c.pendingFirstWrite.Reset()
		} else {
			// Arbitrary TCP

			// HACK. http.ReadRequest also does this.
			reqURL, err := url.Parse("http://" + c.tgt)
			if err != nil {
				return 0, err
			}
			method := "CONNECT"
			if !c.proxy.transport {
				reqURL.Scheme = ""
			} else {
				method = "PUT"
			}

			req, err = http.NewRequest(method, reqURL.String(), nil)
			if err != nil {
				return 0, err
			}
			c.pendingFirstWrite.Reset()
		}
		defer c.cancelShakeFinished()
		if c.proxy.Host != "" {
			req.Host = c.proxy.Host
		} else if c.proxy.transport {
			req.Host = "www.example.com"
		}
		if c.proxy.transport {
			req.URL.Path = c.proxy.Path
		}
		req.Close = false
		if c.proxy.HaveAuth {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.proxy.Username+":"+c.proxy.Password)))
		}
		// https://www.rfc-editor.org/rfc/rfc7230#appendix-A.1.2
		// As a result, clients are encouraged not to send the Proxy-Connection header field in any requests.
		if len(req.Header.Values("Proxy-Connection")) > 0 {
			req.Header.Del("Proxy-Connection")
		}

		connectHttp1 := func(handshakeCtx context.Context, rawConn netproxy.Conn) (conn netproxy.Conn, n int, err error) {
			if handshakeCtx != nil {
				if err := handshakeCtx.Err(); err != nil {
					return nil, 0, err
				}
			}
			restoreDeadline, err := netproxy.ApplyConnDeadlineFromContext(handshakeCtx, rawConn)
			if err != nil {
				return nil, 0, err
			}
			defer restoreDeadline()
			stopWatch := watchConnCancel(handshakeCtx, rawConn)
			defer stopWatch()

			proxyReq := req.Clone(context.Background())
			err = proxyReq.WriteProxy(rawConn)
			if err != nil {
				return nil, 0, err
			}

			if isHttpReq {
				// Forward-proxy request: the proxy streams the origin's
				// response verbatim, so the caller keeps reading rawConn.
				// Allow read here to void race.
				return rawConn, len(b), nil
			}

			// We should read tcp connection here, and we will be guaranteed higher priority by chShakeFinished.
			// The response is consumed through a bufio.Reader so any bytes the
			// reader pulled past the header (coalesced early tunnel data) are
			// preserved via prefixedConn instead of being lost to the kernel
			// buffer.
			br := bufio.NewReaderSize(rawConn, 4096)
			resp, err := http.ReadResponse(br, proxyReq)
			if err != nil {
				if resp != nil {
					_ = resp.Body.Close()
				}
				return nil, 0, err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				err = fmt.Errorf("connect server using proxy error, StatusCode [%d]", resp.StatusCode)
				return nil, 0, err
			}
			conn = rawConn
			if buffered := br.Buffered(); buffered > 0 {
				prefix := make([]byte, buffered)
				read, _ := io.ReadFull(br, prefix)
				if read > 0 {
					conn = &prefixedConn{Conn: rawConn, prefix: prefix[:read]}
				}
			}
			written, err := conn.Write(payload)
			if err != nil {
				if written <= bufferedPrefixLen {
					return conn, 0, err
				}
				return conn, written - bufferedPrefixLen, err
			}
			if written < len(payload) {
				if written <= bufferedPrefixLen {
					return conn, 0, io.ErrShortWrite
				}
				return conn, written - bufferedPrefixLen, io.ErrShortWrite
			}
			return conn, len(b), nil
		}

		// Thanks to v2fly/v2ray-core.
		// The candidate is typed netproxy.Conn, not *http2Conn: a plain nil
		// *http2Conn on the failure paths below would wrap into a non-nil
		// interface at the finishHandshake call, and discardCandidate would
		// then call Close on a nil *http2Conn and panic. connectHttp1 has the
		// same shape and already returns the interface.
		connectHttp2 := func(handshakeCtx context.Context, rawConn netproxy.Conn, h2clientConn *http2.ClientConn, req *http.Request) (conn netproxy.Conn, n int, err error) {
			if handshakeCtx != nil {
				select {
				case <-handshakeCtx.Done():
					return nil, 0, handshakeCtx.Err()
				default:
				}
			}

			requestCtx, cancelRequest := context.WithCancel(c.closeCtx)
			requestOwnedByConn := false
			defer func() {
				if !requestOwnedByConn {
					cancelRequest()
				}
			}()
			proxyReq := req.Clone(requestCtx)
			pr, pw := io.Pipe()
			proxyReq.Body = pr

			var stopHandshakeWatch func() bool
			var handshakeWatchDone chan struct{}
			if handshakeCtx != nil {
				handshakeWatchDone = make(chan struct{})
				stopHandshakeWatch = context.AfterFunc(handshakeCtx, func() {
					cancelRequest()
					close(handshakeWatchDone)
				})
			}
			detachHandshakeWatch := func() error {
				if stopHandshakeWatch == nil {
					return nil
				}
				if stopHandshakeWatch() {
					stopHandshakeWatch = nil
					return nil
				}
				<-handshakeWatchDone
				stopHandshakeWatch = nil
				return handshakeCtx.Err()
			}
			defer func() {
				if stopHandshakeWatch != nil {
					_ = stopHandshakeWatch()
				}
			}()

			var pErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, pErr = pw.Write(b)
			}()

			resp, err := h2clientConn.RoundTrip(proxyReq) // nolint: bodyclose
			if err != nil {
				_ = pw.CloseWithError(err)
				<-done
				if handshakeErr := detachHandshakeWatch(); handshakeErr != nil {
					return nil, 0, handshakeErr
				}
				return nil, 0, err
			}

			<-done
			if pErr != nil {
				_ = resp.Body.Close()
				return nil, 0, pErr
			}
			if handshakeErr := detachHandshakeWatch(); handshakeErr != nil {
				_ = resp.Body.Close()
				return nil, 0, handshakeErr
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				return nil, 0, fmt.Errorf("proxy responded with non 200 code: %v", resp.Status)
			}

			requestOwnedByConn = true
			return newHTTP2Conn(&netproxy.FakeNetConn{
				Conn: rawConn,
			}, pw, resp.Body, cancelRequest), len(b), nil
		}

		c.life.CompareAndSwap(connLifeIdle, connLifeHandshaking)
		if c.closed() {
			return 0, io.EOF
		}

		finishHandshake := func(candidate netproxy.Conn, h2 bool, n int, err error) (int, error) {
			if err != nil {
				c.discardCandidate(candidate)
				return n, err
			}
			if candidate == nil {
				if c.closed() {
					return 0, io.EOF
				}
				return n, nil
			}
			switch c.publishConn(candidate, h2) {
			case publishOK:
				c.applyFinishShakeFuncs(candidate)
				return n, nil
			case publishStolen:
				return 0, io.EOF
			default:
				c.discardCandidate(candidate)
				return 0, io.EOF
			}
		}

		if !c.proxy.https {
			ctx, cancel := c.newHandshakeContext()
			defer cancel()
			conn, err := c.nextDialer.DialContext(ctx, c.magicNetwork, c.proxy.Addr)
			if err != nil {
				if conn != nil {
					c.discardCandidate(conn)
				}
				return 0, err
			}
			if c.closed() {
				c.discardCandidate(conn)
				return 0, io.EOF
			}
			effConn, n, err := connectHttp1(ctx, conn)
			if err != nil && effConn == nil {
				c.discardCandidate(conn)
				return n, err
			}
			return finishHandshake(effConn, false, n, err)
		}

		handshakeCtx, cancel := c.newHandshakeContext()
		defer cancel()
		rawConn, h2Conn, err := connPool.GetConn(handshakeCtx, c.nextDialer, c.proxy.Addr, c.magicNetwork)
		if err != nil {
			if rawConn != nil && h2Conn == nil {
				c.discardCandidate(rawConn)
			}
			return 0, err
		}
		if c.closed() {
			if h2Conn == nil {
				c.discardCandidate(rawConn)
			}
			return 0, io.EOF
		}
		if h2Conn != nil {
			proxyConn, n, err := connectHttp2(handshakeCtx, rawConn, h2Conn, req)
			return finishHandshake(proxyConn, true, n, err)
		}
		effConn, n, err := connectHttp1(handshakeCtx, rawConn)
		if err != nil && effConn == nil {
			c.discardCandidate(rawConn)
			return n, err
		}
		return finishHandshake(effConn, false, n, err)
	}
}

func readHTTPFirstLine(b []byte) ([]byte, bool) {
	lineEnd := bytes.IndexByte(b, '\n')
	if lineEnd < 0 {
		return nil, false
	}
	return bytes.TrimRight(b[:lineEnd], "\r"), true
}

func isPossibleHTTPRequestLinePrefix(b []byte) bool {
	method := b
	if methodEnd := bytes.IndexByte(b, ' '); methodEnd >= 0 {
		method = b[:methodEnd]
	}
	if len(method) == 0 {
		return false
	}
	for _, c := range method {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	for _, httpMethod := range httpMethods {
		if bytes.Equal(method, httpMethod) {
			return true
		}
		if bytes.HasPrefix(httpMethod, method) {
			return true
		}
	}
	return false
}

func (c *Conn) Read(b []byte) (n int, err error) {
	<-c.ctxShakeFinished.Done()
	conn, _ := c.currentConn()
	if conn == nil {
		return 0, io.EOF
	}
	return conn.Read(b)
}

func (c *Conn) CloseWrite() error {
	conn, h2 := c.currentConn()
	if conn == nil {
		return nil
	}
	if h2 {
		if wc, ok := conn.(netproxy.WriteCloser); ok {
			return wc.CloseWrite()
		}
		return nil
	}
	return netproxy.ForwardCloseWrite(conn)
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.life.Store(connLifeClosed)
		if c.closeCancel != nil {
			c.closeCancel()
		}
		if hs := c.hsCancel.Load(); hs != nil && hs.cancel != nil {
			hs.cancel()
		}
		if c.cancelShakeFinished != nil {
			c.cancelShakeFinished()
		}
		published := c.published.Swap(nil)
		if published == nil || published.conn == nil {
			return
		}
		// Logical H2 Close closes the request pipe + response body only.
		// The pooled physical HTTP/2 connection stays in the pool because
		// http2Conn.Close does not close the underlay.
		err = published.conn.Close()
	})
	return err
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser, cancel context.CancelFunc) *http2Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody, cancel: cancel}
}

// prefixedConn replays bytes a handshake bufio.Reader consumed past the
// CONNECT response before handing reads to the underlying tunnel, so
// coalesced early application data is not dropped.
type prefixedConn struct {
	netproxy.Conn
	prefix []byte
}

func (p *prefixedConn) Read(b []byte) (n int, err error) {
	if len(p.prefix) > 0 {
		n = copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *prefixedConn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(p.Conn)
}

type http2Conn struct {
	net.Conn
	in        *io.PipeWriter
	out       io.ReadCloser
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) CloseWrite() error {
	if h.in == nil {
		return nil
	}
	return h.in.Close()
}

func (h *http2Conn) Close() error {
	h.closeOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		inErr := h.in.Close()
		outErr := h.out.Close()
		if inErr != nil && outErr != nil {
			h.closeErr = fmt.Errorf("in.Close(): %w; out.Close(): %v", inErr, outErr)
		} else if inErr != nil {
			h.closeErr = inErr
		} else {
			h.closeErr = outErr
		}
	})
	return h.closeErr
}

type h2Conn struct {
	rawConn netproxy.Conn
	h2Conn  *http2.ClientConn
}

type lockedList struct {
	l    *list.List
	mu   sync.Mutex
	refs int
}

func newLockedList() *lockedList {
	return &lockedList{
		l:    list.New(),
		mu:   sync.Mutex{},
		refs: 0,
	}
}

type poolIdent struct {
	ele *list.Element
	// key is the full pool map key: namespace|magicNetwork|addr.
	// MarkDead / cleanup must use this, not the bare host:port.
	key string
}
type addrDialerBinding struct {
	key          string
	dialer       netproxy.Dialer
	magicNetwork string
}

type h2ConnsPool struct {
	mu           sync.Mutex
	h2ConnsPool  map[string]*lockedList
	h2Conn2Ident map[*http2.ClientConn]*poolIdent
	// addr2Dialer keeps all live scoped bindings in insertion order for each
	// bare host:port. GetClientConn uses the latest binding; removing it falls
	// back to the previous live scope.
	addr2Dialer map[string][]addrDialerBinding
}

func newH2ConnsPool() *h2ConnsPool {
	return &h2ConnsPool{
		mu:           sync.Mutex{},
		h2ConnsPool:  make(map[string]*lockedList),
		h2Conn2Ident: make(map[*http2.ClientConn]*poolIdent),
		addr2Dialer:  make(map[string][]addrDialerBinding),
	}
}

func (p *h2ConnsPool) registerAddrToDialerMapping(addr string, dialer netproxy.Dialer, magicNetwork string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := string(netproxy.TransportCacheNamespace(dialer)) + "|" + magicNetwork + "|" + addr
	p.retainAddrDialerLocked(addr, key, dialer, magicNetwork)
}

func (p *h2ConnsPool) retainAddrDialerLocked(addr, key string, dialer netproxy.Dialer, magicNetwork string) {
	bindings := p.addr2Dialer[addr]
	for i := range bindings {
		if bindings[i].key == key {
			bindings[i].dialer = dialer
			bindings[i].magicNetwork = magicNetwork
			p.addr2Dialer[addr] = bindings
			return
		}
	}
	p.addr2Dialer[addr] = append(bindings, addrDialerBinding{
		key:          key,
		dialer:       dialer,
		magicNetwork: magicNetwork,
	})
}

func (p *h2ConnsPool) releaseAddrDialerLocked(addr, key string) {
	bindings := p.addr2Dialer[addr]
	for i := range bindings {
		if bindings[i].key != key {
			continue
		}
		copy(bindings[i:], bindings[i+1:])
		bindings = bindings[:len(bindings)-1]
		if len(bindings) == 0 {
			delete(p.addr2Dialer, addr)
		} else {
			p.addr2Dialer[addr] = bindings
		}
		return
	}
}

func poolKeyBareAddr(key string) string {
	// key is namespace|magicNetwork|addr; addr itself may contain ':'.
	i := strings.IndexByte(key, '|')
	if i < 0 {
		return key
	}
	j := strings.IndexByte(key[i+1:], '|')
	if j < 0 {
		return key
	}
	return key[i+1+j+1:]
}

func (p *h2ConnsPool) acquireConnList(addr string) (*lockedList, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns, cached := p.h2ConnsPool[addr]
	if conns == nil {
		conns = newLockedList()
		p.h2ConnsPool[addr] = conns
	}
	conns.refs++
	return conns, cached
}

func (p *h2ConnsPool) acquireConnListForDialer(key string, addr string, dialer netproxy.Dialer, magicNetwork string) (*lockedList, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns, cached := p.h2ConnsPool[key]
	if conns == nil {
		conns = newLockedList()
		p.h2ConnsPool[key] = conns
		p.retainAddrDialerLocked(addr, key, dialer, magicNetwork)
	} else {
		p.retainAddrDialerLocked(addr, key, dialer, magicNetwork)
	}
	conns.refs++
	return conns, cached
}

func (p *h2ConnsPool) releaseConnList(addr string, conns *lockedList) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conns.refs > 0 {
		conns.refs--
	}
	p.cleanupConnListLocked(addr, conns)
}

func (p *h2ConnsPool) cleanupConnListLocked(addr string, conns *lockedList) {
	if conns == nil || p.h2ConnsPool[addr] != conns || conns.refs != 0 {
		return
	}
	conns.mu.Lock()
	empty := conns.l.Len() == 0
	conns.mu.Unlock()
	if !empty {
		return
	}
	delete(p.h2ConnsPool, addr)
	p.releaseAddrDialerLocked(poolKeyBareAddr(addr), addr)
}

func (p *h2ConnsPool) GetConn(ctx context.Context, nextDialer netproxy.Dialer, addr string, magicNetwork string) (netproxy.Conn, *http2.ClientConn, error) {
	// Key by address + network + the chained dialer's transport namespace:
	// a config reload that swaps the underlying chain must not reuse
	// connections dialed through the previous generation.
	scopeKey := string(netproxy.TransportCacheNamespace(nextDialer)) + "|" + magicNetwork
	fullKey := scopeKey + "|" + addr
	conns, cachedConnsFound := p.acquireConnListForDialer(fullKey, addr, nextDialer, magicNetwork)
	defer p.releaseConnList(fullKey, conns)

	if cachedConnsFound {
		conns.mu.Lock()
		if conns.l.Len() > 0 {
			for p := conns.l.Front(); p != nil; p = p.Next() {
				h2Conn := p.Value.(*h2Conn)
				if h2Conn.h2Conn.CanTakeNewRequest() {
					conns.mu.Unlock()
					return h2Conn.rawConn, h2Conn.h2Conn, nil
				}
			}
		}
		conns.mu.Unlock()
	}

	// New.
	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	defer cancel()
	rawConn, err := nextDialer.DialContext(dialCtx, magicNetwork, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("h2ConnsPool.GetClientConn: %w", err)
	}
	nextProto := ""
	// An https proxy reaches this pool through transport/tls, which returns a
	// coalescer wrapper around the *tls.Conn: peeling before the assertion is
	// what makes the negotiated ALPN visible here. Asserting on rawConn alone
	// left nextProto empty and silently downgraded every https proxy to
	// HTTP/1.1 CONNECT.
	if tlsConn, ok := netproxy.UnwrapIntrinsicConn(rawConn).(*tls.Conn); ok {
		if err := netproxy.HandshakeWithContext(dialCtx, tlsConn); err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	switch nextProto {
	case "", "http/1.1":
		return rawConn, nil, nil
	case "h2":
		t := http2.Transport{
			ConnPool:        p,
			IdleConnTimeout: 90 * time.Second,
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
		h2clientConn, err := t.NewClientConn(&netproxy.FakeNetConn{
			Conn: rawConn,
		})
		if err != nil {
			return nil, nil, err
		}
		conns.mu.Lock()
		ele := conns.l.PushFront(&h2Conn{
			rawConn: rawConn,
			h2Conn:  h2clientConn,
		})
		conns.mu.Unlock()
		p.mu.Lock()
		p.h2Conn2Ident[h2clientConn] = &poolIdent{
			ele: ele,
			key: fullKey,
		}
		p.mu.Unlock()
		return rawConn, h2clientConn, nil
	default:
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("negotiated unsupported application layer protocol: %v", nextProto)
	}
}

func (p *h2ConnsPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.Lock()
	bindings := p.addr2Dialer[addr]
	if len(bindings) == 0 {
		p.mu.Unlock()
		return nil, fmt.Errorf("no valid dialer for h2ConnsPool.GetClientConn")
	}
	e := bindings[len(bindings)-1]
	p.mu.Unlock()
	if e.dialer == nil {
		return nil, fmt.Errorf("no valid dialer for h2ConnsPool.GetClientConn")
	}
	_, h2Conn, err := p.GetConn(req.Context(), e.dialer, addr, e.magicNetwork)
	return h2Conn, err
}

func (p *h2ConnsPool) MarkDead(h2c *http2.ClientConn) {
	p.mu.Lock()
	ident, ok := p.h2Conn2Ident[h2c]
	if !ok {
		p.mu.Unlock()
		return
	}
	key := ident.key
	conns := p.h2ConnsPool[key]
	delete(p.h2Conn2Ident, h2c)
	p.mu.Unlock()
	if conns == nil {
		return
	}
	conns.mu.Lock()
	conns.l.Remove(ident.ele)
	conns.mu.Unlock()
	p.mu.Lock()
	p.cleanupConnListLocked(key, conns)
	p.mu.Unlock()
}

var connPool = newH2ConnsPool()
