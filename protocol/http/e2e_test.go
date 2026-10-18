package http_test

// True end-to-end coverage for the HTTP proxy client stack: an in-test HTTP
// CONNECT server (own wire implementations for HTTP/1.1 and HTTP/2, not a
// copy of protocol/http) fronting a real loopback echo target, reached through
// the same dialer chain dae builds (direct -> [transport/tls] -> protocol/http
// via dialer/http's registered constructor).
//
// The plain variant exercises the raw HTTP/1.1 CONNECT relay. The https
// variant goes through transport/tls and its UnderlyingConnForwarder
// wrapper; the
// negotiated ALPN decides between the client's HTTP/1.1 and HTTP/2 CONNECT
// implementations (protocol/http/conn.go connPool.GetConn), so the server
// dispatches on ALPN exactly like a normal dual-stack proxy and records what
// it observed. The tests then pin the ALPN and the wire path instead of
// letting a silent protocol downgrade pass.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/daeuniverse/outbound/dialer"
	dialerhttp "github.com/daeuniverse/outbound/dialer/http"
	"github.com/daeuniverse/outbound/netproxy"
)

// ---- shared helpers (the per-protocol e2e convention) ----

// loopbackEchoTarget starts a TCP echo server; everything received is sent
// back, and a peer half-close (FIN) is propagated back as EOF after the
// remaining output is flushed. The echo is an explicit read/write loop so the
// relay volume never depends on io.Copy's splice fast paths.
func loopbackEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32<<10)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr()
}

// e2eSelfSignedCert mints the server certificate for the in-test TLS listener.
func e2eSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// deadlineCtx bounds every dial in the e2e so a hung protocol layer fails the
// test instead of hanging it.
func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// hangWatchdog fails the test if the scenario outlives d. The HTTP/2 client
// path deliberately makes per-flow deadlines no-ops (a multiplexed session
// cannot honor a per-stream socket deadline), so the h2 scenarios need this
// second hang guard next to the ordinary read deadlines.
func hangWatchdog(t *testing.T, d time.Duration) (stop func()) {
	t.Helper()
	var done atomic.Bool
	timer := time.AfterFunc(d, func() {
		if !done.Load() {
			t.Errorf("watchdog: scenario exceeded %v; the relay stalled", d)
		}
	})
	return func() {
		done.Store(true)
		timer.Stop()
	}
}

// verifyRelayRoundTrip writes a large deterministic payload through c while
// concurrently reading it back, and checks integrity. Large enough to cross
// TLS record and buffer boundaries. A write-side error fails the test
// immediately instead of leaving the read loop waiting for bytes nobody will
// produce.
func verifyRelayRoundTrip(t *testing.T, c netproxy.Conn, total int) {
	t.Helper()
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sent := 0
	var werr error
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		for sent < total {
			n := len(payload)
			if total-sent < n {
				n = total - sent
			}
			if _, err := c.Write(payload[:n]); err != nil {
				werr = err
				t.Errorf("relay writer stopped at %d/%d: %v", sent, total, err)
				return
			}
			sent += n
		}
	}()
	got := 0
	buf := make([]byte, 32<<10)
	if err := c.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for got < total {
		n, err := c.Read(buf)
		if err != nil {
			<-wrote
			t.Fatalf("read back at %d/%d (writer sent %d, writer err=%v): %v", got, total, sent, werr, err)
		}
		// Verify every byte, which also crosses record and buffer boundaries.
		for i := 0; i < n; i++ {
			if want := byte(((got + i) % len(payload)) * 7); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
	<-wrote
	if werr != nil {
		t.Fatalf("relay writer failed after full read: %v", werr)
	}
}

// halfCloseAndExpectEOF asserts the CloseWrite capability on the conn the
// client actually returned, half-closes, and expects the target EOF to
// propagate back through the proxy. A lost capability must fail the test, not
// skip the check. armDeadline is false for the h2 path, where per-flow
// deadlines are documented no-ops and the test-level watchdog bounds the wait.
func halfCloseAndExpectEOF(t *testing.T, c netproxy.Conn, armDeadline bool) {
	t.Helper()
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("http conn %T lost the CloseWrite capability", c)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if armDeadline {
		if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
	}
	buf := make([]byte, 1024)
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
	}
}

// ---- in-test HTTP CONNECT server (independent wire implementations) ----

type proxyMode int

const (
	// proxyPlain speaks plain HTTP/1.1 CONNECT on a raw TCP listener.
	proxyPlain proxyMode = iota
	// proxyTLSHTTP11 terminates TLS but only advertises http/1.1, so the
	// client (which offers h2 first by default) must fall back to its
	// HTTP/1.1 CONNECT implementation.
	proxyTLSHTTP11
	// proxyTLSH2 advertises ["h2", "http/1.1"] like a normal proxy; the
	// client's default ALPN list is h2-first, so this negotiates h2 and the
	// server dispatches the stream to its HTTP/2 CONNECT implementation.
	proxyTLSH2
)

// proxyServer is the in-test CONNECT proxy. It records what it observes so the
// tests can pin the negotiated ALPN and the wire path the client actually
// took, instead of trusting that no downgrade happened.
type proxyServer struct {
	addr string
	// alpnCh records the negotiated ALPN protocol of every accepted TLS conn.
	alpnCh chan string
	// http11Connect records the authority of HTTP/1.1 CONNECT requests.
	http11Connect chan string
	// h2Connect records the authority of HTTP/2 CONNECT streams.
	h2Connect chan string
}

// startProxyServer runs the in-test CONNECT proxy in the requested mode.
// denyCode != 0 makes every CONNECT reply with that status without dialing
// the target.
func startProxyServer(t *testing.T, mode proxyMode, denyCode int) *proxyServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ps := &proxyServer{
		addr:          ln.Addr().String(),
		alpnCh:        make(chan string, 16),
		http11Connect: make(chan string, 16),
		h2Connect:     make(chan string, 16),
	}
	h2srv := &http2.Server{}
	var tlsCfg *tls.Config
	if mode != proxyPlain {
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
			NextProtos:   []string{"http/1.1"},
		}
		if mode == proxyTLSH2 {
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		}
		ln = tls.NewListener(ln, tlsCfg)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go ps.serveConn(c, mode, denyCode, h2srv)
		}
	}()
	return ps
}

// serveConn terminates TLS when the mode needs it, records the negotiated
// ALPN, and dispatches to the HTTP/1.1 or HTTP/2 implementation exactly like a
// normal dual-stack proxy.
func (ps *proxyServer) serveConn(c net.Conn, mode proxyMode, denyCode int, h2srv *http2.Server) {
	if mode == proxyPlain {
		ps.serveHTTP11Connect(bufio.NewReader(c), c, denyCode)
		return
	}
	tc, ok := c.(*tls.Conn)
	if !ok {
		_ = c.Close()
		return
	}
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		return
	}
	alpn := tc.ConnectionState().NegotiatedProtocol
	select {
	case ps.alpnCh <- alpn:
	default:
	}
	if alpn == "h2" {
		h2srv.ServeConn(c, &http2.ServeConnOpts{Handler: ps.h2ConnectHandler(denyCode)})
		return
	}
	ps.serveHTTP11Connect(bufio.NewReader(c), c, denyCode)
}

// relayPump copies src to dst through an explicit read/write loop and, on src
// EOF, propagates a FIN to the target when it is a TCP conn. flush, when
// non-nil, runs after every write burst: the x/net http2 response writer
// buffers output in a small bufio, and a CONNECT handler never exits
// mid-tunnel to flush it, so an unflushed tail strands the peer's read.
func relayPump(dst io.Writer, flush func(), src io.Reader, fin interface{ CloseWrite() error }) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			if flush != nil {
				flush()
			}
		}
		if err != nil {
			if fin != nil {
				_ = fin.CloseWrite()
			}
			return
		}
	}
}

// serveHTTP11Connect is the independent HTTP/1.1 CONNECT implementation: the
// request is parsed with net/http's own request reader, CONNECT is answered
// with 200 Connection established, and the tunnel is a blind relay with FIN
// propagation in both directions.
func (ps *proxyServer) serveHTTP11Connect(br *bufio.Reader, downstream net.Conn, denyCode int) {
	defer downstream.Close()
	req, err := stdhttp.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != "CONNECT" {
		_, _ = io.WriteString(downstream, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	select {
	case ps.http11Connect <- req.Host:
	default:
	}
	if denyCode != 0 {
		_, _ = io.WriteString(downstream, fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", denyCode, stdhttp.StatusText(denyCode)))
		return
	}
	target, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		_, _ = io.WriteString(downstream, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	tcpTarget, _ := target.(*net.TCPConn)
	defer target.Close()
	_, _ = io.WriteString(downstream, "HTTP/1.1 200 Connection established\r\n\r\n")
	// Blind relay. The client->target pump reads through br so bytes the
	// request reader already buffered (early tunnel payload) stay in flight.
	go relayPump(target, nil, br, tcpTarget)
	relayPump(downstream, nil, target, nil)
}

// h2ConnectHandler is the independent HTTP/2 CONNECT implementation: each
// CONNECT stream is one tunnel; the request body is the client->target
// direction and the response body the target->client direction.
func (ps *proxyServer) h2ConnectHandler(denyCode int) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != "CONNECT" {
			w.WriteHeader(stdhttp.StatusMethodNotAllowed)
			return
		}
		select {
		case ps.h2Connect <- r.Host:
		default:
		}
		if denyCode != 0 {
			w.WriteHeader(denyCode)
			return
		}
		target, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			w.WriteHeader(stdhttp.StatusBadGateway)
			return
		}
		tcpTarget, _ := target.(*net.TCPConn)
		defer target.Close()
		w.WriteHeader(stdhttp.StatusOK)
		w.(stdhttp.Flusher).Flush()
		// The response pump must flush after every burst: the x/net http2
		// response writer buffers, and this handler only returns when the
		// target closes, so nothing else would push the tail out.
		go relayPump(target, nil, r.Body, tcpTarget)
		relayPump(w, w.(stdhttp.Flusher).Flush, target, nil)
	})
}

// waitALPN asserts that the recorded negotiated ALPN of the observed TLS
// handshake is exactly want.
func (ps *proxyServer) waitALPN(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-ps.alpnCh:
		if got != want {
			t.Fatalf("negotiated ALPN = %q, want %q", got, want)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("no TLS handshake observed within 30s, want ALPN %q", want)
	}
}

// waitConnectAuthority asserts that a CONNECT for want arrived on the wire
// path the channel stands for.
func (ps *proxyServer) waitConnectAuthority(t *testing.T, ch <-chan string, label, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("%s authority = %q, want %q", label, got, want)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("no %s for %q observed within 30s", label, want)
	}
}

// assertNoConnect asserts that no CONNECT arrived on the wrong wire path.
func (ps *proxyServer) assertNoConnect(t *testing.T, ch <-chan string, label string) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("client issued a %s to %q on the wrong path", label, got)
	default:
	}
}

// ---- client (built exactly the way the consumer builds it) ----

// newHTTPProxyClientDialer builds the client the way dae does for an
// http/https subscription link: dialer/http's registered constructor over a
// direct underlay. For an https link the constructor wraps transport/tls
// itself, so the client conn chain ends in the UnderlyingConnForwarder
// wrapper.
func newHTTPProxyClientDialer(t *testing.T, link string) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	d, _, err := dialerhttp.NewHTTP(&dialer.ExtraOption{}, direct, link)
	if err != nil {
		t.Fatalf("http dialer(%q): %v", link, err)
	}
	return d
}

// httpsLink is the https proxy subscription link for the in-test server: the
// sni parameter is what makes dialer/http keep allowInsecure through its URL
// round-trip, and the client's ALPN stays at its h2-first default.
func httpsLink(ps *proxyServer) string {
	return "https://" + ps.addr + "?sni=127.0.0.1&allowInsecure=1"
}

// ---- the e2e tests ----

// TestE2EHTTPPlainConnectRelay pushes 4MiB through client -> plain HTTP proxy
// -> echo target -> back over a real CONNECT tunnel, then half-closes and
// expects the target EOF to propagate back.
func TestE2EHTTPPlainConnectRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	ps := startProxyServer(t, proxyPlain, 0)
	d := newHTTPProxyClientDialer(t, "http://"+ps.addr)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	stop := hangWatchdog(t, 60*time.Second)
	defer stop()

	verifyRelayRoundTrip(t, c, 4<<20)

	// The proxy must have seen an HTTP/1.1 CONNECT for the dialed target.
	ps.waitConnectAuthority(t, ps.http11Connect, "HTTP/1.1 CONNECT", echoAddr.String())

	halfCloseAndExpectEOF(t, c, true)
}

// TestE2EHTTPSConnectRelayHTTP11 covers the https proxy variant through
// transport/tls (the UnderlyingConnForwarder chain) against a server that only
// advertises http/1.1. The recorded ALPN pins that the client really ran
// HTTP/1.1 CONNECT over TLS; a client that kept speaking h2 would leave the
// HTTP/1.1 CONNECT channel empty and fail here.
func TestE2EHTTPSConnectRelayHTTP11(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	ps := startProxyServer(t, proxyTLSHTTP11, 0)
	d := newHTTPProxyClientDialer(t, httpsLink(ps))

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	stop := hangWatchdog(t, 60*time.Second)
	defer stop()

	verifyRelayRoundTrip(t, c, 4<<20)

	ps.waitALPN(t, "http/1.1")
	ps.waitConnectAuthority(t, ps.http11Connect, "HTTP/1.1 CONNECT", echoAddr.String())
	ps.assertNoConnect(t, ps.h2Connect, "HTTP/2 CONNECT")

	halfCloseAndExpectEOF(t, c, true)
}

// TestE2EHTTPSConnectRelayH2 covers the HTTP/2 CONNECT path. protocol/http
// reaches it only for an https proxy whose TLS handshake negotiates ALPN h2
// (protocol/http/conn.go connPool.GetConn inspects the peeled *tls.Conn),
// which is exactly the client's default ALPN preference. A plain http proxy
// never reaches the h2 path: its Write implementation always speaks HTTP/1.1
// CONNECT over the direct underlay. The half-close here exercises the h2
// logical CloseWrite (request-body pipe close), not a TCP FIN.
//
// Bring-up note: an early version of the in-test h2 handler flushed its
// response only once after the 200 header, so the tail of the echoed payload
// stayed in the x/net server's response bufio (a CONNECT handler never exits
// mid-tunnel to flush it) and the client stalled waiting for the last chunk.
// Byte counters on a plain x/net client with no protocol/http code pinned the
// missing tail to the server's response buffering; the handler now flushes
// after every burst. The watchdog remains as a hang guard (per-flow deadlines
// are documented no-ops on the h2 path).
func TestE2EHTTPSConnectRelayH2(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	ps := startProxyServer(t, proxyTLSH2, 0)
	d := newHTTPProxyClientDialer(t, httpsLink(ps))

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	stop := hangWatchdog(t, 60*time.Second)
	defer stop()

	verifyRelayRoundTrip(t, c, 4<<20)

	ps.waitALPN(t, "h2")
	ps.waitConnectAuthority(t, ps.h2Connect, "HTTP/2 CONNECT", echoAddr.String())
	ps.assertNoConnect(t, ps.http11Connect, "HTTP/1.1 CONNECT")

	halfCloseAndExpectEOF(t, c, false)
}

// TestE2EHTTPProxyErrorReplySurfacesAsClientError checks that a non-200
// CONNECT reply surfaces as a client error from the handshake-triggering
// Write, with no panic and no hang, on every client path.
func TestE2EHTTPProxyErrorReplySurfacesAsClientError(t *testing.T) {
	cases := []struct {
		name     string
		mode     proxyMode
		denyCode int
		wantCode string // substring the surfaced error must contain ("" = any error)
	}{
		{name: "plain_403", mode: proxyPlain, denyCode: 403, wantCode: "403"},
		{name: "https_http11_502", mode: proxyTLSHTTP11, denyCode: 502, wantCode: "502"},
		// On the h2 path the piped request body abort and the 502 response
		// arrive in a racing order, so the surfaced message is either the
		// status error or the aborted-body error; only the error itself is
		// deterministic. This subtest also pins the typed-nil regression: a
		// denied h2 CONNECT used to panic in discardCandidate instead of
		// returning an error.
		{name: "https_h2_502", mode: proxyTLSH2, denyCode: 502, wantCode: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			echoAddr := loopbackEchoTarget(t)
			ps := startProxyServer(t, tc.mode, tc.denyCode)
			link := "http://" + ps.addr
			if tc.mode != proxyPlain {
				link = httpsLink(ps)
			}
			d := newHTTPProxyClientDialer(t, link)

			ctx := deadlineCtx(t)
			c, err := d.DialContext(ctx, "tcp", echoAddr.String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			stop := hangWatchdog(t, 30*time.Second)
			defer stop()

			// DialContext is lazy; the handshake (and the denial) surfaces
			// on the first Write.
			n, err := c.Write([]byte("tunnel payload"))
			if err == nil {
				t.Fatalf("Write through a denying proxy = (%d, nil), want error", n)
			}
			if tc.wantCode != "" && !strings.Contains(err.Error(), tc.wantCode) {
				t.Fatalf("error %q does not mention status %s", err, tc.wantCode)
			}

			// The proxy must have received our CONNECT before denying it.
			if tc.mode == proxyTLSH2 {
				ps.waitConnectAuthority(t, ps.h2Connect, "HTTP/2 CONNECT", echoAddr.String())
			} else {
				ps.waitConnectAuthority(t, ps.http11Connect, "HTTP/1.1 CONNECT", echoAddr.String())
			}

			if err := c.Close(); err != nil {
				t.Fatalf("Close after denial: %v", err)
			}
		})
	}
}
