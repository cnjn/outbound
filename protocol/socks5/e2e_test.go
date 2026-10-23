package socks5_test

// True end-to-end coverage for the socks5 client stack: an in-test SOCKS5
// server (own wire-format implementation straight from RFC 1928 / RFC 1929,
// not a copy of protocol/socks5 or protocol/infra/socks) fronting real
// loopback echo targets, reached through the same dialer chain dialer/socks
// builds (direct -> link registry -> socks5).

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/socks" // registers the socks/socks5 link schemes
	"github.com/daeuniverse/outbound/netproxy"
)

// ---- shared helpers (the per-protocol e2e convention) ----

// loopbackEchoTarget starts a TCP echo server; everything received is sent
// back, and a peer half-close (FIN) is propagated back as EOF after the
// remaining output is flushed.
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
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr()
}

// startUDPEchoTarget echoes datagrams back to their sender.
func startUDPEchoTarget(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr()
}

// deadlineCtx bounds every dial in the e2e so a hung protocol layer fails the
// test instead of hanging it.
func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// readFullOrDead wraps io.ReadFull with the test deadline.
func readFullOrDead(t *testing.T, c net.Conn, buf []byte) error {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, buf)
	return err
}

// writeFullOrDead wraps a bounded write for the server side.
func writeFullOrDead(t *testing.T, c net.Conn, b []byte) error {
	t.Helper()
	if err := c.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, err := c.Write(b)
	return err
}

// ---- in-test socks5 server (independent wire-format implementation) ----

// Wire constants for RFC 1928 and RFC 1929, spelled out locally so the test
// server can never accidentally lean on the client's own constants.
const (
	socks5TestVer                    byte = 5
	socks5TestAuthNone               byte = 0x00
	socks5TestAuthPassword           byte = 0x02
	socks5TestAuthNoAcceptable       byte = 0xff
	socks5TestPasswordSubNegotiation byte = 1 // RFC 1929 VER inside the auth exchange
	socks5TestCmdConnect             byte = 1
	socks5TestCmdUDPAssociate        byte = 3
	socks5TestAtypIPv4               byte = 1
	socks5TestAtypDomain             byte = 3
	socks5TestAtypIPv6               byte = 4
	socks5TestRepSuccess             byte = 0
	socks5TestRepGeneralFailure      byte = 1
)

// socks5ServerOptions configures the in-test SOCKS5 server.
type socks5ServerOptions struct {
	// requireAuth offers only method 0x02 (username/password, RFC 1929).
	// A client offering no usable method gets 0xff and a close.
	requireAuth bool
	username    string
	password    string
	// connectReply != 0 makes every CONNECT request get this reply code
	// instead of a real relay (error-path coverage).
	connectReply byte
	// strictAssociateSource makes the UDP relay accept datagrams only from
	// the DST.ADDR/DST.PORT of the UDP ASSOCIATE request, as RFC 1928
	// section 7 permits ("The server MAY use this information to limit
	// access to the association"). A zero address or port matches any.
	strictAssociateSource bool
}

type socks5TestServer struct {
	ln   net.Listener
	opts socks5ServerOptions

	mu            sync.Mutex
	chosenMethod  byte
	authUser      string
	authPass      string
	downstreamEOF chan struct{}
	eofOnce       sync.Once
	associateDst  []string
}

// startSocks5Server runs the in-test SOCKS5 server on a real loopback
// listener and returns it (use addr() for the client-facing address).
func startSocks5Server(t *testing.T, opts socks5ServerOptions) *socks5TestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &socks5TestServer{
		ln:            ln,
		opts:          opts,
		downstreamEOF: make(chan struct{}),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serveSocks5Conn(t, c)
		}
	}()
	return srv
}

func (srv *socks5TestServer) addr() string { return srv.ln.Addr().String() }

func (srv *socks5TestServer) recordMethod(method byte) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.chosenMethod = method
}

func (srv *socks5TestServer) recordAssociate(dst string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.associateDst = append(srv.associateDst, dst)
}

func (srv *socks5TestServer) associateRequests() []string {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return append([]string(nil), srv.associateDst...)
}

func (srv *socks5TestServer) negotiatedMethod() byte {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.chosenMethod
}

func (srv *socks5TestServer) recordAuth(user, pass string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.authUser, srv.authPass = user, pass
}

func (srv *socks5TestServer) authCredentials() (user, pass string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.authUser, srv.authPass
}

func (srv *socks5TestServer) markDownstreamEOF() {
	srv.eofOnce.Do(func() { close(srv.downstreamEOF) })
}

func (srv *socks5TestServer) downstreamEOFObserved() <-chan struct{} {
	return srv.downstreamEOF
}

// readSocks5TestAddress decodes ATYP + address + port (RFC 1928 section 5)
// from the stream.
func readSocks5TestAddress(t *testing.T, c net.Conn) (host string, port int, err error) {
	t.Helper()
	var atyp [1]byte
	if err = readFullOrDead(t, c, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case socks5TestAtypIPv4:
		var raw [6]byte
		if err = readFullOrDead(t, c, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:4]).String(), int(binary.BigEndian.Uint16(raw[4:])), nil
	case socks5TestAtypIPv6:
		var raw [18]byte
		if err = readFullOrDead(t, c, raw[:]); err != nil {
			return "", 0, err
		}
		return net.IP(raw[:16]).String(), int(binary.BigEndian.Uint16(raw[16:])), nil
	case socks5TestAtypDomain:
		var l [1]byte
		if err = readFullOrDead(t, c, l[:]); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(l[0])+2)
		if err = readFullOrDead(t, c, raw); err != nil {
			return "", 0, err
		}
		return string(raw[:l[0]]), int(binary.BigEndian.Uint16(raw[l[0]:])), nil
	default:
		return "", 0, io.ErrUnexpectedEOF
	}
}

// writeSocks5TestReply writes VER REP RSV BND.ADDR BND.PORT.
func writeSocks5TestReply(t *testing.T, c net.Conn, rep byte, bndIP net.IP, bndPort int) error {
	t.Helper()
	frame := []byte{socks5TestVer, rep, 0, socks5TestAtypIPv4, 0, 0, 0, 0, 0, 0}
	if rep == socks5TestRepSuccess {
		ip := bndIP.To4()
		if ip == nil {
			ip = bndIP.To16()
			frame[3] = socks5TestAtypIPv6
		}
		copy(frame[4:], ip)
		binary.BigEndian.PutUint16(frame[len(frame)-2:], uint16(bndPort))
	}
	return writeFullOrDead(t, c, frame)
}

// decodeSocks5UdpDatagram splits one RFC 1928 section 7 datagram
// (RSV FRAG ATYP DST.ADDR DST.PORT DATA) into its target and payload.
func decodeSocks5UdpDatagram(b []byte) (dst net.Addr, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return nil, nil, false // RSV/FRAG must be zero: we never fragment
	}
	rest := b[3:]
	switch rest[0] {
	case socks5TestAtypIPv4:
		if len(rest) < 7 {
			return nil, nil, false
		}
		ip := append(net.IP(nil), rest[1:5]...)
		return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(rest[5:7]))}, rest[7:], true
	case socks5TestAtypIPv6:
		if len(rest) < 19 {
			return nil, nil, false
		}
		ip := append(net.IP(nil), rest[1:17]...)
		return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(rest[17:19]))}, rest[19:], true
	case socks5TestAtypDomain:
		if len(rest) < 2 {
			return nil, nil, false
		}
		l := int(rest[1])
		if len(rest) < 2+l+2 {
			return nil, nil, false
		}
		host := net.JoinHostPort(string(rest[2:2+l]), strconv.Itoa(int(binary.BigEndian.Uint16(rest[2+l:]))))
		ua, err := net.ResolveUDPAddr("udp", host)
		if err != nil {
			return nil, nil, false
		}
		return ua, rest[2+l+2:], true
	default:
		return nil, nil, false
	}
}

// encodeSocks5UdpDatagram frames a relayed datagram with its source address
// the same RFC 1928 section 7 layout.
func encodeSocks5UdpDatagram(from net.Addr, payload []byte) ([]byte, bool) {
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return nil, false
	}
	ip := ua.IP.To4()
	atyp := socks5TestAtypIPv4
	if ip == nil {
		ip = ua.IP.To16()
		atyp = socks5TestAtypIPv6
		if ip == nil {
			return nil, false
		}
	}
	frame := make([]byte, 0, 4+len(ip)+2+len(payload))
	frame = append(frame, 0, 0, 0, atyp)
	frame = append(frame, ip...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(ua.Port))
	frame = append(frame, port[:]...)
	frame = append(frame, payload...)
	return frame, true
}

// serveSocks5Conn handles one accepted control connection: method negotiation
// (0x00 or 0x02), optional RFC 1929 username/password, then CONNECT relay to
// a real loopback target with half-close propagation, or UDP ASSOCIATE relay.
func (srv *socks5TestServer) serveSocks5Conn(t *testing.T, downstream net.Conn) {
	t.Helper()
	defer downstream.Close()

	// RFC 1928 section 3: method negotiation.
	var hdr [2]byte // VER NMETHODS
	if err := readFullOrDead(t, downstream, hdr[:]); err != nil {
		return
	}
	if hdr[0] != socks5TestVer || hdr[1] == 0 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if err := readFullOrDead(t, downstream, methods); err != nil {
		return
	}
	method := socks5TestAuthNoAcceptable
	if srv.opts.requireAuth {
		if bytes.IndexByte(methods, socks5TestAuthPassword) >= 0 {
			method = socks5TestAuthPassword
		}
	} else if bytes.IndexByte(methods, socks5TestAuthNone) >= 0 {
		method = socks5TestAuthNone
	}
	srv.recordMethod(method)
	if err := writeFullOrDead(t, downstream, []byte{socks5TestVer, method}); err != nil {
		return
	}
	if method == socks5TestAuthNoAcceptable {
		return // real servers close after offering nothing acceptable
	}

	if method == socks5TestAuthPassword {
		// RFC 1929 section 2: VER ULEN UNAME PLEN PASSWD.
		var verAndUlen [2]byte
		if err := readFullOrDead(t, downstream, verAndUlen[:]); err != nil {
			return
		}
		if verAndUlen[0] != socks5TestPasswordSubNegotiation {
			return
		}
		uname := make([]byte, int(verAndUlen[1]))
		if err := readFullOrDead(t, downstream, uname); err != nil {
			return
		}
		var plen [1]byte
		if err := readFullOrDead(t, downstream, plen[:]); err != nil {
			return
		}
		passwd := make([]byte, int(plen[0]))
		if err := readFullOrDead(t, downstream, passwd); err != nil {
			return
		}
		srv.recordAuth(string(uname), string(passwd))
		if string(uname) != srv.opts.username || string(passwd) != srv.opts.password {
			_ = writeFullOrDead(t, downstream, []byte{socks5TestPasswordSubNegotiation, 1}) // status: failure
			return
		}
		if err := writeFullOrDead(t, downstream, []byte{socks5TestPasswordSubNegotiation, 0}); err != nil {
			return
		}
	}

	// RFC 1928 section 4: request.
	var req [3]byte // VER CMD RSV
	if err := readFullOrDead(t, downstream, req[:]); err != nil {
		return
	}
	if req[0] != socks5TestVer {
		return
	}
	host, port, err := readSocks5TestAddress(t, downstream)
	if err != nil {
		return
	}
	destination := net.JoinHostPort(host, strconv.Itoa(port))

	switch req[1] {
	case socks5TestCmdConnect:
		if srv.opts.connectReply != socks5TestRepSuccess {
			// REP != 0 with a zero BND: the client must fail the dial.
			_ = writeSocks5TestReply(t, downstream, srv.opts.connectReply, net.IPv4zero, 0)
			return
		}
		target, err := net.DialTimeout("tcp", destination, 10*time.Second)
		if err != nil {
			_ = writeSocks5TestReply(t, downstream, socks5TestRepGeneralFailure, net.IPv4zero, 0)
			return
		}
		defer target.Close()
		bnd, ok := srv.ln.Addr().(*net.TCPAddr)
		if !ok {
			return
		}
		if err := writeSocks5TestReply(t, downstream, socks5TestRepSuccess, bnd.IP, bnd.Port); err != nil {
			return
		}
		// Relay; drop the handshake deadlines so the relay is not bounded by
		// them, and propagate the client's FIN to the echo target.
		_ = downstream.SetDeadline(time.Time{})
		go func() {
			_, copyErr := io.Copy(target, downstream)
			if copyErr == nil {
				srv.markDownstreamEOF() // a clean client half-close reached us
			}
			if tcp, ok := target.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()
		_, _ = io.Copy(downstream, target)
	case socks5TestCmdUDPAssociate:
		srv.recordAssociate(destination)
		srv.serveUdpAssociate(t, downstream, host, port)
	}
}

// serveUdpAssociate replies with a real UDP relay endpoint and relays
// framed datagrams between the client endpoint and the echo targets it
// addresses (RFC 1928 section 7).
func (srv *socks5TestServer) serveUdpAssociate(t *testing.T, control net.Conn, clientHost string, clientPort int) {
	t.Helper()
	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer relay.Close()
	relayAddr, ok := relay.LocalAddr().(*net.UDPAddr)
	if !ok {
		return
	}
	if err := writeSocks5TestReply(t, control, socks5TestRepSuccess, relayAddr.IP, relayAddr.Port); err != nil {
		return
	}
	// The control connection now only idles until the association ends, so
	// drop the handshake deadlines.
	_ = control.SetDeadline(time.Time{})

	// Tear the relay down when the control connection dies.
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := control.Read(buf); err != nil {
				_ = relay.Close()
				return
			}
		}
	}()

	// One dispatch loop: datagrams from the learned client endpoint are
	// decoded and forwarded to their DST.ADDR/DST.PORT; datagrams from the
	// echo targets are framed with their source address and sent back.
	var clientAddr net.Addr
	buf := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFrom(buf)
		if err != nil {
			return
		}
		if clientAddr == nil {
			if srv.opts.strictAssociateSource && !associateSourceMatches(from, clientHost, clientPort) {
				continue // not the endpoint the client declared: drop silently
			}
			clientAddr = from
		}
		if from.String() == clientAddr.String() {
			dst, payload, ok := decodeSocks5UdpDatagram(buf[:n])
			if !ok {
				return // malformed frame: kill the association like a real server
			}
			if _, err := relay.WriteTo(payload, dst); err != nil {
				return
			}
			continue
		}
		frame, ok := encodeSocks5UdpDatagram(from, buf[:n])
		if !ok {
			return
		}
		if _, err := relay.WriteTo(frame, clientAddr); err != nil {
			return
		}
	}
}

// associateSourceMatches reports whether a datagram source matches the
// DST.ADDR/DST.PORT of a UDP ASSOCIATE request; zeros match anything.
func associateSourceMatches(from net.Addr, host string, port int) bool {
	udp, ok := from.(*net.UDPAddr)
	if !ok {
		return false
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsUnspecified() {
		if ip == nil || !ip.Equal(udp.IP) {
			return false
		}
	}
	return port == 0 || port == udp.Port
}

// ---- the client, built exactly the way the consumer (dialer/socks) builds it ----

// newSocks5ClientDialer runs the dialer/socks constructor chain against the
// in-test server: link registry -> NewSocks -> ParseSocksURL -> Socks.Dialer
// -> ExportToURL -> socks5.NewSocks5Dialer, on top of a fullcone direct
// base dialer (dialer/socks notes "Socks5 Proxy supports full-cone").
func newSocks5ClientDialer(t *testing.T, proxyAddr, username, password string) netproxy.Dialer {
	t.Helper()
	u := url.URL{Scheme: "socks5", Host: proxyAddr}
	if username != "" || password != "" {
		u.User = url.UserPassword(username, password)
	}
	base, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, true)
	d, _, err := dialer.NewNetproxyDialerFromLink(base, &dialer.ExtraOption{}, u.String())
	if err != nil {
		t.Fatalf("socks5 dialer from link: %v", err)
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c, reads
// it back concurrently, and checks every byte. Large enough to cross record
// and buffer boundaries.
func verifyRelayRoundTrip(t *testing.T, c netproxy.Conn, total int) {
	t.Helper()
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sent := 0
	go func() {
		for sent < total {
			n := len(payload)
			if total-sent < n {
				n = total - sent
			}
			if _, err := c.Write(payload[:n]); err != nil {
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
			t.Fatalf("read back at %d/%d: %v", got, total, err)
		}
		// Verify every byte, which also crosses buffer boundaries.
		for i := 0; i < n; i++ {
			if want := byte(((got + i) % len(payload)) * 7); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
}

// ---- the e2e tests ----

// TestE2ESocks5NoAuthConnectRelay pushes 4MiB through client -> socks5
// server -> echo target -> back over a real TCP session, writing and reading
// concurrently, and checks the server picked the no-auth method.
func TestE2ESocks5NoAuthConnectRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{})
	d := newSocks5ClientDialer(t, srv.addr(), "", "")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if got := srv.negotiatedMethod(); got != socks5TestAuthNone {
		t.Fatalf("server chose method %#x, want no-auth %#x", got, socks5TestAuthNone)
	}
	verifyRelayRoundTrip(t, c, 4<<20)
}

// TestE2ESocks5UserPassAuthConnect covers method 0x02: the server offers only
// username/password, the client must complete the RFC 1929 exchange with the
// credentials from the link, and the server must have received them verbatim.
func TestE2ESocks5UserPassAuthConnect(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{
		requireAuth: true,
		username:    "e2e-user",
		password:    "e2e-pass",
	})
	d := newSocks5ClientDialer(t, srv.addr(), "e2e-user", "e2e-pass")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial with credentials: %v", err)
	}
	defer c.Close()

	if got := srv.negotiatedMethod(); got != socks5TestAuthPassword {
		t.Fatalf("server chose method %#x, want username/password %#x", got, socks5TestAuthPassword)
	}
	user, pass := srv.authCredentials()
	if user != "e2e-user" || pass != "e2e-pass" {
		t.Fatalf("server saw credentials %q/%q, want e2e-user/e2e-pass", user, pass)
	}
	verifyRelayRoundTrip(t, c, 2<<20)
}

// TestE2ESocks5HalfClosePropagatesEOF half-closes the relayed stream and
// requires the FIN to reach the server, be relayed to the echo target, and
// come back as a clean EOF. CloseWrite is an optional capability, so losing
// it to a wrapper must fail this e2e instead of silently skipping the check.
func TestE2ESocks5HalfClosePropagatesEOF(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{})
	d := newSocks5ClientDialer(t, srv.addr(), "", "")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 256<<10)

	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("socks5 conn %T lost the CloseWrite capability", c)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read after half-close: %v", err)
		}
		if n == 0 {
			t.Fatal("read after half-close returned 0 bytes without EOF")
		}
	}
	// The server relays our FIN strictly before the echo target's close can
	// come back to us, so this must already be observable.
	select {
	case <-srv.downstreamEOFObserved():
	case <-time.After(30 * time.Second):
		t.Fatal("server never observed the client half-close as a clean EOF")
	}
}

// TestE2ESocks5UDPRelayTwoTargets exercises UDP ASSOCIATE: several datagrams
// to two different UDP echo targets, with integrity and source-address
// checks per RFC 1928 section 7.
func TestE2ESocks5UDPRelayTwoTargets(t *testing.T) {
	targets := []net.Addr{startUDPEchoTarget(t), startUDPEchoTarget(t)}
	srv := startSocks5Server(t, socks5ServerOptions{})
	d := newSocks5ClientDialer(t, srv.addr(), "", "")

	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", targets[0].String())
	if err != nil {
		t.Fatalf("dial udp (UDP ASSOCIATE): %v", err)
	}
	defer pc.Close()

	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	for i := 0; i < 12; i++ {
		target := targets[i%len(targets)]
		payload := make([]byte, 100+i*37)
		for j := range payload {
			payload[j] = byte(i*3 + j)
		}
		if _, err := packetConn.WriteTo(payload, target.String()); err != nil {
			t.Fatalf("WriteTo datagram %d: %v", i, err)
		}
		buf := make([]byte, 65535)
		if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, from, err := packetConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom datagram %d: %v", i, err)
		}
		if n != len(payload) || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("datagram %d mismatch: n=%d want %d", i, n, len(payload))
		}
		if from.String() != target.String() {
			t.Fatalf("datagram %d source = %v, want %v", i, from, target.String())
		}
	}
}

// TestE2ESocks5UDPAssociateDeclaresNoSourceAddress: RFC 1928 section 7 makes
// DST.ADDR/DST.PORT of a UDP ASSOCIATE the address the client will send
// datagrams from, and a client that does not know it must send zeros. The
// client cannot know it (the relay may see it through NAT). Sending the
// target there instead makes a server that limits the association to the
// declared source drop every datagram.
func TestE2ESocks5UDPAssociateDeclaresNoSourceAddress(t *testing.T) {
	target := startUDPEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{strictAssociateSource: true})
	d := newSocks5ClientDialer(t, srv.addr(), "", "")

	pc, err := d.DialContext(deadlineCtx(t), "udp", target.String())
	if err != nil {
		t.Fatalf("dial udp (UDP ASSOCIATE): %v", err)
	}
	defer pc.Close()

	if got := srv.associateRequests(); len(got) != 1 || got[0] != "0.0.0.0:0" {
		t.Fatalf("UDP ASSOCIATE DST.ADDR/DST.PORT = %v, want [0.0.0.0:0]", got)
	}

	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	payload := []byte("rfc1928 section 7")
	if _, err := packetConn.WriteTo(payload, target.String()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, _, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom through a source-limited relay: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}
}

// TestE2ESocks5AuthOnlyServerRefusesCredentiallessClient: the server offers
// only method 0x02, the client has no credentials to offer, so the server
// answers 0xff and the dial must fail with an error (no panic, no hang).
func TestE2ESocks5AuthOnlyServerRefusesCredentiallessClient(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{
		requireAuth: true,
		username:    "e2e-user",
		password:    "e2e-pass",
	})
	d := newSocks5ClientDialer(t, srv.addr(), "", "")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err == nil {
		c.Close()
		t.Fatal("dial against an auth-only server that refuses the client must fail")
	}
	if !strings.Contains(err.Error(), "requires authentication") {
		t.Fatalf("dial error = %v, want the no-acceptable-methods (0xff) failure", err)
	}
}

// TestE2ESocks5WrongPasswordIsAnError: the server completes the 0x02
// negotiation but rejects the submitted password (RFC 1929 status != 0);
// the dial must fail with an error.
func TestE2ESocks5WrongPasswordIsAnError(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{
		requireAuth: true,
		username:    "e2e-user",
		password:    "right-pass",
	})
	d := newSocks5ClientDialer(t, srv.addr(), "e2e-user", "wrong-pass")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err == nil {
		c.Close()
		t.Fatal("dial with a rejected password must fail")
	}
	if !strings.Contains(err.Error(), "rejected username/password") {
		t.Fatalf("dial error = %v, want the RFC 1929 auth rejection", err)
	}
}

// TestE2ESocks5ConnectRejectIsAnError: the server accepts the method
// negotiation but answers CONNECT with REP != 0; the dial must fail with an
// error instead of returning a dead connection.
func TestE2ESocks5ConnectRejectIsAnError(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	srv := startSocks5Server(t, socks5ServerOptions{
		connectReply: 5, // connection refused
	})
	d := newSocks5ClientDialer(t, srv.addr(), "", "")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err == nil {
		c.Close()
		t.Fatal("dial against a rejecting server must fail")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Fatalf("dial error = %v, want the SOCKS5 REP failure", err)
	}
}
