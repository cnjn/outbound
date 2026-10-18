package hysteria2_test

// True end-to-end coverage for the Hysteria2 client stack: an in-test QUIC
// server (own wire-format implementation, not a copy of protocol/hysteria2)
// speaking enough of the Hysteria2 protocol for what this repo's client
// exercises, on real loopback UDP sockets:
//
//   - auth: an HTTP/3 POST to https://hysteria/auth carrying Hysteria-Auth /
//     Hysteria-CC-RX / Hysteria-Padding, answered with status 233 and
//     Hysteria-UDP / Hysteria-CC-RX response headers;
//   - TCP relay: request frames (0x401 + varint-prefixed address + padding)
//     on bidirectional QUIC streams, hijacked server-side, answered with a
//     status/message/padding response followed by raw relayed bytes;
//   - UDP relay: QUIC datagrams carrying sessionID/packetID/fragID/fragCount
//     header + varint-prefixed "host:port" address + payload, with
//     fragmentation/reassembly on both ends;
//   - salamander obfuscation: the shared per-packet codec applied on the
//     server socket (the transport layer is symmetric, like TLS in the
//     trojanc e2e harness).
//
// The client is built exactly the way the consumer (dae) builds it:
// dialer/hysteria2.FromLink over a direct dialer. Everything is bounded by
// deadlines so a hung protocol layer fails the test instead of hanging it.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	dialerhysteria2 "github.com/daeuniverse/outbound/dialer/hysteria2"
	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/obfs"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/http3"
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

// e2eSelfSignedCert mints the server certificate for the in-test QUIC
// listener; the client runs with InsecureSkipVerify.
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

// ---- in-test Hysteria2 server (independent wire-format implementation) ----

const (
	// The TCP request frame type the client writes as the first varint of a
	// bidirectional stream. The in-test server hijacks such streams out of
	// the HTTP/3 layer right after the frame-type varint.
	hy2FrameTCPRequest uint64 = 0x401

	// hysteria2 auth success status (HTTP/3 response code).
	hy2StatusAuthOK = 233

	// Wire-format sanity limits (independent copies of the protocol's DoS
	// caps; the values only need to be compatible with what the client sends).
	hy2MaxAddressLength = 2048
	hy2MaxMessageLength = 2048
	hy2MaxPaddingLength = 4096
)

// hy2Varint reads a QUIC variable-length integer (RFC 9000 section 16)
// byte-at-a-time. It never wraps the stream in a buffered reader: after the
// hijack handoff every remaining stream byte belongs to the relayed payload.
func hy2Varint(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	prefix := b[0] >> 6
	b[0] &= 0x3f
	val := uint64(b[0])
	for i := 0; i < (1<<prefix)-1; i++ {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		val = val<<8 | uint64(b[0])
	}
	return val, nil
}

// hy2SliceVarint reads a QUIC variable-length integer from b, returning the
// value and the number of bytes consumed.
func hy2SliceVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("varint: empty")
	}
	prefix := b[0] >> 6
	n := 1 << prefix
	if len(b) < n {
		return 0, 0, fmt.Errorf("varint: truncated")
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		val = val<<8 | uint64(b[i])
	}
	return val, n, nil
}

// hy2AppendVarint appends a QUIC variable-length integer.
func hy2AppendVarint(b []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(b, byte(v))
	case v <= 16383:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 1073741823:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// readHy2TCPRequest decodes the TCP request body that follows the hijacked
// 0x401 frame type: varint address length, address, varint padding length,
// padding bytes (skipped).
func readHy2TCPRequest(r io.Reader) (string, error) {
	addrLen, err := hy2Varint(r)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > hy2MaxAddressLength {
		return "", fmt.Errorf("invalid address length %d", addrLen)
	}
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", err
	}
	padLen, err := hy2Varint(r)
	if err != nil {
		return "", err
	}
	if padLen > hy2MaxPaddingLength {
		return "", fmt.Errorf("invalid padding length %d", padLen)
	}
	if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
		return "", err
	}
	return string(addrBuf), nil
}

// writeHy2TCPResponse writes the TCP response the client's
// ReadTCPResponse parses: status byte, varint message length, message,
// varint padding length, padding.
func writeHy2TCPResponse(w io.Writer, ok bool, msg string, padLen int) error {
	if padLen < 0 || padLen > hy2MaxPaddingLength {
		return fmt.Errorf("invalid test padding length %d", padLen)
	}
	buf := make([]byte, 0, 1+len(msg)+2*10+padLen)
	if ok {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 1)
	}
	buf = hy2AppendVarint(buf, uint64(len(msg)))
	buf = append(buf, msg...)
	buf = hy2AppendVarint(buf, uint64(padLen))
	buf = append(buf, make([]byte, padLen)...)
	_, err := w.Write(buf)
	return err
}

// hy2UDPHeaderSize is the fixed part of a UDP message:
// sessionID(4) + packetID(2) + fragID(1) + fragCount(1).
const hy2UDPHeaderSize = 8

// hy2UDPMessage is the in-test server's view of the datagram wire format.
type hy2UDPMessage struct {
	SessionID uint32
	PacketID  uint16
	FragID    uint8
	FragCount uint8
	Addr      string
	Data      []byte
}

// hy2HeaderSize returns the full header size including the varint-prefixed
// address, which is what fragmentation budgeting needs.
func (m *hy2UDPMessage) headerSize() int {
	return hy2UDPHeaderSize + 1 + len(m.Addr) + 1 // + slop for a 2-byte varint
}

// parseHy2UDPMessage decodes one datagram.
func parseHy2UDPMessage(buf []byte) (*hy2UDPMessage, error) {
	if len(buf) < hy2UDPHeaderSize {
		return nil, fmt.Errorf("datagram header too short: %d", len(buf))
	}
	m := &hy2UDPMessage{
		SessionID: binary.BigEndian.Uint32(buf[0:4]),
		PacketID:  binary.BigEndian.Uint16(buf[4:6]),
		FragID:    buf[6],
		FragCount: buf[7],
	}
	addrLen, skip, err := hy2SliceVarint(buf[8:])
	if err != nil {
		return nil, err
	}
	if addrLen == 0 || addrLen > hy2MaxMessageLength {
		return nil, fmt.Errorf("invalid datagram address length %d", addrLen)
	}
	rest := buf[8+skip:]
	if len(rest) < int(addrLen) {
		return nil, fmt.Errorf("datagram address truncated")
	}
	m.Addr = string(rest[:addrLen])
	m.Data = rest[addrLen:]
	return m, nil
}

// serializeHy2UDPMessage encodes a datagram into b, returning the slice.
func serializeHy2UDPMessage(b []byte, m *hy2UDPMessage) []byte {
	b = binary.BigEndian.AppendUint32(b, m.SessionID)
	b = binary.BigEndian.AppendUint16(b, m.PacketID)
	b = append(b, m.FragID, m.FragCount)
	b = hy2AppendVarint(b, uint64(len(m.Addr)))
	b = append(b, m.Addr...)
	return append(b, m.Data...)
}

// hy2ConnStateKey carries per-QUIC-connection state into HTTP handlers.
type hy2ConnStateKey struct{}

// hy2UDPSession is one client UDP session: a real UDP socket toward the
// target plus partial-fragment state for the reply direction.
type hy2UDPSession struct {
	sock *net.UDPConn
	// frag holds partial fragments of one outbound (server->client) reply,
	// keyed by packet ID. Guarded by hy2ConnState.mu.
	frag map[uint16]*hy2FragSet
	// replyPktID is the server->client fragment packet ID counter. Guarded
	// by hy2ConnState.mu.
	replyPktID uint32
}

// hy2FragSet reassembles one fragmented server->client datagram.
type hy2FragSet struct {
	count uint8
	got   uint8
	size  int
	parts [][]byte
}

// hy2ConnState is the server-side state of one QUIC connection.
type hy2ConnState struct {
	srv  *hy2Server
	conn quic.Connection
	// authorized flips to true when the HTTP/3 auth handler accepts the
	// connection. Relay streams and datagrams from unauthorized connections
	// are refused.
	authorized atomic.Bool

	mu       sync.Mutex
	sessions map[uint32]*hy2UDPSession
}

// pumpDatagrams is the per-connection QUIC datagram receive loop.
func (st *hy2ConnState) pumpDatagrams() {
	for {
		buf, err := st.conn.ReceiveDatagram(context.Background())
		if err != nil {
			st.closeAllSessions()
			return
		}
		if !st.authorized.Load() {
			st.conn.ReleaseDatagram(buf)
			continue
		}
		msg, perr := parseHy2UDPMessage(buf)
		st.conn.ReleaseDatagram(buf)
		if perr != nil {
			// Malformed datagrams are dropped, matching a server that
			// cannot make sense of a payload; nothing downstream waits
			// on them.
			continue
		}
		st.handleUDPMessage(msg)
	}
}

// handleUDPMessage relays one (possibly fragmented) client datagram to its
// target through the session's UDP socket.
func (st *hy2ConnState) handleUDPMessage(msg *hy2UDPMessage) {
	sess := st.session(msg.SessionID)
	if sess == nil {
		return
	}
	if msg.FragCount > 1 {
		if data, ok := st.feedFragment(sess, msg); ok {
			st.sendToTarget(sess, msg.Addr, data)
		}
		return
	}
	st.sendToTarget(sess, msg.Addr, msg.Data)
}

// sendToTarget writes a reassembled client datagram to its address.
func (st *hy2ConnState) sendToTarget(sess *hy2UDPSession, addr string, data []byte) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return
	}
	udpAddr := &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
	_, _ = sess.sock.WriteToUDP(data, udpAddr)
}

// feedFragment reassembles client->server fragments; it returns the full
// payload once the last fragment arrives.
func (st *hy2ConnState) feedFragment(sess *hy2UDPSession, msg *hy2UDPMessage) ([]byte, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if sess.frag == nil {
		sess.frag = make(map[uint16]*hy2FragSet)
	}
	set, ok := sess.frag[msg.PacketID]
	if !ok || set.count != msg.FragCount {
		set = &hy2FragSet{count: msg.FragCount, parts: make([][]byte, msg.FragCount)}
		sess.frag[msg.PacketID] = set
	}
	if set.parts[msg.FragID] == nil {
		set.parts[msg.FragID] = append([]byte(nil), msg.Data...)
		set.got++
		set.size += len(msg.Data)
	}
	if int(set.got) != int(set.count) {
		return nil, false
	}
	data := make([]byte, 0, set.size)
	for _, part := range set.parts {
		data = append(data, part...)
	}
	delete(sess.frag, msg.PacketID)
	return data, true
}

// session returns the UDP session for an ID, creating the socket lazily.
func (st *hy2ConnState) session(id uint32) *hy2UDPSession {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.srv.closed.Load() {
		return nil
	}
	if sess, ok := st.sessions[id]; ok {
		return sess
	}
	sock, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil
	}
	sess := &hy2UDPSession{sock: sock}
	st.sessions[id] = sess
	go st.pumpReplies(id, sess)
	return sess
}

// pumpReplies reads datagrams from a session's UDP socket and sends them back
// to the client as QUIC datagrams, fragmenting when the transport limit
// requires it.
func (st *hy2ConnState) pumpReplies(id uint32, sess *hy2UDPSession) {
	buf := make([]byte, 65535)
	for {
		n, raddr, err := sess.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		st.sendReply(id, sess, raddr.String(), buf[:n])
	}
}

// sendReply wraps one reply datagram in the UDP message format and sends it,
// splitting into fragments if it exceeds the connection datagram limit.
func (st *hy2ConnState) sendReply(id uint32, sess *hy2UDPSession, from string, data []byte) {
	msg := &hy2UDPMessage{SessionID: id, FragID: 0, FragCount: 1, Addr: from, Data: data}
	if err := st.conn.SendDatagram(serializeHy2UDPMessage(nil, msg)); err == nil {
		return
	}
	// Too large for one datagram: fragment. The per-fragment budget mirrors
	// the wire format: fixed header + varint-prefixed address + payload.
	st.mu.Lock()
	sess.replyPktID++
	pktID := uint16(sess.replyPktID % 0xffff)
	if pktID == 0 {
		pktID = 1
	}
	st.mu.Unlock()
	budget := st.srv.datagramBudget()
	if budget <= msg.headerSize()+1 {
		return // cannot fragment any further; drop
	}
	maxPayload := budget - msg.headerSize()
	fragCount := uint8((len(data) + maxPayload - 1) / maxPayload)
	off := 0
	for fragID := uint8(0); fragID < fragCount; fragID++ {
		end := off + maxPayload
		if end > len(data) {
			end = len(data)
		}
		frag := &hy2UDPMessage{
			SessionID: id,
			PacketID:  pktID,
			FragID:    fragID,
			FragCount: fragCount,
			Addr:      from,
			Data:      data[off:end],
		}
		off = end
		if err := st.conn.SendDatagram(serializeHy2UDPMessage(nil, frag)); err != nil {
			return
		}
	}
}

// closeAllSessions closes every UDP session socket on this connection.
func (st *hy2ConnState) closeAllSessions() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, sess := range st.sessions {
		_ = sess.sock.Close()
	}
	st.sessions = nil
}

// hy2Server is the in-test Hysteria2 server.
type hy2Server struct {
	t          *testing.T
	password   string
	rejectAuth bool
	obfsPSK    []byte

	closed atomic.Bool

	mu    sync.Mutex
	conns map[quic.ConnectionTracingID]*hy2ConnState

	srv     *http3.Server
	pktConn net.PacketConn
}

// hy2ServerOption configures the in-test server.
type hy2ServerOption func(*hy2Server)

// withRejectAuth makes the server answer every auth with 401.
func withRejectAuth() hy2ServerOption { return func(s *hy2Server) { s.rejectAuth = true } }

// withObfs enables salamander packet obfuscation on the server socket.
func withObfs(psk []byte) hy2ServerOption { return func(s *hy2Server) { s.obfsPSK = psk } }

// startHysteria2Server runs the in-test server on a real loopback UDP socket
// and returns its address.
func startHysteria2Server(t *testing.T, password string, opts ...hy2ServerOption) string {
	t.Helper()
	s := &hy2Server{t: t, password: password, conns: make(map[quic.ConnectionTracingID]*hy2ConnState)}
	for _, opt := range opts {
		opt(s)
	}
	pkt, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hysteria2 listen: %v", err)
	}
	if s.obfsPSK != nil {
		wrapped, err := obfs.WrapPacketConnSalamander(pkt, s.obfsPSK)
		if err != nil {
			t.Fatalf("obfs wrap: %v", err)
		}
		pkt = wrapped
	}
	s.pktConn = pkt

	srv := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
			NextProtos:   []string{http3.NextProtoH3},
		},
		// QUIC-level datagrams must be negotiated (the client relays UDP
		// over raw QUIC datagrams), but the HTTP/3 H3_DATAGRAM setting must
		// NOT be advertised: this fork's http3 client starts a
		// receiveDatagrams loop whenever the peer advertises it, and that
		// loop would consume the raw QUIC datagrams the hysteria2 client
		// depends on. This matches a real hysteria2 server, where UDP
		// relay datagrams are transport-level, not HTTP/3 datagrams.
		EnableDatagrams: false,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		Handler:         http.HandlerFunc(s.handleAuth),
		// TCP requests arrive as raw frames on bidirectional streams; the
		// fork's http3.Server hands such streams over after the frame-type
		// varint (verified: quicvarint.NewReader does not buffer raw QUIC
		// streams).
		StreamHijacker: func(ft http3.FrameType, id quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
			if err != nil {
				return false, err
			}
			if uint64(ft) != hy2FrameTCPRequest {
				return false, nil
			}
			st := s.connState(id)
			if st == nil || !st.authorized.Load() {
				// Refuse relay attempts from unauthenticated connections
				// without logging from a server goroutine: the test that
				// owns t may already be done.
				stream.CancelRead(1)
				stream.CancelWrite(1)
				return true, nil
			}
			go st.serveTCPRequest(stream)
			return true, nil
		},
		ConnContext: func(ctx context.Context, c quic.Connection) context.Context {
			st := s.registerConn(ctx, c)
			return context.WithValue(ctx, hy2ConnStateKey{}, st)
		},
	}
	s.srv = srv
	go func() { _ = srv.Serve(pkt) }()
	t.Cleanup(func() {
		s.closed.Store(true)
		states := s.takeConnStates()
		for _, st := range states {
			st.closeAllSessions()
		}
		_ = srv.Close()
		_ = pkt.Close()
	})
	return pkt.LocalAddr().String()
}

// datagramBudget is the server-side fragment size budget. QUIC datagram
// frames cannot exceed the QUIC packet size; 1200 bytes is the safe default
// wire budget and everything above is a bonus.
func (s *hy2Server) datagramBudget() int { return 1200 }

// handleAuth is the HTTP/3 auth handler: it validates Hysteria-Auth and
// answers with the Hysteria2 response headers.
func (s *hy2Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	st, ok := r.Context().Value(hy2ConnStateKey{}).(*hy2ConnState)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Hysteria-UDP", "true")
	w.Header().Set("Hysteria-CC-RX", "0")
	w.Header().Set("Hysteria-Padding", strings.Repeat("a", 256))
	if s.rejectAuth || r.Header.Get("Hysteria-Auth") != s.password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	st.authorized.Store(true)
	w.WriteHeader(hy2StatusAuthOK)
}

// serveTCPRequest handles one hijacked TCP request stream: it decodes the
// request, dials the target, answers, then relays both directions with
// half-close propagation.
func (st *hy2ConnState) serveTCPRequest(stream quic.Stream) {
	defer stream.Close()
	// Everything below is bounded: loopback relays finish in well under a
	// minute, and a stuck relay must not outlive the test.
	deadline := time.Now().Add(60 * time.Second)
	_ = stream.SetDeadline(deadline)
	addr, err := readHy2TCPRequest(stream)
	if err != nil {
		st.srv.t.Logf("e2e debug: readHy2TCPRequest: %v", err)
		return
	}
	target, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		_ = writeHy2TCPResponse(stream, false, err.Error(), 128)
		return
	}
	defer target.Close()
	_ = target.SetDeadline(deadline)
	if err := writeHy2TCPResponse(stream, true, "", 128); err != nil {
		return
	}
	// Client FIN (half-close) propagates to the target; the target's EOF
	// finishes the reverse copy and closes the stream.
	go func() {
		_, _ = io.Copy(target, stream)
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	_, _ = io.Copy(stream, target)
}

// registerConn tracks a QUIC connection, starts its datagram pump, and
// cleans up when the connection context dies.
func (s *hy2Server) registerConn(ctx context.Context, c quic.Connection) *hy2ConnState {
	st := &hy2ConnState{srv: s, conn: c, sessions: make(map[uint32]*hy2UDPSession)}
	if id, ok := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID); ok {
		s.mu.Lock()
		s.conns[id] = st
		s.mu.Unlock()
		context.AfterFunc(ctx, func() { s.dropConn(id) })
	}
	go st.pumpDatagrams()
	return st
}

// connState looks up a connection by its QUIC tracing ID.
func (s *hy2Server) connState(id quic.ConnectionTracingID) *hy2ConnState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[id]
}

// dropConn forgets a connection and closes its sessions.
func (s *hy2Server) dropConn(id quic.ConnectionTracingID) {
	s.mu.Lock()
	st := s.conns[id]
	delete(s.conns, id)
	s.mu.Unlock()
	if st != nil {
		st.closeAllSessions()
	}
}

// takeConnStates snapshots and forgets all tracked connections.
func (s *hy2Server) takeConnStates() []*hy2ConnState {
	s.mu.Lock()
	defer s.mu.Unlock()
	states := make([]*hy2ConnState, 0, len(s.conns))
	for id, st := range s.conns {
		states = append(states, st)
		delete(s.conns, id)
	}
	return states
}

// ---- the client, built exactly the way the consumer builds it ----

// newHysteria2ClientDialerFromLink builds the dae-side dialer for a
// hysteria2:// link: dialer/hysteria2.FromLink over a direct dialer. extra
// carries query parameters (obfs=..., etc.).
func newHysteria2ClientDialerFromLink(t *testing.T, proxyAddr, user, password, extra string) netproxy.Dialer {
	t.Helper()
	link := fmt.Sprintf("hysteria2://%s:%s@%s?sni=example.com&insecure=1%s", user, password, proxyAddr, extra)
	d, _, err := dialerhysteria2.NewHysteria2(
		&dialer.ExtraOption{AllowInsecure: true},
		func() netproxy.Dialer {
			direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
			return direct
		}(),
		link,
	)
	if err != nil {
		t.Fatalf("hysteria2 dialer: %v", err)
	}
	// netproxy.Dialer carries no Close; the concrete hysteria2 dialer does,
	// and the QUIC client behind it must not outlive the test.
	if closer, ok := d.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c while
// concurrently reading it back and checking every byte. Large enough to cross
// QUIC stream buffer and write-boundary sizes.
func verifyRelayRoundTrip(t *testing.T, c netproxy.Conn, total int) {
	t.Helper()
	payload := make([]byte, 64<<10)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	written := make(chan error, 1)
	go func() {
		sent := 0
		var werr error
		for sent < total && werr == nil {
			n := len(payload)
			if total-sent < n {
				n = total - sent
			}
			_, werr = c.Write(payload[:n])
			sent += n
		}
		written <- werr
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
		for i := 0; i < n; i++ {
			if want := byte(((got + i) % len(payload)) * 7); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
	if err := <-written; err != nil {
		t.Fatalf("write side: %v", err)
	}
}

// requireHalfCloseCaps asserts the connection kept the half-close surface the
// raw QUIC stream provides.
func requireHalfCloseCaps(t *testing.T, c netproxy.Conn) {
	t.Helper()
	if _, ok := c.(interface{ CloseWrite() error }); !ok {
		t.Fatalf("hysteria2 conn %T lost the CloseWrite capability", c)
	}
	if _, ok := c.(interface{ CloseRead() error }); !ok {
		t.Fatalf("hysteria2 conn %T lost the CloseRead capability", c)
	}
}

// ---- the e2e tests ----

// TestE2EHysteria2TCPRelayHalfClose pushes 4MiB through client -> hysteria2
// server -> echo target -> back over a real QUIC connection with concurrent
// write+read, then half-closes and expects EOF.
func TestE2EHysteria2TCPRelayHalfClose(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startHysteria2Server(t, "user:pass")
	d := newHysteria2ClientDialerFromLink(t, proxyAddr, "user", "pass", "")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	requireHalfCloseCaps(t, c)
	verifyRelayRoundTrip(t, c, 4<<20)

	// Half-close must propagate: the server relays our FIN to the echo
	// target, the target finishes and closes, and we see EOF.
	closeWrite := c.(interface{ CloseWrite() error })
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := c.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
	}
	// Full close is clean: the deferred c.Close() runs without error.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestE2EHysteria2TCPConcurrentStreams multiplexes concurrent relays over the
// shared QUIC connection: each client.TCP call opens another stream, and all
// payloads must stay byte-exact.
func TestE2EHysteria2TCPConcurrentStreams(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startHysteria2Server(t, "user:pass")
	d := newHysteria2ClientDialerFromLink(t, proxyAddr, "user", "pass", "")

	const streams = 4
	const perStream = 1 << 20
	ctx := deadlineCtx(t)
	var wg sync.WaitGroup
	errCh := make(chan error, streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := d.DialContext(ctx, "tcp", echoAddr.String())
			if err != nil {
				errCh <- fmt.Errorf("stream %d dial: %w", i, err)
				return
			}
			defer c.Close()
			if err := c.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
				errCh <- fmt.Errorf("stream %d SetWriteDeadline: %w", i, err)
				return
			}
			// Stream-distinct pattern: every stream checks its own transform.
			total := perStream
			payload := make([]byte, 32<<10)
			for j := range payload {
				payload[j] = byte(j*11 + i + 1)
			}
			written := make(chan error, 1)
			go func() {
				sent := 0
				var werr error
				for sent < total && werr == nil {
					n := len(payload)
					if total-sent < n {
						n = total - sent
					}
					_, werr = c.Write(payload[:n])
					sent += n
				}
				written <- werr
			}()
			got := 0
			buf := make([]byte, 16<<10)
			if err := c.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
				errCh <- fmt.Errorf("stream %d SetReadDeadline: %w", i, err)
				return
			}
			for got < total {
				n, err := c.Read(buf)
				if err != nil {
					errCh <- fmt.Errorf("stream %d read at %d/%d: %w", i, got, total, err)
					return
				}
				for j := 0; j < n; j++ {
					if want := byte(((got+j)%(32<<10))*11 + i + 1); buf[j] != want {
						errCh <- fmt.Errorf("stream %d mismatch at %d", i, got+j)
						return
					}
				}
				got += n
			}
			if err := <-written; err != nil {
				errCh <- fmt.Errorf("stream %d write: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestE2EHysteria2UDPRelayIntegrityAndAddressing exercises UDP relay over
// QUIC datagrams: integrity, per-datagram addressing across two echo targets,
// and payloads large enough to require datagram fragmentation.
func TestE2EHysteria2UDPRelayIntegrityAndAddressing(t *testing.T) {
	echoA := startUDPEchoTarget(t)
	echoB := startUDPEchoTarget(t)
	proxyAddr := startHysteria2Server(t, "user:pass")
	d := newHysteria2ClientDialerFromLink(t, proxyAddr, "user", "pass", "")

	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", echoA.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()
	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}

	relay := newUDPRelaySession(t, packetConn)

	// Small datagrams to the session's default target.
	for i := 0; i < 10; i++ {
		payload := make([]byte, 100+i*80)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		relay.roundTrip(payload, echoA, fmt.Sprintf("default target #%d", i))
	}

	// Per-datagram addressing: the same session can target a second echo
	// server, and replies must carry that source address.
	for i := 0; i < 4; i++ {
		payload := []byte(fmt.Sprintf("second-target-%02d", i))
		relay.roundTrip(payload, echoB, fmt.Sprintf("second target #%d", i))
	}

	// Near-MTU datagrams: 1300 and 1400 bytes of payload exceed the QUIC
	// datagram budget (so the client fragments on send and/or the server
	// fragments on reply, with reassembly on the other side) while staying
	// small enough for raw UDP toward the echo target. Integrity must hold
	// whichever side fragments.
	for _, size := range []int{1300, 1400} {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(j * 13)
		}
		relay.roundTrip(payload, echoA, fmt.Sprintf("large %d", size))
	}
}

// TestE2EHysteria2BadPasswordIsAnErrorNotAPanic checks the auth-failure path:
// the server answers 401, the client Dial must surface an AuthError within
// the deadline, and closing the dialer must not panic.
func TestE2EHysteria2BadPasswordIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startHysteria2Server(t, "user:pass", withRejectAuth())
	d := newHysteria2ClientDialerFromLink(t, proxyAddr, "user", "pass", "")

	ctx := deadlineCtx(t)
	_, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err == nil {
		t.Fatal("dial against a rejecting server unexpectedly succeeded")
	}
	var authErr coreErrs.AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("dial error = %v, want protocol/hysteria2/errors.AuthError", err)
	}
	if authErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth status = %d, want %d", authErr.StatusCode, http.StatusUnauthorized)
	}
	// Close must be clean and prompt (bounded by the test deadline). The
	// concrete hysteria2 dialer exposes Close even though the netproxy
	// interface does not.
	closer, ok := d.(interface{ Close() error })
	if !ok {
		t.Fatalf("hysteria2 dialer %T lost Close", d)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("dialer Close after auth failure: %v", err)
	}
	// Closing twice must stay clean (idempotent shutdown).
	if err := closer.Close(); err != nil {
		t.Fatalf("second dialer Close: %v", err)
	}
}

// TestE2EHysteria2CloseReadAbortsRelay documents the client's half-close
// capability set: CloseRead maps to QUIC CancelRead, which aborts the relay
// instead of producing a clean EOF; reads on the canceled stream fail fast.
func TestE2EHysteria2CloseReadAbortsRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startHysteria2Server(t, "user:pass")
	d := newHysteria2ClientDialerFromLink(t, proxyAddr, "user", "pass", "")

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Establish the relay (the fast-open response is consumed by the first
	// Read; write until the echo answers so the stream is live).
	payload := make([]byte, 2048)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo round trip: %v", err)
	}

	// CloseRead aborts the read side: subsequent reads must fail promptly
	// (stream canceled), not hang and not return clean EOF data.
	closeRead, ok := c.(interface{ CloseRead() error })
	if !ok {
		t.Fatalf("hysteria2 conn %T lost the CloseRead capability", c)
	}
	if err := closeRead.CloseRead(); err != nil {
		t.Fatalf("CloseRead: %v", err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, err := c.Read(buf)
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("read after CloseRead unexpectedly succeeded")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("read after CloseRead hung")
	}
}

// TestE2EHysteria2ObfsSalamander runs the full stack under salamander packet
// obfuscation: QUIC packets are wrapped client-side and unwrapped by the
// server socket before the QUIC layer, then a TCP relay and UDP datagrams
// flow end to end.
func TestE2EHysteria2ObfsSalamander(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	udpEcho := startUDPEchoTarget(t)
	const obfsPassword = "s3cr3t-psk"
	proxyAddr := startHysteria2Server(t, "user:pass", withObfs([]byte(obfsPassword)))
	d := newHysteria2ClientDialerFromLink(t, proxyAddr, "user", "pass",
		"&obfs=salamander&obfs-password="+obfsPassword)

	ctx := deadlineCtx(t)

	// TCP relay with half-close.
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	verifyRelayRoundTrip(t, c, 1<<20)
	closeWrite := c.(interface{ CloseWrite() error })
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := c.Read(make([]byte, 1024)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
	}

	// UDP relay through the same obfuscated transport.
	pc, err := d.DialContext(ctx, "udp", udpEcho.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()
	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	relay := newUDPRelaySession(t, packetConn)
	for i := 0; i < 4; i++ {
		payload := []byte("obfs-udp-" + strconv.Itoa(i))
		relay.roundTrip(payload, udpEcho, fmt.Sprintf("obfs udp #%d", i))
	}
}
