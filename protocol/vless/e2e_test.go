package vless_test

// True end-to-end coverage for the VLESS client stack (protocol/vless and its
// vision flow): an in-test VLESS server implementing the wire protocol
// independently from the spec (version 0, 16-byte UUID, addons length +
// protobuf addons, command byte, ATYP address, port), fronting real loopback
// echo targets, reached through the same dialer chain dae builds
// (direct -> transport/tls -> vless, with xtls-rprx-vision where noted).
//
// The in-test server never calls the client's own pack helpers: request
// headers, the 2-byte response header, the vision padding frames (commands
// continue/end), and the mux "packet" frames used by vision UDP are all
// encoded/decoded here from the wire format alone.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vless"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
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

// ---- in-test VLESS server (independent wire-format implementation) ----

// Wire command bytes and address types per the VLESS spec (independent
// constants: the server must not share the client's vocabulary).
const (
	vlessCmdTCP byte = 0x01
	vlessCmdUDP byte = 0x02
	vlessCmdMux byte = 0x03

	vlessATYPIPv4   byte = 0x01
	vlessATYPDomain byte = 0x02
	vlessATYPIPv6   byte = 0x03

	// xtls-rprx-vision. The server string-checks the addons flow so the e2e
	// fails loudly if the client ever stops sending it.
	vlessFlowVision = "xtls-rprx-vision"

	// Vision padding frame commands (server-side view of the spec).
	visionCmdContinue byte = 0x00
	visionCmdEnd      byte = 0x01
	visionCmdDirect   byte = 0x02

	// Mux ("packet") datagram frame fields used by the vision UDP path.
	xudpTypeKeep   byte = 0x02
	xudpProtoUDP   byte = 0x02
	xudpIPOptions  byte = 0x01
	xudpIPTypeIPv4 byte = 0x01
	xudpIPTypeIPv6 byte = 0x03

	// serverDeadline bounds every server-side conn so nothing can hang the
	// test past this point.
	serverDeadline = 120 * time.Second
)

// requestRecord is one parsed VLESS request header, kept for assertions.
type requestRecord struct {
	uuid [16]byte
	cmd  byte
	host string
	port uint16
	flow string
}

// serverStats records what the in-test server actually saw on the wire.
type serverStats struct {
	mu       sync.Mutex
	requests []requestRecord
	sawEnd   int // vision commandPaddingEnd/Direct frames from the client
}

func (s *serverStats) addRequest(rec requestRecord) {
	s.mu.Lock()
	s.requests = append(s.requests, rec)
	s.mu.Unlock()
}

func (s *serverStats) addEnd() {
	s.mu.Lock()
	s.sawEnd++
	s.mu.Unlock()
}

func (s *serverStats) snapshot() (requests []requestRecord, sawEnd int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]requestRecord(nil), s.requests...), s.sawEnd
}

// serverConfig binds one in-test server instance to its expected clients.
type serverConfig struct {
	// allowedUUIDs is the auth set; sessions with any other UUID are closed
	// immediately (the real-server behavior the bad-UUID test relies on).
	allowedUUIDs map[[16]byte]struct{}
	// wantFlow, when non-empty, must appear in every request's addons.
	wantFlow string
	// vision enables the vision padding/mux framing on top of VLESS.
	vision bool
	stats  serverStats
}

// readN reads exactly len(buf) bytes through the buffered server reader.
func readN(br *bufio.Reader, buf []byte) error {
	_, err := io.ReadFull(br, buf)
	return err
}

// parseAddonsFlow decodes only the protobuf Addons flow field (field 1,
// string) the way the spec defines it, independently of the generated types.
func parseAddonsFlow(addons []byte) (string, error) {
	flow := ""
	for len(addons) > 0 {
		tag := addons[0]
		addons = addons[1:]
		field, wire := tag>>3, tag&0x7
		switch wire {
		case 2: // length-delimited
			if len(addons) == 0 {
				return "", io.ErrUnexpectedEOF
			}
			l := int(addons[0])
			addons = addons[1:]
			if l > len(addons) {
				return "", io.ErrUnexpectedEOF
			}
			if field == 1 {
				flow = string(addons[:l])
			}
			addons = addons[l:]
		case 0: // varint
			for len(addons) > 0 && addons[0]&0x80 != 0 {
				addons = addons[1:]
			}
			if len(addons) == 0 {
				return "", io.ErrUnexpectedEOF
			}
			addons = addons[1:]
		default:
			return "", errors.New("unsupported addons wire type")
		}
	}
	return flow, nil
}

// readVlessRequest parses one VLESS request header from the server's view:
// version 0, 16-byte UUID, addons length + addons, command, and (except for
// the mux command) port + ATYP + address.
func readVlessRequest(br *bufio.Reader, cfg *serverConfig) (requestRecord, error) {
	rec := requestRecord{}
	var b [1]byte
	if err := readN(br, b[:]); err != nil {
		return rec, err
	}
	if b[0] != 0 {
		return rec, errors.New("bad vless version")
	}
	if err := readN(br, rec.uuid[:]); err != nil {
		return rec, err
	}
	if _, ok := cfg.allowedUUIDs[rec.uuid]; !ok {
		return rec, errors.New("unknown uuid")
	}
	if err := readN(br, b[:]); err != nil {
		return rec, err
	}
	addons := make([]byte, int(b[0]))
	if err := readN(br, addons); err != nil {
		return rec, err
	}
	flow, err := parseAddonsFlow(addons)
	if err != nil {
		return rec, err
	}
	rec.flow = flow
	if cfg.wantFlow != "" && flow != cfg.wantFlow {
		return rec, errors.New("unexpected addons flow: " + flow)
	}
	if err := readN(br, b[:]); err != nil {
		return rec, err
	}
	rec.cmd = b[0]
	if rec.cmd == vlessCmdMux {
		// Mux requests carry no destination; addressing is per-frame.
		return rec, nil
	}
	var portAndType [3]byte
	if err := readN(br, portAndType[:]); err != nil {
		return rec, err
	}
	rec.port = binary.BigEndian.Uint16(portAndType[0:2])
	switch portAndType[2] {
	case vlessATYPIPv4:
		var ip [4]byte
		if err := readN(br, ip[:]); err != nil {
			return rec, err
		}
		rec.host = net.IP(ip[:]).String()
	case vlessATYPDomain:
		var l [1]byte
		if err := readN(br, l[:]); err != nil {
			return rec, err
		}
		host := make([]byte, int(l[0]))
		if err := readN(br, host); err != nil {
			return rec, err
		}
		rec.host = string(host)
	case vlessATYPIPv6:
		var ip [16]byte
		if err := readN(br, ip[:]); err != nil {
			return rec, err
		}
		rec.host = net.IP(ip[:]).String()
	default:
		return rec, errors.New("bad address type")
	}
	return rec, nil
}

// writeResponseHeader emits the VLESS response header: version 0 + addons
// length 0.
func writeResponseHeader(w io.Writer) error {
	_, err := w.Write([]byte{0x00, 0x00})
	return err
}

// serveVlessTCPRelay is the plain (non-vision) TCP data path: the target is
// the address from the request header and both legs are raw byte streams
// after the response header.
func serveVlessTCPRelay(t *testing.T, downstream net.Conn, br *bufio.Reader, rec requestRecord) {
	t.Helper()
	destination := net.JoinHostPort(rec.host, strconv.Itoa(int(rec.port)))
	target, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	if err := writeResponseHeader(downstream); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(target, br)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(downstream, target)
}

// serveVlessUDPRelay is the plain UDP data path: the session target is the
// request address and every datagram rides the stream as a 2-byte big-endian
// length prefix + payload, in both directions.
func serveVlessUDPRelay(t *testing.T, downstream net.Conn, br *bufio.Reader, rec requestRecord) {
	t.Helper()
	destination := net.JoinHostPort(rec.host, strconv.Itoa(int(rec.port)))
	udp, err := net.Dial("udp", destination)
	if err != nil {
		return
	}
	defer udp.Close()
	if err := writeResponseHeader(downstream); err != nil {
		return
	}
	var lenBuf [2]byte
	for {
		if err := readN(br, lenBuf[:]); err != nil {
			return
		}
		payload := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if len(payload) > 0 {
			if err := readN(br, payload); err != nil {
				return
			}
		}
		if _, err := udp.Write(payload); err != nil {
			return
		}
		// The test's datagram ping-pong lets the server relay the echo
		// immediately after relaying the request.
		echo := make([]byte, 65535)
		n, err := udp.Read(echo)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
		if _, err := downstream.Write(lenBuf[:]); err != nil {
			return
		}
		if _, err := downstream.Write(echo[:n]); err != nil {
			return
		}
	}
}

// visionFrameReader parses the client->server vision padding stream: frames
// of [16-byte UUID (first frame only)][command][content length][padding
// length][content][padding]. After a commandPaddingEnd/Direct frame the
// client writes raw bytes, so the reader turns into a plain byte source.
type visionFrameReader struct {
	br        *bufio.Reader
	cfg       *serverConfig
	wantUUID  [16]byte
	firstDone bool
	raw       bool
}

func (r *visionFrameReader) readFrame() (cmd byte, content []byte, err error) {
	if r.raw {
		return visionCmdEnd, nil, errors.New("readFrame after raw mode")
	}
	header := make([]byte, 5)
	if !r.firstDone {
		header = make([]byte, 21)
		if err := readN(r.br, header); err != nil {
			return 0, nil, err
		}
		if !bytes.Equal(header[:16], r.wantUUID[:]) {
			return 0, nil, errors.New("vision frame uuid mismatch")
		}
		header = header[16:]
		r.firstDone = true
	} else {
		if err := readN(r.br, header); err != nil {
			return 0, nil, err
		}
	}
	cmd = header[0]
	contentLen := int(binary.BigEndian.Uint16(header[1:3]))
	paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
	content = make([]byte, contentLen)
	if err := readN(r.br, content); err != nil {
		return 0, nil, err
	}
	if _, err := io.CopyN(io.Discard, r.br, int64(paddingLen)); err != nil {
		return 0, nil, err
	}
	if cmd != visionCmdContinue {
		r.cfg.stats.addEnd()
		r.raw = true
	}
	return cmd, content, nil
}

// copyClientToTarget drives the client->server leg of a vision TCP session.
func (r *visionFrameReader) copyClientToTarget(target net.Conn) error {
	for {
		_, content, err := r.readFrame()
		if err != nil {
			return err
		}
		if _, err := target.Write(content); err != nil {
			return err
		}
		if r.raw {
			// After End/Direct the rest of the stream is raw bytes.
			_, err := io.Copy(target, r.br)
			return err
		}
	}
}

// writeVisionFrame emits one server->client padding frame. The first frame
// carries the client's UUID (the client filters it); command is always
// continue so the client stays in framed mode, which is the conservative
// legal server behavior for non-XTLS traffic.
func writeVisionFrame(w io.Writer, first bool, clientUUID [16]byte, cmd byte, content []byte, padLen int) error {
	buf := make([]byte, 0, len(content)+21+padLen)
	if first {
		buf = append(buf, clientUUID[:]...)
	}
	var lens [4]byte
	buf = append(buf, cmd)
	binary.BigEndian.PutUint16(lens[0:2], uint16(len(content)))
	binary.BigEndian.PutUint16(lens[2:4], uint16(padLen))
	buf = append(buf, lens[:]...)
	buf = append(buf, content...)
	for i := 0; i < padLen; i++ {
		buf = append(buf, byte(i))
	}
	_, err := w.Write(buf)
	return err
}

// readXudpFrame parses one client->server mux datagram frame:
// [2-byte length][session id 2B][type][option][protocol][port 2B]
// [ip type][ip][2-byte data length][payload], the layout the vision
// PacketConn's mux write path emits.
func readXudpFrame(br *bufio.Reader) (host string, port uint16, payload []byte, err error) {
	var l [2]byte
	if err = readN(br, l[:]); err != nil {
		return "", 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(l[:]))
	if err = readN(br, body); err != nil {
		return "", 0, nil, err
	}
	// body: session id(2) type(1) option(1) proto(1) port(2) iptype(1) ip.
	const fixedLen = 2 + 1 + 1 + 1 + 2 + 1
	if len(body) < fixedLen+4 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	ipType := body[fixedLen-1]
	ipLen := 4
	if ipType == xudpIPTypeIPv6 {
		ipLen = 16
	}
	if len(body) < fixedLen+ipLen {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	port = binary.BigEndian.Uint16(body[5:7])
	host = net.IP(body[fixedLen : fixedLen+ipLen]).String()
	var dataLen [2]byte
	if err = readN(br, dataLen[:]); err != nil {
		return "", 0, nil, err
	}
	payload = make([]byte, binary.BigEndian.Uint16(dataLen[:]))
	if len(payload) > 0 {
		if err = readN(br, payload); err != nil {
			return "", 0, nil, err
		}
	}
	return host, port, payload, nil
}

// writeXudpKeepFrame builds one server->client mux datagram frame with the
// keep type, matching the layout the client's ReadFrom parses.
func writeXudpKeepFrame(host string, port uint16, payload []byte) []byte {
	ip := net.ParseIP(host)
	ipLen := 4
	ipType := xudpIPTypeIPv4
	ipBytes := ip.To4()
	if ipBytes == nil {
		ipLen = 16
		ipType = xudpIPTypeIPv6
		ipBytes = ip.To16()
	}
	frameLen := 2 + 1 + 1 + 1 + 2 + 1 + ipLen // session id + type + option + proto + port + iptype + ip
	buf := make([]byte, 0, 2+frameLen+2+len(payload))
	var lens [2]byte
	binary.BigEndian.PutUint16(lens[:], uint16(frameLen))
	buf = append(buf, lens[:]...)
	buf = append(buf, 0, 0, xudpTypeKeep, xudpIPOptions, xudpProtoUDP)
	binary.BigEndian.PutUint16(lens[:], port)
	buf = append(buf, lens[:]...)
	buf = append(buf, ipType)
	buf = append(buf, ipBytes[:ipLen]...)
	binary.BigEndian.PutUint16(lens[:], uint16(len(payload)))
	buf = append(buf, lens[:]...)
	buf = append(buf, payload...)
	return buf
}

// serveVisionTCPRelay is the vision TCP data path: the client's padding
// stream carries the payload until an End/Direct frame, and the target's
// replies are padded back as continue frames until the target closes.
func serveVisionTCPRelay(t *testing.T, cfg *serverConfig, downstream net.Conn, br *bufio.Reader, rec requestRecord, clientUUID [16]byte) {
	t.Helper()
	destination := net.JoinHostPort(rec.host, strconv.Itoa(int(rec.port)))
	target, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	if err := writeResponseHeader(downstream); err != nil {
		return
	}
	reader := &visionFrameReader{br: br, cfg: cfg, wantUUID: clientUUID}
	go func() {
		_ = reader.copyClientToTarget(target)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	first := true
	frameIdx := 0
	buf := make([]byte, 32<<10)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			padLen := frameIdx % 256
			if werr := writeVisionFrame(downstream, first, clientUUID, visionCmdContinue, buf[:n], padLen); werr != nil {
				return
			}
			first = false
			frameIdx++
		}
		if err != nil {
			return
		}
	}
}

// serveVisionUDPRelay is the vision UDP ("mux command") data path: the client
// writes raw xudp datagram frames (its mux write path bypasses padding), the
// server relays each through a real UDP socket and pads every reply frame as
// a vision continue frame (the client's mux read path expects padding frames
// with a leading UUID on the first one).
func serveVisionUDPRelay(t *testing.T, downstream net.Conn, br *bufio.Reader, clientUUID [16]byte) {
	t.Helper()
	if err := writeResponseHeader(downstream); err != nil {
		return
	}
	firstFrame := true
	for {
		host, port, payload, err := readXudpFrame(br)
		if err != nil {
			return
		}
		destination := net.JoinHostPort(host, strconv.Itoa(int(port)))
		udp, err := net.Dial("udp", destination)
		if err != nil {
			return
		}
		if _, err := udp.Write(payload); err != nil {
			udp.Close()
			return
		}
		echo := make([]byte, 65535)
		n, err := udp.Read(echo)
		udp.Close()
		if err != nil {
			return
		}
		frame := writeXudpKeepFrame(host, port, echo[:n])
		if err := writeVisionFrame(downstream, firstFrame, clientUUID, visionCmdContinue, frame, 0); err != nil {
			return
		}
		firstFrame = false
	}
}

// serveVlessConn dispatches one accepted (possibly TLS) server connection.
func serveVlessConn(t *testing.T, cfg *serverConfig, downstream net.Conn) {
	t.Helper()
	defer downstream.Close()
	_ = downstream.SetDeadline(time.Now().Add(serverDeadline))
	if tc, ok := downstream.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			return
		}
		if cfg.vision && tc.ConnectionState().Version != tls.VersionTLS13 {
			t.Errorf("vision needs TLS 1.3, negotiated %#x", tc.ConnectionState().Version)
			return
		}
	}
	br := bufio.NewReaderSize(downstream, 32<<10)
	rec, err := readVlessRequest(br, cfg)
	if err != nil {
		// Unknown UUID or garbage: real servers close; do the same.
		return
	}
	cfg.stats.addRequest(rec)
	if cfg.vision {
		switch rec.cmd {
		case vlessCmdTCP:
			serveVisionTCPRelay(t, cfg, downstream, br, rec, rec.uuid)
		case vlessCmdMux:
			serveVisionUDPRelay(t, downstream, br, rec.uuid)
		default:
			t.Errorf("vision server got unexpected command %#x", rec.cmd)
		}
		return
	}
	switch rec.cmd {
	case vlessCmdTCP:
		serveVlessTCPRelay(t, downstream, br, rec)
	case vlessCmdUDP:
		serveVlessUDPRelay(t, downstream, br, rec)
	default:
		t.Errorf("server got unexpected command %#x", rec.cmd)
	}
}

// startVlessServer runs the in-test server on a real loopback listener.
func startVlessServer(t *testing.T, cfg *serverConfig, withTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("vless listen: %v", err)
	}
	if withTLS {
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
			NextProtos:   []string{"h2", "http/1.1"},
		})
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveVlessConn(t, cfg, c)
		}
	}()
	return ln.Addr().String()
}

// ---- client side (the exact construction chain dae builds) ----

// uuidKey maps a UUID string to the 16 auth bytes, per the spec's UUID
// mapping (hex of the dash-free UUID).
func uuidKey(t *testing.T, id string) [16]byte {
	t.Helper()
	raw := []byte(strings.ReplaceAll(id, "-", ""))
	if len(raw) != 32 {
		t.Fatalf("test bug: %q is not a UUID", id)
	}
	var key [16]byte
	if _, err := hex.Decode(key[:], raw); err != nil {
		t.Fatalf("uuid %q: %v", id, err)
	}
	return key
}

// newVlessClientDialer builds the dae-side dialer chain for vless:
// direct -> transport/tls (when withTLS) -> vless, with flow selecting the
// vision mode exactly like dialer/v2ray does.
func newVlessClientDialer(t *testing.T, proxyAddr, uuid, flow string, withTLS bool) netproxy.Dialer {
	t.Helper()
	direct, _ := dialer.NewDirectDialer(&dialer.ExtraOption{}, false)
	if withTLS {
		tlsDialer, _, err := tls2.NewTls(&dialer.ExtraOption{
			AllowInsecure:     true,
			TlsImplementation: "tls",
		}, direct, "tls://"+proxyAddr+"?sni=127.0.0.1&allowInsecure=1")
		if err != nil {
			t.Fatalf("tls dialer: %v", err)
		}
		direct = tlsDialer
	}
	d, err := protocol.NewDialer("vless", direct, protocol.Header{
		IsClient:     true,
		ProxyAddress: proxyAddr,
		Password:     uuid,
		Feature1:     flow,
	})
	if err != nil {
		t.Fatalf("vless dialer: %v", err)
	}
	return d
}

// verifyRelayRoundTrip writes a large deterministic payload through c, reads
// it back, and checks integrity. writeChunk must divide the 64KiB payload
// period. Large enough to cross record/buffer/frame boundaries, with the
// write and read legs running concurrently.
func verifyRelayRoundTrip(t *testing.T, c netproxy.Conn, total, writeChunk int) {
	t.Helper()
	period := 64 << 10
	payload := make([]byte, period)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	sent := 0
	writeDone := make(chan error, 1)
	go func() {
		for sent < total {
			n := writeChunk
			if total-sent < n {
				n = total - sent
			}
			if _, err := c.Write(payload[:n]); err != nil {
				writeDone <- err
				return
			}
			sent += n
		}
		writeDone <- nil
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
		// Verify every byte, which also crosses record, buffer, and padding
		// frame boundaries.
		for i := 0; i < n; i++ {
			if want := byte(((got + i) % period) * 7); buf[i] != want {
				t.Fatalf("payload mismatch at %d: got %#x want %#x", got+i, buf[i], want)
			}
		}
		got += n
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("concurrent write leg: %v", err)
	}
}

// requireCloseWrite asserts the half-close capability survived the wrapper
// chain, half-closes, and expects the relayed EOF. Optional capabilities that
// silently vanish behind a wrapper must fail the e2e instead of skipping.
func requireCloseWrite(t *testing.T, c netproxy.Conn) {
	t.Helper()
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("vless conn %T lost the CloseWrite capability", c)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1024)
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatalf("read after half-close = %d, %v, want 0, EOF", n, err)
	}
}

// ---- the e2e tests ----

// TestE2EVlessOverRawTCPRelay pushes 4MiB through client -> in-test vless
// server -> echo target -> back over a raw TCP session, then half-closes and
// expects the propagated EOF (a real TCP FIN on this chain).
func TestE2EVlessOverRawTCPRelay(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	uuidA := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	cfg := &serverConfig{allowedUUIDs: map[[16]byte]struct{}{uuidKey(t, uuidA): {}}}
	proxyAddr := startVlessServer(t, cfg, false)
	d := newVlessClientDialer(t, proxyAddr, uuidA, "", false)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	verifyRelayRoundTrip(t, c, 4<<20, 64<<10)

	requests, _ := cfg.stats.snapshot()
	if len(requests) != 1 || requests[0].cmd != vlessCmdTCP {
		t.Fatalf("server saw %+v, want one tcp-command request", requests)
	}
	if requests[0].host != "127.0.0.1" || requests[0].port != uint16(echoAddr.(*net.TCPAddr).Port) {
		t.Fatalf("server routed to %s:%d, want the echo target", requests[0].host, requests[0].port)
	}
	requireCloseWrite(t, c)
}

// TestE2EVlessOverTLSRelayTwoUUIDs runs the same 4MiB relay through a real
// crypto/tls server with two different client UUIDs configured, exercising
// the coalesce.FlushConn chain end to end, including its half-close forward
// (TLS close_notify at the transport layer, since crypto/tls owns the
// session and the chain has no TCP FIN surface).
func TestE2EVlessOverTLSRelayTwoUUIDs(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	uuidA := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	uuidB := "2f4d6c8e-0a1c-4e5b-9d3f-7b8a2c1e6d90"
	cfg := &serverConfig{allowedUUIDs: map[[16]byte]struct{}{
		uuidKey(t, uuidA): {},
		uuidKey(t, uuidB): {},
	}}
	proxyAddr := startVlessServer(t, cfg, true)

	ctx := deadlineCtx(t)
	authenticated := map[[16]byte]bool{}
	for _, uuid := range []string{uuidA, uuidB} {
		d := newVlessClientDialer(t, proxyAddr, uuid, "", true)
		c, err := d.DialContext(ctx, "tcp", echoAddr.String())
		if err != nil {
			t.Fatalf("dial with %s: %v", uuid, err)
		}
		verifyRelayRoundTrip(t, c, 4<<20, 64<<10)
		requireCloseWrite(t, c)
		c.Close()
		authenticated[uuidKey(t, uuid)] = true
	}

	requests, _ := cfg.stats.snapshot()
	if len(requests) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(requests))
	}
	for _, rec := range requests {
		if rec.cmd != vlessCmdTCP {
			t.Fatalf("request command = %#x, want tcp", rec.cmd)
		}
		if _, ok := cfg.allowedUUIDs[rec.uuid]; !ok {
			t.Fatalf("server accepted unknown uuid %x", rec.uuid)
		}
		delete(authenticated, rec.uuid)
	}
	if len(authenticated) != 0 {
		t.Fatalf("uuids never observed by the server: %v", authenticated)
	}
}

// TestE2EVlessUDPRelayOverTLS exercises UDP over the vless stream through the
// TLS chain: length-prefixed datagrams to the session target, integrity and
// source addressing on the way back, including jumbo datagrams.
func TestE2EVlessUDPRelayOverTLS(t *testing.T) {
	udpEcho := startUDPEchoTarget(t)
	uuidA := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	cfg := &serverConfig{allowedUUIDs: map[[16]byte]struct{}{uuidKey(t, uuidA): {}}}
	proxyAddr := startVlessServer(t, cfg, true)
	d := newVlessClientDialer(t, proxyAddr, uuidA, "", true)

	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", udpEcho.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()

	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	sizes := make([]int, 0, 18)
	for i := 0; i < 16; i++ {
		sizes = append(sizes, 200+i*31)
	}
	// One full-MTU datagram. Larger single datagrams need IP fragmentation,
	// which this sandboxed environment drops (a plain net.UDPConn probe
	// reproduces it), so jumbo sizes cannot be exercised here.
	sizes = append(sizes, 1472)
	for i, size := range sizes {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		if _, err := packetConn.WriteTo(payload, udpEcho.String()); err != nil {
			t.Fatalf("datagram %d WriteTo: %v", i, err)
		}
		buf := make([]byte, 65535)
		if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, from, err := packetConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d ReadFrom: %v", i, err)
		}
		if n != len(payload) || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("datagram %d mismatch: n=%d want %d", i, n, len(payload))
		}
		requireDatagramSource(t, i, from, udpEcho)
	}

	requests, _ := cfg.stats.snapshot()
	if len(requests) != 1 || requests[0].cmd != vlessCmdUDP {
		t.Fatalf("server saw %+v, want one udp-command request", requests)
	}
}

// requireDatagramSource checks the datagram's reported source address
// semantically (loopback IP + echo port). The plain-vless path reports the
// client's cached session target, which ResolveUDPAddr renders as a 4-in-6
// address on this toolchain ("[::ffff:127.0.0.1]:p"), so string equality
// against the echo address would be the wrong assertion there.
func requireDatagramSource(t *testing.T, i int, from netip.AddrPort, want net.Addr) {
	t.Helper()
	wantAddr, err := netip.ParseAddr(want.(*net.UDPAddr).IP.String())
	if err != nil {
		t.Fatalf("parse echo addr: %v", err)
	}
	if from.Addr().Unmap() != wantAddr || int(from.Port()) != want.(*net.UDPAddr).Port {
		t.Fatalf("datagram %d source = %v, want %v", i, from, want)
	}
}

// TestE2EVlessVisionTCPRelayOverTLS is the vision stretch goal: a full
// xtls-rprx-vision session over TLS 1.3 against an in-test vision-aware
// server. The client pads its writes (handshake frame with UUID, then the
// commandPaddingEnd switch for non-TLS payload, then raw), the server pads
// its replies as continue frames; 4MiB must come back byte-exact through the
// padding state machine. Half-close is drained (the client may still hold
// unread padding of the final frame, so EOF arrives after the server closes).
func TestE2EVlessVisionTCPRelayOverTLS(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	uuidA := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	cfg := &serverConfig{
		allowedUUIDs: map[[16]byte]struct{}{uuidKey(t, uuidA): {}},
		wantFlow:     vlessFlowVision,
		vision:       true,
	}
	proxyAddr := startVlessServer(t, cfg, true)
	d := newVlessClientDialer(t, proxyAddr, uuidA, vless.XRV, true)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// 16KiB writes keep the vision reshape/split path out of the test and
	// cross the padding frame boundaries repeatedly.
	verifyRelayRoundTrip(t, c, 4<<20, 16<<10)

	requests, sawEnd := cfg.stats.snapshot()
	if len(requests) != 1 || requests[0].cmd != vlessCmdTCP || requests[0].flow != vlessFlowVision {
		t.Fatalf("server saw %+v (sawEnd=%d), want one vision tcp request", requests, sawEnd)
	}
	if sawEnd == 0 {
		t.Fatal("client never sent a vision commandPaddingEnd frame; the padding state machine did not run")
	}

	// Half-close: with vision the CloseWrite forward reaches the same TLS
	// chain (close_notify). Drain to EOF instead of a single-read assertion:
	// trailing padding of the last server frame may still be in flight.
	closeWrite, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("vision conn %T lost the CloseWrite capability", c)
	}
	if err := closeWrite.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
}

// serveVisionDirectTCPRelay simulates a real Xray-core server handling an
// inner TLS 1.3 connection over Vision: once either side sends a frame with
// commandPaddingDirect (0x02), that leg switches from the outer TLS connection
// directly to the underlying raw TCP connection (DirectCopy/Splice) for all
// subsequent inner TLS 1.3 ApplicationData records.
func serveVisionDirectTCPRelay(t *testing.T, cfg *serverConfig, tc *tls.Conn, rawConn net.Conn, br *bufio.Reader, rec requestRecord, clientUUID [16]byte) {
	t.Helper()
	destination := net.JoinHostPort(rec.host, strconv.Itoa(int(rec.port)))
	target, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	if err := writeResponseHeader(tc); err != nil {
		return
	}
	reader := &visionFrameReader{br: br, cfg: cfg, wantUUID: clientUUID}
	go func() {
		for {
			cmd, content, err := reader.readFrame()
			if err != nil {
				return
			}
			if _, err := target.Write(content); err != nil {
				return
			}
			if cmd == visionCmdDirect {
				// Drain any buffered outer TLS plaintext, then read raw inner
				// TLS records directly from rawConn (matching Xray-core's
				// DirectCopy uplink transition).
				if br.Buffered() > 0 {
					_, _ = io.CopyN(target, br, int64(br.Buffered()))
				}
				_, _ = io.Copy(target, rawConn)
				if tcp, ok := target.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				return
			}
			if cmd == visionCmdEnd {
				_, _ = io.Copy(target, br)
				if tcp, ok := target.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				return
			}
		}
	}()
	first := true
	buf := make([]byte, 32<<10)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			cmd := visionCmdContinue
			if len(chunk) >= 6 && bytes.Equal(chunk[:3], []byte{0x17, 0x03, 0x03}) {
				cmd = visionCmdDirect
			}
			if werr := writeVisionFrame(tc, first, clientUUID, cmd, chunk, 32); werr != nil {
				return
			}
			first = false
			if cmd == visionCmdDirect {
				_, _ = io.Copy(rawConn, target)
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestE2EVlessVisionInnerTLS13DirectCopy runs a real inner TLS 1.3 handshake
// and data transfer inside an outer TLS 1.3 VLESS+Vision tunnel, verifying
// that:
//  1. Each Vision padding frame is emitted in a single outer TLS record so the
//     server's outer TLS reader never swallows trailing DirectCopy records into
//     rawInput while reading padding;
//  2. Inner TLS 1.3 ChangeCipherSpec + Finished stays on commandPaddingContinue
//     and does not prematurely trigger DirectCopy;
//  3. The first inner TLS 1.3 ApplicationData record triggers commandPaddingDirect
//     and cleanly transitions both directions to raw underlay DirectCopy.
func TestE2EVlessVisionInnerTLS13DirectCopy(t *testing.T) {
	// Start an inner TLS 1.3 echo target (simulating an HTTPS origin on :443).
	rawTargetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inner tls listen: %v", err)
	}
	innerTargetLn := tls.NewListener(rawTargetLn, &tls.Config{
		Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	t.Cleanup(func() { _ = innerTargetLn.Close() })
	go func() {
		for {
			c, err := innerTargetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	uuidA := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	cfg := &serverConfig{
		allowedUUIDs: map[[16]byte]struct{}{uuidKey(t, uuidA): {}},
		wantFlow:     vlessFlowVision,
		vision:       true,
	}
	outerRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("outer listen: %v", err)
	}
	t.Cleanup(func() { _ = outerRawLn.Close() })
	outerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{e2eSelfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	go func() {
		for {
			rawConn, err := outerRawLn.Accept()
			if err != nil {
				return
			}
			go func(rawConn net.Conn) {
				defer rawConn.Close()
				_ = rawConn.SetDeadline(time.Now().Add(serverDeadline))
				tc := tls.Server(rawConn, outerTLSConfig)
				if err := tc.Handshake(); err != nil {
					return
				}
				br := bufio.NewReaderSize(tc, 32<<10)
				rec, err := readVlessRequest(br, cfg)
				if err != nil {
					return
				}
				cfg.stats.addRequest(rec)
				serveVisionDirectTCPRelay(t, cfg, tc, rawConn, br, rec, rec.uuid)
			}(rawConn)
		}
	}()

	d := newVlessClientDialer(t, outerRawLn.Addr().String(), uuidA, vless.XRV, true)
	ctx := deadlineCtx(t)
	tunnelConn, err := d.DialContext(ctx, "tcp", innerTargetLn.Addr().String())
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer tunnelConn.Close()

	// Perform a real inner TLS 1.3 handshake over the Vision tunnel.
	innerTLSClient := tls.Client(&netproxy.FakeNetConn{Conn: tunnelConn}, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	defer innerTLSClient.Close()
	if err := innerTLSClient.HandshakeContext(ctx); err != nil {
		t.Fatalf("inner TLS 1.3 handshake over Vision failed: %v", err)
	}

	// Send multiple small and large application records to exercise the
	// transition frame (HTTP/2 preface + request) and subsequent DirectCopy frames.
	for i, size := range []int{24, 90, 512, 16 << 10, 64 << 10} {
		msg := bytes.Repeat([]byte{byte(0x30 + i)}, size)
		if _, err := innerTLSClient.Write(msg); err != nil {
			t.Fatalf("inner TLS write %d (size=%d): %v", i, size, err)
		}
		reply := make([]byte, size)
		if _, err := io.ReadFull(innerTLSClient, reply); err != nil {
			t.Fatalf("inner TLS read %d (size=%d): %v", i, size, err)
		}
		if !bytes.Equal(reply, msg) {
			t.Fatalf("inner TLS echo mismatch on chunk %d (size=%d)", i, size)
		}
	}

	_, sawEnd := cfg.stats.snapshot()
	if sawEnd != 1 {
		t.Fatalf("server saw %d End/Direct transition frames, want 1", sawEnd)
	}
}

// TestE2EVlessVisionUDPRelayOverTLS covers vision UDP: the client sends mux
// packet frames addressed per datagram, the server relays through a real UDP
// socket and pads every reply; integrity and source addressing are checked.
func TestE2EVlessVisionUDPRelayOverTLS(t *testing.T) {
	udpEcho := startUDPEchoTarget(t)
	uuidA := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	cfg := &serverConfig{
		allowedUUIDs: map[[16]byte]struct{}{uuidKey(t, uuidA): {}},
		wantFlow:     vlessFlowVision,
		vision:       true,
	}
	proxyAddr := startVlessServer(t, cfg, true)
	d := newVlessClientDialer(t, proxyAddr, uuidA, vless.XRV, true)

	ctx := deadlineCtx(t)
	pc, err := d.DialContext(ctx, "udp", udpEcho.String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer pc.Close()

	packetConn, ok := pc.(netproxy.PacketConn)
	if !ok {
		t.Fatalf("DialContext(udp) returned %T, want a PacketConn", pc)
	}
	sizes := []int{200, 431, 1200, 1472}
	for i, size := range sizes {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(i*3 + j)
		}
		if _, err := packetConn.WriteTo(payload, udpEcho.String()); err != nil {
			t.Fatalf("datagram %d WriteTo: %v", i, err)
		}
		buf := make([]byte, 65535)
		if err := pc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, from, err := packetConn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d ReadFrom: %v", i, err)
		}
		if n != len(payload) || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("datagram %d mismatch: n=%d want %d", i, n, len(payload))
		}
		requireDatagramSource(t, i, from, udpEcho)
	}

	requests, _ := cfg.stats.snapshot()
	if len(requests) != 1 || requests[0].cmd != vlessCmdMux {
		t.Fatalf("server saw %+v, want one mux-command request", requests)
	}
}

// TestE2EVlessBadUUIDIsAnErrorNotAPanic checks the auth-failure path: the
// server closes on the unknown UUID and the client surfaces an error on some
// write or read instead of panicking or hanging.
func TestE2EVlessBadUUIDIsAnErrorNotAPanic(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	goodUUID := "6b3b0a6c-9b7e-4f1d-8c2a-3f5e1d7b9c01"
	badUUID := "11111111-2222-3333-4444-555555555555"
	cfg := &serverConfig{allowedUUIDs: map[[16]byte]struct{}{uuidKey(t, goodUUID): {}}}
	proxyAddr := startVlessServer(t, cfg, true)
	d := newVlessClientDialer(t, proxyAddr, badUUID, "", true)

	ctx := deadlineCtx(t)
	c, err := d.DialContext(ctx, "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	_, _ = c.Write([]byte("hello"))
	for i := 0; i < 10; i++ {
		if _, err := c.Read(buf); err != nil {
			return // an error surfaced: pass
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("server closed the session but the client never surfaced an error")
}
