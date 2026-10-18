package vision

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// recordingOverlayConn captures every discrete Write call received by the
// overlay (or underlay) connection so tests can assert both the Vision wire
// command and that each Vision frame is emitted in a single Write call.
type recordingOverlayConn struct {
	mu      sync.Mutex
	writes  [][]byte
	writeCh chan []byte
}

func (c *recordingOverlayConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordingOverlayConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	c.mu.Lock()
	c.writes = append(c.writes, cp)
	ch := c.writeCh
	c.mu.Unlock()
	if ch != nil {
		select {
		case ch <- cp:
		default:
		}
	}
	return len(p), nil
}
func (c *recordingOverlayConn) Close() error                     { return nil }
func (c *recordingOverlayConn) LocalAddr() net.Addr              { return nil }
func (c *recordingOverlayConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingOverlayConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingOverlayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingOverlayConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingOverlayConn) snapshotWrites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

type recordingIntrinsicOverlay struct {
	*recordingOverlayConn
	intrinsic netproxy.Conn
}

func (r *recordingIntrinsicOverlay) IntrinsicConn() netproxy.Conn {
	return r.intrinsic
}

func handshakedTLS13ClientConn(t *testing.T) *gotls.Conn {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	errCh := make(chan error, 1)
	go func() {
		sConn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		t.Cleanup(func() { _ = sConn.Close() })
		srv := gotls.Server(sConn, &gotls.Config{
			Certificates:           []gotls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
			MinVersion:             gotls.VersionTLS13,
			MaxVersion:             gotls.VersionTLS13,
			SessionTicketsDisabled: true,
		})
		errCh <- srv.Handshake()
	}()
	cConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cConn.Close() })
	cli := gotls.Client(cConn, &gotls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         gotls.VersionTLS13,
		MaxVersion:         gotls.VersionTLS13,
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client TLS 1.3 handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server TLS 1.3 handshake: %v", err)
	}
	return cli
}

// parseVisionFrameHeader decodes a single Vision padding frame written by the
// client (without leading UUID) and verifies that its length matches the exact
// slice written in a single Write call.
func parseVisionFrameHeader(t *testing.T, frame []byte) (cmd byte, content []byte, paddingLen int) {
	t.Helper()
	if len(frame) < 5 {
		t.Fatalf("vision frame too short: %d bytes", len(frame))
	}
	cmd = frame[0]
	contentLen := int(binary.BigEndian.Uint16(frame[1:3]))
	paddingLen = int(binary.BigEndian.Uint16(frame[3:5]))
	if got, want := len(frame), 5+contentLen+paddingLen; got != want {
		t.Fatalf("vision frame length = %d, want 5 + %d + %d = %d (frame was split across multiple Write calls)",
			got, contentLen, paddingLen, want)
	}
	return cmd, frame[5 : 5+contentLen], paddingLen
}

// buildTLS13ServerHelloRecord builds a TLS 1.3 ServerHello record with
// TLS_AES_128_GCM_SHA256 (0x1301) and the supported_versions extension
// (0x00 0x2b 0x00 0x02 0x03 0x04), which causes FilterTLS to set
// isTLS=true, isTLS12orAbove=true, enableXTLS=true, and packetsToFilter=0.
func buildTLS13ServerHelloRecord() []byte {
	buf := buildServerHello(32, 0xAA)
	binary.BigEndian.PutUint16(buf[serverHelloFixedOverhead+32:], 0x1301)
	copy(buf[serverHelloFixedOverhead+32+2:], tls13SupportedVersions)
	return buf
}

// buildTLSAppDataRecord wraps payload in a single TLS 1.3 ApplicationData
// record (0x17 0x03 0x03 + 2-byte big-endian length).
func buildTLSAppDataRecord(payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	rec[0], rec[1], rec[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

func TestIsCompleteAppDataRecords(t *testing.T) {
	rec1 := buildTLSAppDataRecord([]byte("hello world"))
	rec2 := buildTLSAppDataRecord([]byte("second record"))
	twoRecs := append(append([]byte(nil), rec1...), rec2...)

	if !isCompleteAppDataRecords(rec1) {
		t.Fatal("expected single complete 0x17 0x03 0x03 record to be complete")
	}
	if !isCompleteAppDataRecords(twoRecs) {
		t.Fatal("expected two concatenated complete 0x17 0x03 0x03 records to be complete")
	}
	// Truncated record must return false.
	if isCompleteAppDataRecords(rec1[:len(rec1)-1]) {
		t.Fatal("expected truncated 0x17 0x03 0x03 record to be incomplete")
	}
	// Zero-length record must return false.
	if isCompleteAppDataRecords([]byte{0x17, 0x03, 0x03, 0x00, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0xAA}) {
		t.Fatal("expected zero-length 0x17 0x03 0x03 record to return false")
	}
	// TLS 1.3 ChangeCipherSpec + encrypted Finished (starts with 0x14 0x03 0x03)
	// must NOT be treated as a pure ApplicationData record.
	ccsAndFinished := append([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}, rec1...)
	if isCompleteAppDataRecords(ccsAndFinished) {
		t.Fatal("expected ChangeCipherSpec + Finished (0x14...) to return false")
	}
}

// TestVisionTLS13HandshakeWaitsForApplicationDataBeforeDirectCopy reproduces
// the exact TLS 1.3 handshake sequence over Vision:
//  1. ServerHello is filtered on the read path -> packetsToFilter becomes 0,
//     isTLS=true, isTLS12orAbove=true, enableXTLS=true.
//  2. Client writes inner TLS 1.3 ChangeCipherSpec + Encrypted Finished
//     (starts with 0x14 0x03 0x03, NOT 0x17 0x03 0x03).
//     Previously, `sn.packetsToFilter <= 0` fired on this packet and emitted
//     commandPaddingDirect (0x02), switching the client to raw DirectCopy too
//     early so the subsequent HTTP/2 request was sent unencrypted over the
//     outer tunnel.
//  3. Client writes inner TLS 1.3 ApplicationData (0x17 0x03 0x03, e.g. HTTP/2
//     preface + GET). This frame must carry commandPaddingDirect (0x02) in a
//     single coalesced Write, and only subsequent writes go directly to the
//     underlay connection.
func TestVisionTLS13HandshakeWaitsForApplicationDataBeforeDirectCopy(t *testing.T) {
	underlay := &recordingOverlayConn{}
	overlay := &recordingOverlayConn{}
	vc := &Conn{
		Conn:                       underlay,
		overlayConn:                overlay,
		userUUID:                   make([]byte, 16),
		packetsToFilter:            6,
		needHandshake:              false, // inner ClientHello already sent
		writeFilterApplicationData: true,
	}
	vc.writer = &writeWrapper{vision: vc}
	vc.reader = &readWrapper{vision: vc}

	// Step 1: Inner ClientHello + ServerHello filtered.
	clientHello := []byte{0x16, 0x03, 0x01, 0x00, 0x10, tlsHandshakeTypeClientHello}
	clientHello = append(clientHello, make([]byte, 15)...)
	vc.FilterTLS(clientHello)
	vc.FilterTLS(buildTLS13ServerHelloRecord())

	sn := vc.filterSnapshot()
	if !sn.isTLS || !sn.isTLS12orAbove || !sn.enableXTLS || sn.packetsToFilter != 0 {
		t.Fatalf("unexpected filter snapshot after TLS 1.3 ServerHello: %+v", sn)
	}

	// Step 2: Client writes TLS 1.3 ChangeCipherSpec + Encrypted Finished.
	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	finishedRecord := buildTLSAppDataRecord(bytes.Repeat([]byte{0xFE}, 53))
	ccsAndFinished := append(append([]byte(nil), ccs...), finishedRecord...)

	if _, err := vc.Write(ccsAndFinished); err != nil {
		t.Fatalf("Write(CCS+Finished): %v", err)
	}
	if len(overlay.writes) != 1 {
		t.Fatalf("overlay writes after CCS+Finished = %d, want 1 single coalesced write", len(overlay.writes))
	}
	cmd, content, padLen := parseVisionFrameHeader(t, overlay.writes[0])
	if cmd != commandPaddingContinue {
		t.Fatalf("CCS+Finished Vision command = %d, want commandPaddingContinue (%d)", cmd, commandPaddingContinue)
	}
	if !bytes.Equal(content, ccsAndFinished) {
		t.Fatal("CCS+Finished content mismatch")
	}
	if padLen == 0 {
		t.Fatal("expected longPadding > 0 on TLS 1.3 CCS+Finished frame")
	}
	if !vc.writeFilterApplicationData || vc.toWriteDirect || vc.writer.writeDirect {
		t.Fatalf("premature switch to DirectCopy after CCS+Finished: writeFilterApplicationData=%v toWriteDirect=%v writeDirect=%v",
			vc.writeFilterApplicationData, vc.toWriteDirect, vc.writer.writeDirect)
	}
	if len(underlay.writes) != 0 {
		t.Fatalf("underlay writes after CCS+Finished = %d, want 0", len(underlay.writes))
	}

	// Step 3: Client writes first TLS 1.3 ApplicationData (e.g. HTTP/2 preface + HEADERS).
	firstAppData := buildTLSAppDataRecord(bytes.Repeat([]byte{0xAA}, 90))
	if _, err := vc.Write(firstAppData); err != nil {
		t.Fatalf("Write(firstAppData): %v", err)
	}
	if len(overlay.writes) != 2 {
		t.Fatalf("overlay writes after firstAppData = %d, want 2 (1 single coalesced write per frame)", len(overlay.writes))
	}
	cmd2, content2, padLen2 := parseVisionFrameHeader(t, overlay.writes[1])
	if cmd2 != commandPaddingDirect {
		t.Fatalf("firstAppData Vision command = %d, want commandPaddingDirect (%d)", cmd2, commandPaddingDirect)
	}
	if !bytes.Equal(content2, firstAppData) {
		t.Fatal("firstAppData content mismatch")
	}
	if padLen2 == 0 {
		t.Fatal("expected longPadding > 0 on transition ApplicationData frame")
	}
	if vc.writeFilterApplicationData || !vc.toWriteDirect || !vc.writer.writeDirect {
		t.Fatalf("expected DirectCopy enabled after firstAppData: writeFilterApplicationData=%v toWriteDirect=%v writeDirect=%v",
			vc.writeFilterApplicationData, vc.toWriteDirect, vc.writer.writeDirect)
	}

	// Step 4: Subsequent ApplicationData writes bypass overlay and go directly to underlay.
	secondAppData := buildTLSAppDataRecord(bytes.Repeat([]byte{0xBB}, 64))
	if _, err := vc.Write(secondAppData); err != nil {
		t.Fatalf("Write(secondAppData): %v", err)
	}
	if len(overlay.writes) != 2 {
		t.Fatalf("overlay writes after DirectCopy = %d, want 2 (no new overlay writes)", len(overlay.writes))
	}
	if len(underlay.writes) != 1 || !bytes.Equal(underlay.writes[0], secondAppData) {
		t.Fatalf("underlay writes = %d, want 1 exact raw TLS record", len(underlay.writes))
	}
}

// TestVisionTLS13ReshapedMultiRecordAppData covers the two-chunk ReshapeBytes
// branch: when a single Write carries multiple complete ApplicationData records
// whose total size exceeds BufferSize - PaddingHeaderLen, the first chunk stays
// on commandPaddingContinue and the trailing record carries commandPaddingDirect.
func TestVisionTLS13ReshapedMultiRecordAppData(t *testing.T) {
	underlay := &recordingOverlayConn{}
	overlay := &recordingOverlayConn{}
	vc := &Conn{
		Conn:                       underlay,
		overlayConn:                overlay,
		userUUID:                   make([]byte, 16),
		packetsToFilter:            6,
		needHandshake:              false,
		writeFilterApplicationData: true,
	}
	vc.writer = &writeWrapper{vision: vc}
	vc.reader = &readWrapper{vision: vc}

	vc.FilterTLS(buildTLS13ServerHelloRecord())

	rec1 := buildTLSAppDataRecord(bytes.Repeat([]byte{0x11}, 20<<10))
	rec2 := buildTLSAppDataRecord(bytes.Repeat([]byte{0x22}, 16<<10))
	combined := append(append([]byte(nil), rec1...), rec2...)

	if _, err := vc.Write(combined); err != nil {
		t.Fatalf("Write(combined): %v", err)
	}
	writes := overlay.snapshotWrites()
	if len(writes) != 2 {
		t.Fatalf("overlay writes = %d, want 2 frames", len(writes))
	}
	cmd1, content1, _ := parseVisionFrameHeader(t, writes[0])
	if cmd1 != commandPaddingContinue || !bytes.Equal(content1, rec1) {
		t.Fatalf("chunk 1 cmd=%d len=%d, want Continue and %d bytes", cmd1, len(content1), len(rec1))
	}
	cmd2, content2, _ := parseVisionFrameHeader(t, writes[1])
	if cmd2 != commandPaddingDirect || !bytes.Equal(content2, rec2) {
		t.Fatalf("chunk 2 cmd=%d len=%d, want Direct and %d bytes", cmd2, len(content2), len(rec2))
	}
	if !vc.writer.writeDirect {
		t.Fatal("expected writeDirect = true after reshaped ApplicationData transition")
	}
}

// TestHandshakeFlushFallbackEmitsOneContinueFrameWithUUID verifies that
// NewPacketConn on a TCP stream arms the 100ms handshake-flush timer:
//  1. After handshakeFlushDelay with no client write, exactly one Continue
//     frame is emitted in a single Write call;
//  2. That frame carries the 16-byte user UUID, empty content, and long
//     padding ([900, 1400) bytes);
//  3. Subsequent writes do NOT repeat the 16-byte user UUID;
//  4. Closing a connection before the delay stops the timer so no frame is sent.
func TestHandshakeFlushFallbackEmitsOneContinueFrameWithUUID(t *testing.T) {
	userUUID := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	tlsConn := handshakedTLS13ClientConn(t)
	overlay := &recordingOverlayConn{writeCh: make(chan []byte, 4)}
	pc, err := NewPacketConn(&recordingIntrinsicOverlay{
		recordingOverlayConn: overlay,
		intrinsic:            tlsConn,
	}, userUUID, "tcp", "203.0.113.10:22")
	if err != nil {
		t.Fatalf("NewPacketConn: %v", err)
	}
	defer func() { _ = pc.Close() }()

	var firstFrame []byte
	select {
	case firstFrame = <-overlay.writeCh:
	case <-time.After(handshakeFlushDelay + 400*time.Millisecond):
		t.Fatal("timed out waiting for handshake flush frame")
	}

	if len(firstFrame) < PaddingHeaderLen {
		t.Fatalf("first frame too short: %d bytes", len(firstFrame))
	}
	if !bytes.Equal(firstFrame[:16], userUUID) {
		t.Fatalf("first frame UUID = %x, want %x", firstFrame[:16], userUUID)
	}
	cmd, content, padLen := parseVisionFrameHeader(t, firstFrame[16:])
	if cmd != commandPaddingContinue {
		t.Fatalf("handshake flush command = %d, want commandPaddingContinue (%d)", cmd, commandPaddingContinue)
	}
	if len(content) != 0 {
		t.Fatalf("handshake flush content length = %d, want 0", len(content))
	}
	if padLen < 900 || padLen >= 1400 {
		t.Fatalf("handshake flush padding length = %d, want in [900, 1400)", padLen)
	}

	// Calling flushHandshakeIfNeeded again must be a no-op.
	if err := pc.flushHandshakeIfNeeded(); err != nil {
		t.Fatalf("second flushHandshakeIfNeeded: %v", err)
	}
	if got := len(overlay.snapshotWrites()); got != 1 {
		t.Fatalf("overlay writes after duplicate flush = %d, want 1", got)
	}

	// Next client write must NOT include the 16-byte userUUID prefix.
	payload := []byte("SSH-2.0-client\r\n")
	if _, err := pc.Write(payload); err != nil {
		t.Fatalf("Write after flush: %v", err)
	}
	writes := overlay.snapshotWrites()
	if len(writes) != 2 {
		t.Fatalf("overlay writes after payload = %d, want 2", len(writes))
	}
	cmd2, content2, _ := parseVisionFrameHeader(t, writes[1])
	if cmd2 != commandPaddingEnd {
		t.Fatalf("second frame command = %d, want commandPaddingEnd (%d)", cmd2, commandPaddingEnd)
	}
	if !bytes.Equal(content2, payload) {
		t.Fatalf("second frame content = %q, want %q", content2, payload)
	}

	// Closing before handshakeFlushDelay must stop the timer so nothing is written.
	earlyOverlay := &recordingOverlayConn{writeCh: make(chan []byte, 1)}
	earlyPC, err := NewPacketConn(&recordingIntrinsicOverlay{
		recordingOverlayConn: earlyOverlay,
		intrinsic:            tlsConn,
	}, userUUID, "tcp", "203.0.113.10:22")
	if err != nil {
		t.Fatalf("NewPacketConn (early close): %v", err)
	}
	if err := earlyPC.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case unexpected := <-earlyOverlay.writeCh:
		t.Fatalf("unexpected frame written after Close (%d bytes)", len(unexpected))
	case <-time.After(handshakeFlushDelay + 50*time.Millisecond):
	}
}
