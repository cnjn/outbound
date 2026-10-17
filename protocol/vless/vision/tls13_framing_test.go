package vision

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// recordingOverlayConn captures every discrete Write call received by the
// overlay (or underlay) connection so tests can assert both the Vision wire
// command and that each Vision frame is emitted in a single Write call.
type recordingOverlayConn struct {
	writes [][]byte
}

func (c *recordingOverlayConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *recordingOverlayConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	c.writes = append(c.writes, cp)
	return len(p), nil
}
func (c *recordingOverlayConn) Close() error                     { return nil }
func (c *recordingOverlayConn) LocalAddr() net.Addr              { return nil }
func (c *recordingOverlayConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingOverlayConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingOverlayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingOverlayConn) SetWriteDeadline(time.Time) error { return nil }

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

func TestIsCompleteRecord(t *testing.T) {
	rec1 := buildTLSAppDataRecord([]byte("hello world"))
	rec2 := buildTLSAppDataRecord([]byte("second record"))
	twoRecs := append(append([]byte(nil), rec1...), rec2...)

	if !isCompleteRecord(rec1) {
		t.Fatal("expected single complete 0x17 0x03 0x03 record to be complete")
	}
	if !isCompleteRecord(twoRecs) {
		t.Fatal("expected two concatenated complete 0x17 0x03 0x03 records to be complete")
	}
	// Truncated record must return false.
	if isCompleteRecord(rec1[:len(rec1)-1]) {
		t.Fatal("expected truncated 0x17 0x03 0x03 record to be incomplete")
	}
	// TLS 1.3 ChangeCipherSpec + encrypted Finished (starts with 0x14 0x03 0x03)
	// must NOT be treated as a pure ApplicationData record.
	ccsAndFinished := append([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}, rec1...)
	if isCompleteRecord(ccsAndFinished) {
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
