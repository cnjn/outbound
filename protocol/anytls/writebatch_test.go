package anytls

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// batchRecConn captures every write for byte-equivalence comparison.
type batchRecConn struct {
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

func (r *batchRecConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, cp)
	return len(p), nil
}
func (r *batchRecConn) Read(p []byte) (int, error) { time.Sleep(time.Hour); return 0, nil }
func (r *batchRecConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}
func (r *batchRecConn) LocalAddr() net.Addr                { return nil }
func (r *batchRecConn) RemoteAddr() net.Addr               { return nil }
func (r *batchRecConn) SetDeadline(t time.Time) error      { return nil }
func (r *batchRecConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *batchRecConn) SetWriteDeadline(t time.Time) error { return nil }

func (r *batchRecConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []byte
	for _, w := range r.writes {
		out = append(out, w...)
	}
	return out
}

func newBatchTestSession(t *testing.T, rc *batchRecConn) *session {
	t.Helper()
	s := &session{
		conn:            rc,
		streams:         make(map[uint32]*stream),
		done:            make(chan struct{}),
		closeStreamChan: make(chan uint32, 4),
		probeMu:         sync.Mutex{},
	}
	return s
}

// TestWriteBatchMatchesSequentialWriteTo verifies the batched datagram path
// emits byte-identical framing to the per-datagram path, in ONE socket
// write instead of N.
func TestWriteBatchMatchesSequentialWriteTo(t *testing.T) {
	const sid = uint32(7)
	addr := "1.2.3.4:443"
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 1200),
		bytes.Repeat([]byte{0xBB}, 64),
		bytes.Repeat([]byte{0xCC}, 4500), // crosses maxFramePayloadSize split
	}

	// Sequential reference.
	seqConn := &batchRecConn{}
	seqSession := newBatchTestSession(t, seqConn)
	seqPacket := &packetStream{
		stream: &stream{session: seqSession, id: sid},
		addr:   addr,
	}
	for _, p := range payloads {
		if _, err := seqPacket.WriteTo(p, addr); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	// Batched.
	batConn := &batchRecConn{}
	batSession := newBatchTestSession(t, batConn)
	batPacket := &packetStream{
		stream: &stream{session: batSession, id: sid},
		addr:   addr,
	}
	if n, err := batPacket.WriteBatch([]netproxy.BatchItem{
		{Data: payloads[0], Addr: addr},
		{Data: payloads[1], Addr: addr},
		{Data: payloads[2], Addr: addr},
	}); err != nil || n != 3 {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}

	if !bytes.Equal(seqConn.bytes(), batConn.bytes()) {
		t.Fatalf("batched framing differs from sequential: seq=%d bytes (%d writes), batch=%d bytes (%d writes)",
			len(seqConn.bytes()), len(seqConn.writes), len(batConn.bytes()), len(batConn.writes))
	}
	if len(batConn.writes) != 1 {
		t.Fatalf("batched path used %d socket writes, want 1", len(batConn.writes))
	}
	if len(seqConn.writes) != len(payloads) {
		t.Fatalf("sequential path used %d writes, want %d", len(seqConn.writes), len(payloads))
	}
}

// TestWriteBatchRejectsOversizedAllOrNothing: per the PacketBatchWriter
// contract, a validation failure must send nothing (n == 0).
func TestWriteBatchRejectsOversizedAllOrNothing(t *testing.T) {
	rc := &batchRecConn{}
	s := newBatchTestSession(t, rc)
	ps := &packetStream{stream: &stream{session: s, id: 1}, addr: "1.1.1.1:53"}
	n, err := ps.WriteBatch([]netproxy.BatchItem{
		{Data: make([]byte, 64), Addr: "1.1.1.1:53"},
		{Data: make([]byte, maxUDPPayloadSize+1), Addr: "1.1.1.1:53"},
	})
	if err == nil || n != 0 {
		t.Fatalf("want error and n=0, got n=%d err=%v", n, err)
	}
	if len(rc.writes) != 0 {
		t.Fatalf("%d writes left despite validation failure", len(rc.writes))
	}
}

// TestWriteToMalformedAddrDoesNotPinUnconnectedFraming pins the mode-flag
// contract: the switch to unconnected framing must only happen after the
// first address actually parses. A malformed first address used to flip the
// flag before the parse, so every later datagram silently went out without
// an address the server had never learned, making the whole UDP session
// unparseable. The write after the failure must produce framing identical
// to a stream whose first write succeeded.
func TestWriteToMalformedAddrDoesNotPinUnconnectedFraming(t *testing.T) {
	const sid = uint32(7)
	addr := "1.2.3.4:443"
	payload := []byte("hello")

	refConn := &batchRecConn{}
	refPacket := &packetStream{stream: &stream{session: newBatchTestSession(t, refConn), id: sid}, addr: addr}
	// A write deadline keeps each write synchronous (confirmed flush through
	// the session writer), so the byte comparison below cannot race the
	// writer goroutine on a slow CI runner.
	if err := refPacket.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := refPacket.WriteTo(payload, addr); err != nil {
		t.Fatalf("reference WriteTo: %v", err)
	}

	conn := &batchRecConn{}
	ps := &packetStream{stream: &stream{session: newBatchTestSession(t, conn), id: sid}, addr: addr}
	if err := ps.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := ps.WriteTo(payload, "malformed-no-colon"); err == nil {
		t.Fatal("WriteTo with a malformed address must be rejected")
	}
	if _, err := ps.WriteTo(payload, addr); err != nil {
		t.Fatalf("WriteTo after a malformed address: %v", err)
	}
	if !bytes.Equal(refConn.bytes(), conn.bytes()) {
		t.Fatal("write after a malformed address lost connected framing: the stream was pinned to unconnected framing")
	}
}

// TestWriteBatchMalformedAddrDoesNotPinUnconnectedFraming verifies the same
// contract for the batched path: a batch whose first address is malformed
// must fail as a whole without flipping the mode flag.
func TestWriteBatchMalformedAddrDoesNotPinUnconnectedFraming(t *testing.T) {
	const sid = uint32(8)
	addr := "1.2.3.4:443"
	payload := []byte("hello")

	refConn := &batchRecConn{}
	refPacket := &packetStream{stream: &stream{session: newBatchTestSession(t, refConn), id: sid}, addr: addr}
	// Same synchronous-flush rationale as the WriteTo variant above.
	if err := refPacket.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := refPacket.WriteTo(payload, addr); err != nil {
		t.Fatalf("reference WriteTo: %v", err)
	}

	conn := &batchRecConn{}
	ps := &packetStream{stream: &stream{session: newBatchTestSession(t, conn), id: sid}, addr: addr}
	if err := ps.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := ps.WriteBatch([]netproxy.BatchItem{{Data: payload, Addr: "malformed-no-colon"}}); err == nil {
		t.Fatal("WriteBatch with a malformed address must be rejected")
	}
	if _, err := ps.WriteTo(payload, addr); err != nil {
		t.Fatalf("WriteTo after a malformed batch: %v", err)
	}
	if !bytes.Equal(refConn.bytes(), conn.bytes()) {
		t.Fatal("write after a malformed batch lost connected framing: the stream was pinned to unconnected framing")
	}
}
