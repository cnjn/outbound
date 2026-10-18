package anytls

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

type stubConn struct {
	closed bool
}

func (c *stubConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *stubConn) Close() error                       { c.closed = true; return nil }
func (c *stubConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *stubConn) LocalAddr() net.Addr                { return testAddr("local") }
func (c *stubConn) RemoteAddr() net.Addr               { return testAddr("remote") }

type recordingConn struct {
	mu                 sync.Mutex
	writes             [][]byte
	closed             bool
	readDeadlineCalls  int
	writeDeadlineCalls int
	lastWriteDeadline  time.Time
}

func (c *recordingConn) Read(_ []byte) (int, error) { return 0, io.EOF }

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := make([]byte, len(p))
	copy(buf, p)
	c.writes = append(c.writes, buf)
	return len(p), nil
}

func (c *recordingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *recordingConn) LocalAddr() net.Addr  { return testAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr { return testAddr("remote") }

func (c *recordingConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *recordingConn) SetReadDeadline(time.Time) error {
	c.mu.Lock()
	c.readDeadlineCalls++
	c.mu.Unlock()
	return nil
}

func (c *recordingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadlineCalls++
	c.lastWriteDeadline = t
	c.mu.Unlock()
	return nil
}

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestSessionCloseClosesActiveStreamsWithoutDeadlock(t *testing.T) {
	conn := &stubConn{}
	s := newSession(conn, 1)
	s.streams[1] = newStream(s, 1)
	s.streams[2] = newStream(s, 2)
	s.streams[3] = newStream(s, 3)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Close()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() timed out with active streams")
	}

	if !conn.closed {
		t.Fatal("expected session connection to be closed")
	}
	if len(s.streams) != 0 {
		t.Fatalf("remaining streams = %d, want 0", len(s.streams))
	}
}

func TestDialerWatchSessionStopsAfterSessionClose(t *testing.T) {
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
	}
	s := newSession(&stubConn{}, 7)
	stream := newStream(s, 1)
	if err := s.addStream(stream); err != nil {
		t.Fatalf("addStream() error = %v", err)
	}
	d.sessions[s.seq] = s

	done := make(chan struct{})
	go func() {
		d.watchSession(s)
		close(done)
	}()

	if err := stream.Close(); err != nil {
		t.Fatalf("stream Close() error = %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		d.idleSessionLock.Lock()
		_, ok := d.idleSessions[s.seq]
		d.idleSessionLock.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session was not added to idleSessions")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchSession did not exit after session close")
	}

	d.idleSessionLock.Lock()
	_, ok := d.idleSessions[s.seq]
	d.idleSessionLock.Unlock()
	if ok {
		t.Fatal("closed session remained in idleSessions")
	}
}

func TestDialerCloseClosesTrackedSessions(t *testing.T) {
	conn1 := &stubConn{}
	conn2 := &stubConn{}
	s1 := newSession(conn1, 1)
	s2 := newSession(conn2, 2)
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
		janitorDone:  make(chan struct{}),
	}
	d.idleSessions[s1.seq] = s1
	d.sessions[s1.seq] = s1
	d.sessions[s2.seq] = s2

	if err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !conn1.closed || !conn2.closed {
		t.Fatalf("expected all sessions to close: conn1=%v conn2=%v", conn1.closed, conn2.closed)
	}
	if len(d.idleSessions) != 0 || len(d.sessions) != 0 {
		t.Fatalf("session maps not cleared: idle=%d sessions=%d", len(d.idleSessions), len(d.sessions))
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestDialerCloseStopsIdleJanitor(t *testing.T) {
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
		janitorDone:  make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		d.runIdleJanitor()
		close(done)
	}()

	if err := d.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle janitor did not exit after Dialer.Close")
	}
}

func TestPacketStreamTransportDoneFollowsStreamClose(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	stream := newStream(s, 1)
	if err := s.addStream(stream); err != nil {
		t.Fatalf("addStream() error = %v", err)
	}
	packet := &packetStream{
		stream: stream,
		addr:   "127.0.0.1:53",
	}

	lifecycle, ok := any(packet).(interface{ TransportDone() <-chan struct{} })
	if !ok {
		t.Fatalf("packetStream does not implement TransportDone")
	}
	if lifecycle.TransportDone() != packet.closeCh {
		t.Fatal("TransportDone should expose the packet stream close channel")
	}

	select {
	case <-lifecycle.TransportDone():
		t.Fatal("TransportDone closed before stream close")
	default:
	}

	if err := packet.remoteClose(); err != nil {
		t.Fatalf("remoteClose() error = %v", err)
	}
	select {
	case <-lifecycle.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("TransportDone did not close after stream close")
	}
	select {
	case <-s.Done():
		t.Fatal("remote stream close should not close the reusable session")
	default:
	}
}

func TestPacketStreamTransportDoneClosesOnSessionClose(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	stream := newStream(s, 1)
	if err := s.addStream(stream); err != nil {
		t.Fatalf("addStream() error = %v", err)
	}
	packet := &packetStream{
		stream: stream,
		addr:   "127.0.0.1:53",
	}
	lifecycle := any(packet).(interface{ TransportDone() <-chan struct{} })

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-lifecycle.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("TransportDone did not close after session close")
	}
}

func TestStreamWriteSplitsOversizedPayload(t *testing.T) {
	conn := &recordingConn{}
	s := newSession(conn, 1)
	s.sendPadding = false
	stream := newStream(s, 1)
	payload := make([]byte, maxFramePayloadSize+10)

	n, err := stream.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() n = %d, want %d", n, len(payload))
	}
	if len(conn.writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(conn.writes))
	}
	if got := binary.BigEndian.Uint16(conn.writes[0][5:7]); got != maxFramePayloadSize {
		t.Fatalf("first frame length = %d, want %d", got, maxFramePayloadSize)
	}
	if got := binary.BigEndian.Uint16(conn.writes[1][5:7]); got != 10 {
		t.Fatalf("second frame length = %d, want 10", got)
	}
}

func TestWriteFrameRejectsOversizedControlPayload(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	s.sendPadding = false
	frame := newFrame(cmdSettings, 1)
	frame.data = make([]byte, maxFramePayloadSize+1)

	if _, err := writeFrame(s, frame); err == nil {
		t.Fatal("writeFrame() error = nil, want oversized payload error")
	}
}

func TestPacketReadFromDrainsShortBuffer(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	packet := &packetStream{
		stream: newStream(s, 1),
		addr:   "127.0.0.1:53",
	}
	packetBytes := appendLengthPrefixed(nil, []byte("abcd"))
	packetBytes = appendLengthPrefixed(packetBytes, []byte("ef"))
	chunk := pool.Get(len(packetBytes))
	copy(chunk, packetBytes)
	if err := packet.enqueue(chunk); err != nil {
		t.Fatalf("enqueue() error = %v", err)
	}

	if _, _, err := packet.ReadFrom(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short ReadFrom() error = %v, want %v", err, io.ErrShortBuffer)
	} else {
		var dropped *netproxy.ErrDatagramDropped
		if !errors.As(err, &dropped) {
			t.Fatalf("short ReadFrom() error = %v, want the datagram-dropped contract", err)
		}
	}
	buf := make([]byte, 2)
	n, _, err := packet.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom() error = %v", err)
	}
	if n != 2 || string(buf) != "ef" {
		t.Fatalf("second packet = %q/%d, want ef/2", string(buf), n)
	}
}

func TestReadDeadlineIsStreamLocal(t *testing.T) {
	conn := &recordingConn{}
	s := newSession(conn, 1)
	stream := newStream(s, 1)

	if err := stream.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	if conn.readDeadlineCalls != 0 {
		t.Fatalf("underlying read deadline calls = %d, want 0", conn.readDeadlineCalls)
	}
	_, err := stream.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() error = %v, want deadline exceeded", err)
	}
	if conn.readDeadlineCalls != 0 {
		t.Fatalf("underlying read deadline calls after Read = %d, want 0", conn.readDeadlineCalls)
	}
}

func TestSetWriteDeadlineAppliesOnlyDuringWrite(t *testing.T) {
	conn := &recordingConn{}
	s := newSession(conn, 1)
	s.sendPadding = false
	stream := newStream(s, 1)
	deadline := time.Now().Add(time.Minute)

	if err := stream.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	if conn.writeDeadlineCalls != 0 {
		t.Fatalf("underlying write deadline calls after SetWriteDeadline = %d, want 0", conn.writeDeadlineCalls)
	}
	if _, err := stream.Write([]byte("abc")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if conn.writeDeadlineCalls != 2 {
		t.Fatalf("underlying write deadline calls after Write = %d, want 2", conn.writeDeadlineCalls)
	}
	if !conn.lastWriteDeadline.IsZero() {
		t.Fatalf("last write deadline = %v, want zero restore", conn.lastWriteDeadline)
	}
}

func TestIdleSessionReuseRequiresIdleState(t *testing.T) {
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
	}
	s := newSession(&recordingConn{}, 7)
	stream := newStream(s, 1)
	if err := s.addStream(stream); err != nil {
		t.Fatalf("addStream() error = %v", err)
	}
	d.sessions[s.seq] = s
	done := make(chan struct{})
	go func() {
		d.watchSession(s)
		close(done)
	}()

	if err := stream.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		d.idleSessionLock.Lock()
		_, ok := d.idleSessions[s.seq]
		d.idleSessionLock.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session was not returned to idle pool")
		}
		time.Sleep(time.Millisecond)
	}

	reused, err := d.popIdleSessionForReuse()
	if err != nil {
		t.Fatalf("popIdleSessionForReuse() error = %v", err)
	}
	if reused != s {
		t.Fatalf("reused session = %p, want %p", reused, s)
	}
	if state := s.state.Load(); state != sessionStateActive {
		t.Fatalf("session state = %d, want active", state)
	}
	_ = s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchSession did not exit")
	}
}

func appendLengthPrefixed(dst, payload []byte) []byte {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	dst = append(dst, lenBuf[:]...)
	return append(dst, payload...)
}
