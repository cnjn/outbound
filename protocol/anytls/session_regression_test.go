package anytls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/pkg/bufferred_conn"
	"github.com/daeuniverse/outbound/pool"
)

type scriptedReadConn struct {
	*recordingConn
	reader *bytes.Reader
}

func (c *scriptedReadConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

type readStartedConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *readStartedConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(p)
}

type decodedTestFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

func decodeTestFrames(t *testing.T, data []byte) []decodedTestFrame {
	t.Helper()
	var frames []decodedTestFrame
	for len(data) > 0 {
		if len(data) < headerOverHeadSize {
			t.Fatalf("truncated frame header: %d bytes", len(data))
		}
		length := int(binary.BigEndian.Uint16(data[5:7]))
		frameSize := headerOverHeadSize + length
		if len(data) < frameSize {
			t.Fatalf("truncated frame payload: have %d, need %d", len(data), frameSize)
		}
		frames = append(frames, decodedTestFrame{
			cmd:  data[0],
			sid:  binary.BigEndian.Uint32(data[1:5]),
			data: append([]byte(nil), data[headerOverHeadSize:frameSize]...),
		})
		data = data[frameSize:]
	}
	return frames
}

func TestSessionCloseUnblocksHeaderRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	conn := &readStartedConn{
		Conn:    client,
		started: make(chan struct{}),
	}
	s := newSession(conn, 1)
	runDone := make(chan error, 1)
	go func() { runDone <- s.run() }()

	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("session run did not start reading")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("session run remained blocked after Close")
	}
}

func TestSessionRunRejectsDataOnEmptyControlFrames(t *testing.T) {
	for _, cmd := range []byte{cmdFIN, cmdHeartRequest, cmdHeartResponse} {
		t.Run(string(rune('0'+cmd)), func(t *testing.T) {
			var header rawHeader
			header[0] = cmd
			binary.BigEndian.PutUint16(header[5:], 1)
			conn := &scriptedReadConn{
				recordingConn: &recordingConn{},
				reader:        bytes.NewReader(header[:]),
			}
			s := newSession(conn, 1)
			if err := s.run(); err == nil {
				t.Fatalf("run() accepted payload for command %d", cmd)
			}
		})
	}
}

func TestStreamCloseWaitsForWriteSectionBeforeFIN(t *testing.T) {
	conn := &recordingConn{}
	s := newSession(conn, 1)
	s.sendPadding = false
	stream := newStream(s, 1)
	if err := s.addStream(stream); err != nil {
		t.Fatalf("addStream() error = %v", err)
	}

	stream.writeMutex.Lock()
	closeDone := make(chan error, 1)
	go func() { closeDone <- stream.Close() }()
	select {
	case <-stream.closeCh:
	case <-time.After(time.Second):
		stream.writeMutex.Unlock()
		t.Fatal("stream close did not start")
	}
	select {
	case err := <-closeDone:
		stream.writeMutex.Unlock()
		t.Fatalf("Close() returned before the write section was released: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	stream.writeMutex.Unlock()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not finish after the write section was released")
	}
	if len(conn.writes) != 1 || conn.writes[0][0] != cmdFIN {
		t.Fatalf("writes = %v, want one FIN frame", conn.writes)
	}
}

func TestStreamCloseWaitsForAdmittedEnqueueBeforeDrain(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	stream := newStream(s, 1)
	chunk := pool.Get(3)
	copy(chunk, "abc")

	stream.enqueueMu.RLock()
	stream.inbound <- chunk
	closeDone := make(chan error, 1)
	go func() { closeDone <- stream.closeLocal(false, net.ErrClosed) }()
	select {
	case <-stream.closeCh:
	case <-time.After(time.Second):
		stream.enqueueMu.RUnlock()
		t.Fatal("stream close did not start")
	}
	select {
	case err := <-closeDone:
		stream.enqueueMu.RUnlock()
		t.Fatalf("close completed before admitted enqueue exited: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	stream.enqueueMu.RUnlock()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("closeLocal() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closeLocal did not finish")
	}
	if got := len(stream.inbound); got != 0 {
		t.Fatalf("inbound retained %d chunks after close", got)
	}
}

func TestStreamReadSkipsEmptyChunks(t *testing.T) {
	s := newSession(&recordingConn{}, 1)
	stream := newStream(s, 1)
	if err := stream.enqueue(pool.Get(0)); err != nil {
		t.Fatalf("enqueue(empty) error = %v", err)
	}
	chunk := pool.Get(3)
	copy(chunk, "abc")
	if err := stream.enqueue(chunk); err != nil {
		t.Fatalf("enqueue(data) error = %v", err)
	}

	buf := make([]byte, 3)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 3 || string(buf) != "abc" {
		t.Fatalf("Read() = %q/%d, want abc/3", string(buf), n)
	}
}

func TestStreamZeroLengthWriteDoesNotEmitFrame(t *testing.T) {
	conn := &recordingConn{}
	s := newSession(conn, 1)
	s.sendPadding = false
	stream := newStream(s, 1)

	n, err := stream.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil) error = %v", err)
	}
	if n != 0 || len(conn.writes) != 0 {
		t.Fatalf("Write(nil) = %d, writes = %d; want 0 and no frame", n, len(conn.writes))
	}
}

func TestNewStreamBatchesInitialSessionFrames(t *testing.T) {
	conn := &recordingConn{}
	s := newSession(conn, 1)
	s.sendPadding = false

	first, err := s.newStream("example.com:443")
	if err != nil {
		t.Fatalf("newStream(first) error = %v", err)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("initial writes = %d, want 1", len(conn.writes))
	}
	frames := decodeTestFrames(t, conn.writes[0])
	if len(frames) != 3 {
		t.Fatalf("initial frame count = %d, want 3", len(frames))
	}
	if frames[0].cmd != cmdSettings || frames[0].sid != 0 {
		t.Fatalf("first frame = cmd %d sid %d, want Settings/0", frames[0].cmd, frames[0].sid)
	}
	if frames[1].cmd != cmdSYN || frames[1].sid != first.id {
		t.Fatalf("second frame = cmd %d sid %d, want SYN/%d", frames[1].cmd, frames[1].sid, first.id)
	}
	if frames[2].cmd != cmdPSH || frames[2].sid != first.id {
		t.Fatalf("third frame = cmd %d sid %d, want PSH/%d", frames[2].cmd, frames[2].sid, first.id)
	}

	if err := first.remoteClose(); err != nil {
		t.Fatalf("remoteClose(first) error = %v", err)
	}
	second, err := s.newStream("example.org:80")
	if err != nil {
		t.Fatalf("newStream(second) error = %v", err)
	}
	if len(conn.writes) != 3 {
		t.Fatalf("writes after reuse = %d, want initial batch plus SYN and PSH", len(conn.writes))
	}
	for i, want := range []byte{cmdSYN, cmdPSH} {
		reusedFrames := decodeTestFrames(t, conn.writes[i+1])
		if len(reusedFrames) != 1 || reusedFrames[0].cmd != want || reusedFrames[0].sid != second.id {
			t.Fatalf("reuse write %d = %+v, want cmd %d sid %d", i, reusedFrames, want, second.id)
		}
	}
	_ = s.Close()
}

func TestAuthenticationPacketUsesPaddingRuleZero(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	packet, err := buildAuthenticationPacket(key, DefaultPaddingFactory.Load())
	if err != nil {
		t.Fatalf("buildAuthenticationPacket() error = %v", err)
	}
	defer pool.Put(packet)

	if len(packet) != 64 {
		t.Fatalf("authentication packet length = %d, want 64", len(packet))
	}
	if !bytes.Equal(packet[:32], key) {
		t.Fatal("authentication packet key mismatch")
	}
	if got := binary.BigEndian.Uint16(packet[32:34]); got != 30 {
		t.Fatalf("padding length = %d, want 30", got)
	}
	if !bytes.Equal(packet[34:], make([]byte, 30)) {
		t.Fatal("authentication padding was not zeroed")
	}
}

func TestPaddingFactoryOwnsRawScheme(t *testing.T) {
	raw := []byte("stop=1\n0=30-30")
	padding := NewPaddingFactory(raw)
	if padding == nil {
		t.Fatal("NewPaddingFactory() returned nil")
	}
	raw[0] = 'X'
	if padding.RawScheme[0] == 'X' {
		t.Fatal("padding factory retained caller-owned raw scheme memory")
	}
}

func TestSessionRunReleasesBufferedReader(t *testing.T) {
	client, server := net.Pipe()
	buffered := bufferred_conn.NewBufferedConnSize(client, 64)
	s := newSession(buffered, 1)

	runDone := make(chan error, 1)
	go func() { runDone <- s.run() }()
	_ = server.Close()

	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("session run returned nil after peer close")
		}
	case <-time.After(time.Second):
		t.Fatal("session run did not return after peer close")
	}

	if _, err := buffered.Peek(0); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Peek after session reader release: %v", err)
	}
}
