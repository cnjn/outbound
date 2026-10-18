package netproxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// scriptConn is a deterministic Conn for the pooled-buffer lifecycle tests: it
// serves scripted payload bytes, then a settable error (io.EOF when unset).
// Close is a no-op so a test can keep draining bytes that are already buffered.
type scriptConn struct {
	mu       sync.Mutex
	data     []byte
	failWith error
}

func (c *scriptConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) > 0 {
		n := copy(p, c.data)
		c.data = c.data[n:]
		return n, nil
	}
	if c.failWith != nil {
		return 0, c.failWith
	}
	return 0, io.EOF
}

func (c *scriptConn) script(data []byte, failWith error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = data
	c.failWith = failWith
}

func (c *scriptConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// stagedReadConn blocks inside Read until Close runs, and reports the address
// of the buffer the reader handed to the underlay, so a test can prove that a
// second connection never receives an array a blocked reader still holds. It
// is the same staged shape pkg/bufferred_conn uses for that invariant.
type stagedReadConn struct {
	readStarted  chan *byte
	closeStarted chan struct{}
	releaseClose chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
}

func newStagedReadConn() *stagedReadConn {
	return &stagedReadConn{
		readStarted:  make(chan *byte, 1),
		closeStarted: make(chan struct{}),
		releaseClose: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *stagedReadConn) Read(p []byte) (int, error) {
	c.readStarted <- &p[0]
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stagedReadConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *stagedReadConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeStarted)
		<-c.releaseClose
		close(c.closed)
	})
	return nil
}

func (c *stagedReadConn) SetDeadline(time.Time) error      { return nil }
func (c *stagedReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stagedReadConn) SetWriteDeadline(time.Time) error { return nil }

// lifecycleState reports whether the pooled array has gone back to the pool,
// and how large a window the reader still holds (zero once released).
func lifecycleState(c *BufferedReaderConn) (released bool, bufSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.released, c.reader.Size()
}

// A terminal EOF is the read loop's exit path: it must return the pooled array
// and keep reporting the same error afterwards.
func TestBufferedReaderReleasesOnEOF(t *testing.T) {
	c := ForceBufferedReaderConn(&scriptConn{}, 0)
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("first read = %v, want io.EOF", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("after EOF: released=%v buffer size=%d, want released with no window", released, size)
	}
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("post-release read = %v, want stable io.EOF", err)
	}
	if n := c.ReadBuffered(); n != 0 {
		t.Fatalf("ReadBuffered after release = %d, want 0", n)
	}
}

// A payload must be served whole, and the array only returned once the stream
// it belongs to has actually ended.
func TestBufferedReaderServesPayloadThenReleases(t *testing.T) {
	c := ForceBufferedReaderConn(&scriptConn{data: []byte("hello")}, 0)
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if released, _ := lifecycleState(c); !released {
		t.Fatal("pooled array not released after the stream ended")
	}
}

// Deadline timeouts are retryable by net.Conn semantics: they must not release
// the array, and a later read must still be served.
func TestBufferedReaderTimeoutRetryKeepsBuffer(t *testing.T) {
	raw := &scriptConn{failWith: os.ErrDeadlineExceeded}
	c := ForceBufferedReaderConn(raw, 0)
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first read = %v, want deadline exceeded", err)
	}
	if released, _ := lifecycleState(c); released {
		t.Fatal("retryable deadline error released the pooled array")
	}
	raw.script([]byte("data"), nil)
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "data" {
		t.Fatalf("retry read = %q, %v; want \"data\"", buf, err)
	}
}

// Close on an idle connection ends the session without a draining read, so it
// must return the array and keep reporting the closed connection.
func TestBufferedReaderIdleCloseReleases(t *testing.T) {
	c := ForceBufferedReaderConn(&scriptConn{}, 0)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("idle Close: released=%v buffer size=%d, want released with no window", released, size)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-release read = %v, want net.ErrClosed", err)
	}
}

// Bytes that are already buffered stay readable after Close, exactly as the
// pre-pooling wrapper served them; the array goes back only once they drain.
func TestBufferedReaderCloseWithBufferedBytesKeepsThenReleases(t *testing.T) {
	payload := []byte("a payload that stays buffered until drained")
	c := ForceBufferedReaderConn(&scriptConn{data: payload}, 0)
	one := make([]byte, 1)
	if n, err := c.Read(one); n != 1 || err != nil || one[0] != payload[0] {
		t.Fatalf("first read = %q, %v", one, err)
	}
	if c.ReadBuffered() == 0 {
		t.Fatal("test setup: nothing was buffered")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, _ := lifecycleState(c); released {
		t.Fatal("Close released an array that still holds readable bytes")
	}
	rest := make([]byte, c.ReadBuffered())
	n, err := c.Read(rest)
	if err != nil || n != len(rest) || string(rest) != string(payload[1:]) {
		t.Fatalf("drain after Close = %q, %v; want %q", rest[:n], err, payload[1:])
	}
	if released, _ := lifecycleState(c); !released {
		t.Fatal("draining the buffered remainder did not release the array")
	}
}

// Close racing a blocked read must not pull the array out from under that
// reader: the unblocked reader returns it on its way out.
func TestBufferedReaderCloseWithBlockedReaderKeepsBufferOwned(t *testing.T) {
	// sync.Pool prefers the array most recently released on the same P, so
	// pinning one P makes "the second connection received the blocked
	// reader's array" observable rather than timing-dependent.
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	raw1 := newStagedReadConn()
	conn1 := ForceBufferedReaderConn(raw1, 0)
	read1 := make(chan error, 1)
	go func() {
		_, err := conn1.Read(make([]byte, 1))
		read1 <- err
	}()
	buf1 := <-raw1.readStarted

	close1 := make(chan struct{})
	go func() {
		_ = conn1.Close()
		close(close1)
	}()
	<-raw1.closeStarted

	if released, _ := lifecycleState(conn1); released {
		t.Fatal("Close returned the pooled array while a read was still inside the reader")
	}

	raw2 := newStagedReadConn()
	conn2 := ForceBufferedReaderConn(raw2, 0)
	read2 := make(chan error, 1)
	go func() {
		_, err := conn2.Read(make([]byte, 1))
		read2 <- err
	}()
	buf2 := <-raw2.readStarted
	if buf1 == buf2 {
		t.Fatal("a second connection received the array a blocked reader still holds")
	}

	close(raw1.releaseClose)
	<-close1
	if err := <-read1; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked read woke with %v, want net.ErrClosed", err)
	}
	if released, _ := lifecycleState(conn1); !released {
		t.Fatal("the unblocked reader did not return the pooled array on its way out")
	}

	close(raw2.releaseClose)
	_ = conn2.Close()
	if err := <-read2; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second blocked read woke with %v, want net.ErrClosed", err)
	}
	if released, _ := lifecycleState(conn2); !released {
		t.Fatal("second connection did not return its pooled array")
	}
}

// Every release path funnels through one gate, and that gate must refuse to
// return the array while a read is still inside the reader. The Close path is
// covered end to end above; this pins the same gate for a terminal read error
// observed while another read is in flight, a state that cannot be driven with
// real goroutines without racing the deliberately non-concurrent bufio.Reader.
func TestBufferedReaderReleaseGateWaitsForInFlightReader(t *testing.T) {
	c := ForceBufferedReaderConn(&scriptConn{}, 0)
	c.mu.Lock()
	c.readers = 1      // a read is inside reader.Read
	c.termErr = io.EOF // and the stream has already ended
	c.releaseIfDrainedLocked()
	c.mu.Unlock()
	if released, size := lifecycleState(c); released || size == 0 {
		t.Fatalf("release gate ran with a reader in flight: released=%v buffer size=%d", released, size)
	}
}

// The observable buffered-byte count must not be read while a read is inside
// the reader's window; zero is the only answer that cannot be stale.
func TestBufferedReaderReadBufferedZeroWhileReadInFlight(t *testing.T) {
	raw := newStagedReadConn()
	c := ForceBufferedReaderConn(raw, 0)
	readDone := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		readDone <- err
	}()
	<-raw.readStarted
	if n := c.ReadBuffered(); n != 0 {
		t.Fatalf("ReadBuffered with a read in flight = %d, want 0", n)
	}
	close(raw.releaseClose)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-readDone; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read woke with %v, want net.ErrClosed", err)
	}
}

// Repeated Close must stay safe and must not release twice.
func TestBufferedReaderRepeatedCloseIsIdempotent(t *testing.T) {
	c := ForceBufferedReaderConn(&scriptConn{}, 0)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("after repeated Close: released=%v buffer size=%d", released, size)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-release read = %v, want net.ErrClosed", err)
	}
}

// The optimization's core claim is the round trip itself: the array a released
// session used is the array a later session gets. sync.Pool is free to drop an
// entry at any collection, so the claim is checked as a bounded loop over
// sessions: one P is pinned and GC frozen to make the reuse immediate in
// practice, and the loop tolerates a collection that still lands in between. A
// wrapper that never reaches the pool can never hand its array back, so every
// round allocates fresh and the loop stays a real falsifier.
func TestBufferedReaderReturnsArrayToThePool(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	// Finish any collection already in flight before pools are frozen.
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	const rounds = 8
	var previous *byte
	for round := 0; round < rounds; round++ {
		raw := newStagedReadConn()
		c := ForceBufferedReaderConn(raw, 0)
		read := make(chan error, 1)
		go func() {
			_, err := c.Read(make([]byte, 1))
			read <- err
		}()
		buf := <-raw.readStarted
		// Let the parked read finish: the array is released by that reader.
		close(raw.releaseClose)
		if err := c.Close(); err != nil {
			t.Fatalf("round %d Close: %v", round, err)
		}
		if err := <-read; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("round %d read woke with %v, want net.ErrClosed", round, err)
		}
		if released, size := lifecycleState(c); !released || size != 0 {
			t.Fatalf("round %d session did not release: released=%v buffer size=%d", round, released, size)
		}
		if previous != nil && previous == buf {
			return // the array went back to the pool and came out again
		}
		previous = buf
	}
	t.Fatalf("no session in %d rounds received the array the previous session released: the pool round trip is broken", rounds)
}

// negativeReadConn returns a negative count from Read, which is how a
// misbehaving underlay makes the pooled reader panic for real: bufio guards
// the count and panics with errNegativeRead from its own frame. The panic
// therefore originates inside reader.Read, exactly as it would in production,
// and leaves the reader's window as bufio left it - which is what Close has to
// read afterwards.
type negativeReadConn struct{ scriptConn }

func (*negativeReadConn) Read([]byte) (int, error) { return -1, nil }

// panickingConn panics from Read directly, covering the panic that does not
// come from the pooled reader's own guards.
type panickingConn struct{ scriptConn }

func (*panickingConn) Read([]byte) (int, error) { panic("underlay violated the Read contract") }

func inFlightReaders(c *BufferedReaderConn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readers
}

// A panic inside reader.Read unwinds that read, so it must also leave the
// in-flight count. A count left raised refuses every later release, Close
// included, which would strand the array for a connection that is already torn
// down. The panic itself must still propagate, and it must not release
// anything: the session has no terminal state yet.
func TestBufferedReaderPanicInUnderlayReleasesOnClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn Conn
	}{
		{"pools own guard (negative count)", &negativeReadConn{}},
		{"underlay panics from Read", &panickingConn{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ForceBufferedReaderConn(tc.conn, 0)

			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Fatal("the panic was swallowed instead of propagating")
					}
				}()
				_, _ = c.Read(make([]byte, 8))
			}()

			if readers := inFlightReaders(c); readers != 0 {
				t.Fatalf("a panicking read left %d read(s) counted as in flight", readers)
			}
			if released, size := lifecycleState(c); released || size == 0 {
				t.Fatalf("the panic released the array without a terminal state: released=%v buffer size=%d", released, size)
			}
			if err := c.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if released, size := lifecycleState(c); !released || size != 0 {
				t.Fatalf("Close after a panicking read did not release: released=%v buffer size=%d", released, size)
			}
		})
	}
}

// closeThenPanicConn blocks inside Read until Close runs, then panics instead
// of returning the close error: a reader that dies on a session which Close
// already made terminal.
type closeThenPanicConn struct {
	readStarted chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func newCloseThenPanicConn() *closeThenPanicConn {
	return &closeThenPanicConn{readStarted: make(chan struct{}), release: make(chan struct{})}
}

func (c *closeThenPanicConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.release
	panic("reader died while the session was already closing")
}

func (c *closeThenPanicConn) Write([]byte) (int, error) { return 0, nil }

func (c *closeThenPanicConn) Close() error {
	c.closeOnce.Do(func() { close(c.release) })
	return nil
}

func (c *closeThenPanicConn) SetDeadline(time.Time) error      { return nil }
func (c *closeThenPanicConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeThenPanicConn) SetWriteDeadline(time.Time) error { return nil }

// overlongReadConn returns one byte more than the reader asked for. bufio
// records that oversized window and then panics slicing it, so this is the one
// panic shape that leaves a non-empty window behind - readable bytes as far as
// the wrapper can tell.
type overlongReadConn struct{ scriptConn }

func (*overlongReadConn) Read(p []byte) (int, error) { return len(p) + 1, nil }

// A panic that unwinds a session Close already made terminal must still return
// the array: every release condition holds (terminal state, no reader in
// flight, empty window), and this exit is exactly what the deferred accounting
// exists to reach. Close itself must not have released anything while the read
// was still inside the reader.
func TestBufferedReaderPanicAfterTerminalStateReleases(t *testing.T) {
	raw := newCloseThenPanicConn()
	c := ForceBufferedReaderConn(raw, 0)
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_, _ = c.Read(make([]byte, 8))
	}()
	<-raw.readStarted

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, _ := lifecycleState(c); released {
		t.Fatal("Close released the array while a read was still inside the reader")
	}
	if r := <-panicked; r == nil {
		t.Fatal("the reader panic was swallowed")
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("the panic did not release the terminal session: released=%v buffer size=%d", released, size)
	}
}

// A panic that leaves the window dirty keeps the array, Close included. The
// wrapper cannot tell those bytes from readable ones, and recycling the array
// would hand another connection memory this reader still claims to hold; the
// cost of being wrong here is cross-connection corruption, so the failure mode
// is losing one array to GC.
func TestBufferedReaderPanicLeavingDirtyWindowKeepsArray(t *testing.T) {
	c := ForceBufferedReaderConn(&overlongReadConn{}, 0)
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("the pooled reader did not panic on an overlong read count")
			}
		}()
		_, _ = c.Read(make([]byte, 8))
	}()

	if released, size := lifecycleState(c); released || size == 0 {
		t.Fatalf("a corrupt window was released: released=%v buffer size=%d", released, size)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, size := lifecycleState(c); released || size == 0 {
		t.Fatalf("Close recycled an array whose window still reports buffered bytes: released=%v buffer size=%d", released, size)
	}
}

// A proxied session on the pooled wrapper: read the payload, drain to the
// terminal error (which returns the array to the pool), then Close. The plain
// baseline below keeps the pooling win visible: without it every session pays
// a fresh defaultReadBufferSize allocation.
func BenchmarkBufferedReaderSession(b *testing.B) {
	b.ReportAllocs()
	payload := make([]byte, 64)
	buf := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		c := ForceBufferedReaderConn(&scriptConn{data: payload}, 0)
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Read(buf) // terminal EOF releases the pooled array
		_ = c.Close()
	}
}

// plainBufioConn reproduces the pre-pooling wrapper (a fresh bufio.Reader per
// connection) so the benchmark above has a same-shape baseline.
type plainBufioConn struct {
	Conn
	r *bufio.Reader
}

func (c *plainBufioConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func BenchmarkPlainBufioSession(b *testing.B) {
	b.ReportAllocs()
	payload := make([]byte, 64)
	buf := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		inner := &scriptConn{data: payload}
		c := &plainBufioConn{Conn: inner, r: bufio.NewReaderSize(readerOf{inner}, defaultReadBufferSize)}
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Read(buf)
		_ = c.Close()
	}
}
