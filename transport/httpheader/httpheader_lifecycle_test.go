package httpheader

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

// scriptConn is a deterministic netproxy.Conn for the pooled-buffer lifecycle
// tests: it serves scripted payload bytes, then a settable error (io.EOF when
// unset). Close is a no-op so a test can keep draining bytes that are already
// buffered.
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

func (c *scriptConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

// responseWithBody builds one complete HTTP response whose header is followed
// by body.
func responseWithBody(body string) []byte {
	return []byte("HTTP/1.1 200 OK\r\nServer: httpheader-test\r\n\r\n" + body)
}

// lifecycleState reports whether the pooled array has gone back to the pool,
// and how large a window the reader still holds (zero once released). It must
// only be called while no read is in flight.
func lifecycleState(c *conn) (released bool, bufSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.released, c.reader.Size()
}

func inFlightReaders(c *conn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readers
}

func bufferedBytes(c *conn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return 0
	}
	return c.reader.Buffered()
}

// stagedReadConn blocks inside Read until Close runs, and reports the address
// of the buffer the reader handed to the underlay, so a test can prove that a
// second connection never receives an array a blocked reader still holds.
type stagedReadConn struct {
	readStarted  chan *byte
	closeStarted chan struct{}
	releaseClose chan struct{}
	closed       chan struct{}
	readOnce     sync.Once
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
	c.readOnce.Do(func() { c.readStarted <- &p[0] })
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

// negativeReadConn returns a negative count from Read, which is how a
// misbehaving underlay makes the pooled reader panic for real: bufio guards
// the count and panics with its own errNegativeRead from inside fill.
type negativeReadConn struct{ scriptConn }

func (*negativeReadConn) Read([]byte) (int, error) { return -1, nil }

// A terminal EOF is the read loop's exit path: it must return the pooled array
// and keep reporting the same error afterwards.
func TestConnReleasesPooledReaderOnEOF(t *testing.T) {
	c := newConn(&scriptConn{data: responseWithBody("payload")}, defaultHost, "/")
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "payload" {
		t.Fatalf("ReadAll = %q, %v; want \"payload\"", got, err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("after EOF: released=%v buffer size=%d, want released with no window", released, size)
	}
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, io.EOF) {
		t.Fatalf("post-release read = %v, want stable io.EOF", err)
	}
}

// Deadline timeouts are retryable by net.Conn semantics: they must not release
// the array, must not make the header error sticky, and the retry must resume
// the parse from the bytes the timeout left in place.
func TestConnTimeoutRetryKeepsPooledReader(t *testing.T) {
	clientRaw, server := net.Pipe()
	defer func() { _ = server.Close() }()
	c := newConn(clientRaw, defaultHost, "/")
	defer func() { _ = c.Close() }()

	wrote := make(chan error, 1)
	go func() {
		_, err := io.WriteString(server, "HTTP/1.1 200 OK\r\nX-Pad: 1")
		wrote <- err
	}()

	if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := c.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline read = %v, want os.ErrDeadlineExceeded", err)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("staged write: %v", err)
	}
	if released, size := lifecycleState(c); released || size == 0 {
		t.Fatalf("a retryable deadline error released the pooled array: released=%v buffer size=%d", released, size)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go func() {
		// Terminate the response header and send the body.
		_, err := io.WriteString(server, "\r\nbody")
		wrote <- err
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "body" {
		t.Fatalf("retry after deadline = %q, %v; want \"body\"", buf, err)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("continuation write: %v", err)
	}
}

// A deadline that expires while the body is being read is equally retryable:
// nothing may be released, and the reader keeps serving afterwards.
func TestConnBodyTimeoutRetryKeepsPooledReader(t *testing.T) {
	clientRaw, server := net.Pipe()
	defer func() { _ = server.Close() }()
	c := newConn(clientRaw, defaultHost, "/")
	defer func() { _ = c.Close() }()

	wrote := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("HTTP/1.1 200 OK\r\n\r\nab"))
		wrote <- err
	}()
	buf := make([]byte, 4)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "ab" {
		t.Fatalf("first body read = %q, %v; want \"ab\"", buf[:n], err)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("staged write: %v", err)
	}

	if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("body deadline read = %v, want os.ErrDeadlineExceeded", err)
	}
	if released, size := lifecycleState(c); released || size == 0 {
		t.Fatalf("a body deadline released the pooled array: released=%v buffer size=%d", released, size)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go func() {
		_, err := server.Write([]byte("cdef"))
		wrote <- err
	}()
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "cdef" {
		t.Fatalf("retry after body deadline = %q, %v; want \"cdef\"", buf[:n], err)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("continuation write: %v", err)
	}
}

// Close on an idle connection ends the session without a draining read, so it
// must return the array and keep reporting the closed connection.
func TestConnIdleCloseReleasesPooledReader(t *testing.T) {
	c := newConn(&scriptConn{}, defaultHost, "/")
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("idle Close: released=%v buffer size=%d, want released with no window", released, size)
	}
	// A repeated Close must stay safe and must not release a second time.
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

// Bytes that are already buffered stay readable after Close, exactly as the
// pre-pooling conn served them; the array goes back only once they drain.
func TestConnCloseWithBufferedBytesKeepsThenReleases(t *testing.T) {
	payload := "a payload that stays buffered until drained"
	c := newConn(&scriptConn{data: responseWithBody(payload)}, defaultHost, "/")
	one := make([]byte, 1)
	if n, err := c.Read(one); n != 1 || err != nil || one[0] != payload[0] {
		t.Fatalf("first read = %q, %v", one, err)
	}
	// The header parse filled the reader from a single socket read, so the
	// rest of the payload is still in the pooled window.
	if bufferedBytes(c) == 0 {
		t.Fatal("test setup: nothing was buffered")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, _ := lifecycleState(c); released {
		t.Fatal("Close released an array that still holds readable bytes")
	}
	rest := make([]byte, bufferedBytes(c))
	n, err := c.Read(rest)
	if err != nil || n != len(rest) || string(rest) != payload[1:] {
		t.Fatalf("drain after Close = %q, %v; want %q", rest[:n], err, payload[1:])
	}
	if released, _ := lifecycleState(c); !released {
		t.Fatal("draining the buffered remainder did not release the array")
	}
	if _, err := c.Read(one); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after the release = %v, want net.ErrClosed", err)
	}
}

// Close racing a blocked read must not pull the array out from under that
// reader: the unblocked reader returns it on its way out, and a second
// connection must never be handed the same array in the meantime.
func TestConnCloseWithBlockedReadKeepsBufferOwned(t *testing.T) {
	// sync.Pool prefers the array most recently released on the same P, so
	// pinning one P makes "the second connection received the blocked
	// reader's array" observable rather than timing-dependent.
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	raw1 := newStagedReadConn()
	conn1 := newConn(raw1, defaultHost, "/")
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
	conn2 := newConn(raw2, defaultHost, "/")
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
	if released, size := lifecycleState(conn1); !released || size != 0 {
		t.Fatalf("the unblocked reader did not return the pooled array: released=%v buffer size=%d", released, size)
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

// A panic inside the reader unwinds that read, so it must also leave the
// in-flight count: a count left raised refuses every later release, Close
// included, which would strand the array for a connection that is already torn
// down. The panic itself must still propagate, and it must not release
// anything: the session has no terminal state yet.
func TestConnPanicInUnderlayAccountsForTheRead(t *testing.T) {
	c := newConn(&negativeReadConn{}, defaultHost, "/")
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
}

// The optimization's core claim is the round trip itself: the array a released
// session used is the array a later session gets. sync.Pool is free to drop an
// entry at any collection, so the claim is checked as a bounded loop over
// sessions: one P is pinned and GC frozen to make the reuse immediate in
// practice, and the loop tolerates a collection that still lands in between. A
// conn that never reaches the pool can never hand its array back, so every
// round allocates fresh and the loop stays a real falsifier.
func TestConnReturnsArrayToThePool(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	// Finish any collection already in flight before pools are frozen.
	runtime.GC()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	const rounds = 8
	var previous *byte
	for round := 0; round < rounds; round++ {
		raw := newStagedReadConn()
		c := newConn(raw, defaultHost, "/")
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

// plainConn is the pre-change conn: a fresh stdlib bufio.Reader per
// connection, never returned to any pool. It is the differential oracle for
// the read semantics (and the benchmark baseline for the array the pool
// removes), so it mirrors the old Read path verbatim.
type plainConn struct {
	netproxy.Conn
	reader     *bufio.Reader
	readMu     sync.Mutex
	headerRead bool
	readErr    error
}

func newPlainConn(raw netproxy.Conn) *plainConn {
	return &plainConn{Conn: raw, reader: bufio.NewReaderSize(raw, bufioBufferSize)}
}

func (c *plainConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if !c.headerRead {
		if err := discardPlainResponseHeader(c.reader); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, err
			}
			var to interface{ Timeout() bool }
			if errors.As(err, &to) && to.Timeout() {
				return 0, err
			}
			c.headerRead = true
			c.readErr = err
			return 0, err
		}
		c.headerRead = true
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(p)
}

func discardPlainResponseHeader(reader *bufio.Reader) error {
	total := 0
	for {
		line, err := reader.ReadSlice('\n')
		total += len(line)
		if total > maxResponseHeader || errors.Is(err, bufio.ErrBufferFull) {
			return errResponseHeaderTooLarge
		}
		if err != nil {
			return fmt.Errorf("httpheader: read response header: %w", err)
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return nil
		}
	}
}

// The pooled conn must stay observationally identical to the pre-change conn
// on every read path the release machinery touches: the same bytes, the same
// error text, and the same behavior after a terminal or retryable error. Both
// implementations are driven with identical scripted underlays and compared
// read by read.
func TestConnMatchesPreChangeReadSemantics(t *testing.T) {
	header := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	cases := []struct {
		name     string
		data     []byte
		failWith error
		reads    int
		bufSize  int
	}{
		{"header then body", []byte(header), nil, 6, 0},
		{"header without terminator", []byte("HTTP/1.1 200 OK\r\nX: 1"), nil, 4, 0},
		{"oversized header", []byte(strings.Repeat("x", maxResponseHeader+1)), nil, 3, 0},
		{"closed underlay in the header", nil, net.ErrClosed, 3, 0},
		{"closed underlay in the body", []byte(header), net.ErrClosed, 8, 0},
		{"transient underlay error in the body", []byte(header), errors.New("transient"), 8, 0},
		// Downstream protocol dialers read through netproxy's pooled 32 KiB
		// reader, which passes a buffer as large as this reader's own; the
		// second read below therefore takes bufio's direct path into the
		// caller's buffer instead of the pooled window.
		{"reads at the pooled window size", responseWithBody(strings.Repeat("x", 40000)), nil, 4, bufioBufferSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bufSize := tc.bufSize
			if bufSize == 0 {
				bufSize = 2
			}
			newRaw := func() *scriptConn {
				return &scriptConn{data: tc.data, failWith: tc.failWith}
			}
			pooled := newConn(newRaw(), defaultHost, "/")
			plain := newPlainConn(newRaw())
			pooledBuf := make([]byte, bufSize)
			plainBuf := make([]byte, bufSize)
			for i := 0; i < tc.reads; i++ {
				nPooled, errPooled := pooled.Read(pooledBuf)
				nPlain, errPlain := plain.Read(plainBuf)
				if nPooled != nPlain || string(pooledBuf[:nPooled]) != string(plainBuf[:nPlain]) {
					t.Fatalf("read %d: pooled = %q, %v; plain = %q, %v",
						i, pooledBuf[:nPooled], errPooled, plainBuf[:nPlain], errPlain)
				}
				if errText(errPooled) != errText(errPlain) {
					t.Fatalf("read %d: pooled err = %v; plain err = %v", i, errPooled, errPlain)
				}
			}
		})
	}
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// BenchmarkConnSession is one short session through the pooled reader: parse
// the response header, read the payload, then take the terminal EOF that
// returns the array to the pool.
func BenchmarkConnSession(b *testing.B) {
	b.ReportAllocs()
	response := responseWithBody(strings.Repeat("x", 64))
	buf := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		c := newConn(&scriptConn{data: response}, defaultHost, "/")
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Read(buf) // terminal EOF releases the pooled array
		_ = c.Close()
	}
}

// BenchmarkPlainConnSession is the pre-change shape: a fresh stdlib 32 KiB
// reader per session that is never returned.
func BenchmarkPlainConnSession(b *testing.B) {
	b.ReportAllocs()
	response := responseWithBody(strings.Repeat("x", 64))
	buf := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		c := newPlainConn(&scriptConn{data: response})
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Read(buf)
		_ = c.Conn.Close()
	}
}
