package netproxy

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// The lifecycle tests above drive the buffer contract with a scripted Conn, so
// they can pin every release gate deterministically. Real sockets add the two
// things a fake cannot produce: the error identities a kernel path actually
// surfaces (wrapped EOF, wrapped net.ErrClosed, a real deadline error, an RST
// that is not in the terminal set) and the fact that Close really wakes a read
// blocked in the netpoller. These tests run against loopback TCP for that.
func realTCPPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	type accepted struct {
		conn *net.TCPConn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- accepted{nil, err}
			return
		}
		ch <- accepted{c.(*net.TCPConn), nil}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	return raw.(*net.TCPConn), got.conn
}

// A real FIN: the payload is served, the wrapped EOF releases the array.
func TestBufferedReaderRealSocketEOFReleases(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	if _, err := server.Write([]byte("real-payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	c := ForceBufferedReaderConn(client, 0)
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "real-payload" {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("real EOF did not release: released=%v buffer size=%d", released, size)
	}
}

// A real read-deadline expiry must not release the array, and the retry after
// the deadline is cleared must still be served from the same reader.
func TestBufferedReaderRealSocketDeadlineKeepsBuffer(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := ForceBufferedReaderConn(client, 0)
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("deadline read = %v, want os.ErrDeadlineExceeded", err)
	}
	if released, _ := lifecycleState(c); released {
		t.Fatal("a real deadline error released the pooled array")
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	if _, err := server.Write([]byte("late")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "late" {
		t.Fatalf("retry after deadline = %q, %v; want \"late\"", buf, err)
	}
}

// Close must wake a read blocked in the netpoller, and that read must return
// the array on its way out rather than having it pulled away by Close.
func TestBufferedReaderRealSocketCloseRacingBlockedReadReleases(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = server.Close() }()

	c := ForceBufferedReaderConn(client, 0)
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 8))
		done <- err
	}()
	// Either order is a valid race: Close first makes the read fail
	// immediately, Close while blocked exercises the wakeup path.
	time.Sleep(30 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("blocked read woke with %v, want net.ErrClosed", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("Close racing a blocked read did not release: released=%v buffer size=%d", released, size)
	}
}

// A real RST surfaces ECONNRESET, which is deliberately outside the terminal
// set, so the read path must keep the array and Close must release it. This is
// the documented fallback for terminal errors the classifier does not name.
func TestBufferedReaderRealSocketResetReleasesViaClose(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = client.Close() }()

	c := ForceBufferedReaderConn(client, 0)
	// SO_LINGER(0) makes the peer close with RST instead of FIN.
	if err := server.SetLinger(0); err != nil {
		t.Skipf("SO_LINGER unavailable: %v", err)
	}
	_ = server.Close()

	var err error
	for i := 0; i < 100 && err == nil; i++ {
		_, err = c.Read(make([]byte, 8))
	}
	if err == nil {
		t.Fatal("no read error from a reset connection")
	}
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Logf("note: a reset surfaced as %v", err)
	}
	if released, _ := lifecycleState(c); released &&
		!errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("non-terminal %v released the array on the read path", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("Close after reset did not release: released=%v buffer size=%d", released, size)
	}
}
