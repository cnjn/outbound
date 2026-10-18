package httpheader

import (
	stdbufio "bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
)

// The lifecycle tests above drive the buffer contract with scripted Conn
// fakes, so they can pin every release gate deterministically. Real sockets
// add the two things a fake cannot produce: the error identities a kernel path
// actually surfaces (EOF from a FIN, a real deadline error, net.ErrClosed from
// Close) and the fact that Close really wakes a read blocked in the netpoller.
// These tests run against loopback TCP for that.
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
func TestConnRealSocketEOFReleases(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	if _, err := server.Write(responseWithBody("real-payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := server.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	c := newConn(client, defaultHost, "/")
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "real-payload" {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("real EOF did not release: released=%v buffer size=%d", released, size)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("post-release read = %v, want io.EOF", err)
	}
}

// A real read-deadline expiry must not release the array, and the retry after
// the deadline is cleared must still be served from the same reader.
func TestConnRealSocketDeadlineKeepsPooledReader(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	c := newConn(client, defaultHost, "/")
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
	if _, err := server.Write(responseWithBody("late")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "late" {
		t.Fatalf("retry after deadline = %q, %v; want \"late\"", buf, err)
	}
}

// Close must wake a read blocked in the netpoller, and that read must return
// the array on its way out rather than having it pulled away by Close.
func TestConnRealSocketCloseRacingBlockedReadReleases(t *testing.T) {
	client, server := realTCPPair(t)
	defer func() { _ = server.Close() }()

	c := newConn(client, defaultHost, "/")
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
		t.Fatalf("real Close did not release: released=%v buffer size=%d", released, size)
	}
}

// The exported dialer path must produce the same pooled lifecycle as a bare
// newConn: dial a real listener through httpheader.Dialer (over the direct
// dialer dae uses), complete the request/response header handshake, read to
// the terminal EOF, and confirm the array went back to the pool.
func TestDialerRealSocketSessionReleasesPooledReader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	served := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		defer func() { _ = raw.Close() }()
		req, err := http.ReadRequest(stdbufio.NewReader(raw))
		if err != nil {
			served <- err
			return
		}
		if req.Method != http.MethodGet || req.URL.RequestURI() != "/transport" || req.Host != "front.example" {
			served <- fmt.Errorf("unexpected request line: %s %s host %s", req.Method, req.URL, req.Host)
			return
		}
		_, err = raw.Write(responseWithBody("hello"))
		served <- err
	}()

	d, err := NewDialer(direct.SymmetricDirect, "front.example", "/transport")
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	raw, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	c, ok := raw.(*conn)
	if !ok {
		t.Fatalf("DialContext returned %T, want *conn", raw)
	}
	// The transport writes its one request header before the protocol data.
	if n, err := c.Write(nil); n != 0 || err != nil {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadAll = %q, %v; want \"hello\"", got, err)
	}
	if err := <-served; err != nil {
		t.Fatalf("server: %v", err)
	}
	if released, size := lifecycleState(c); !released || size != 0 {
		t.Fatalf("dialer session did not release: released=%v buffer size=%d", released, size)
	}
}
