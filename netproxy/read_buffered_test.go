package netproxy

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type fakeBufferedConn struct {
	Conn
	n int
}

func (f *fakeBufferedConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (f *fakeBufferedConn) Write(p []byte) (int, error) {
	return len(p), nil
}
func (f *fakeBufferedConn) Close() error                     { return nil }
func (f *fakeBufferedConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeBufferedConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeBufferedConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeBufferedConn) ReadBuffered() int                { return f.n }

type fakeUnderlyingConn struct {
	Conn
	inner any
}

func (f *fakeUnderlyingConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (f *fakeUnderlyingConn) Write(p []byte) (int, error) {
	return len(p), nil
}
func (f *fakeUnderlyingConn) Close() error                     { return nil }
func (f *fakeUnderlyingConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeUnderlyingConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeUnderlyingConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeUnderlyingConn) UnderlyingConn() net.Conn {
	if c, ok := f.inner.(net.Conn); ok {
		return c
	}
	return nil
}

func TestReadBufferedWalker(t *testing.T) {
	if n := ReadBuffered(nil); n != 0 {
		t.Fatalf("nil conn: got %d", n)
	}
	if n := ReadBuffered(&fakeBufferedConn{n: 0}); n != 0 {
		t.Fatalf("zero buffered: got %d", n)
	}
	if n := ReadBuffered(&fakeBufferedConn{n: 4096}); n != 4096 {
		t.Fatalf("buffered conn: got %d", n)
	}
	// Unknown conn types without the capability report zero.
	if n := ReadBuffered(errors.New("not a conn")); n != 0 {
		t.Fatalf("non-conn: got %d", n)
	}
}

func TestBufferedReaderConnReadBuffered(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	brc := ForceBufferedReaderConn(&fakeNetConn{Conn: c1}, 128)
	if n := brc.ReadBuffered(); n != 0 {
		t.Fatalf("empty bufio: got %d", n)
	}
	go func() {
		_, _ = c2.Write([]byte("hello"))
	}()
	buf := make([]byte, 2)
	if _, err := io.ReadFull(brc, buf); err != nil {
		t.Fatal(err)
	}
	if n := brc.ReadBuffered(); n != 3 {
		t.Fatalf("after 2-byte read: got %d want 3", n)
	}
}

// fakeNetConn adapts a net.Conn to the netproxy Conn interface.
type fakeNetConn struct {
	net.Conn
}
