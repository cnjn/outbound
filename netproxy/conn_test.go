package netproxy

import (
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type fakeConnForUnderlying struct {
	net.Conn
}

func (c *fakeConnForUnderlying) Read(_ []byte) (int, error)         { return 0, nil }
func (c *fakeConnForUnderlying) Write(p []byte) (int, error)        { return len(p), nil }
func (c *fakeConnForUnderlying) Close() error                       { return nil }
func (c *fakeConnForUnderlying) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeConnForUnderlying) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeConnForUnderlying) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConnForUnderlying) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConnForUnderlying) SetWriteDeadline(_ time.Time) error { return nil }

func TestFakeNetConnUnderlyingConn(t *testing.T) {
	inner := &fakeConnForUnderlying{}
	conn := &FakeNetConn{Conn: inner}
	if got := conn.UnderlyingConn(); got != inner {
		t.Fatalf("unexpected underlying conn: got %T want %T", got, inner)
	}
}

type fakePacketConnForLifecycle struct {
	done <-chan struct{}
}

func (c *fakePacketConnForLifecycle) Read(_ []byte) (int, error)  { return 0, nil }
func (c *fakePacketConnForLifecycle) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakePacketConnForLifecycle) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *fakePacketConnForLifecycle) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *fakePacketConnForLifecycle) Close() error                            { return nil }
func (c *fakePacketConnForLifecycle) SetDeadline(_ time.Time) error           { return nil }
func (c *fakePacketConnForLifecycle) SetReadDeadline(_ time.Time) error       { return nil }
func (c *fakePacketConnForLifecycle) SetWriteDeadline(_ time.Time) error      { return nil }
func (c *fakePacketConnForLifecycle) TransportDone() <-chan struct{}          { return c.done }

func TestFakeNetPacketConnForwardsTransportLifecycle(t *testing.T) {
	done := make(chan struct{})
	conn := NewFakeNetPacketConn(&fakePacketConnForLifecycle{done: done}, nil, nil)

	lifecycle, ok := conn.(interface{ TransportDone() <-chan struct{} })
	if !ok {
		t.Fatalf("expected wrapped fake packet conn to expose TransportDone, got %T", conn)
	}
	if got := lifecycle.TransportDone(); got != done {
		t.Fatal("expected fake packet conn wrapper to forward underlying TransportDone channel")
	}
}

type fakePacketReceiver struct {
	registered atomic.Bool
	stopped    atomic.Bool
}

func (c *fakePacketReceiver) Read([]byte) (int, error)    { return 0, nil }
func (c *fakePacketReceiver) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakePacketReceiver) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *fakePacketReceiver) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *fakePacketReceiver) Close() error                            { return nil }
func (c *fakePacketReceiver) SetDeadline(time.Time) error             { return nil }
func (c *fakePacketReceiver) SetReadDeadline(time.Time) error         { return nil }
func (c *fakePacketReceiver) SetWriteDeadline(time.Time) error        { return nil }
func (c *fakePacketReceiver) RegisterPacketReceiver(PacketReceiveHandler) (func(), bool) {
	c.registered.Store(true)
	return func() { c.stopped.Store(true) }, true
}

func TestReceivedPacketReleaseIsIdempotent(t *testing.T) {
	var releases atomic.Int32
	p := NewReceivedPacket([]byte("payload"), netip.MustParseAddrPort("192.0.2.1:53"), nil, func() {
		releases.Add(1)
	})
	p.Release()
	p.Release()
	if got := releases.Load(); got != 1 {
		t.Fatalf("release calls = %d, want 1", got)
	}
}

func TestFakeNetPacketConnForwardsPacketReceiver(t *testing.T) {
	inner := &fakePacketReceiver{}
	conn := NewFakeNetPacketConn(inner, nil, nil)
	receiver, ok := conn.(PacketReceiver)
	if !ok {
		t.Fatalf("expected wrapped packet conn to expose PacketReceiver, got %T", conn)
	}
	unregister, registered := receiver.RegisterPacketReceiver(nil)
	if !registered || unregister == nil {
		t.Fatal("expected wrapper to forward packet receiver registration")
	}
	if !inner.registered.Load() {
		t.Fatal("underlying packet receiver was not registered")
	}
	unregister()
	if !inner.stopped.Load() {
		t.Fatal("underlying packet receiver was not unregistered")
	}
}

func TestTCPDialControl(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return TCPDialControl(c, 0)
		},
	}

	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed with TCPDialControl: %v", err)
	}
	defer conn.Close()
}
