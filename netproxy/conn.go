package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/olicesx/quic-go"
)

var UnsupportedTunnelTypeError = net.UnknownNetworkError("unsupported tunnel type")

type FullConn interface {
	Conn
	PacketConn
}

type Conn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type PacketConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	ReadFrom(p []byte) (n int, addr netip.AddrPort, err error)
	WriteTo(p []byte, addr string) (n int, err error)
	Close() error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// BatchItem is one datagram for a batched packet write. Data must remain
// valid until the WriteBatch call returns.
type BatchItem struct {
	Data []byte
	Addr string
}

// PacketBatchWriter is an optional extension of PacketConn. Transports that
// can amortize per-datagram syscalls (e.g. sendmmsg on a direct UDP socket)
// implement it so hot paths can flush several datagrams in a single syscall.
// Implementations must accept items in order. n is the number of datagrams
// that actually left the socket: on a pre-send failure (encapsulation or
// address resolution) n must be 0 even if later items were never examined.
// Partial success after a real send is reported through n together with err.
type PacketBatchWriter interface {
	WriteBatch(items []BatchItem) (n int, err error)
}

// PacketGSOWriter is an optional extension of PacketConn for transports that
// support Generic Segmentation Offload (UDP_SEGMENT). When multiple datagrams
// share the same destination and segment size, callers can transmit them as
// a single aggregated payload, offloading fragmentation to kernel or NIC.
type PacketGSOWriter interface {
	WriteGSO(payload []byte, segmentSize uint16, addr netip.AddrPort) (int, error)
}

// ReceivedPacket is one complete datagram delivered by an optional
// transport-owned packet receiver. The receiver owns the packet after a
// handler accepts it and must call Release exactly once.
type ReceivedPacket struct {
	Data []byte
	From netip.AddrPort
	Err  error

	releaseOnce sync.Once
	release     func()
}

// NewReceivedPacket constructs a packet whose storage can be returned to the
// transport after the consumer finishes processing it.
func NewReceivedPacket(data []byte, from netip.AddrPort, err error, release func()) *ReceivedPacket {
	return &ReceivedPacket{
		Data:    data,
		From:    from,
		Err:     err,
		release: release,
	}
}

// Release returns packet storage to its producer. It is safe to call more
// than once, which lets queue rejection and shutdown cleanup share ownership
// paths without double returning a buffer.
func (p *ReceivedPacket) Release() {
	if p == nil {
		return
	}
	p.releaseOnce.Do(func() {
		if p.release != nil {
			p.release()
		}
		p.Data = nil
	})
}

// PacketReceiveHandler is called by a transport-owned receive loop. Returning
// true transfers packet ownership to the handler; returning false asks the
// transport to release the packet immediately.
type PacketReceiveHandler func(packet *ReceivedPacket) bool

// PacketReceiver is an optional packet-delivery boundary for transports that
// already own a shared receive loop. It avoids adding a blocking ReadFrom
// goroutine in every logical flow while leaving PacketConn compatibility
// unchanged for transports without this capability.
type PacketReceiver interface {
	RegisterPacketReceiver(handler PacketReceiveHandler) (unregister func(), ok bool)
}

// TransportLifecycle is an optional interface that PacketConn implementations
// can expose when the logical packet session depends on another underlying
// transport or control channel whose death may not surface immediately as
// ReadFrom/WriteTo errors on the PacketConn itself.
// When the returned channel is closed, the logical session is defunct and the
// caller should retire it without waiting for a subsequent I/O error.
// A nil channel means the PacketConn does not provide a separate lifecycle
// signal beyond normal I/O errors.
type TransportLifecycle interface {
	// TransportDone returns a channel that is closed when the underlying
	// transport or controlling association is permanently closed.
	TransportDone() <-chan struct{}
}

type FakeNetConn struct {
	Conn
	LAddr net.Addr
	RAddr net.Addr
}

// WriteDeadlineClosesSession forwards the optional destructive write-deadline
// declaration of the wrapped conn. Embedding the Conn interface promotes
// SetWriteDeadline but not this optional method; without the forward a
// session-closing inner conn behind this wrapper (e.g. TUIC under the HTTP/2
// transport) is invisible to deadline-arming callers.
func (conn *FakeNetConn) WriteDeadlineClosesSession() bool {
	return WriteDeadlineClosesSession(conn.Conn)
}

func (conn *FakeNetConn) UnderlyingConn() net.Conn {
	if underlying, ok := conn.Conn.(net.Conn); ok {
		return underlying
	}
	return nil
}

func (conn *FakeNetConn) LocalAddr() net.Addr {
	return conn.LAddr
}
func (conn *FakeNetConn) RemoteAddr() net.Addr {
	return conn.RAddr
}

type fakeNetPacketConn struct {
	PacketConn
	LAddr net.Addr
	RAddr net.Addr
}

type FakeNetPacketConn interface {
	net.PacketConn
	net.Conn
}

func NewFakeNetPacketConn(conn PacketConn, LAddr net.Addr, RAddr net.Addr) FakeNetPacketConn {
	fakeNetConn := &fakeNetPacketConn{
		PacketConn: conn,
		LAddr:      LAddr,
		RAddr:      RAddr,
	}
	if _, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return &fakeNetPacketConn2{
			fakeNetPacketConn: fakeNetConn,
		}
	}
	return fakeNetConn
}

// ReadMsgUDP implements quic.OOBCapablePacketConn.
func (conn *fakeNetPacketConn) ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error) {
	c, ok := conn.PacketConn.(interface {
		ReadMsgUDP(b []byte, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error)
	})
	if !ok {
		return 0, 0, 0, nil, fmt.Errorf("connection doesn't allow to get ReadMsgUDP. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.ReadMsgUDP(b, oob)
}

// WriteMsgUDP implements quic.OOBCapablePacketConn.
func (conn *fakeNetPacketConn) WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error) {
	c, ok := conn.PacketConn.(interface {
		WriteMsgUDP(b []byte, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
	})
	if !ok {
		return 0, 0, fmt.Errorf("connection doesn't allow to get WriteMsgUDP. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.WriteMsgUDP(b, oob, addr)
}

func (conn *fakeNetPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, a, err := conn.PacketConn.ReadFrom(p)
	return n, net.UDPAddrFromAddrPort(a), err
}
func (conn *fakeNetPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return conn.PacketConn.WriteTo(p, addr.String())
}
func (conn *fakeNetPacketConn) LocalAddr() net.Addr {
	return conn.LAddr
}
func (conn *fakeNetPacketConn) RemoteAddr() net.Addr {
	return conn.RAddr
}
func (conn *fakeNetPacketConn) TransportDone() <-chan struct{} {
	lifecycle, ok := conn.PacketConn.(TransportLifecycle)
	if !ok {
		return nil
	}
	return lifecycle.TransportDone()
}

// WriteDeadlineClosesSession forwards the optional destructive
// write-deadline declaration of the wrapped PacketConn through the net.Conn
// compatibility wrapper. Without this, a session-closing inner conn (e.g.
// TUIC) is invisible to deadline-arming callers behind the wrapper, because
// a dynamic interface embedding does not promote unknown methods.
func (conn *fakeNetPacketConn) WriteDeadlineClosesSession() bool {
	return WriteDeadlineClosesSession(conn.PacketConn)
}

// RegisterPacketReceiver forwards the optional transport-owned delivery
// boundary through the net.Conn compatibility wrapper.
func (conn *fakeNetPacketConn) RegisterPacketReceiver(handler PacketReceiveHandler) (func(), bool) {
	receiver, ok := conn.PacketConn.(PacketReceiver)
	if !ok {
		return nil, false
	}
	return receiver.RegisterPacketReceiver(handler)
}
func (conn *fakeNetPacketConn) SetWriteBuffer(size int) error {
	c, ok := conn.PacketConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return fmt.Errorf("connection doesn't allow setting of send buffer size. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.SetWriteBuffer(size)
}
func (conn *fakeNetPacketConn) SetReadBuffer(size int) error {
	c, ok := conn.PacketConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return fmt.Errorf("connection doesn't allow setting of receive buffer size. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.SetReadBuffer(size)
}

type fakeNetPacketConn2 struct {
	*fakeNetPacketConn
}

func (conn *fakeNetPacketConn2) SyscallConn() (syscall.RawConn, error) {
	c, ok := conn.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil, fmt.Errorf("connection doesn't allow to get Syscall.RawConn. Not a *net.UDPConn? : %T", conn.PacketConn)
	}
	return c.SyscallConn()
}

var _ quic.OOBCapablePacketConn = &fakeNetPacketConn2{}
