package netproxy

import "net"

// UnderlyingConnForwarder exposes a raw socket accessor through wrapper
// layers that hide it. Record-framed transports such as TLS present as an
// opaque conn: the socket underneath carries kernel-side receive-queue
// state (pending-byte counts) that copy loops observe to decide whether
// another read completes immediately. utls exposes the socket via NetConn,
// but that method is not part of netproxy.Conn, so unwrapping walks stop at
// the TLS conn unless a forwarder sits above it.
//
// Reads and writes pass straight through to the wrapped conn; the forwarder
// only adds the UnderlyingConnProvider capability.
type UnderlyingConnForwarder struct {
	Conn
	raw func() net.Conn
}

// NewUnderlyingConnForwarder wraps c. raw must return the innermost socket
// (or another conn to continue peeling at); it is called lazily on each
// unwrap so the forwarder can be built before the socket is fully
// initialized.
func NewUnderlyingConnForwarder(c Conn, raw func() net.Conn) Conn {
	return &UnderlyingConnForwarder{Conn: c, raw: raw}
}

// UnderlyingConn returns the wrapped transport's innermost socket.
func (f *UnderlyingConnForwarder) UnderlyingConn() net.Conn {
	if f.raw == nil {
		return nil
	}
	return f.raw()
}

// IntrinsicConn continues the wrapper-peeling convention so capability
// checks that must reach the actual TLS conn (type reflection, record
// buffer inspection) pass through the forwarder instead of stopping here.
func (f *UnderlyingConnForwarder) IntrinsicConn() Conn {
	if ic, ok := f.Conn.(IntrinsicConnProvider); ok {
		return ic.IntrinsicConn()
	}
	return f.Conn
}

// WriteDeadlineClosesSession forwards the optional destructive write-deadline
// declaration of the wrapped conn; embedding the Conn interface promotes
// SetWriteDeadline but not this optional method, so without the forward the
// declaration is erased at this wrapper.
func (f *UnderlyingConnForwarder) WriteDeadlineClosesSession() bool {
	return WriteDeadlineClosesSession(f.Conn)
}

// CloseWrite half-closes the wrapped conn instead of the raw socket
// underneath. Embedding the Conn interface does not promote this optional
// method, so a WriteCloser probe on the forwarder would fall through to
// UnwrapTCPConn, which this forwarder itself feeds the raw socket: a bare
// TCP FIN that skips the close_notify the wrapped record layer (TLS) must
// send first. Forwarding to ForwardCloseWrite keeps the wrapped conn's own
// half-close preferred and preserves the TCP fallback for conns without one.
func (f *UnderlyingConnForwarder) CloseWrite() error {
	return ForwardCloseWrite(f.Conn)
}
