package netproxy

import "fmt"

// Compile-time interface checks.
var _ error = (*ErrDatagramDropped)(nil)

// ErrDatagramDropped is the typed contract for a packet-oriented read that
// consumed and discarded exactly one datagram while leaving the session
// usable, and for the write-side mirror: a single datagram that was refused
// (e.g. it cannot be serialized into a protocol length field) while the
// session stays usable and subsequent datagrams can still be written.
//
// Producers return it (wrapping io.ErrShortBuffer in the common case) when a
// received datagram is larger than the caller's buffer, its source address
// cannot be attributed, or a write-side length field cannot carry the
// datagram. The reader has already drained the frame, so the stream stays
// aligned: the next ReadFrom returns the next datagram. Consumers must treat
// it as a per-datagram event — do not retire the connection, do not close the
// endpoint, and do not report the dialer unavailable.
//
// The Cause chain is preserved, so legacy consumers matching
// errors.Is(err, io.ErrShortBuffer) keep working across pins. The
// domain-address sibling of this contract is protocol.ErrDomainResolution
// (unresolvable peer-supplied source address, same drop-one-datagram
// semantics).
type ErrDatagramDropped struct {
	Cause error
}

func (e *ErrDatagramDropped) Error() string {
	return fmt.Sprintf("datagram dropped: %v", e.Cause)
}

// Unwrap exposes Cause so errors.Is and errors.As reach the underlying
// sentinel (io.ErrShortBuffer) through the wrapper.
func (e *ErrDatagramDropped) Unwrap() error { return e.Cause }

// DatagramDropped wraps cause in the datagram-dropped contract. Producers
// that drained an oversized datagram pass io.ErrShortBuffer as the cause.
func DatagramDropped(cause error) error {
	return &ErrDatagramDropped{Cause: cause}
}
