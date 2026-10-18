package netproxy

import "reflect"

// optionalCapabilityMethods lists the duck-typed capability methods that
// wrapper layers must not hide. A wrapper satisfies the contract for a given
// method either by forwarding or implementing it, or by implementing
// IntrinsicConnProvider so callers can peel down to the real transport with
// UnwrapIntrinsicConn.
//
// Protocol-internal duck typing that lives outside this package (for example
// the SSR obfs SetCipher/SetAddrLen hooks) is intentionally not listed here:
// the sanctioned route for those is the IntrinsicConnProvider peel, which
// this gate enforces. Add every new optional capability declared in this
// package to this list.
var optionalCapabilityMethods = []string{
	"IntrinsicConn",
	"UnderlyingConn",
	"CloseWrite",
	"WriteDeadlineClosesSession",
	"ReadFrom",
	"WriteTo",
	"WriteBatch",
	"RegisterPacketReceiver",
	"LocalAddr",
	"RemoteAddr",
}

// MissingCapabilities reports which optional capability methods reference
// carries but wrapper hides: the method is absent from the wrapper's method
// set and the wrapper does not implement IntrinsicConnProvider. It returns an
// empty slice when the wrapper preserves the reference's capabilities. Both
// conns must be non-nil; a nil argument yields nil.
//
// A wrapper satisfies the contract for a method by forwarding it (or
// overriding it with equivalent behavior); embedding the Conn interface only
// promotes the base method set, which is exactly how capabilities get lost.
func MissingCapabilities(wrapper, reference Conn) []string {
	if wrapper == nil || reference == nil {
		return nil
	}
	if _, ok := wrapper.(IntrinsicConnProvider); ok {
		// The wrapper participates in the peel convention: callers reach the
		// capabilities through UnwrapIntrinsicConn.
		return nil
	}
	wt := reflect.TypeOf(wrapper)
	rt := reflect.TypeOf(reference)
	var missing []string
	for _, name := range optionalCapabilityMethods {
		if _, ok := rt.MethodByName(name); !ok {
			// The reference does not carry this capability; nothing to hide.
			continue
		}
		if _, ok := wt.MethodByName(name); !ok {
			missing = append(missing, name)
		}
	}
	return missing
}
