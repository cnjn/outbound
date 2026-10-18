package hysteria2_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

const (
	// udpRelayAttempts is how many copies of one request a relayed UDP step
	// puts on the wire before it reads a reply.
	//
	// Hysteria2 carries relayed UDP in QUIC DATAGRAM frames (RFC 9221), which
	// are explicitly unreliable: neither the transport nor the relay
	// retransmits, and the kernel may drop datagrams while a loaded machine
	// keeps its socket buffers full. A single-shot request/reply assertion
	// therefore turns transient loss on the relay path into a test failure.
	// udpRelayAttempts copies make a step pass as long as one copy survives end
	// to end, while every reply that does arrive is still checked byte-for-byte
	// and source-for-source. The price is that a step proves "at least one of
	// the copies was delivered", not "every copy was".
	udpRelayAttempts = 3
	// udpRelayCopyGap separates those copies so they do not form one burst
	// that a momentarily full socket buffer can drop as a group.
	udpRelayCopyGap = 20 * time.Millisecond
	// udpRelayStepBudget bounds the wait for a reply, once the copies are on
	// the wire: a step can take udpRelayCopyGap*(udpRelayAttempts-1) longer than
	// this in total. It cannot be repurposed as a retry clock, because hysteria2
	// closes the whole UDP session when a read deadline fires.
	udpRelayStepBudget = 30 * time.Second
)

// relayedDatagram identifies one request/reply pair: the payload a step sent
// and the source address it sent it to.
type relayedDatagram struct {
	payload string
	from    string
}

// udpRelaySession drives request/reply steps over one relayed UDP session and
// keeps the integrity contract strict while tolerating best-effort loss:
//
//   - the expected (payload, source) pair passes;
//   - a reply that matches a pair this session already confirmed is a duplicate
//     of an earlier copy of that step: legal on a best-effort relay, but a step
//     may receive at most one reply per request copy it sent, so a relay that
//     amplifies one request into a flood still fails. Duplicates still queued
//     when the test ends are never read, so this bound can only under-count;
//   - anything else - truncated payload, corrupted payload, wrong source,
//     cross-target leakage - fails immediately.
//
// Every step must use a payload this session has not used before: duplicate
// accounting is per (payload, source) pair, so a reused payload would attribute
// one step's replies to another.
type udpRelaySession struct {
	t       *testing.T
	pc      netproxy.PacketConn
	buf     []byte
	sent    map[string]bool
	settled map[relayedDatagram]bool
	extras  map[relayedDatagram]int
}

func newUDPRelaySession(t *testing.T, pc netproxy.PacketConn) *udpRelaySession {
	t.Helper()
	return &udpRelaySession{
		t:       t,
		pc:      pc,
		buf:     make([]byte, 65535),
		sent:    make(map[string]bool),
		settled: make(map[relayedDatagram]bool),
		extras:  make(map[relayedDatagram]int),
	}
}

// roundTrip sends payload to want and asserts that the relay returns exactly
// that payload from that source, tolerating best-effort datagram loss.
func (s *udpRelaySession) roundTrip(payload []byte, want net.Addr, label string) {
	s.t.Helper()
	key := string(payload)
	if s.sent[key] {
		s.t.Fatalf("%s: payload already used by an earlier step of this session; "+
			"duplicate accounting needs a distinct payload per step", label)
	}
	s.sent[key] = true
	for i := 0; i < udpRelayAttempts; i++ {
		if i > 0 {
			time.Sleep(udpRelayCopyGap)
		}
		if _, err := s.pc.WriteTo(payload, want.String()); err != nil {
			s.t.Fatalf("%s: WriteTo: %v", label, err)
		}
	}
	if err := s.pc.SetReadDeadline(time.Now().Add(udpRelayStepBudget)); err != nil {
		s.t.Fatalf("%s: SetReadDeadline: %v", label, err)
	}
	start := time.Now()
	for {
		n, from, err := s.pc.ReadFrom(s.buf)
		if err != nil {
			// ReadFrom reports io.EOF for any session closure: a fired read
			// deadline and a transport or peer failure cannot be told apart
			// here, so report what was measured instead of asserting a cause.
			elapsed := time.Since(start)
			cause := "the session died before the step deadline (transport or peer failure)"
			if elapsed >= udpRelayStepBudget-time.Second {
				cause = "the step deadline expired (hysteria2 closes the session when its read deadline fires)"
			}
			s.t.Fatalf("%s: ReadFrom: no reply to %d bytes sent %d times after %s: %v (%s)",
				label, len(payload), udpRelayAttempts, elapsed.Round(time.Millisecond), err, cause)
		}
		got := string(s.buf[:n])
		reply := relayedDatagram{payload: got, from: from.String()}
		switch {
		case got == key && reply.from == want.String():
			s.settled[reply] = true
			return
		case s.settled[reply]:
			s.extras[reply]++
			if s.extras[reply] > udpRelayAttempts-1 {
				s.t.Fatalf("%s: %d replies for an already-confirmed datagram, want at most %d "+
					"(one per request copy sent): from %s, %s",
					label, s.extras[reply], udpRelayAttempts-1, from, datagramPreview([]byte(got)))
			}
			continue
		default:
			s.t.Fatalf("%s: unexpected datagram from %v, want %v: got %s, want %s",
				label, from, want, datagramPreview([]byte(got)), datagramPreview(payload))
		}
	}
}

// datagramPreview renders the head of a datagram for failure messages, so a
// corrupted or misrouted payload is recognisable without dumping kilobytes of
// escaped bytes into the test log.
func datagramPreview(b []byte) string {
	const head = 16
	if len(b) <= head {
		return fmt.Sprintf("% x (%d bytes)", b, len(b))
	}
	return fmt.Sprintf("% x… (%d bytes)", b[:head], len(b))
}
