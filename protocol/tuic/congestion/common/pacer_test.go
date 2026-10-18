package common

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// fixedBandwidth returns a getBandwidth closure with a mutable rate, so a test
// can change the rate between calls the way a controller's recalc does.
func fixedBandwidth(rate congestion.ByteCount) (*congestion.ByteCount, func() congestion.ByteCount) {
	v := new(congestion.ByteCount)
	*v = rate
	return v, func() congestion.ByteCount { return *v }
}

// TestPacerInitialBudgetIsMaxBurst pins the first-call contract: before any
// packet is sent there is no lastSentTime, so Budget reports the full burst
// allowance rather than zero (a zero would stall the first send).
func TestPacerInitialBudgetIsMaxBurst(t *testing.T) {
	_, bw := fixedBandwidth(1_000_000)
	p := NewPacer(bw)
	now := time.Now()

	got := p.Budget(now)
	want := p.maxBurstSize()
	if got != want {
		t.Fatalf("initial Budget = %d, want maxBurstSize %d", got, want)
	}
	if got < maxBurstPackets*congestion.InitialPacketSize {
		t.Fatalf("initial Budget = %d, want at least %d bytes (%d packets)",
			got, maxBurstPackets*congestion.InitialPacketSize, maxBurstPackets)
	}
	if !p.TimeUntilSend().IsZero() {
		t.Fatal("TimeUntilSend before any send must report send-now")
	}
}

// TestPacerBudgetAccumulatesWithElapsedTime pins the token-bucket accrual:
// budget grows linearly with elapsed time at the configured rate.
func TestPacerBudgetAccumulatesWithElapsedTime(t *testing.T) {
	const rate = 8_000_000 // bytes/s
	_, bw := fixedBandwidth(rate)
	p := NewPacer(bw)
	start := time.Now()

	// Consume the initial burst first so the accrual is measured from a known
	// budget (maxBurstSize is the cap the accrual saturates at).
	p.SentPacket(start, p.maxBurstSize())

	const elapsed = 2 * time.Millisecond
	later := start.Add(elapsed)
	got := p.Budget(later)
	want := congestion.ByteCount(rate * elapsed.Nanoseconds() / 1e9)
	if got != want {
		t.Fatalf("Budget after consuming the burst and waiting %v = %d, want %d", elapsed, got, want)
	}
}

// TestPacerBudgetIsCappedByMaxBurstSize pins the upper clamp: an idle pacer
// must not bank an unbounded burst, which on a high-rate link would let one
// instant dump far more than maxBurstPackets onto the wire.
func TestPacerBudgetIsCappedByMaxBurstSize(t *testing.T) {
	_, bw := fixedBandwidth(100_000_000)
	p := NewPacer(bw)
	start := time.Now()
	p.SentPacket(start, p.maxBurstSize())

	got := p.Budget(start.Add(time.Hour))
	if got != p.maxBurstSize() {
		t.Fatalf("idle Budget = %d, want it clamped to maxBurstSize %d", got, p.maxBurstSize())
	}
	capBytes := maxBurstPackets * p.maxDatagramSize
	if p.maxBurstSize() < capBytes {
		t.Fatalf("maxBurstSize = %d, want at least the %d-packet floor %d",
			p.maxBurstSize(), maxBurstPackets, capBytes)
	}
}

// TestPacerMaxBurstSizeHasPacketFloor pins the lower bound of maxBurstSize: at
// a low rate the time-based term falls below the packet floor, and the floor is
// what keeps the pacer from stalling a whole burst.
func TestPacerMaxBurstSizeHasPacketFloor(t *testing.T) {
	_, bw := fixedBandwidth(1) // absurdly low rate
	p := NewPacer(bw)
	floor := congestion.ByteCount(maxBurstPackets) * p.maxDatagramSize
	if got := p.maxBurstSize(); got != floor {
		t.Fatalf("maxBurstSize at a low rate = %d, want the packet floor %d", got, floor)
	}
}

// TestPacerTimeUntilSendBoundaries pins the three regimes of TimeUntilSend:
// immediate when the budget covers a datagram, the minimum pacing delay when
// the deficit is tiny, and a scaled delay when the deficit is large.
func TestPacerTimeUntilSendBoundaries(t *testing.T) {
	const rate = 1_000_000 // bytes/s
	_, bw := fixedBandwidth(rate)
	p := NewPacer(bw)
	p.SetMaxDatagramSize(1200)
	start := time.Now()

	// Regime 1: enough budget for a full datagram.
	p.SentPacket(start, 0)
	if p.budgetAtLastSent = 1200; !p.TimeUntilSend().IsZero() {
		t.Fatal("TimeUntilSend must report send-now when the budget covers a datagram")
	}

	// Regime 2: a deficit so small that the scaled delay is under the minimum.
	p.SentPacket(start, 0)
	p.budgetAtLastSent = 1199
	got := p.TimeUntilSend()
	if want := start.Add(congestion.MinPacingDelay); !got.Equal(want) {
		t.Fatalf("TimeUntilSend with a 1-byte deficit = %v, want the MinPacingDelay floor %v", got, want)
	}

	// Regime 3: a large deficit scales with the rate.
	p.budgetAtLastSent = 0
	got = p.TimeUntilSend()
	want := start.Add(time.Duration(float64(1200) * 1e9 / float64(rate)))
	if got.Before(want) {
		t.Fatalf("TimeUntilSend at zero budget = %v, want at least %v", got, want)
	}
	if !got.After(want.Add(-time.Microsecond)) || got.After(want.Add(time.Microsecond)) {
		t.Fatalf("TimeUntilSend at zero budget = %v, want ~%v (ceil of deficit/rate)", got, want)
	}
}

// TestPacerSentPacketConsumesOnlyWhatItSends pins the consumption rule: a send
// larger than the budget drains to zero (never negative), and a send inside the
// budget subtracts exactly its size.
func TestPacerSentPacketConsumesOnlyWhatItSends(t *testing.T) {
	_, bw := fixedBandwidth(1_000_000)
	p := NewPacer(bw)
	start := time.Now()

	p.SentPacket(start, p.maxBurstSize()+5000)
	if p.budgetAtLastSent != 0 {
		t.Fatalf("oversized send left budget = %d, want 0", p.budgetAtLastSent)
	}

	p.SentPacket(start, 0)
	p.budgetAtLastSent = 1000
	p.SentPacket(start, 400)
	if p.budgetAtLastSent != 600 {
		t.Fatalf("budget after sending 400 out of 1000 = %d, want 600", p.budgetAtLastSent)
	}
}

// TestPacerSetMaxDatagramSizeTakesEffect pins that the datagram size is not
// cosmetic: it drives both the burst floor and the send-now threshold.
func TestPacerSetMaxDatagramSizeTakesEffect(t *testing.T) {
	_, bw := fixedBandwidth(1_000_000)
	p := NewPacer(bw)
	p.SetMaxDatagramSize(1400)
	if p.maxDatagramSize != 1400 {
		t.Fatalf("maxDatagramSize = %d, want 1400", p.maxDatagramSize)
	}
	if got, want := p.maxBurstSize(), congestion.ByteCount(maxBurstPackets)*1400; got < want {
		t.Fatalf("maxBurstSize = %d, want at least %d after SetMaxDatagramSize(1400)", got, want)
	}
	p.budgetAtLastSent = 1300
	if p.TimeUntilSend().IsZero() {
		t.Fatal("TimeUntilSend must not report send-now for a budget below the new datagram size")
	}
	p.budgetAtLastSent = 1400
	if !p.TimeUntilSend().IsZero() {
		t.Fatal("TimeUntilSend must report send-now for a budget equal to the datagram size")
	}
}

// TestPacerBudgetOverflowIsClamped pins the overflow guard: a negative accrued
// budget (possible with a caller-supplied huge rate) is clamped to a large
// positive value rather than wrapping, which would stall the pacer forever.
func TestPacerBudgetOverflowIsClamped(t *testing.T) {
	rate, bw := fixedBandwidth(congestion.ByteCount(1) << 60)
	p := NewPacer(bw)
	start := time.Now()
	p.SentPacket(start, p.maxBurstSize())
	*rate = congestion.ByteCount(1) << 62
	if got := p.Budget(start.Add(24 * time.Hour)); got < 0 {
		t.Fatalf("Budget wrapped negative: %d", got)
	}
}

// TestPacerRateChangeAppliesImmediately pins that the bandwisth closure is read
// per call: a controller that lowers its rate must see the new budget at once.
func TestPacerRateChangeAppliesImmediately(t *testing.T) {
	rate, bw := fixedBandwidth(1_000_000)
	p := NewPacer(bw)
	start := time.Now()
	p.SentPacket(start, 0)
	p.budgetAtLastSent = 0

	low := p.Budget(start.Add(10 * time.Millisecond))
	*rate = 10_000_000
	high := p.Budget(start.Add(10 * time.Millisecond))
	if high <= low {
		t.Fatalf("raising the rate did not raise the budget: low=%d high=%d", low, high)
	}
}
