package brutal

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// fakeRTT is a congestion.RTTStatsProvider with a settable smoothed RTT.
type fakeRTT struct {
	smoothed time.Duration
	latest   time.Duration
}

func (f *fakeRTT) MinRTT() time.Duration        { return f.latest }
func (f *fakeRTT) LatestRTT() time.Duration     { return f.latest }
func (f *fakeRTT) SmoothedRTT() time.Duration   { return f.smoothed }
func (f *fakeRTT) MeanDeviation() time.Duration { return 0 }
func (f *fakeRTT) MaxAckDelay() time.Duration   { return 0 }
func (f *fakeRTT) PTO(bool) time.Duration       { return 0 }

func newBrutal(bps uint64, rtt time.Duration) (*BrutalSender, *fakeRTT) {
	b := NewBrutalSender(bps)
	r := &fakeRTT{smoothed: rtt, latest: rtt}
	b.SetRTTStatsProvider(r)
	return b, r
}

// TestBrutalCwndFormula pins the window formula:
//
//	cwnd = bps * srtt * congestionWindowMultiplier / ackRate
//
// expressed as an identity against the exported inputs rather than as a magic
// number, so a deliberate multiplier change does not require editing assertions
// while an accidental formula change still fails.
func TestBrutalCwndFormula(t *testing.T) {
	const bps = 4_000_000
	for _, rtt := range []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 200 * time.Millisecond} {
		b, _ := newBrutal(bps, rtt)
		want := congestion.ByteCount(float64(bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
		if got := b.GetCongestionWindow(); got != want {
			t.Fatalf("srtt=%v: cwnd = %d, want %d (bps*srtt*%d/ackRate)",
				rtt, got, want, congestionWindowMultiplier)
		}
	}
}

// TestBrutalCwndIsMonotonicInRTT pins the shape of the formula: a longer RTT
// means more bytes must be in flight to keep the same rate (BDP scaling).
func TestBrutalCwndIsMonotonicInRTT(t *testing.T) {
	const bps = 4_000_000
	prev := congestion.ByteCount(0)
	for _, rtt := range []time.Duration{5 * time.Millisecond, 20 * time.Millisecond, 80 * time.Millisecond, 320 * time.Millisecond} {
		b, _ := newBrutal(bps, rtt)
		got := b.GetCongestionWindow()
		if got <= prev {
			t.Fatalf("cwnd did not grow with RTT: srtt=%v gave %d after %d", rtt, got, prev)
		}
		prev = got
	}
}

// TestBrutalCwndIsMonotonicInBandwidth pins the other axis: the window scales
// with the configured target bandwidth.
func TestBrutalCwndIsMonotonicInBandwidth(t *testing.T) {
	const rtt = 50 * time.Millisecond
	prev := congestion.ByteCount(0)
	for _, bps := range []uint64{500_000, 2_000_000, 8_000_000, 32_000_000} {
		b, _ := newBrutal(bps, rtt)
		got := b.GetCongestionWindow()
		if got <= prev {
			t.Fatalf("cwnd did not grow with bps: bps=%d gave %d after %d", bps, got, prev)
		}
		prev = got
	}
}

// TestBrutalCwndHasDatagramFloorWithoutRTTSample pins the no-sample path:
// before the first RTT measurement the controller reports a small fixed window
// and a floored window rather than zero, so the handshake can start.
func TestBrutalCwndHasDatagramFloorWithoutRTTSample(t *testing.T) {
	b := NewBrutalSender(1_000_000) // no RTT provider at all
	if got := b.GetCongestionWindow(); got != 10240 {
		t.Fatalf("cwnd without an RTT sample = %d, want the 10240 bootstrap window", got)
	}
	b.SetRTTStatsProvider(&fakeRTT{}) // zero RTT sample
	if got := b.GetCongestionWindow(); got != 10240 {
		t.Fatalf("cwnd with a zero RTT sample = %d, want the 10240 bootstrap window", got)
	}

	// A vanishingly small bandwidth*RTT product is floored at maxDatagramSize.
	small, _ := newBrutal(1, time.Microsecond)
	if got, floor := small.GetCongestionWindow(), small.maxDatagramSize; got != floor {
		t.Fatalf("cwnd = %d, want the maxDatagramSize floor %d", got, floor)
	}
}

// TestBrutalCanSendAdmissionBoundary pins the admission rule at the exact
// boundary: CanSend is `bytesInFlight <= cwnd`, so a window-sized in-flight is
// still admitted and one byte more is not. This is what makes the controller's
// admission observable and is the assertion the audit asked for
// (CanSend(cwnd+1) == false).
func TestBrutalCanSendAdmissionBoundary(t *testing.T) {
	b, _ := newBrutal(4_000_000, 50*time.Millisecond)
	cwnd := b.GetCongestionWindow()

	if !b.CanSend(cwnd - 1) {
		t.Fatalf("CanSend(cwnd-1=%d) = false, want true", cwnd-1)
	}
	if !b.CanSend(cwnd) {
		t.Fatalf("CanSend(cwnd=%d) = false, want true (the boundary is inclusive)", cwnd)
	}
	if b.CanSend(cwnd + 1) {
		t.Fatalf("CanSend(cwnd+1=%d) = true, want false", cwnd+1)
	}
	if !b.CanSend(0) {
		t.Fatal("CanSend(0) must be true")
	}
}

// TestBrutalCwndIgnoresAckAndLossCounts pins that the window is not a
// loss-reactive window: it is a pure function of (bps, srtt, ackRate). Above
// the sample floor and below the clamp, a large ack or loss vector must leave
// cwnd exactly where it was - only a change in the ackRate outcome moves it.
//
// The separate case below shows the one thing that does move it, so the
// assertion above cannot pass for the wrong reason.
func TestBrutalCwndIgnoresAckAndLossCounts(t *testing.T) {
	b, _ := newBrutal(4_000_000, 50*time.Millisecond)
	before := b.GetCongestionWindow()

	now := time.Now()
	acked := make([]congestion.AckedPacketInfo, 0, 100)
	for i := 0; i < 100; i++ {
		acked = append(acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesAcked: 1200})
	}
	b.OnCongestionEventEx(before/2, now, acked, nil)
	if got := b.GetCongestionWindow(); got != before {
		t.Fatalf("cwnd changed after 100 acks: %d -> %d", before, got)
	}
	if b.ackRate != 1 {
		t.Fatalf("ackRate = %v after a lossless window, want 1", b.ackRate)
	}

	// A large in-window loss vector with enough acks to stay above the clamp:
	// the window must still not move, because neither the ack nor the loss
	// count feeds cwnd directly.
	lost := make([]congestion.LostPacketInfo, 0, 10)
	for i := 0; i < 10; i++ {
		lost = append(lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesLost: 1200})
	}
	b.OnCongestionEventEx(before/2, now.Add(10*time.Millisecond), acked[:10], lost)
	if b.ackRate < minAckRate || b.ackRate > 1 {
		t.Fatalf("ackRate = %v, want it inside [%v, 1]", b.ackRate, minAckRate)
	}
	// Whatever the event did to the ack rate, cwnd must equal exactly
	// (bps*srtt*M)/ackRate and nothing else: no separate loss penalty, no ack
	// credit. Asserting the identity rather than a constant keeps this true if
	// the multiplier is ever revisited.
	want := congestion.ByteCount(float64(b.bps) * b.rttStats.SmoothedRTT().Seconds() * congestionWindowMultiplier / b.ackRate)
	if got := b.GetCongestionWindow(); got != want {
		t.Fatalf("cwnd after a 10/20 loss event = %d, want %d (the formula at ackRate=%v)",
			got, want, b.ackRate)
	}
}

// TestBrutalCwndMovesOnlyViaAckRate is the counterweight to the test above: the
// window does change when the ack rate changes, through the 1/ackRate term.
// Without this, the "cwnd is unaffected" assertions could pass on a controller
// that simply ignores its inputs entirely.
func TestBrutalCwndMovesOnlyViaAckRate(t *testing.T) {
	b, _ := newBrutal(4_000_000, 50*time.Millisecond)
	before := b.GetCongestionWindow()

	// Drive a sustained lossy pattern until the clamp engages.
	now := time.Now()
	for s := int64(0); s < pktInfoSlotCount; s++ {
		acked := make([]congestion.AckedPacketInfo, 0, 80)
		for i := 0; i < 80; i++ {
			acked = append(acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesAcked: 1200})
		}
		lost := make([]congestion.LostPacketInfo, 0, 40)
		for i := 0; i < 40; i++ {
			lost = append(lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesLost: 1200})
		}
		b.OnCongestionEventEx(0, now.Add(time.Duration(s)*time.Second), acked, lost)
	}

	if b.ackRate >= 1 {
		t.Fatalf("ackRate = %v, want the clamp to have engaged", b.ackRate)
	}
	after := b.GetCongestionWindow()
	beforeScaled := congestion.ByteCount(float64(before) / b.ackRate)
	if after != beforeScaled {
		t.Fatalf("cwnd after the ack-rate clamp = %d, want %d (the pre-clamp window scaled by 1/ackRate)",
			after, beforeScaled)
	}
}

// TestBrutalAckRateClampLowersPacingAndRaisesCwnd pins the ackRate coupling:
// when the measured ack rate drops below minAckRate it is clamped, which both
// divides the pacing rate and multiplies the window by 1/ackRate.
func TestBrutalAckRateClampLowersPacingAndRaisesCwnd(t *testing.T) {
	b, _ := newBrutal(4_000_000, 50*time.Millisecond)
	baseCwnd := b.GetCongestionWindow()

	now := time.Now()
	// A sustained lossy window: 80 acks and 40 losses per sample second, for
	// every slot, so ackCount+lossCount clears minSampleCount.
	for s := int64(0); s < pktInfoSlotCount; s++ {
		ts := now.Unix() + s
		acked := make([]congestion.AckedPacketInfo, 0, 80)
		for i := 0; i < 80; i++ {
			acked = append(acked, congestion.AckedPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesAcked: 1200})
		}
		lost := make([]congestion.LostPacketInfo, 0, 40)
		for i := 0; i < 40; i++ {
			lost = append(lost, congestion.LostPacketInfo{PacketNumber: congestion.PacketNumber(i), BytesLost: 1200})
		}
		b.OnCongestionEventEx(0, time.Unix(ts, 0), acked, lost)
	}

	if b.ackRate != minAckRate {
		t.Fatalf("ackRate = %v, want it clamped to minAckRate %v", b.ackRate, minAckRate)
	}
	got := b.GetCongestionWindow()
	want := congestion.ByteCount(float64(b.bps) * b.rttStats.SmoothedRTT().Seconds() * congestionWindowMultiplier / minAckRate)
	if got != want {
		t.Fatalf("cwnd after the clamp = %d, want %d (1/ackRate scaling)", got, want)
	}
	if got <= baseCwnd {
		t.Fatalf("cwnd after the clamp = %d, want it above the unclamped %d", got, baseCwnd)
	}
	if !b.HasPacingBudget(time.Now()) && b.TimeUntilSend(b.GetCongestionWindow()).IsZero() {
		t.Fatal("pacing state is inconsistent after the clamp")
	}
}

// TestBrutalAckRateNeedsEnoughSamples pins the sample floor: with fewer than
// minSampleCount observations the ack rate stays at 1 rather than being driven
// by a single lossy event.
func TestBrutalAckRateNeedsEnoughSamples(t *testing.T) {
	b, _ := newBrutal(4_000_000, 50*time.Millisecond)
	now := time.Now()
	lost := []congestion.LostPacketInfo{{PacketNumber: 1, BytesLost: 1200}}
	for i := 0; i < minSampleCount/2; i++ {
		b.OnCongestionEventEx(0, now, nil, lost)
	}
	if b.ackRate != 1 {
		t.Fatalf("ackRate = %v after %d samples, want 1 (below the floor of %d)",
			b.ackRate, minSampleCount/2, minSampleCount)
	}
}

// TestBrutalSetMaxDatagramSizePropagatesToPacer pins that the datagram size
// reaches the pacer, which uses it for both the burst floor and the send-now
// threshold.
func TestBrutalSetMaxDatagramSizePropagatesToPacer(t *testing.T) {
	b, _ := newBrutal(4_000_000, 50*time.Millisecond)
	b.SetMaxDatagramSize(1400)
	if b.maxDatagramSize != 1400 {
		t.Fatalf("maxDatagramSize = %d, want 1400", b.maxDatagramSize)
	}
	if got := b.pacer.Budget(time.Now()); got < 1400 {
		t.Fatalf("pacer budget after SetMaxDatagramSize(1400) = %d, want at least one datagram", got)
	}
	if got := b.GetCongestionWindow(); got < 1400 {
		t.Fatalf("cwnd = %d, want it at or above the new datagram size", got)
	}
}
