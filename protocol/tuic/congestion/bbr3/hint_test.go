package bbr3

import (
	"math"
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

// hintTraffic keeps an eight-packet pipeline with send records and unique ACKs.
// ACKs arrive 80ms after sends; repeated callback timestamps cannot invent rate.
type hintTraffic struct {
	s        *Bbr3Sender
	now      time.Time
	pn       congestion.PacketNumber
	inflight congestion.ByteCount
	rtt      *fakeRTT
	sizes    []congestion.ByteCount
}

func newHintTraffic(hint uint64, enabled bool) *hintTraffic {
	p := DefaultParams()
	p.EnableValidatedHint = enabled
	s := NewBbr3SenderWithParams(1200, hint, p)
	rtt := &fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond}
	s.SetRTTStatsProvider(rtt)
	return &hintTraffic{s: s, now: time.Now(), rtt: rtt}
}
func (h *hintTraffic) step(size congestion.ByteCount) {
	h.now = h.now.Add(10 * time.Millisecond)
	// Process the incoming ACK before waking the sender for its next packet.
	if len(h.sizes) == 8 {
		ackedSize := h.sizes[0]
		h.sizes = h.sizes[1:]
		h.s.OnCongestionEventEx(h.inflight, h.now, []congestion.AckedPacketInfo{{PacketNumber: h.pn - 7, BytesAcked: ackedSize}}, nil)
		h.inflight -= ackedSize
	}
	h.pn++
	h.s.OnPacketSent(h.now, h.inflight, h.pn, size, true)
	h.inflight += size
	h.sizes = append(h.sizes, size)
}
func TestHintValidatesAndRevokesThroughCallbacks(t *testing.T) {
	h := newHintTraffic(100_000, true)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	if got := h.s.HintStatus(); got.State != "validated" || got.Validations == 0 {
		t.Fatalf("no validation: %+v", got)
	}
	// A queue increase must withdraw the target at the next ACK, before refresh.
	h.rtt.latest = 120 * time.Millisecond
	h.step(1000)
	if got := h.s.HintStatus(); got.State != "revoked" || got.Revocations == 0 {
		t.Fatalf("queue did not revoke: %+v", got)
	}
	h.rtt.latest = 80 * time.Millisecond
	for i := 0; i < 250; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().State != "validated" {
		t.Fatal("did not revalidate after clean evidence")
	}
	// Loss without an ACK vector is a real QUIC callback, including ECN with zero.
	h.s.OnCongestionEvent(h.pn, 0, h.inflight)
	if h.s.HintStatus().State != "revoked" {
		t.Fatal("ECN did not revoke")
	}
}

// TestValidatedHintHoldsTheAccessCeiling pins what the validated gate can
// actually be observed to do. With the pacer running at the reference's
// congestion-window gain, the paced rate already reaches the declared ceiling
// whenever the raw estimate is at or above half the hint, so validation cannot
// raise it further: the gate holds the ceiling rather than lifting the rate.
// That is the same inertness the bbr3 diagnostic measured (13/13 runs, zero
// lift) and which docs/bbr3-experimental.md documents; the assertion here pins
// the observable contract instead of a lift that no longer exists.
func TestValidatedHintHoldsTheAccessCeiling(t *testing.T) {
	on, off := newHintTraffic(100_000, true), newHintTraffic(100_000, false)
	off.now = on.now
	sawTarget := false
	for i := 0; i < 300; i++ {
		on.step(950)
		off.step(950)
		if on.s.HintStatus().State == "validated" && on.s.Mode() == "PROBE_BW_CRUISE" && off.s.Mode() == "PROBE_BW_CRUISE" {
			if on.s.PacingRate() != 100_000 || on.s.PacingRate() < off.s.PacingRate() {
				t.Fatalf("validated gate does not hold the access ceiling: on=%d off=%d",
					on.s.PacingRate(), off.s.PacingRate())
			}
			sawTarget = true
		}
	}
	if !sawTarget {
		t.Fatal("no actual validated cruise pacing observation")
	}
}

func TestWrongHintCannotBecomeTarget(t *testing.T) {
	h := newHintTraffic(400_000, true)
	for i := 0; i < 500; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().Validations != 0 {
		t.Fatal("fourfold overhint validated")
	}
}
func TestDeliveryDropAndExpiryRevokeHint(t *testing.T) {
	for _, kind := range []string{"delivery", "expiry", "loss"} {
		t.Run(kind, func(t *testing.T) {
			h := newHintTraffic(100_000, true)
			for i := 0; i < 150; i++ {
				h.step(1000)
			}
			switch kind {
			case "delivery":
				for i := 0; i < 60; i++ {
					h.step(400)
				}
			case "expiry":
				h.s.HasPacingBudget(h.now.Add(2 * time.Second))
			case "loss":
				h.s.OnCongestionEventEx(h.inflight, h.now, nil, []congestion.LostPacketInfo{{PacketNumber: h.pn, BytesLost: 1000}})
			}
			if h.s.HintStatus().State == "validated" {
				t.Fatalf("%s retained target", kind)
			}
			// Each withdrawal must be classified under its own reason and
			// agree with the legacy revocations counter.
			st := h.s.HintStatus()
			if st.Withdrawals[kind] != 1 {
				t.Fatalf("%s withdrawal miscounted: %v", kind, st.Withdrawals)
			}
			if st.RejectionsTotal[kind] != 1 {
				t.Fatalf("%s rejection miscounted: %v", kind, st.RejectionsTotal)
			}
			if sumCounts(st.Withdrawals) != st.Revocations {
				t.Fatalf("%s withdrawals %v disagree with revocations %d", kind, st.Withdrawals, st.Revocations)
			}
		})
	}
}
func TestHintDisabledAndStrictCap(t *testing.T) {
	h := newHintTraffic(100_000, false)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().State != "disabled" {
		t.Fatal("feature enabled by default")
	}
	p := DefaultParams()
	p.StrictHintCap = true
	s := NewBbr3SenderWithParams(1200, 100_000, p)
	seedEstimate(s.model, 1_000_000)
	for _, m := range []mode{modeStartup, modeDrain, modeProbeBWUp, modeProbeBWCruise} {
		s.mode.Store(uint32(m))
		s.recalc()
		if s.PacingRate() > 100_000 {
			t.Fatalf("strict cap exceeded in %v", m)
		}
	}
}
func TestBoundedHintProbeAndTarget(t *testing.T) {
	h := newHintTraffic(100_000, true)
	sawProbe := false
	for i := 0; i < 200; i++ {
		h.step(800)
		if h.s.HintStatus().State == "probing" {
			sawProbe = true
			if rate := h.s.PacingRate(); rate > 88_001 {
				t.Fatalf("unbounded actual probe pacing %d in %s", rate, h.s.Mode())
			}
			if target := h.s.hintEstimate(1); target > 88_001 {
				t.Fatalf("unbounded probe target %d", target)
			}
		}
	}
	if !sawProbe {
		t.Fatal("no bounded probe with near-hint delivery")
	}
	if h.s.HintStatus().Validations != 0 {
		t.Fatal("80% delivery validated")
	}
	h = newHintTraffic(100_000, true)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	h.s.mode.Store(uint32(modeProbeBWCruise))
	if target := h.s.hintEstimate(80_000); target != 100_000 {
		t.Fatalf("validated target %d", target)
	}
}
func TestInvalidParamsRejected(t *testing.T) {
	for _, mutate := range []func(*Params){func(p *Params) { p.CwndGain = math.NaN() }, func(p *Params) { p.Beta = 1 }, func(p *Params) { p.HintProbeOvershoot = 2 }, func(p *Params) { p.MaxBwFilterRounds = 0 }, func(p *Params) { p.CorrectSampleForLoss = true }} {
		p := DefaultParams()
		mutate(&p)
		if p.Validate() == nil {
			t.Fatalf("invalid parameters accepted: %+v", p)
		}
	}
}
func TestInflightUpperBoundWins(t *testing.T) {
	s := newTestSender(0)
	s.mode.Store(uint32(modeProbeBWCruise))
	s.model.inflightHi = 12000
	s.model.inflightLo = 24000
	s.recalc()
	if got := s.GetCongestionWindow(); got > 12000 {
		t.Fatalf("lower bound overrode upper: %d", got)
	}
}
func TestLossBaselineCannotAbsorbCurrentRound(t *testing.T) {
	m := newModel(DefaultParams(), 1200)
	m.roundBytesSent = 120000
	m.lastSent = 100
	m.accountEvent(60000, 60000, 50, 100)
	m.updateLossBaseline()
	if !m.lossRateExceeded() {
		t.Fatal("current round was absorbed into its own threshold")
	}
}

func sumCounts(m map[string]uint64) uint64 {
	var total uint64
	for _, v := range m {
		total += v
	}
	return total
}

func TestHintRejectionAndWithdrawalTelemetry(t *testing.T) {
	h := newHintTraffic(100_000, true)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().State != "validated" {
		t.Fatal("precondition: validated")
	}
	// RTT over the bound rejects and withdraws from validated.
	h.rtt.latest = 120 * time.Millisecond
	h.step(1000)
	st := h.s.HintStatus()
	if st.RejectionsTotal["rtt"] != 1 || st.RttOverBound != 1 || st.RttChecks == 0 {
		t.Fatalf("rtt telemetry missing: %+v", st)
	}
	if st.Withdrawals["rtt"] != 1 {
		t.Fatalf("rtt withdrawal misclassified: %v", st.Withdrawals)
	}
	// A repeat rejection while already revoked still counts as a rejection
	// but never as a withdrawal or a revocation.
	h.step(1000)
	st = h.s.HintStatus()
	if st.RejectionsTotal["rtt"] < 2 || st.Withdrawals["rtt"] != 1 {
		t.Fatalf("repeat rejection misclassified: %+v", st)
	}
	h.rtt.latest = 80 * time.Millisecond
	for i := 0; i < 250; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().State != "validated" {
		t.Fatal("did not revalidate")
	}
	// PTO is not observable through this quic-go's CongestionControl interface
	// (see OnRetransmissionTimeout), so it must neither withdraw the hint nor
	// appear in the reason telemetry.
	h.s.OnRetransmissionTimeout(true)
	if st = h.s.HintStatus(); st.Withdrawals["pto"] != 0 || st.RejectionsTotal["pto"] != 0 {
		t.Fatalf("pto must not be a revoke reason: %+v", st)
	}
	if st.State != "validated" {
		t.Fatalf("state %q changed on an unobservable PTO callback", st.State)
	}
	h.s.OnCongestionEvent(h.pn, 0, h.inflight)
	if st = h.s.HintStatus(); st.Withdrawals["ecn_or_timer"] != 1 {
		t.Fatalf("ecn withdrawal misclassified: %v", st.Withdrawals)
	}
	for i := 0; i < 250; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().State != "validated" {
		t.Fatal("did not revalidate after ecn")
	}
	h.rtt.latest, h.rtt.smoothed = 0, 0
	h.step(1000)
	if st = h.s.HintStatus(); st.Withdrawals["zero_rtt"] != 1 || st.RttZeroSamples == 0 {
		t.Fatalf("zero rtt withdrawal misclassified: %+v", st)
	}
	if sumCounts(st.Withdrawals) != st.Revocations {
		t.Fatalf("withdrawals %v disagree with revocations %d", st.Withdrawals, st.Revocations)
	}
}
func TestRejectionCountedInAnyGateState(t *testing.T) {
	h := newHintTraffic(100_000, true)
	for i := 0; i < 12; i++ {
		h.step(1000)
	}
	if st := h.s.HintStatus(); st.State == "validated" {
		t.Fatal("precondition: expected unvalidated gate")
	}
	h.s.OnCongestionEvent(h.pn, 0, h.inflight)
	st := h.s.HintStatus()
	if st.RejectionsTotal["ecn_or_timer"] != 1 {
		t.Fatalf("unvalidated rejection not counted: %+v", st)
	}
	if sumCounts(st.Withdrawals) != 0 || st.Revocations != 0 {
		t.Fatalf("unvalidated rejection counted as withdrawal: %+v", st)
	}
}
func TestWindowRingRecordsCompletedWindows(t *testing.T) {
	h := newHintTraffic(100_000, true)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	st := h.s.HintStatus()
	if st.WindowsTotal == 0 || len(st.WindowRates) == 0 {
		t.Fatalf("no completed windows recorded: %+v", st)
	}
	if uint64(len(st.WindowRates)) != st.WindowsTotal {
		t.Fatalf("ring size %d disagrees with windows_total %d", len(st.WindowRates), st.WindowsTotal)
	}
	if st.FirstValidatedMS == 0 {
		t.Fatal("first_validated_ms not recorded")
	}
	for i, w := range st.WindowRates {
		if w.TMS == 0 || w.RateBps == 0 || (w.Class != "clean" && w.Class != "probe_band" && w.Class != "low") {
			t.Fatalf("malformed ring entry %+v", w)
		}
		if i > 0 && w.TMS < st.WindowRates[i-1].TMS {
			t.Fatalf("ring not chronological at %d: %+v", i, w)
		}
	}
	// Steady near-hint delivery must produce clean windows and a >=3 streak
	// (validation requires three consecutive clean windows).
	if st.WindowsClean == 0 || st.MaxCleanStreak < 3 {
		t.Fatalf("clean windows not tracked: %+v", st)
	}
	if st.WindowsClean+st.WindowsProbeBand+st.WindowsLow != st.WindowsTotal {
		t.Fatalf("bands %d+%d+%d != total %d", st.WindowsClean, st.WindowsProbeBand, st.WindowsLow, st.WindowsTotal)
	}
	// A fourfold overhint keeps every completed window in the low band, and
	// the ring stays bounded at its capacity while windows keep completing.
	over := newHintTraffic(400_000, true)
	for i := 0; i < 7300; i++ {
		over.step(1000)
	}
	ost := over.s.HintStatus()
	if ost.WindowsLow != ost.WindowsTotal || ost.WindowsClean != 0 || ost.Validations != 0 {
		t.Fatalf("overhint bands misclassified: %+v", ost)
	}
	for _, w := range ost.WindowRates {
		if w.Class != "low" {
			t.Fatalf("overhint ring entry not low: %+v", w)
		}
	}
	if len(ost.WindowRates) != 256 || ost.WindowsTotal <= 256 {
		t.Fatalf("ring cap not enforced: len=%d total=%d", len(ost.WindowRates), ost.WindowsTotal)
	}
}
func TestProbeTimelineTelemetry(t *testing.T) {
	h := newHintTraffic(100_000, true)
	h.rtt.latest, h.rtt.smoothed = 100*time.Millisecond, 100*time.Millisecond
	sawProbe := false
	for i := 0; i < 80 && !sawProbe; i++ {
		h.step(800)
		sawProbe = h.s.HintStatus().State == "probing"
	}
	if !sawProbe {
		t.Fatal("no probe observed")
	}
	// A shorter minimum RTT shrinks the evaluation window below the probe's
	// expiry deadline, so the next window completes inside probing and its
	// failure must be classified probe_fail, not expiry.
	h.rtt.latest, h.rtt.smoothed = 80*time.Millisecond, 80*time.Millisecond
	for i := 0; i < 60; i++ {
		h.step(800)
	}
	st := h.s.HintStatus()
	if st.Withdrawals["probe_fail"] == 0 || st.RejectionsTotal["probe_fail"] == 0 {
		t.Fatalf("failed probe not classified: %+v", st)
	}
	if st.Probes == 0 || st.FirstProbeMS == 0 || st.MsProbing == 0 || st.WindowsProbeBand == 0 {
		t.Fatalf("probe timeline missing: %+v", st)
	}
}
func TestLiftTelemetryCountsRealPacingLift(t *testing.T) {
	// Deterministic sender state: validated target vs several estimates.
	p := DefaultParams()
	p.EnableValidatedHint = true
	s := NewBbr3SenderWithParams(1200, 100_000, p)
	s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})
	s.gate.state = hintValidated
	s.mode.Store(uint32(modeProbeBWCruise))
	if target := s.hintEstimate(90_000); target != 100_000 {
		t.Fatalf("lift target %d", target)
	}
	if target := s.hintEstimate(95_000); target != 100_000 {
		t.Fatalf("lift target %d", target)
	}
	if st := s.HintStatus(); st.LiftEvents != 2 || st.LiftMaxBps != 10_000 {
		t.Fatalf("lift telemetry wrong: %+v", st)
	}
	if target := s.hintEstimate(50_000); target != 100_000 {
		t.Fatalf("lift target %d", target)
	}
	if st := s.HintStatus(); st.LiftEvents != 3 || st.LiftMaxBps != 50_000 {
		t.Fatalf("max lift not tracked: %+v", st)
	}
	if target := s.hintEstimate(150_000); target != 150_000 {
		t.Fatalf("estimate above target altered: %d", target)
	}
	if st := s.HintStatus(); st.LiftEvents != 3 {
		t.Fatalf("non-lift counted: %+v", st)
	}
	// End-to-end: a validated gate lifts the estimate it is fed.
	h := newHintTraffic(100_000, true)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	h.s.mode.Store(uint32(modeProbeBWCruise))
	before := h.s.HintStatus()
	if target := h.s.hintEstimate(80_000); target != 100_000 {
		t.Fatalf("validated target %d", target)
	}
	after := h.s.HintStatus()
	if after.LiftEvents != before.LiftEvents+1 || after.LiftMaxBps < 20_000 {
		t.Fatalf("traffic lift not counted: %+v -> %+v", before, after)
	}
	// The disabled gate never lifts.
	off := newHintTraffic(100_000, false)
	for i := 0; i < 150; i++ {
		off.step(1000)
	}
	if target := off.s.hintEstimate(1); target != 1 {
		t.Fatalf("disabled sender altered estimate: %d", target)
	}
	if st := off.s.HintStatus(); st.LiftEvents != 0 || st.LiftMaxBps != 0 {
		t.Fatalf("disabled lift telemetry nonzero: %+v", st)
	}
}
func TestDisabledHintTelemetryStaysZero(t *testing.T) {
	h := newHintTraffic(100_000, false)
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	h.s.OnCongestionEvent(h.pn, 500, h.inflight)
	// A no-op PTO callback must not move telemetry either.
	h.s.OnRetransmissionTimeout(true)
	h.s.HasPacingBudget(h.now.Add(2 * time.Second))
	st := h.s.HintStatus()
	if st.State != "disabled" {
		t.Fatalf("state %q", st.State)
	}
	if st.Probes != 0 || st.Validations != 0 || st.Revocations != 0 {
		t.Fatalf("legacy counters moved while disabled: %+v", st)
	}
	if len(st.RejectionsTotal) != 0 || len(st.Withdrawals) != 0 || len(st.WindowRates) != 0 {
		t.Fatalf("telemetry maps/ring not empty: %+v", st)
	}
	for _, v := range []uint64{st.WindowsTotal, st.WindowsClean, st.WindowsProbeBand, st.WindowsLow, st.MaxCleanStreak,
		st.FirstProbeMS, st.FirstValidatedMS, st.LastValidatedMS, st.MsProbing, st.MsValidated,
		st.LiftEvents, st.LiftMaxBps, st.RttChecks, st.RttOverBound, st.RttZeroSamples} {
		if v != 0 {
			t.Fatalf("disabled telemetry nonzero: %+v", st)
		}
	}
}

// TestHintCapUsesDivergenceAwareRTT pins the cap-side mirror of the b141c8a
// floor protection: once the smoothed RTT rises past minRTT, the hint budget
// must be sized with the diverged RTT. A minRTT-sized cap would under-fill
// the pipe at the hint's own rate and cut the srtt-based floor support below
// the window the path needs.
func TestHintCapUsesDivergenceAwareRTT(t *testing.T) {
	h := newHintTraffic(100_000, true)
	// Sustain traffic until the hint validates and the pipeline is steady.
	for i := 0; i < 150; i++ {
		h.step(1000)
	}
	if h.s.HintStatus().State != "validated" {
		t.Fatal("hint did not validate")
	}
	// Diverge the path: smoothed RTT triples while minRTT stays 80ms.
	h.rtt.smoothed = 240 * time.Millisecond
	h.rtt.latest = 240 * time.Millisecond
	for i := 0; i < 30; i++ {
		h.step(1000)
	}
	cwnd := h.s.GetCongestionWindow()
	// The old, minRTT-sized cap for a 100KB/s hint at 80ms and CwndGain 2 is
	// 100_000 * 0.08 * 2 = 16_000 bytes (observed pinning exactly there on
	// the pre-fix code). The divergence-aware cap is three times that; the
	// window must not be pinned to the minRTT-sized budget.
	minRTTCap := congestion.ByteCount(float64(100_000) * 0.08 * 2.0)
	if cwnd <= minRTTCap {
		t.Fatalf("cwnd %d pinned to the minRTT-sized hint cap %d: the cap must size its budget with the diverged RTT", cwnd, minRTTCap)
	}
}
