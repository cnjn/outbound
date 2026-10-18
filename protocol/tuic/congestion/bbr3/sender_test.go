package bbr3

import (
	"testing"
	"time"

	"github.com/olicesx/quic-go/congestion"
)

func TestAccessHintCapsSteadyStatePacingAndWindow(t *testing.T) {
	const hint = 1_000_000 // bytes per second
	s := newTestSender(hint)
	seedEstimate(s.model, 10_000_000) // path estimate far above the access link
	s.model.round = 0
	s.mode.Store(uint32(modeProbeBWCruise))
	s.recalc()

	if s.PacingRate() > Bandwidth(hint) {
		t.Fatalf("steady-state pacing = %d, want <= hint %d", s.PacingRate(), hint)
	}
	capCwnd := congestion.ByteCount(float64(hint) * s.model.minRttValue().Seconds() * s.params.CwndGain)
	if s.GetCongestionWindow() > capCwnd {
		t.Fatalf("cwnd = %d, want <= hint window %d", s.GetCongestionWindow(), capCwnd)
	}
}

func TestAccessHintAllowsBoundedProbeOvershoot(t *testing.T) {
	const hint = 1_000_000
	s := newTestSender(hint)
	seedEstimate(s.model, 10_000_000)
	s.model.round = 0

	// A probe may exceed the hint, but only by the configured factor: otherwise
	// a hint equal to path capacity would pin the estimate below capacity.
	s.mode.Store(uint32(modeProbeBWUp))
	s.recalc()
	ceiling := Bandwidth(float64(hint) * s.params.HintProbeOvershoot)
	if s.PacingRate() > ceiling {
		t.Fatalf("probe pacing = %d, want <= %d", s.PacingRate(), ceiling)
	}
	if s.PacingRate() <= Bandwidth(hint) {
		t.Fatalf("probe pacing = %d, want it to exceed the hint and discover capacity", s.PacingRate())
	}
	// Never an unbounded probe either.
	s.mode.Store(uint32(modeStartup))
	s.recalc()
	if s.PacingRate() > ceiling {
		t.Fatalf("startup pacing = %d, want <= %d", s.PacingRate(), ceiling)
	}
}

func TestNoHintDoesNotCapPacing(t *testing.T) {
	s := newTestSender(0)
	seedEstimate(s.model, 10_000_000)
	s.model.round = 0
	s.recalc()

	if s.PacingRate() <= Bandwidth(1_000_000) {
		t.Fatalf("pacing = %d, want an uncapped estimate", s.PacingRate())
	}
}

func TestLegacyCallbacksAreNoOps(t *testing.T) {
	// quic-go reports each ack both per packet and as a vector; acting on the
	// per-packet callback would count every ack twice.
	s := newTestSender(0)
	now := time.Now()
	s.OnPacketSent(now, 0, 1, 1200, true)
	before := s.model.roundBytesAcked
	s.model.roundBytesSent = 12_000

	s.OnPacketAcked(1, 1200, 1200, now)
	s.OnCongestionEvent(1, 1200, 1200)

	if s.model.roundBytesAcked != before {
		t.Fatalf("roundBytesAcked changed to %d, want %d", s.model.roundBytesAcked, before)
	}
	if s.model.roundBytesLost != 0 {
		t.Fatalf("roundBytesLost = %d, want 0", s.model.roundBytesLost)
	}
	// quic-go's OnPacketSent argument is inclusive of the packet being sent
	// (sent_packet_handler.go:275-282 increments bytesInFlight first), so the
	// model must record the argument verbatim.
	if s.model.bytesInFlight != 0 {
		t.Fatalf("bytesInFlight = %d, want 0: the argument was 0 and the stack had not counted this packet",
			s.model.bytesInFlight)
	}
}

// TestOnPacketSentTracksTheStackInFlightAccounting drives a realistic send/ack
// sequence exactly as quic-go's sentPacketHandler would and asserts the model
// mirrors the stack's own arithmetic: the inclusive argument on send, and the
// pre-subtraction priorInFlight on ack.
func TestOnPacketSentTracksTheStackInFlightAccounting(t *testing.T) {
	s := newTestSender(0)
	now := time.Now()

	// The stack increments its counter before calling the controller.
	stackInFlight := congestion.ByteCount(0)
	stackInFlight += 1200
	s.OnPacketSent(now, stackInFlight, 1, 1200, true)
	if s.model.bytesInFlight != stackInFlight {
		t.Fatalf("after send 1: model in-flight = %d, want the stack's %d",
			s.model.bytesInFlight, stackInFlight)
	}

	stackInFlight += 1200
	s.OnPacketSent(now.Add(time.Millisecond), stackInFlight, 2, 1200, true)
	if s.model.bytesInFlight != stackInFlight {
		t.Fatalf("after send 2: model in-flight = %d, want the stack's %d",
			s.model.bytesInFlight, stackInFlight)
	}

	// Acking packet 1: the stack reads priorInFlight before removing the ack.
	priorInFlight := stackInFlight
	stackInFlight -= 1200
	acked := []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}
	s.OnCongestionEventEx(priorInFlight, now.Add(80*time.Millisecond), acked, nil)
	if s.model.bytesInFlight != stackInFlight {
		t.Fatalf("after acking 1200: model in-flight = %d, want the stack's %d",
			s.model.bytesInFlight, stackInFlight)
	}
}

func TestStartupSurvivesSustainedLossWithoutSettingInflightHi(t *testing.T) {
	s := newTestSender(0)
	now := time.Now()
	now = drive(s, now, 6, 80*time.Millisecond)

	s.mode.Store(uint32(modeStartup))
	s.model.inflightHi = 0
	// Background loss must not abort STARTUP: a per-round loss gate fires on
	// a few percent of random loss as soon as rounds carry enough packets,
	// which stranded the sender at a fraction of path capacity on degraded
	// paths (see the STARTUP case in sender.go). Overshoot is answered by
	// the full-bandwidth test and, once probing, by PROBE_UP's inflight_hi
	// cap.
	losePackets(s, now, 100_000, 5_000)

	if mode(s.mode.Load()) != modeStartup {
		t.Fatalf("mode = %s, want STARTUP to survive sustained loss", s.Mode())
	}
	// PROBE_UP owns the upper bound; pinning it from a startup loss would clamp
	// the sender to a tiny window for the rest of the connection.
	if s.model.inflightHi != 0 {
		t.Fatalf("inflightHi = %d, want it left unset at startup", s.model.inflightHi)
	}
}

func TestSingleLossEventIsNotTreatedAsOvershoot(t *testing.T) {
	s := newTestSender(0)
	now := time.Now()
	now = drive(s, now, 6, 80*time.Millisecond)

	s.mode.Store(uint32(modeStartup))
	losePackets(s, now, 8_000, 400) // tiny round: below the volume floor
	if mode(s.mode.Load()) != modeStartup {
		t.Fatalf("mode = %s, want STARTUP to survive a stray loss", s.Mode())
	}
}

func TestStartupReachesFullBandwidthAndDrains(t *testing.T) {
	s := newTestSender(0)
	now := time.Now()
	now = drive(s, now, 40, 80*time.Millisecond)
	if mode(s.mode.Load()) == modeStartup {
		t.Fatal("still in STARTUP after 40 rounds of a saturated path")
	}
	if s.model.estimate() == 0 {
		t.Fatal("no bandwidth estimate after driving the sender")
	}
	_ = now
}

func TestProbeRttEntryAndExit(t *testing.T) {
	s := newTestSender(0)
	now := time.Now()
	now = drive(s, now, 6, 80*time.Millisecond)
	s.model.inflightHi = 400_000

	// Expire the min-RTT filter to force PROBE_RTT.
	now = now.Add(DefaultParams().MinRttFilterLen + time.Second)
	s.OnCongestionEventEx(0, now, []congestion.AckedPacketInfo{{PacketNumber: s.model.lastSent, BytesAcked: 0}}, nil)
	if mode(s.mode.Load()) != modeProbeRTT {
		t.Fatalf("mode = %s, want PROBE_RTT after min RTT expiry", s.Mode())
	}
	if s.model.probeRttTarget() <= s.model.minCwnd {
		t.Fatalf("probe target %d collapsed to minCwnd", s.model.probeRttTarget())
	}

	// Drain to the target, then hold for the probe duration plus a round.
	s.model.bytesInFlight = 0
	now = now.Add(time.Millisecond)
	s.OnCongestionEventEx(0, now, []congestion.AckedPacketInfo{{PacketNumber: s.model.lastSent + 1, BytesAcked: 0}}, nil)
	now = now.Add(DefaultParams().ProbeRttDuration + 80*time.Millisecond)
	s.OnCongestionEventEx(0, now, []congestion.AckedPacketInfo{{PacketNumber: s.model.lastSent + 2, BytesAcked: 0}}, nil)
	if mode(s.mode.Load()) == modeProbeRTT {
		t.Fatal("stuck in PROBE_RTT after the probe duration and a round")
	}
}

func TestModeCycleAdvancesPerRound(t *testing.T) {
	s := newTestSender(0)
	s.mode.Store(uint32(modeProbeBWDown))

	seen := map[mode]bool{}
	for i := 0; i < 8; i++ {
		s.model.lastSent += 10
		s.OnCongestionEventEx(0, time.Now(), []congestion.AckedPacketInfo{{
			PacketNumber: s.model.lastSent,
			BytesAcked:   1200,
		}}, nil)
		seen[mode(s.mode.Load())] = true
	}
	for _, m := range []mode{modeProbeBWUp, modeProbeBWDown, modeProbeBWCruise, modeProbeBWRefill} {
		if !seen[m] {
			t.Fatalf("PROBE_BW cycle never visited %s", m)
		}
	}
}
