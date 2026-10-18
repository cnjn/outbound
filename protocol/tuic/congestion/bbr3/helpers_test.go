package bbr3

import (
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr"
	"github.com/olicesx/quic-go/congestion"
)

// fakeRTT is a minimal congestion.RTTStatsProvider.
type fakeRTT struct {
	latest   time.Duration
	smoothed time.Duration
}

func (f *fakeRTT) MinRTT() time.Duration        { return f.latest }
func (f *fakeRTT) LatestRTT() time.Duration     { return f.latest }
func (f *fakeRTT) SmoothedRTT() time.Duration   { return f.smoothed }
func (f *fakeRTT) MeanDeviation() time.Duration { return 0 }
func (f *fakeRTT) MaxAckDelay() time.Duration   { return 0 }
func (f *fakeRTT) PTO(bool) time.Duration       { return 0 }

func newTestSender(hint uint64) *Bbr3Sender {
	s := NewBbr3Sender(1200, hint)
	s.SetRTTStatsProvider(&fakeRTT{latest: 80 * time.Millisecond, smoothed: 80 * time.Millisecond})
	return s
}

// drive keeps a pipeline running: each round fills the current congestion window
// with fresh packets and acknowledges the previous round's batch, so bytes stay
// in flight and the sampler is never app-limited.
//
// It maintains its own in-flight counter the way quic-go's sentPacketHandler
// does - incremented before OnPacketSent, read before the acked bytes are
// subtracted for OnCongestionEventEx - because that is the convention the
// controller is written against. Feeding the CONTROLLER's own field back in
// would make this helper a mirror of whatever accounting the controller has,
// which is how the double-count in OnPacketSent stayed invisible.
func drive(s *Bbr3Sender, now time.Time, rounds int, rtt time.Duration) time.Time {
	var nextPn congestion.PacketNumber
	var pending []congestion.PacketNumber
	var stackInFlight congestion.ByteCount
	for r := 0; r < rounds; r++ {
		n := int(s.GetCongestionWindow()/1200) + 2
		for i := 0; i < n; i++ {
			nextPn++
			stackInFlight += 1200
			s.OnPacketSent(now, stackInFlight, nextPn, 1200, true)
			now = now.Add(time.Millisecond)
		}
		if len(pending) > 0 {
			acked := make([]congestion.AckedPacketInfo, 0, len(pending))
			for _, pn := range pending {
				acked = append(acked, congestion.AckedPacketInfo{PacketNumber: pn, BytesAcked: 1200})
			}
			priorInFlight := stackInFlight
			stackInFlight -= congestion.ByteCount(1200 * len(pending))
			s.OnCongestionEventEx(priorInFlight, now, acked, nil)
		}
		pending = pending[:0]
		for i := 0; i < n; i++ {
			pending = append(pending, nextPn-congestion.PacketNumber(i))
		}
		now = now.Add(rtt)
	}
	return now
}

// losePackets feeds a round that sent sentBytes and lost lostBytes across
// MinLossPackets separate loss events, the shape a real overshoot has.
func losePackets(s *Bbr3Sender, now time.Time, sentBytes, lostBytes congestion.ByteCount) {
	s.model.roundBytesSent = sentBytes
	s.model.roundBytesAcked = sentBytes - lostBytes
	per := lostBytes / congestion.ByteCount(s.params.MinLossPackets)
	lost := make([]congestion.LostPacketInfo, 0, s.params.MinLossPackets)
	for i := 0; i < s.params.MinLossPackets; i++ {
		lost = append(lost, congestion.LostPacketInfo{
			PacketNumber: s.model.lastSent - congestion.PacketNumber(i),
			BytesLost:    per,
		})
	}
	s.OnCongestionEventEx(s.model.bytesInFlight, now, nil, lost)
}

// seedEstimate gives the model a known delivery-rate estimate by driving the
// shared reference estimator with one sent and acknowledged packet: 1200 bytes
// acknowledged after 1200/bw seconds samples bw bytes per second. Tests that
// used to write model.bw directly use this instead, because the estimate is now
// owned by bbr.RefSampler.
func seedEstimate(m *model, bw Bandwidth) {
	if bw == 0 {
		return
	}
	const bytes congestion.ByteCount = 1200
	t0 := time.Unix(0, 0)
	delta := time.Duration(float64(bytes) / float64(bw) * float64(time.Second))
	if delta <= 0 {
		delta = time.Nanosecond
	}
	m.ref.OnPacketSent(t0, 0, bytes, 0, true)
	m.ref.OnCongestionEvent(t0.Add(delta),
		[]congestion.AckedPacketInfo{{PacketNumber: 0, BytesAcked: bytes}}, nil, 0)
}

// setEstimate replaces the model's estimate with a known value, which is what
// the removed local filter expressed as bw.Reset() followed by bw.Update(v, 0).
// The reference estimator has no reset, so a fresh sampler is installed and
// seeded; every other model field is left alone.
func setEstimate(m *model, bw Bandwidth) {
	m.ref = bbr.NewRefSampler(m.params.MaxBwFilterRounds)
	seedEstimate(m, bw)
}
