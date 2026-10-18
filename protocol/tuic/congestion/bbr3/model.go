package bbr3

import (
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr"
	"github.com/olicesx/quic-go/congestion"
)

// model is the network model: everything the sender estimates about the path.
// It owns no policy about modes; the sender reads it and decides.
type model struct {
	params          Params
	ref             *bbr.RefSampler
	maxDatagramSize congestion.ByteCount
	initialCwnd     congestion.ByteCount
	minCwnd         congestion.ByteCount

	// Round accounting.
	round    uint64
	roundEnd congestion.PacketNumber
	lastSent congestion.PacketNumber

	bytesInFlight congestion.ByteCount

	// Loss-driven lower bound on the delivery-rate estimate.
	bwLo Bandwidth

	// inflight_hi / inflight_lo: the upper and lower bounds the sender keeps on
	// bytes in flight, per the BBRv2 bound pair.
	inflightHi congestion.ByteCount
	inflightLo congestion.ByteCount

	minRtt      time.Duration
	minRttStamp time.Time

	fullBwReached  bool
	fullBwBaseline Bandwidth
	fullBwRounds   int

	// Per-round loss accounting, plus the completed round's snapshot so a
	// round-boundary decision still sees the finished round.
	roundBytesSent         congestion.ByteCount
	roundBytesLost         congestion.ByteCount
	roundBytesAcked        congestion.ByteCount
	roundLostPackets       int
	lastRoundSent          congestion.ByteCount
	lastRoundLost          congestion.ByteCount
	lastRoundAcked         congestion.ByteCount
	lastRoundLostPkts      int
	lastRoundLossThreshold float64

	lossBaseline    float64
	lossBaselineSet bool

	// Rounds spent in the current PROBE_UP, bounded by ProbeUpRounds.
	probeUpRounds int
}

func newModel(params Params, maxDatagramSize congestion.ByteCount) *model {
	if maxDatagramSize <= 0 {
		maxDatagramSize = congestion.InitialPacketSize
	}
	return &model{
		params:          params,
		maxDatagramSize: maxDatagramSize,
		initialCwnd:     congestion.ByteCount(params.InitialCwndPackets) * maxDatagramSize,
		minCwnd:         congestion.ByteCount(params.MinCwndPackets) * maxDatagramSize,
		roundEnd:        -1,
		lastSent:        -1,
		ref:             bbr.NewRefSampler(params.MaxBwFilterRounds),
	}
}

// setMaxDatagramSize updates the per-packet size ceiling. This is NOT the path
// MTU: it is the largest single datagram the sender may put on the wire, and it
// is the unit every packet-count-derived window is expressed in, so all of them
// must be recomputed here. Recomputed: minCwnd and initialCwnd (P3-53). The
// sender's maxCwnd is recomputed in Bbr3Sender.SetMaxDatagramSize.
func (m *model) setMaxDatagramSize(s congestion.ByteCount) {
	if s <= 0 {
		return
	}
	m.maxDatagramSize = s
	m.minCwnd = congestion.ByteCount(m.params.MinCwndPackets) * s
	m.initialCwnd = congestion.ByteCount(m.params.InitialCwndPackets) * s
}

// estimate is the windowed-max delivery-rate estimate.
func (m *model) accountEvent(ackedBytes, lostBytes congestion.ByteCount, lostPackets int, maxPn congestion.PacketNumber) (roundStart bool) {
	roundStart = m.updateRound(maxPn)
	m.roundBytesLost += lostBytes
	m.roundBytesAcked += ackedBytes
	m.roundLostPackets += lostPackets
	if !roundStart {
		return false
	}
	m.lastRoundLossThreshold = m.lossThresholdNow()
	m.lastRoundSent = m.roundBytesSent
	m.lastRoundLost = m.roundBytesLost
	m.lastRoundAcked = m.roundBytesAcked
	m.lastRoundLostPkts = m.roundLostPackets
	m.roundBytesSent = 0
	m.roundBytesLost = 0
	m.roundBytesAcked = 0
	m.roundLostPackets = 0
	return true
}

// updateBandwidth folds a delivery-rate sample into the estimate. App-limited
// samples must not raise it.
