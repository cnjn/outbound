package brutal

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/daeuniverse/outbound/protocol/tuic/congestion/common"

	"github.com/olicesx/quic-go/congestion"
)

const (
	pktInfoSlotCount = 5 // slot index is based on seconds, so this is basically how many seconds we sample
	minSampleCount   = 50
	minAckRate       = 0.8
	// congestionWindowMultiplier is the fork's deliberate divergence from the
	// upstream hysteria implementation this controller is derived from, which
	// uses 2 (/root/sing-quic-src/hysteria/congestion/brutal.go:18). It is 3
	// here: the larger cwnd headroom lets game heartbeats survive an ackRate
	// drop without hitting SendAck.
	//
	// Contract (P2-33): a closed-loop A/B over a single-bottleneck FIFO with
	// the real BrutalSender and the real common.Pacer showed every behaviour
	// metric identical between 2 and 3 (queue depth, p95 RTT, throughput,
	// loss, in-flight), with cwnd_bound=false in all eight scenarios: because
	// the pacer holds ~one BDP in flight while cwnd allows M of them, CanSend
	// is structurally true for any M >= 1. The only observable difference is
	// the reported window, which is exactly M x. So this constant must NOT be
	// changed on performance grounds - there are none to gain - and any future
	// change needs a reason that is not a throughput claim.
	congestionWindowMultiplier = 3

	debugEnv           = "HYSTERIA_BRUTAL_DEBUG"
	debugPrintInterval = 2
)

var _ congestion.CongestionControl = &BrutalSender{}

type BrutalSender struct {
	rttStats        congestion.RTTStatsProvider
	bps             congestion.ByteCount
	maxDatagramSize congestion.ByteCount
	pacer           *common.Pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64

	debug                 bool
	lastAckPrintTimestamp int64
}

type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
}

func NewBrutalSender(bps uint64) *BrutalSender {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	bs := &BrutalSender{
		bps:             congestion.ByteCount(bps),
		maxDatagramSize: congestion.InitialPacketSize,
		ackRate:         1,
		debug:           debug,
	}
	bs.pacer = common.NewPacer(func() congestion.ByteCount {
		return congestion.ByteCount(float64(bs.bps) / bs.ackRate)
	})
	return bs
}

func (b *BrutalSender) SetRTTStatsProvider(rttStats congestion.RTTStatsProvider) {
	b.rttStats = rttStats
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *BrutalSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

// GetCongestionWindow returns the controller's window:
//
//	cwnd = max(bps * smoothedRTT * congestionWindowMultiplier / ackRate, maxDatagramSize)
//
// The window is a pure function of the target bandwidth, the RTT and the ack
// rate: it is not grown by acks and not cut by loss, which is what makes this a
// sender-side rate limiter rather than a loss-reactive controller. The
// maxDatagramSize floor keeps a non-zero window even before an RTT sample
// exists. See congestionWindowMultiplier for the fork delta and its contract.
func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	// The window is computed on every CanSend call, which quic-go can reach
	// before SetRTTStatsProvider installs the provider (and every test that
	// constructs a sender by hand reaches it without one). A nil provider must
	// fall back to the bootstrap window, not dereference nil.
	rtt := time.Duration(0)
	if b.rttStats != nil {
		rtt = b.rttStats.SmoothedRTT()
	}
	if rtt <= 0 {
		return 10240
	}
	cwnd := congestion.ByteCount(float64(b.bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}
	return cwnd
}

func (b *BrutalSender) OnPacketSent(sentTime time.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime time.Time,
) {
	// Stub
}

func (b *BrutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
) {
	// Stub
}

func (b *BrutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime time.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	currentTimestamp := eventTime.Unix()
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
		b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
	} else {
		// uninitialized slot or too old, reset
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = uint64(len(ackedPackets))
		b.pktInfoSlots[slot].LossCount = uint64(len(lostPackets))
	}
	b.updateAckRate(currentTimestamp)
}

func (b *BrutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
	if b.debug {
		b.debugPrint("SetMaxDatagramSize: %d", size)
	}
}

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
	}
	if ackCount+lossCount < minSampleCount {
		b.ackRate = 1
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("Not enough samples (total=%d, ack=%d, loss=%d, rtt=%d)",
				ackCount+lossCount, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
		}
		return
	}
	rate := float64(ackCount) / float64(ackCount+lossCount)
	if rate < minAckRate {
		b.ackRate = minAckRate
		if b.canPrintAckRate(currentTimestamp) {
			b.lastAckPrintTimestamp = currentTimestamp
			b.debugPrint("ACK rate too low: %.2f, clamped to %.2f (total=%d, ack=%d, loss=%d, rtt=%d)",
				rate, minAckRate, ackCount+lossCount, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
		}
		return
	}
	b.ackRate = rate
	if b.canPrintAckRate(currentTimestamp) {
		b.lastAckPrintTimestamp = currentTimestamp
		b.debugPrint("ACK rate: %.2f (total=%d, ack=%d, loss=%d, rtt=%d)",
			rate, ackCount+lossCount, ackCount, lossCount, b.rttStats.SmoothedRTT().Milliseconds())
	}
}

func (b *BrutalSender) InSlowStart() bool {
	return false
}

func (b *BrutalSender) InRecovery() bool {
	return false
}

func (b *BrutalSender) MaybeExitSlowStart() {}

func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

func (b *BrutalSender) canPrintAckRate(currentTimestamp int64) bool {
	return b.debug && currentTimestamp-b.lastAckPrintTimestamp >= debugPrintInterval
}

func (b *BrutalSender) debugPrint(format string, a ...any) {
	fmt.Printf("[BrutalSender] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}
