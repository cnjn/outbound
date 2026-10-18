package tuic

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	outboundcommon "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/pool/bytes"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

// packetChanCap bounds the per-association UDP packet queue. 2048 covers
// bursty game ticks / DNS floods; when full, PushBack drops the packet
// instead of blocking so one slow consumer cannot stall the demux goroutine
// that serves every association on the QUIC connection.
const packetChanCap = 2048

type Packets struct {
	mu sync.Mutex
	// ch is the bounded queue. It is nil until the first PushBack that has to
	// enqueue: an association whose receiver is registered immediately, or
	// which only ever sends, never pays for the 2048-slot buffer.
	ch       chan *Packet
	receiver *packetHandlerRegistration
	closed   atomic.Bool

	// cond wakes a blocked PopFrontBlock when a packet is enqueued or the
	// queue closes. A bare receive cannot do that job on a lazily allocated
	// queue: receiving from a nil channel blocks forever, and re-reading the
	// field after the check would race a channel that materializes later.
	// L is p.mu, so the wait predicate is always evaluated under the same lock
	// that PushBack and Close mutate under.
	cond *sync.Cond

	// dropped counts packets discarded because the queue was full, and
	// droppedNoReceiver counts packets discarded because no receiver was
	// registered at delivery time. Both are loss that would otherwise be
	// completely unobservable; see DroppedPackets.
	dropped           atomic.Uint64
	droppedNoReceiver atomic.Uint64

	// deliverMu serializes direct receiver delivery (PushBack) against the
	// receiver swap + queued-prefix drain in registerPacketHandler, so a
	// packet pushed after the swap cannot overtake the drained prefix (FIFO).
	deliverMu sync.Mutex
}

// DroppedPackets reports how many packets this association discarded without
// delivering them, split into (queue full, no receiver). ReadFrom-based
// consumers silently lose these; RegisterPacketReceiver-based consumers have
// no error return either, so this is the only signal that loss happened.
func (p *Packets) DroppedPackets() (full uint64, noReceiver uint64) {
	return p.dropped.Load(), p.droppedNoReceiver.Load()
}

type packetHandlerRegistration struct {
	active  atomic.Bool
	handler func(*Packet) bool
}

func NewPackets() *Packets {
	// The 2048-slot data queue is allocated lazily by ensureChan; only the
	// mutex and the condition variable are eager.
	p := &Packets{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// ensureChan lazily allocates the bounded data queue. Callers must hold p.mu,
// which also serializes channel creation against the close in Close.
func (p *Packets) ensureChan() chan *Packet {
	if p.ch == nil {
		p.ch = make(chan *Packet, packetChanCap)
	}
	return p.ch
}

func (p *Packets) PushBack(packet *Packet) {
	p.deliverMu.Lock()
	defer p.deliverMu.Unlock()
	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		packet.releaseData()
		return
	}
	if receiver := p.receiver; receiver != nil {
		p.mu.Unlock()
		if receiver.active.Load() {
			receiver.handler(packet)
			return
		}
		p.droppedNoReceiver.Add(1)
		packet.releaseData()
		return
	}
	// Channel send while holding mu so a concurrent Close cannot close the
	// channel underneath us (Close also acquires mu before close).
	// When full, drop instead of blocking: this call runs on the single
	// demux goroutine serving every association on the QUIC connection, and
	// blocking here would stall all of them (head-of-line blocking).
	ch := p.ensureChan()
	select {
	case ch <- packet:
		if p.cond != nil {
			p.cond.Signal()
		}
	default:
		p.dropped.Add(1)
		packet.releaseData()
	}
	p.mu.Unlock()
}

func (p *Packets) registerPacketHandler(handler func(*Packet) bool) (func(), bool) {
	if handler == nil {
		return nil, false
	}
	registration := &packetHandlerRegistration{handler: handler}
	registration.active.Store(true)

	// Hold deliverMu across the receiver swap and the drain so a concurrent
	// PushBack that observes the new receiver cannot deliver its packet
	// before the drained prefix (FIFO, same pattern as hysteria2).
	p.deliverMu.Lock()
	defer p.deliverMu.Unlock()

	p.mu.Lock()
	if p.closed.Load() || p.receiver != nil {
		p.mu.Unlock()
		return nil, false
	}
	p.receiver = registration
	// The queue may never have been materialized (no PushBack has had to
	// enqueue yet), in which case there is no prefix to drain.
	queued := make([]*Packet, 0, len(p.ch))
drainLoop:
	for {
		select {
		case pkt, ok := <-p.ch:
			if !ok {
				break drainLoop
			}
			queued = append(queued, pkt)
		default:
			break drainLoop
		}
	}
	p.mu.Unlock()

	for _, packet := range queued {
		if !registration.active.Load() {
			packet.releaseData()
			continue
		}
		handler(packet)
	}

	var unregisterOnce sync.Once
	return func() {
		unregisterOnce.Do(func() {
			// Do not take deliverMu here: handlers run while PushBack holds it,
			// and are allowed to unregister themselves synchronously.
			registration.active.Store(false)
			p.mu.Lock()
			if p.receiver == registration {
				p.receiver = nil
			}
			p.mu.Unlock()
		})
	}, true
}

// PopFrontBlock blocks until a packet is queued or the queue is closed.
//
// It waits on p.cond rather than receiving directly, so it works on a queue
// whose data channel has not been materialized yet: a receive would otherwise
// park on a nil channel (forever) or on a channel that is created after the
// reader's check (a lost wakeup). The predicate is evaluated under p.mu, the
// same lock PushBack Signals and Close Broadcasts under.
func (p *Packets) PopFrontBlock() (packet *Packet, closed bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.closed.Load() {
			return nil, true
		}
		if p.ch != nil {
			select {
			case packet := <-p.ch:
				return packet, false
			default:
			}
		}
		if p.cond == nil {
			// Only reachable for a zero-value Packets (not produced by
			// NewPackets, but constructed by tests); report closed rather
			// than spinning.
			return nil, true
		}
		p.cond.Wait()
	}
}

func (p *Packets) Close() error {
	// Do not take deliverMu: a synchronous receiver callback may close its
	// association. p.mu still serializes channel close with PushBack sends.
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return nil
	}
	p.closed.Store(true)
	if p.receiver != nil {
		p.receiver.active.Store(false)
		p.receiver = nil
	}
	// Drain buffered packets so PopFrontBlock returns closed immediately,
	// matching the previous list.Init() drop-on-close semantics. No new
	// PushBack can run concurrently — it would block on p.mu.
	//
	// The data queue is left nil when PushBack never materialized it: there is
	// nothing to drain, and the Broadcast below is what wakes a parked reader,
	// so allocating ~18.5 KB at teardown just to close it would defeat the
	// lazy allocation entirely.
	if p.ch != nil {
		for len(p.ch) > 0 {
			if pkt := <-p.ch; pkt != nil {
				pkt.releaseData()
			}
		}
		close(p.ch)
	}
	if p.cond != nil {
		p.cond.Broadcast()
	}
	return nil
}

type quicStreamPacketConn struct {
	mu sync.Mutex

	target string
	// addr caches the serialized wire Address per destination so the send
	// path stops re-parsing the cached metadata on every datagram.
	addr outboundcommon.LastStringValue[*Address]

	connId          uint16
	quicConn        quic.Connection
	incomingPackets *Packets

	udpRelayMode          common.UdpRelayMode
	maxUdpRelayPacketSize int

	deferQuicConnFn func(quicConn quic.Connection, err error)
	closeDeferFn    func()

	// done is the owning client's retirement channel (nil for bare test
	// literals): once closed, this association is logically retired and
	// WriteTo must fail immediately, even while the QUIC transport is kept
	// for its close grace period.
	done <-chan struct{}

	// writeMu serializes datagram assembly and send on this association's
	// private scratch buffer (writeScratch), the same per-flow lock shape
	// as hysteria2/juicity. The shared pool LIFO costs a global mutex round
	// per datagram; the hot send path now bypasses it entirely.
	writeMu      sync.Mutex
	writeScratch *bytes.Buffer

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool

	// deadlineExceeded records that the conn was torn down by its own
	// deadline timer rather than an explicit Close, so ReadFrom can report a
	// timeout instead of net.ErrClosed.
	deadlineExceeded atomic.Bool

	deFraggers sync.Map

	lastDeFraggerCleanupNano atomic.Int64

	muTimer       sync.Mutex
	deadlineTimer *time.Timer
}

var deFraggerIdleTimeout = 30 * time.Second

var deFraggerCleanupInterval = 5 * time.Second

var parseMetadata = protocol.ParseMetadata

type deFraggerBucket struct {
	mu         sync.Mutex
	deFraggers []*deFragger
}

func (b *deFraggerBucket) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.deFraggers)
}

func (b *deFraggerBucket) removeAt(index int) {
	if index < 0 || index >= len(b.deFraggers) {
		return
	}
	if d := b.deFraggers[index]; d != nil {
		d.release()
	}
	last := len(b.deFraggers) - 1
	b.deFraggers[index] = b.deFraggers[last]
	b.deFraggers[last] = nil
	b.deFraggers = b.deFraggers[:last]
}

func (b *deFraggerBucket) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range b.deFraggers {
		if d != nil {
			d.release()
		}
	}
	b.deFraggers = nil
}

func (b *deFraggerBucket) pruneExpired(nowNano int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if deFraggerIdleTimeout <= 0 {
		return
	}
	dst := b.deFraggers[:0]
	for _, d := range b.deFraggers {
		if d == nil {
			continue
		}
		if d.IsExpired(nowNano, deFraggerIdleTimeout) {
			d.release()
			continue
		}
		dst = append(dst, d)
	}
	for i := len(dst); i < len(b.deFraggers); i++ {
		b.deFraggers[i] = nil
	}
	b.deFraggers = dst
}

func (b *deFraggerBucket) feed(packet *Packet, p []byte, nowNano int64) (n int, addr netip.AddrPort, assembled bool, assembledLen int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if packet == nil {
		for i, d := range b.deFraggers {
			if d == nil {
				continue
			}
			if size, ready := d.assembledLen(); ready && len(p) >= size {
				var trigger *Packet
				for _, frag := range d.frags {
					if frag != nil {
						trigger = frag
						break
					}
				}
				n, addr, assembled = d.Feed(trigger, p, nowNano)
				if assembled {
					last := len(b.deFraggers) - 1
					b.deFraggers[i] = b.deFraggers[last]
					b.deFraggers[last] = nil
					b.deFraggers = b.deFraggers[:last]
				}
				return n, addr, assembled, size
			}
		}
		return 0, netip.AddrPort{}, false, 0
	}
	if packet.FRAG_TOTAL <= 1 || packet.FRAG_ID >= packet.FRAG_TOTAL {
		packet.releaseData()
		return 0, netip.AddrPort{}, false, 0
	}

	var candidates []int
	for i, d := range b.deFraggers {
		if d != nil && d.matches(packet) {
			candidates = append(candidates, i)
		}
	}

	selectedIndex := -1
	switch len(candidates) {
	case 0:
		b.deFraggers = append(b.deFraggers, newDeFragger(nowNano))
		selectedIndex = len(b.deFraggers) - 1
	case 1:
		selectedIndex = candidates[0]
	default:
		if packet.FRAG_ID == 0 {
			addrPort := packetFragmentAddrPort(packet)
			for _, idx := range candidates {
				if d := b.deFraggers[idx]; d != nil && d.hasFirstFrag && d.firstAddrPort == addrPort {
					selectedIndex = idx
					break
				}
			}
			if selectedIndex == -1 {
				for _, idx := range candidates {
					if d := b.deFraggers[idx]; d != nil && !d.hasFirstFrag {
						selectedIndex = idx
						break
					}
				}
			}
			if selectedIndex == -1 {
				b.deFraggers = append(b.deFraggers, newDeFragger(nowNano))
				selectedIndex = len(b.deFraggers) - 1
			}
		} else {
			// The protocol only carries a 16-bit packet ID on non-first fragments.
			// If multiple in-flight fragment sets remain compatible, routing this
			// fragment is ambiguous. Drop it rather than corrupt another payload.
			for _, idx := range candidates {
				if d := b.deFraggers[idx]; d != nil && d.hasFirstFrag {
					if selectedIndex != -1 {
						packet.releaseData()
						return 0, netip.AddrPort{}, false, 0
					}
					selectedIndex = idx
				}
			}
			if selectedIndex == -1 {
				packet.releaseData()
				return 0, netip.AddrPort{}, false, 0
			}
		}
	}

	d := b.deFraggers[selectedIndex]
	if d == nil {
		packet.releaseData()
		return 0, netip.AddrPort{}, false, 0
	}
	assembledLen, ready := d.assembledLen()
	if ready && len(p) < assembledLen {
		return 0, netip.AddrPort{}, false, assembledLen
	}
	n, addr, assembled = d.Feed(packet, p, nowNano)
	if assembled {
		last := len(b.deFraggers) - 1
		b.deFraggers[selectedIndex] = b.deFraggers[last]
		b.deFraggers[last] = nil
		b.deFraggers = b.deFraggers[:last]
		return n, addr, true, assembledLen
	}
	if size, ready := d.assembledLen(); ready {
		return 0, netip.AddrPort{}, false, size
	}
	return 0, netip.AddrPort{}, false, 0
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		q.closed.Store(true)
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamPacketConn) close() (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	incomingPackets := q.incomingPackets
	q.incomingPackets = nil
	if incomingPackets != nil {
		_ = incomingPackets.Close()
	}
	q.clearDeFraggers()
	// Release the serialization scratch so a closed association does not
	// pin its peak frame size until GC.
	q.writeMu.Lock()
	q.writeScratch = nil
	q.writeMu.Unlock()
	if incomingPackets != nil && q.quicConn != nil {

		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)
		err = NewDissociate(q.connId, Ver5).WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
		err = stream.Close()
		if err != nil {
			return
		}
	}
	return
}

func (q *quicStreamPacketConn) clearDeFraggers() {
	q.deFraggers.Range(func(key, value any) bool {
		if q.deFraggers.CompareAndDelete(key, value) {
			value.(*deFraggerBucket).release()
		}
		return true
	})
}

func (q *quicStreamPacketConn) maybeCleanupDeFraggers(nowNano int64) {
	if deFraggerIdleTimeout <= 0 {
		return
	}
	lastCleanupNano := q.lastDeFraggerCleanupNano.Load()
	if lastCleanupNano != 0 && nowNano-lastCleanupNano < deFraggerCleanupInterval.Nanoseconds() {
		return
	}
	if !q.lastDeFraggerCleanupNano.CompareAndSwap(lastCleanupNano, nowNano) {
		return
	}
	q.deFraggers.Range(func(key, value any) bool {
		bucket := value.(*deFraggerBucket)
		bucket.pruneExpired(nowNano)
		if bucket.len() == 0 {
			q.deFraggers.CompareAndDelete(key, bucket)
		}
		return true
	})
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	q.muTimer.Lock()
	defer q.muTimer.Unlock()
	// Always re-arm with a fresh timer instead of Reset: Reset cannot
	// retract a callback that already fired and is waiting on muTimer.
	if q.deadlineTimer != nil {
		q.deadlineTimer.Stop()
		q.deadlineTimer = nil
	}
	if t.IsZero() {
		// A zero time clears the deadline per the net.Conn contract;
		// time.Until would yield a hugely negative duration and fire the
		// close callback immediately.
		return nil
	}
	var timer *time.Timer
	timer = time.AfterFunc(time.Until(t), func() {
		q.muTimer.Lock()
		// Only act when this timer is still the armed deadline: a fired
		// callback racing a newer SetDeadline must not tear down an
		// association whose deadline was just pushed out.
		if q.deadlineTimer != timer {
			q.muTimer.Unlock()
			return
		}
		q.deadlineTimer = nil
		q.muTimer.Unlock()
		q.deadlineExceeded.Store(true)
		_ = q.Close()
	})
	q.deadlineTimer = timer
	return nil
}

func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	q.mu.Lock()
	incomingPackets := q.incomingPackets
	q.mu.Unlock()

	if incomingPackets == nil {
		if q.deadlineExceeded.Load() {
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
		return 0, netip.AddrPort{}, net.ErrClosed
	}

	for {
		packet, closed := incomingPackets.PopFrontBlock()
		if closed {
			if q.deadlineExceeded.Load() {
				err = os.ErrDeadlineExceeded
			} else {
				err = net.ErrClosed
			}
			return
		}
		if packet.FRAG_TOTAL <= 1 {
			if packet.ADDR == nil {
				packet.releaseData()
				continue
			}
			full := len(packet.DATA)
			n := copy(p, packet.DATA)
			addr := packet.ADDR.UDPAddrPort()
			packet.releaseData()
			if full > len(p) {
				// The datagram is consumed either way; delivering the truncated
				// bytes as success would corrupt it silently. Surface the drop.
				return n, addr, netproxy.DatagramDropped(io.ErrShortBuffer)
			}
			return n, addr, nil
		}
		nowNano := time.Now().UnixNano()
		q.maybeCleanupDeFraggers(nowNano)
		bucketAny, loaded := q.deFraggers.Load(packet.PKT_ID)
		if !loaded {
			// First fragment of this packet id: allocate the bucket only now.
			// Hitting LoadOrStore on every fragment would allocate a bucket
			// per datagram and throw it away on an existing key.
			bucketAny, _ = q.deFraggers.LoadOrStore(packet.PKT_ID, &deFraggerBucket{})
		}
		bucket := bucketAny.(*deFraggerBucket)
		if n, addr, assembled, assembledLen := bucket.feed(packet, p, nowNano); assembled {
			if bucket.len() == 0 {
				q.deFraggers.CompareAndDelete(packet.PKT_ID, bucket)
			}
			return n, addr, nil
		} else if assembledLen > len(p) {
			buffer := pool.GetFullCap(assembledLen)
			n, addr, assembled, _ := bucket.feed(nil, buffer, nowNano)
			if assembled {
				copyN := copy(p, buffer[:n])
				buffer.Put()
				if bucket.len() == 0 {
					q.deFraggers.CompareAndDelete(packet.PKT_ID, bucket)
				}
				// Caller buffer smaller than the reassembled datagram:
				// surface the drop instead of silently corrupting it.
				if n > len(p) {
					return copyN, addr, netproxy.DatagramDropped(io.ErrShortBuffer)
				}
				return copyN, addr, nil
			}
			buffer.Put()
		}
	}
}

// RegisterPacketReceiver uses the TUIC transport reader's existing packet
// demultiplexing loop instead of requiring one blocking ReadFrom goroutine for
// every logical UDP association.
func (q *quicStreamPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if handler == nil || q.closed.Load() {
		return nil, false
	}

	q.mu.Lock()
	incomingPackets := q.incomingPackets
	q.mu.Unlock()
	if incomingPackets == nil {
		return nil, false
	}

	unregister, ok := incomingPackets.registerPacketHandler(func(packet *Packet) bool {
		return q.deliverPacket(handler, packet)
	})
	return unregister, ok
}

func (q *quicStreamPacketConn) deliverPacket(handler netproxy.PacketReceiveHandler, packet *Packet) bool {
	if packet == nil {
		return false
	}
	if q.closed.Load() {
		// Callers rely on "a false return means deliverPacket already
		// released DATA"; honor that contract on this early exit too.
		packet.releaseData()
		return false
	}
	if packet.FRAG_TOTAL <= 1 {
		if packet.ADDR == nil {
			packet.releaseData()
			return true
		}
		received := netproxy.NewReceivedPacket(
			packet.DATA,
			packet.ADDR.UDPAddrPort(),
			nil,
			packet.releaseData,
		)
		if handler(received) {
			return true
		}
		received.Release()
		return false
	}

	nowNano := time.Now().UnixNano()
	q.maybeCleanupDeFraggers(nowNano)
	bucketAny, loaded := q.deFraggers.Load(packet.PKT_ID)
	if !loaded {
		bucketAny, _ = q.deFraggers.LoadOrStore(packet.PKT_ID, &deFraggerBucket{})
	}
	bucket := bucketAny.(*deFraggerBucket)
	_, _, assembled, assembledLen := bucket.feed(packet, nil, nowNano)
	if !assembled && assembledLen == 0 {
		return true
	}
	buffer := pool.GetFullCap(assembledLen)
	n, addr, assembled, _ := bucket.feed(nil, buffer, nowNano)
	if !assembled {
		buffer.Put()
		return true
	}
	if bucket.len() == 0 {
		// Mirror ReadFrom: only retire the bucket once every in-flight
		// defragger for this recycled 16-bit PKT_ID has completed. Deleting
		// while other candidates remain strands their received fragments.
		q.deFraggers.CompareAndDelete(packet.PKT_ID, bucket)
	}
	received := netproxy.NewReceivedPacket(buffer[:n], addr, nil, buffer.Put)
	if handler(received) {
		return true
	}
	received.Release()
	return false
}

func (q *quicStreamPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	if len(p) > 0xffff { // uint16 max
		return 0, &quic.DatagramTooLargeError{MaxDataLen: 0xffff}
	}
	if q.closed.Load() {
		return 0, net.ErrClosed
	}
	// Logical retirement of the owning client blocks writes immediately,
	// without waiting for the retired transport to surface an I/O error.
	select {
	case <-q.done:
		return 0, net.ErrClosed
	default:
	}
	q.writeMu.Lock()
	defer q.writeMu.Unlock()
	// Conn-private serialization scratch: grown to this association's peak
	// frame once, then reused without touching the shared pool. Nil-ed on
	// Close so a closed association does not pin its peak size.
	buf := q.writeScratch
	if buf == nil {
		buf = bytes.NewBuffer(nil)
		q.writeScratch = buf
	}
	buf.Reset()
	// Parse the destination before installing the shared-tunnel error
	// defer: a local address-parse failure belongs to this association
	// only and must never retire the shared client via deferQuicConnFn.
	// The parse and the address cache stay under writeMu.
	address, err := q.addressForAddr(addr)
	if err != nil {
		return 0, err
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	pktId := uint16(fastrand.Uint32())
	packet := NewPacket(q.connId, pktId, 1, 0, uint16(len(p)), address, p, Ver5)
	switch q.udpRelayMode {
	case common.QUIC:
		err = packet.WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		defer func() { _ = stream.Close() }()
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
	default: // native
		err = packet.WriteTo(buf)
		if err != nil {
			return
		}
		err = q.quicConn.SendDatagram(buf.Bytes())
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			firstHeaderLen := packet.BytesLen() - len(packet.DATA)
			fragSize := int(tooLarge.MaxDataLen) - firstHeaderLen
			if q.maxUdpRelayPacketSize > 0 && fragSize > q.maxUdpRelayPacketSize {
				fragSize = q.maxUdpRelayPacketSize
			}
			err = fragWriteNative(q.quicConn, packet, buf, fragSize)
		}
		if err != nil {
			return
		}
	}
	n = len(p)

	return
}

func (q *quicStreamPacketConn) addressForAddr(addr string) (*Address, error) {
	if cached, ok := q.addr.Load(addr); ok {
		return cached, nil
	}
	mdata, err := parseMetadata(addr)
	if err != nil {
		return nil, err
	}
	address := NewAddress(&mdata)
	q.addr.Store(addr, address)
	return address, nil
}

// WriteBatch implements netproxy.PacketBatchWriter as a sequential loop over
// the per-datagram path. The pinned quic-go exposes no batch-send surface
// (Connection.SendDatagram enqueues exactly one DATAGRAM frame, and the QUIC
// relay mode opens one uni-stream per datagram by protocol design), so there
// is nothing to fuse at this layer; the connection's own send queue already
// coalesces queued datagrams into QUIC packets. The loop keeps the interface
// contract: ordered items, datagram-count n, and partial success reported as
// n together with err.
func (q *quicStreamPacketConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	sent := 0
	for _, item := range items {
		if _, err := q.WriteTo(item.Data, item.Addr); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (q *quicStreamPacketConn) LocalAddr() net.Addr {
	return q.quicConn.LocalAddr()
}

func (conn *quicStreamPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return n, err
}

func (conn *quicStreamPacketConn) Write(b []byte) (n int, err error) {
	return conn.WriteTo(b, conn.target)
}

var (
	_ netproxy.PacketConn     = (*quicStreamPacketConn)(nil)
	_ netproxy.PacketReceiver = (*quicStreamPacketConn)(nil)
)

// TransportDone implements netproxy.TransportLifecycle.
// The returned channel is closed when the QUIC transport backing this
// UDP session is permanently dead. With a lifecycle-capable owner the
// channel is the client's done signal, so logical retirement (force-close)
// is reported immediately instead of after the transport grace period.
func (q *quicStreamPacketConn) TransportDone() <-chan struct{} {
	if q.done != nil {
		return q.done
	}
	if q.quicConn == nil {
		return make(chan struct{})
	}
	return q.quicConn.Context().Done()
}

// WriteDeadlineClosesSession reports that a fired write deadline ends the
// whole UDP session: SetDeadline tears down this association on expiry, so
// deadline callers must treat it as session-fatal, not a per-write failure.
func (q *quicStreamPacketConn) WriteDeadlineClosesSession() bool {
	return true
}
