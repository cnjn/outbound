package tuic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
	"github.com/sirupsen/logrus"
)

const Ver5 = 0x5

// uniStreamReadIdleTimeout bounds how long a server-opened uni stream may
// stall before the relay goroutine gives up. Each uni stream carries exactly
// one packet command, so this only fires on a wedged or hostile peer; without
// it such streams would pin uni-stream semaphore slots forever.
const uniStreamReadIdleTimeout = 30 * time.Second

type ClientOption struct {
	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          common.UdpRelayMode
	MaxUdpRelayPacketSize int
	CongestionController  string
	ReduceRtt             bool
	// CWND carries the brutal controller's target bandwidth (bytes per
	// second); ignored by other controllers.
	CWND uint64
}

type clientImpl struct {
	*ClientOption
	udp bool

	underConn net.PacketConn
	quicConn  quic.Connection
	connMutex sync.Mutex

	// closed is read without connMutex on the per-dial fast path and set
	// under it in forceClose; atomicity keeps those entry checks race-free.
	closed atomic.Bool

	// done is the client-owned retirement signal: forceClose closes it
	// exactly once, immediately, while the QUIC transport itself is still
	// kept for its close grace period. Associations capture it so logical
	// retirement unblocks writes/readers without waiting for transport I/O
	// to fail. Built via newClientImpl; a nil done (bare struct literals in
	// tests) degrades to the old transport-context-only behavior.
	done chan struct{}

	udpIncomingPacketsMap sync.Map

	streamSem chan struct{}

	// malformedDatagrams counts inbound datagrams the shared tunnel dropped
	// because the peer's bytes did not parse. A single bad datagram must not
	// retire the tunnel (every multiplexed stream rides it), but an unbounded
	// stream of them means the peer is broken or hostile, so
	// malformedDatagramsWindow escalates to forceClose at
	// malformedDatagramEscalationThreshold. Both are observable through
	// MalformedDatagramStats.
	malformedDatagrams       atomic.Uint64
	malformedDatagramsWindow atomic.Uint64

	// lastMalformedLogNano rate-limits the drop warning to one line per
	// malformedDatagramLogInterval so a flood cannot turn the fix into a
	// log-spam amplifier.
	lastMalformedLogNano atomic.Int64

	onClose func()
}

// ClientStatSnapshot is the observability surface for inbound UDP loss on a
// shared TUIC tunnel.
type ClientStatSnapshot struct {
	// MalformedDatagrams is the lifetime count of dropped unparseable
	// inbound datagrams.
	MalformedDatagrams uint64
	// MalformedDatagramsWindow is the count since the last escalation-window
	// reset; reaching malformedDatagramEscalationThreshold retires the tunnel.
	MalformedDatagramsWindow uint64
}

// MalformedDatagramStats reports the malformed-datagram drop counters.
func (t *clientImpl) MalformedDatagramStats() ClientStatSnapshot {
	return ClientStatSnapshot{
		MalformedDatagrams:       t.malformedDatagrams.Load(),
		MalformedDatagramsWindow: t.malformedDatagramsWindow.Load(),
	}
}

// newClientImpl builds a TUIC client around option with its lifecycle state
// initialized: udp selects the UDP relay setup and streamSemSize bounds the
// concurrent uni-stream slots (0 = unbounded). The returned client owns a
// done channel that forceClose closes exactly once.
func newClientImpl(option *ClientOption, udp bool, streamSemSize int) *clientImpl {
	t := &clientImpl{
		ClientOption: option,
		udp:          udp,
		done:         make(chan struct{}),
	}
	if streamSemSize > 0 {
		t.streamSem = make(chan struct{}, streamSemSize)
	}
	return t
}

func (t *clientImpl) acquireUniStreamSlot(ctx context.Context) error {
	if t.streamSem == nil {
		return nil
	}
	select {
	case t.streamSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *clientImpl) releaseUniStreamSlot() {
	if t.streamSem == nil {
		return
	}
	<-t.streamSem
}

func (t *clientImpl) getQuicConn(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	return t.getQuicConnLocked(ctx, dialer, dialFn)
}

func (t *clientImpl) getQuicConnLocked(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (quic.Connection, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	if t.quicConn != nil {
		// Cached branch: reusing the tunnel never consults ctx, so a
		// canceled caller must be rejected here instead of being handed a
		// session on an already-dead request.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return t.quicConn, nil
	}
	transport, addr, err := dialFn(ctx, dialer)
	if err != nil {
		return nil, err
	}
	var quicConn quic.Connection
	if t.ReduceRtt {
		quicConn, err = transport.DialEarly(ctx, addr, t.TlsConfig, t.QuicConfig)
	} else {
		quicConn, err = transport.Dial(ctx, addr, t.TlsConfig, t.QuicConfig)
	}
	if err != nil {
		_ = transport.Close()
		_ = transport.Conn.Close()
		return nil, err
	}

	common.SetCongestionController(quicConn, t.CongestionController, t.CWND)

	if err = t.sendAuthentication(quicConn); err != nil {
		_ = quicConn.CloseWithError(ProtocolError, err.Error())
		_ = transport.Close()
		_ = transport.Conn.Close()
		return nil, err
	}

	if t.udp && t.UdpRelayMode == common.QUIC {
		go func() {
			_ = t.handleUniStream(quicConn)
		}()
	}
	go func() {
		_ = t.handleMessage(quicConn) // always handleMessage because tuicV5 using datagram to send the Heartbeat
	}()
	t.underConn = transport.Conn

	t.quicConn = quicConn
	return quicConn, nil
}

func (t *clientImpl) sendAuthentication(quicConn quic.Connection) (err error) {
	// The caller holds connMutex until authentication succeeds and owns cleanup
	// on failure. Calling deferQuicConn here would re-enter forceClose and
	// deadlock on that mutex.
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	token, err := GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	err = NewAuthenticate(t.Uuid, token, Ver5).WriteTo(buf)
	if err != nil {
		return err
	}
	_, err = buf.WriteTo(stream)
	if err != nil {
		return err
	}
	// The Authenticate command is a one-shot message, and a v5 server stops
	// reading the stream as soon as it has consumed it (sing-quic's service
	// does `defer stream.CancelRead(0)`): a STOP_SENDING that reaches this side
	// before the FIN makes quic-go refuse the Close ("close called for canceled
	// stream N") and skip the FIN. That is not an authentication result — the
	// command was written in full, and a server that rejects the credentials
	// closes the connection with an auth error — so the FIN is best effort.
	// The reference client discards this Close for the same reason; propagating
	// it turned a legal peer ordering into a sporadic dial failure.
	_ = stream.Close()
	return nil
}

func (t *clientImpl) handleUniStream(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		var stream quic.ReceiveStream
		stream, err = quicConn.AcceptUniStream(quicConn.Context())
		if err != nil {
			return err
		}
		if err = t.acquireUniStreamSlot(quicConn.Context()); err != nil {
			stream.CancelRead(0)
			return err
		}
		go func(stream quic.ReceiveStream) {
			defer t.releaseUniStreamSlot()
			var err error
			var assocId uint16
			defer func() {
				t.deferQuicConn(quicConn, err)
				if err != nil && assocId != 0 {
					if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
						_ = val.(*Packets).Close()
					}
				}
				stream.CancelRead(0)
			}()
			// Each uni stream carries exactly one packet command; parse it
			// incrementally instead of wrapping the stream in a fresh
			// bufio.Reader and routing every field through binary.Read.
			// A non-Packet command is a spec violation: readPacketFromStream
			// errors and deferQuicConn forceCloses the tunnel.
			_ = stream.SetReadDeadline(time.Now().Add(uniStreamReadIdleTimeout))
			var packet *Packet
			packet, err = readPacketFromStream(stream)
			if err != nil {
				var nErr net.Error
				if errors.As(err, &nErr) && nErr.Timeout() {
					// The stream stalled past the idle timeout. Reclaim the
					// slot without tearing down the tunnel: treat it like a
					// benign dropped stream (CancelRead runs in the defer),
					// not like a protocol violation.
					err = nil
				}
				return
			}
			if t.udp && t.UdpRelayMode == common.QUIC {
				assocId = packet.ASSOC_ID
				if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
					packets := val.(*Packets)
					packets.PushBack(packet)
					return
				}
			}
			packet.releaseData()
		}(stream)
	}
}

func (t *clientImpl) handleMessage(quicConn quic.Connection) (err error) {
	defer func() {
		t.deferQuicConn(quicConn, err)
	}()
	for {
		// Use context.Background() instead of fixed timeout
		// QUIC's keepalive mechanism will handle connection health
		message, err := quicConn.ReceiveDatagram(context.Background())
		if err != nil {
			if outbounderrors.IsTemporaryError(err) {
				// Some temporary errors (notably stateless reset) are
				// delivered after the datagram queue is already closed, so
				// Receive returns immediately from then on. Exit via the
				// connection context instead of spinning in a tight loop.
				if ctxErr := quicConn.Context().Err(); ctxErr != nil {
					return ctxErr
				}
				continue
			}
			return err
		}
		// processDatagram copies everything it keeps (packet DATA is
		// copied by readPacketFromMessage), so the datagram buffer can be
		// returned to the pool immediately after processing.
		t.processDatagram(quicConn, message)
		quicConn.ReleaseDatagram(message)
	}
}

func (t *clientImpl) processDatagram(quicConn quic.Connection, message []byte) {
	var err error
	var assocId uint16
	defer func() {
		t.deferQuicConn(quicConn, err)
		if err != nil && assocId != 0 {
			if val, loaded := t.udpIncomingPacketsMap.LoadAndDelete(assocId); loaded {
				_ = val.(*Packets).Close()
			}
		}
	}()
	if len(message) < 2 {
		// Too short to even carry a command type: peer data, not a local
		// failure. Count it so the drop is observable, and still hand the
		// tunnel over so a flood of these escalates - dropping them forever
		// would be exactly the silent degradation this classification exists
		// to avoid. There is no association to name, so the deferred cleanup
		// has nothing to release.
		var ctx context.Context
		if quicConn != nil {
			ctx = quicConn.Context()
		}
		t.noteMalformedDatagram(ctx, quicConn, "datagram shorter than a command header")
		return
	}
	switch CommandType(message[1]) {
	case PacketType:
		// Learn the association before parsing: if the malformed datagram
		// flood escalates, the deferred cleanup must still retire the queue
		// the hostile peer is aiming at. ASSOC_ID sits at a fixed offset
		// (VER(1)+TYPE(1)+ASSOC_ID(2)); a datagram too short to carry it is
		// malformed anyway, so the deferred cleanup simply has no association
		// to release.
		if len(message) >= 4 {
			assocId = binary.BigEndian.Uint16(message[2:4])
		}
		packet, parseErr := readPacketFromMessage(message)
		if parseErr != nil {
			if errors.Is(parseErr, errMalformedDatagram) {
				// One peer's garbage packet does not break the connection:
				// every multiplexed TCP stream and every other UDP
				// association rides this same QUIC connection. Drop it,
				// count it, and let the escalation threshold decide when the
				// peer has proven itself broken.
				t.noteMalformedDatagram(quicConn.Context(), quicConn, parseErr.Error())
				return
			}
			err = parseErr
			return
		}
		if t.udp && t.UdpRelayMode == common.NATIVE {
			assocId = packet.ASSOC_ID
			if val, ok := t.udpIncomingPacketsMap.Load(assocId); ok {
				val.(*Packets).PushBack(packet)
				return
			}
		}
		// Dropped (no matching association / not datagram mode): return the
		// pool-backed DATA so the buffer is not leaked.
		packet.releaseData()
	case HeartbeatType:
		// Fixed 2-byte command (VER+TYPE); no further bytes to consume.
	}
}

// malformedDatagramEscalationThreshold is the number of unparseable inbound
// datagrams that turns a per-packet drop into a tunnel teardown. It is set
// high enough that ordinary corruption (a truncated read, a single stray
// datagram) never retires a healthy tunnel, and low enough that a peer which
// cannot produce one valid datagram is retired quickly instead of parking the
// connection in a permanent drop loop.
const malformedDatagramEscalationThreshold = 4096

// malformedDatagramLogInterval rate-limits the drop warning: at datagram line
// rate an unthrottled log would cost more than the datagrams do.
const malformedDatagramLogInterval = 5 * time.Second

// noteMalformedDatagram records a dropped unparseable datagram: it bumps both
// counters, emits a rate-limited warning, and escalates to forceClose once the
// window reaches malformedDatagramEscalationThreshold. ctx is used for the
// log's cancellation context and may be nil (background).
func (t *clientImpl) noteMalformedDatagram(ctx context.Context, quicConn quic.Connection, reason string) {
	total := t.malformedDatagrams.Add(1)
	window := t.malformedDatagramsWindow.Add(1)

	now := time.Now().UnixNano()
	if last := t.lastMalformedLogNano.Load(); last == 0 ||
		now-last >= malformedDatagramLogInterval.Nanoseconds() {
		if t.lastMalformedLogNano.CompareAndSwap(last, now) {
			fields := logrus.Fields{
				"reason":             reason,
				"dropped_total":      total,
				"dropped_in_window":  window,
				"escalation_at":      malformedDatagramEscalationThreshold,
				"udp_relay_mode":     t.UdpRelayMode,
				"tunnel_retirement":  "on threshold",
				"next_log_in_second": int64(malformedDatagramLogInterval / time.Second),
			}
			if ctx != nil {
				logrus.WithContext(ctx).WithFields(fields).
					Warn("tuic: dropped malformed inbound datagram")
			} else {
				logrus.WithFields(fields).
					Warn("tuic: dropped malformed inbound datagram")
			}
		}
	}

	if window >= malformedDatagramEscalationThreshold {
		// Reset the window so the escalation log is emitted once per window
		// rather than on every datagram past the threshold.
		t.malformedDatagramsWindow.Store(0)
		logrus.WithFields(logrus.Fields{
			"threshold":     malformedDatagramEscalationThreshold,
			"dropped_total": total,
			"reason":        reason,
		}).Error("tuic: peer exceeded the malformed-datagram threshold; retiring the shared tunnel")
		if quicConn != nil {
			t.forceClose(quicConn, fmt.Errorf("%w: %d malformed inbound datagrams (last: %s)",
				errMalformedDatagram, malformedDatagramEscalationThreshold, reason))
		}
	}
}

func (t *clientImpl) deferQuicConn(quicConn quic.Connection, err error) {
	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return
	}
	// A closed QUIC connection can surface as a temporary net.Error
	// (stateless reset) or context.Canceled. Those must still retire the
	// shared tunnel; otherwise getQuicConn keeps handing out the dead conn.
	if quicConn != nil && quicConn.Context().Err() != nil {
		t.forceClose(quicConn, err)
		return
	}
	// Only close connection on non-temporary errors. Stream exhaustion is a
	// per-attempt condition: quic-go reports it as *quic.StreamLimitReachedError
	// ("too many open streams"), which IsStreamExhausted matches, so the shared
	// tunnel survives and callers fall back instead of tearing it down.
	if err != nil &&
		!outbounderrors.IsTemporaryError(err) &&
		!outbounderrors.IsStreamExhausted(err) {
		t.forceClose(quicConn, err)
	}
}

// forceCloseGracePeriod bounds how long the QUIC transport and underlay
// stay alive after the client is logically retired. A package var so tests
// can shrink the window.
var forceCloseGracePeriod = 10 * time.Second

func (t *clientImpl) forceClose(quicConn quic.Connection, err error) {
	t.connMutex.Lock()
	if t.closed.Load() {
		t.connMutex.Unlock()
		return
	}
	t.closed.Store(true)
	// Publish retirement exactly once, immediately: TransportDone consumers
	// and WriteTo see it while the transport close below still waits out
	// its grace period.
	if t.done != nil {
		close(t.done)
	}
	if t.onClose != nil {
		go t.onClose()
		t.onClose = nil
	}
	t.connMutex.Unlock()
	// Tear the association queues down immediately: polling ReadFrom
	// callers must not stay blocked in PopFrontBlock for the whole grace
	// period after the transport is already dead. This runs outside
	// connMutex and drains/releases each queue via Packets.Close.
	t.udpIncomingPacketsMap.Range(func(key, value any) bool {
		_ = value.(*Packets).Close()
		t.udpIncomingPacketsMap.Delete(key)
		return true
	})
	// Give the transport its grace period. The timer only captures and
	// detaches the shared resources under connMutex; the actual
	// CloseWithError / underConn.Close calls do real I/O and therefore run
	// outside the lock.
	time.AfterFunc(forceCloseGracePeriod, func() {
		t.connMutex.Lock()
		qc := quicConn
		if qc == nil {
			qc = t.quicConn
		}
		t.quicConn = nil
		underConn := t.underConn
		t.underConn = nil
		t.connMutex.Unlock()
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		if qc != nil {
			_ = qc.CloseWithError(ProtocolError, errStr)
		}
		if underConn != nil {
			_ = underConn.Close()
		}
	})
}

func (t *clientImpl) Close() error {
	t.forceClose(nil, common.ErrClientClosed)
	return nil
}

func tuicContextCause(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return context.Canceled
}

func checkImmediateTUICConnectFailure(ctx context.Context, quicConn quic.Connection, stream quic.Stream) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-quicConn.Context().Done():
		return tuicContextCause(quicConn.Context())
	case <-stream.Context().Done():
		return tuicContextCause(stream.Context())
	default:
		return nil
	}
}

func (t *clientImpl) DialContextWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (netproxy.Conn, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConn(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	stream, err := func() (stream net.Conn, err error) {
		defer func() {
			t.deferQuicConn(quicConn, err)
		}()
		connect := NewConnect(NewAddress(metadata), Ver5)
		buf := pool.Get(connect.BytesLen())
		defer buf.Put()
		n := connect.WriteToBytes(buf)
		if n != len(buf) {
			return nil, fmt.Errorf("n != len(buf)")
		}
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
		if _, err = quicStream.Write(buf); err != nil {
			_ = quicStream.Close()
			return nil, err
		}
		if err = checkImmediateTUICConnectFailure(ctx, quicConn, quicStream); err != nil {
			_ = quicStream.Close()
			return nil, err
		}
		stream = common.NewSafeStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			nil,
		)
		return stream, err
	}()
	if err != nil {
		return nil, err
	}

	return stream, nil
}

func (t *clientImpl) ListenPacketWithDialer(ctx context.Context, metadata *protocol.Metadata, dialer netproxy.Dialer, dialFn common.DialFunc) (*quicStreamPacketConn, error) {
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.closed.Load() {
		return nil, common.ErrClientClosed
	}
	quicConn, err := t.getQuicConnLocked(ctx, dialer, dialFn)
	if err != nil {
		return nil, err
	}
	// Post-lock re-check before the association is published: a caller
	// canceled while the cache lookup ran must not own an association slot.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var connId uint16
	incomingPackets := NewPackets()
	for {
		connId = uint16(fastrand.Intn(0xFFFF))
		_, loaded := t.udpIncomingPacketsMap.LoadOrStore(connId, incomingPackets)
		if !loaded {
			break
		}
	}
	pc := &quicStreamPacketConn{
		connId:                connId,
		quicConn:              quicConn,
		incomingPackets:       incomingPackets,
		udpRelayMode:          t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize,
		deferQuicConnFn:       t.deferQuicConn,
		done:                  t.done,
		closeDeferFn: func() {
			t.udpIncomingPacketsMap.CompareAndDelete(connId, incomingPackets)
		},
	}
	return pc, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.onClose = f
}
