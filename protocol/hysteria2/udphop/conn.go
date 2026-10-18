package udphop

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
	"golang.org/x/net/ipv4"
)

const (
	packetQueueSize = 1024
	udpBufferSize   = 2048 // QUIC packets are at most 1500 bytes long, so 2k should be more than enough

	// recvBatchSize bounds the number of packets drained per recvmmsg in
	// the batch recvLoop. It mirrors quic-go's batchSize on Linux so the
	// kernel side and the userspace queue stay in step.
	recvBatchSize = 8

	defaultHopInterval = 30 * time.Second
)

// oobWriteMsgUDP is the subset of *net.UDPConn (and the FakeNetPacketConn
// wrapper) that performs a single sendmsg with ancillary data. quic-go uses
// it to enable UDP GSO segmentation offload, which collapses many small QUIC
// datagrams into one syscall.
type oobWriteMsgUDP interface {
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n int, oobn int, err error)
}

// oobReadMsgUDP mirrors the read side; it is required only so the
// OOBCapablePacketConn type assertion in quic-go succeeds. The actual read
// path in quic-go's oobConn goes through the batchConn interface (ReadBatch),
// never through ReadMsgUDP.
type oobReadMsgUDP interface {
	ReadMsgUDP(b, oob []byte) (n int, oobn int, flags int, addr *net.UDPAddr, err error)
}

type udpHopPacketConn struct {
	Addr        net.Addr
	Addrs       []net.Addr
	HopInterval time.Duration
	dialFunc    contextDialFunc
	ctx         context.Context
	cancel      context.CancelFunc

	connMutex   sync.RWMutex
	prevConn    net.PacketConn
	currentAddr net.Addr
	currentConn net.PacketConn

	readBufferSize  int
	writeBufferSize int

	recvQueue chan *udpPacket
	closeChan chan struct{}
	closed    bool

	bufPool *hopBufPool
}

// hopBufPool recycles the udpBufferSize receive buffers. sync.Pool is cleared
// on every GC cycle, so under GC pressure every udphop datagram re-allocates
// its 2KB buffer, feeding the GC loop. A bounded channel pool survives GC.
type hopBufPool struct {
	ch       chan []byte
	newCount atomic.Int64 // number of pool misses (buffer allocations)
}

func newHopBufPool() *hopBufPool {
	p := &hopBufPool{ch: make(chan []byte, recvBatchSize*4)}
	for i := 0; i < recvBatchSize; i++ {
		p.ch <- make([]byte, udpBufferSize)
	}
	return p
}

func (p *hopBufPool) Get() []byte {
	select {
	case b := <-p.ch:
		return b
	default:
		p.newCount.Add(1)
		return make([]byte, udpBufferSize)
	}
}

func (p *hopBufPool) Put(b []byte) {
	select {
	case p.ch <- b:
	default:
		// pool full: drop the buffer, GC reclaims it
	}
}

type udpPacket struct {
	Buf  []byte
	N    int
	Addr net.Addr
	Err  error
}

type dialFunc = func(addr net.Addr) (net.PacketConn, error)
type contextDialFunc = func(ctx context.Context, addr net.Addr) (net.PacketConn, error)

// Compile-time guarantees that udpHopPacketConn satisfies the interfaces
// quic-go probes for. OOBCapablePacketConn enables GSO batch writes and ECN,
// while the (unexported) batchConn ReadBatch method makes quic-go route reads
// through our queue instead of pinning a recvmmsg reader to a single hop's fd.
var (
	_ quic.OOBCapablePacketConn = (*udpHopPacketConn)(nil)
	_ batchReader               = (*udpHopPacketConn)(nil)
)

// batchReader mirrors quic-go's unexported batchConn interface so we can assert
// it at compile time without reaching into the package's internals.
type batchReader interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

func NewUDPHopPacketConn(addr *UDPHopAddr, hopInterval time.Duration, dialFunc dialFunc) (net.PacketConn, error) {
	return NewUDPHopPacketConnContext(context.Background(), addr, hopInterval, func(_ context.Context, addr net.Addr) (net.PacketConn, error) {
		return dialFunc(addr)
	})
}

func NewUDPHopPacketConnContext(ctx context.Context, addr *UDPHopAddr, hopInterval time.Duration, dialFunc contextDialFunc) (net.PacketConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if hopInterval == 0 {
		hopInterval = defaultHopInterval
	} else if hopInterval < 5*time.Second {
		return nil, errors.New("hop interval must be at least 5 seconds")
	}
	addrs, err := addr.addrs()
	if err != nil {
		return nil, err
	}

	newAddrIndex := rand.Intn(len(addrs))
	curAddr := addrs[newAddrIndex]
	curConn, err := dialFunc(ctx, curAddr)
	if err != nil {
		return nil, err
	}
	if actualAddr := remoteAddrOfPacketConn(curConn); actualAddr != nil {
		if frozenAddrs, frozenCurrentAddr, ok := freezeAddrsForResolvedIP(addr, actualAddr); ok {
			addrs = frozenAddrs
			curAddr = frozenCurrentAddr
		} else {
			curAddr = actualAddr
		}
	}
	hopCtx, cancel := context.WithCancel(context.Background())
	hConn := &udpHopPacketConn{
		Addr:        addr,
		Addrs:       addrs,
		HopInterval: hopInterval,
		dialFunc:    dialFunc,
		ctx:         hopCtx,
		cancel:      cancel,
		prevConn:    nil,
		currentAddr: curAddr,
		currentConn: curConn,
		recvQueue:   make(chan *udpPacket, packetQueueSize),
		closeChan:   make(chan struct{}),
		bufPool:     newHopBufPool(),
	}
	go hConn.recvLoop(curConn)
	go hConn.hopLoop()
	if _, ok := curConn.(syscall.Conn); !ok {
		// Proxied underlay (no raw socket fd). Hide the OOB/batch surface
		// from QUIC's capability probes: udpHopPacketConn advertises
		// ReadMsgUDP/WriteMsgUDP/SyscallConn/ReadBatch, and a transport that
		// probes any of them would take the optimized path and fail on the
		// first syscall (a SyscallConn error aborts quic-go's dial). With
		// the surface hidden, the transport falls back to plain
		// ReadFrom/WriteTo, which the hop conn fully supports. The probe
		// mirrors recvLoop's own capability check.
		return &oobBlindPacketConn{PacketConn: hConn}, nil
	}
	return hConn, nil
}

// oobBlindPacketConn wraps a udpHopPacketConn whose underlay has no raw
// socket. Embedding only the net.PacketConn interface leaves the hop conn's
// OOB, batch, and SyscallConn methods unpromoted, so capability probes based
// on method presence (quic.OOBCapablePacketConn, syscall.Conn, ReadBatch,
// SetReadBuffer) all report "unsupported" and callers stay on the portable
// ReadFrom/WriteTo path. The write-deadline behavior marker is orthogonal to
// the OOB surface and stays promoted, so consumers keep reading the hop
// conn's forwarded answer.
type oobBlindPacketConn struct{ net.PacketConn }

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding to the wrapped hop conn.
func (c *oobBlindPacketConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.PacketConn)
}

func (u *udpHopPacketConn) recvLoop(conn net.PacketConn) {
	// Use recvmmsg batch reads when the underlying conn exposes a raw socket
	// fd (direct dial / FakeNetPacketConn2). Each recvmmsg amortises up to
	// recvBatchSize packets into one syscall. Proxied transports that do not
	// implement syscall.Conn fall back to per-packet ReadFrom.
	if _, ok := conn.(syscall.Conn); ok {
		pconn := ipv4.NewPacketConn(conn)
		if pconn != nil {
			u.recvLoopBatch(conn, pconn)
			return
		}
	}
	u.recvLoopSingle(conn)
}

// connStillLive reports whether conn is still owned by this hop conn as its
// current or previous connection, i.e. its receive loop has not been retired
// by a hop or by a full close.
func (u *udpHopPacketConn) connStillLive(conn net.PacketConn) bool {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.closed {
		return false
	}
	return conn == u.currentConn || conn == u.prevConn
}

// recvLoopBatch reads packets in batches via recvmmsg. It is the hot path for
// direct connections and is responsible for collapsing the recvfrom storm that
// otherwise dominates QUIC CPU under load.
func (u *udpHopPacketConn) recvLoopBatch(conn net.PacketConn, pconn *ipv4.PacketConn) {
	msgs := make([]ipv4.Message, recvBatchSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{u.bufPool.Get()}
	}
	defer func() {
		for i := range msgs {
			if buf := msgs[i].Buffers[0]; buf != nil {
				u.bufPool.Put(buf) // nolint:staticcheck
			}
		}
	}()
	for {
		// flags=0 makes recvmmsg block until the first datagram arrives, then
		// drain any immediately-available packets without blocking. This mirrors
		// the blocking semantics of the single-packet ReadFrom path.
		n, err := pconn.ReadBatch(msgs, 0)
		if err == nil && n == 0 {
			// Spurious empty batch: retry instead of silently deafening
			// the transport (same treatment as quic-go's batch reader).
			continue
		}
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if u.connStillLive(conn) {
				// Transient error on a conn we still own (e.g. Linux
				// surfaces ICMP errors as ECONNREFUSED on connected UDP
				// sockets): back off briefly and retry. Retired conns
				// report errors from their Close and must terminate.
				select {
				case <-u.closeChan:
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			u.handleRecvError(err)
			return
		}
		for i := 0; i < n; i++ {
			msg := &msgs[i]
			if msg.N <= 0 {
				continue
			}
			buf := msg.Buffers[0]
			select {
			case u.recvQueue <- &udpPacket{buf, msg.N, msg.Addr, nil}:
				// Ownership of buf transfers to the consumer; refill the slot
				// so the next ReadBatch has somewhere to land.
				msg.Buffers[0] = u.bufPool.Get()
			default:
				// Queue full: drop the packet and reuse the same buffer for
				// the next batch (mirrors the single-path backpressure policy).
			}
		}
	}
}

// recvLoopSingle is the fallback per-packet reader used when the underlying
// transport does not expose a raw socket fd (e.g. proxied UDP relays).
func (u *udpHopPacketConn) recvLoopSingle(conn net.PacketConn) {
	for {
		buf := u.bufPool.Get()
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			u.bufPool.Put(buf) // nolint:staticcheck
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if u.connStillLive(conn) {
				// Transient error on a conn we still own: retry instead of
				// terminating the only receive loop for this transport.
				select {
				case <-u.closeChan:
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			u.handleRecvError(err)
			return
		}
		select {
		case u.recvQueue <- &udpPacket{buf, n, addr, nil}:
			// Packet successfully queued
		default:
			// Queue is full, drop the packet
			u.bufPool.Put(buf) // nolint:staticcheck
		}
	}
}

// handleRecvError classifies a read error from the underlying connection.
// Timeout errors are forwarded to the queue so the consumer can react; all
// other errors (notably connection closed on hop) are swallowed because the
// recvLoop is expected to terminate whenever its conn is retired.
func (u *udpHopPacketConn) handleRecvError(err error) {
	if err == nil {
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		select {
		case u.recvQueue <- &udpPacket{nil, 0, nil, netErr}:
		case <-u.closeChan:
		default:
			// If the consumer is already backlogged, dropping the timeout
			// notification is better than pinning this goroutine forever.
		}
	}
}

func (u *udpHopPacketConn) hopLoop() {
	ticker := time.NewTicker(u.HopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			u.hop()
		case <-u.closeChan:
			return
		}
	}
}

func (u *udpHopPacketConn) hop() {
	u.connMutex.RLock()
	if u.closed || len(u.Addrs) == 0 {
		u.connMutex.RUnlock()
		return
	}
	addrs := append([]net.Addr(nil), u.Addrs...)
	dialFunc := u.dialFunc
	u.connMutex.RUnlock()

	newAddrIndex := rand.Intn(len(addrs))
	newAddr := addrs[newAddrIndex]
	newConn, err := dialFunc(u.context(), newAddr)
	if err != nil {
		// Could be temporary, just skip this hop
		return
	}
	if actualAddr := remoteAddrOfPacketConn(newConn); actualAddr != nil {
		newAddr = actualAddr
	}

	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.closed {
		_ = newConn.Close()
		return
	}
	// We need to keep receiving packets from the previous connection,
	// because otherwise there will be packet loss due to the time gap
	// between we hop to a new port and the server acknowledges this change.
	// So we do the following:
	// Close prevConn,
	// move currentConn to prevConn,
	// set newConn as currentConn,
	// start recvLoop on newConn.
	if u.prevConn != nil {
		_ = u.prevConn.Close() // recvLoop for this conn will exit
	}
	u.prevConn = u.currentConn
	u.currentAddr = newAddr
	u.currentConn = newConn
	// Set buffer sizes if previously set
	if u.readBufferSize > 0 {
		_ = trySetReadBuffer(u.currentConn, u.readBufferSize)
	}
	if u.writeBufferSize > 0 {
		_ = trySetWriteBuffer(u.currentConn, u.writeBufferSize)
	}
	go u.recvLoop(newConn)
}

func (u *udpHopPacketConn) context() context.Context {
	if u.ctx == nil {
		return context.Background()
	}
	return u.ctx
}

func (u *udpHopPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		select {
		case p := <-u.recvQueue:
			if p.Err != nil {
				return 0, nil, p.Err
			}
			// Preserve the actual packet source so callers see the concrete
			// hop address instead of the logical port-union descriptor.
			n := copy(b, p.Buf[:p.N])
			u.bufPool.Put(p.Buf) // nolint:staticcheck
			addr = p.Addr
			if addr == nil {
				u.connMutex.RLock()
				addr = u.currentAddr
				u.connMutex.RUnlock()
			}
			return n, addr, nil
		case <-u.closeChan:
			return 0, nil, net.ErrClosed
		}
	}
}

func (u *udpHopPacketConn) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.closed {
		return 0, net.ErrClosed
	}
	return u.currentConn.WriteTo(b, u.currentAddr)
}

// ReadMsgUDP implements quic.OOBCapablePacketConn. quic-go's oobConn never
// calls this for reads (it uses ReadBatch via the batchConn interface), but
// the method must exist so the type assertion in quic.wrapConn succeeds.
// It drains from the recvQueue to stay consistent with ReadFrom and avoid
// racing the recvLoop on the underlying socket.
func (u *udpHopPacketConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	_ = oob
	n, src, err := u.ReadFrom(b)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	udpAddr, _ := src.(*net.UDPAddr)
	if udpAddr == nil {
		udpAddr = &net.UDPAddr{}
	}
	return n, 0, 0, udpAddr, nil
}

// WriteMsgUDP implements quic.OOBCapablePacketConn. Forwarding to the
// underlying conn preserves the GSO/ECN ancillary data that quic-go attaches,
// so a single sendmsg can segment many QUIC datagrams. The destination is
// always the active hop address: the addr argument is the peer quic-go
// learned at handshake time and may lag behind an in-flight hop.
func (u *udpHopPacketConn) WriteMsgUDP(b, oob []byte, _ *net.UDPAddr) (n, oobn int, err error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.closed {
		return 0, 0, net.ErrClosed
	}
	wc, ok := u.currentConn.(oobWriteMsgUDP)
	if !ok {
		// Proxied transport without a raw socket: degrade to WriteTo so
		// the packet still reaches the server, just without GSO.
		n, err := u.currentConn.WriteTo(b, u.currentAddr)
		return n, 0, err
	}
	addr, _ := u.currentAddr.(*net.UDPAddr)
	if addr == nil {
		n, err := u.currentConn.WriteTo(b, u.currentAddr)
		return n, 0, err
	}
	return wc.WriteMsgUDP(b, oob, addr)
}

// ReadBatch implements quic-go's (unexported) batchConn interface via Go's
// structural typing. When this method is present, quic-go's oobConn uses it
// instead of ipv4.NewPacketConn(c).ReadBatch(), which is critical for port
// hopping: a kernel-bound batch reader would pin itself to the fd of the
// first hop conn and silently stop receiving after every hop. By draining the
// shared recvQueue we stay correct across hops while still handing quic-go a
// batch of packets per wakeup.
func (u *udpHopPacketConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	_ = flags
	if len(ms) == 0 {
		return 0, nil
	}
	select {
	case p := <-u.recvQueue:
		if p.Err != nil {
			return 0, p.Err
		}
		count := u.fillBatchMessage(&ms[0], p)
		// Drain any further queued packets without blocking so quic-go can
		// process a burst in a single receive-loop iteration.
		for count < len(ms) {
			select {
			case p := <-u.recvQueue:
				if p.Err != nil {
					return count, p.Err
				}
				count += u.fillBatchMessage(&ms[count], p)
			default:
				return count, nil
			}
		}
		return count, nil
	case <-u.closeChan:
		return 0, net.ErrClosed
	}
}

// fillBatchMessage copies one queued packet into an ipv4.Message slot and
// recycles its pool buffer. Returns 1 on success.
func (u *udpHopPacketConn) fillBatchMessage(msg *ipv4.Message, p *udpPacket) int {
	if len(msg.Buffers) == 0 || len(msg.Buffers[0]) == 0 {
		// Caller did not provide a usable buffer; drop the packet but
		// still recycle its backing buffer.
		u.bufPool.Put(p.Buf) // nolint:staticcheck
		return 0
	}
	n := copy(msg.Buffers[0], p.Buf[:p.N])
	u.bufPool.Put(p.Buf) // nolint:staticcheck
	msg.N = n
	msg.NN = 0
	msg.Flags = 0
	addr := p.Addr
	if addr == nil {
		u.connMutex.RLock()
		addr = u.currentAddr
		u.connMutex.RUnlock()
	}
	msg.Addr = addr
	return 1
}

func (u *udpHopPacketConn) Close() error {
	if u.cancel != nil {
		u.cancel()
	}
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	if u.closed {
		return nil
	}
	// Close prevConn and currentConn
	// Close closeChan to unblock ReadFrom & hopLoop
	// Set closed flag to true to prevent double close
	if u.prevConn != nil {
		_ = u.prevConn.Close()
	}
	err := u.currentConn.Close()
	close(u.closeChan)
	u.closed = true
	u.Addrs = nil // For GC
	u.currentAddr = nil
	return err
}

func (u *udpHopPacketConn) RemoteAddr() net.Addr {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	return u.currentAddr
}

func (u *udpHopPacketConn) LocalAddr() net.Addr {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	return u.currentConn.LocalAddr()
}

func (u *udpHopPacketConn) SetDeadline(t time.Time) error {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.prevConn != nil {
		_ = u.prevConn.SetDeadline(t)
	}
	return u.currentConn.SetDeadline(t)
}

func (u *udpHopPacketConn) SetReadDeadline(t time.Time) error {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.prevConn != nil {
		_ = u.prevConn.SetReadDeadline(t)
	}
	return u.currentConn.SetReadDeadline(t)
}

func (u *udpHopPacketConn) SetWriteDeadline(t time.Time) error {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if u.prevConn != nil {
		_ = u.prevConn.SetWriteDeadline(t)
	}
	return u.currentConn.SetWriteDeadline(t)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the underlay conns: SetWriteDeadline arms
// them all, so the declaration is true if any armed underlay declares a
// session-closing deadline.
func (u *udpHopPacketConn) WriteDeadlineClosesSession() bool {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	if netproxy.WriteDeadlineClosesSession(u.currentConn) {
		return true
	}
	return u.prevConn != nil && netproxy.WriteDeadlineClosesSession(u.prevConn)
}

// UDP-specific methods below

func (u *udpHopPacketConn) SetReadBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.readBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetReadBuffer(u.prevConn, bytes)
	}
	return trySetReadBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SetWriteBuffer(bytes int) error {
	u.connMutex.Lock()
	defer u.connMutex.Unlock()
	u.writeBufferSize = bytes
	if u.prevConn != nil {
		_ = trySetWriteBuffer(u.prevConn, bytes)
	}
	return trySetWriteBuffer(u.currentConn, bytes)
}

func (u *udpHopPacketConn) SyscallConn() (syscall.RawConn, error) {
	u.connMutex.RLock()
	defer u.connMutex.RUnlock()
	sc, ok := u.currentConn.(syscall.Conn)
	if !ok {
		return nil, errors.New("not supported")
	}
	return sc.SyscallConn()
}

func trySetReadBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetReadBuffer(bytes int) error
	})
	if ok {
		return sc.SetReadBuffer(bytes)
	}
	return nil
}

func trySetWriteBuffer(pc net.PacketConn, bytes int) error {
	sc, ok := pc.(interface {
		SetWriteBuffer(bytes int) error
	})
	if ok {
		return sc.SetWriteBuffer(bytes)
	}
	return nil
}

func remoteAddrOfPacketConn(conn net.PacketConn) net.Addr {
	type remoteAddrConn interface {
		RemoteAddr() net.Addr
	}
	if c, ok := conn.(remoteAddrConn); ok {
		if addr := c.RemoteAddr(); addr != nil {
			return addr
		}
	}
	return nil
}

func freezeAddrsForResolvedIP(addr *UDPHopAddr, actualAddr net.Addr) ([]net.Addr, net.Addr, bool) {
	if addr == nil || len(addr.Ports) == 0 {
		return nil, nil, false
	}
	udpAddr, ok := actualAddr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.IP == nil {
		return nil, nil, false
	}
	ip := append(net.IP(nil), udpAddr.IP...)
	addrs := make([]net.Addr, 0, len(addr.Ports))
	for _, port := range addr.Ports {
		addrs = append(addrs, &net.UDPAddr{
			IP:   ip,
			Port: int(port),
			Zone: udpAddr.Zone,
		})
	}
	currentAddr := &net.UDPAddr{
		IP:   append(net.IP(nil), udpAddr.IP...),
		Port: udpAddr.Port,
		Zone: udpAddr.Zone,
	}
	return addrs, currentAddr, true
}
