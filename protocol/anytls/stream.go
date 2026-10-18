package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

var (
	_ netproxy.Conn               = (*stream)(nil)
	_ netproxy.PacketConn         = (*packetStream)(nil)
	_ netproxy.TransportLifecycle = (*packetStream)(nil)
)

type stream struct {
	*session

	inbound   chan pool.PB
	readBuf   []byte
	readBufPB pool.PB // pool buffer backing readBuf; nil when readBuf is empty or not pool-backed

	writeMutex sync.Mutex
	readMutex  sync.Mutex
	enqueueMu  sync.RWMutex

	closed      atomic.Bool
	writeClosed atomic.Bool
	closeCh     chan struct{}
	closeMu     sync.Mutex
	closeErr    error

	readDeadline    atomic.Int64
	writeDeadline   atomic.Int64
	deadlineChanged chan struct{}

	id uint32
}

func newStream(session *session, id uint32) *stream {
	return &stream{
		session:         session,
		inbound:         make(chan pool.PB, 16),
		closeCh:         make(chan struct{}),
		deadlineChanged: make(chan struct{}, 1),
		id:              id,
	}
}

// enqueue takes ownership of chunk, including when it returns an error.
func (c *stream) enqueue(chunk pool.PB) error {
	c.enqueueMu.RLock()
	defer c.enqueueMu.RUnlock()

	if c.closed.Load() {
		pool.Put(chunk)
		return io.ErrClosedPipe
	}
	select {
	case <-c.session.done:
		pool.Put(chunk)
		return net.ErrClosed
	default:
	}
	select {
	case c.inbound <- chunk:
		return nil
	case <-c.closeCh:
		pool.Put(chunk)
		return io.ErrClosedPipe
	case <-c.session.done:
		pool.Put(chunk)
		return net.ErrClosed
	}
}

func (c *stream) Write(b []byte) (n int, err error) {
	if c.closed.Load() || c.writeClosed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.closed.Load() || c.writeClosed.Load() {
		return 0, net.ErrClosed
	}

	return writeDataFrames(c.session, c.id, b, unixNanoToTime(c.writeDeadline.Load()))
}

func (c *stream) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	return c.readLocked(b)
}

func (c *stream) readLocked(b []byte) (n int, err error) {
	for len(c.readBuf) == 0 {
		// Return the previous pool buffer before getting a new chunk.
		if c.readBufPB != nil {
			pool.Put(c.readBufPB)
			c.readBufPB = nil
		}
		chunk, err := c.nextChunkLocked()
		if err != nil {
			return 0, err
		}
		if len(chunk) == 0 {
			pool.Put(chunk)
			continue
		}
		c.readBuf = chunk
		c.readBufPB = chunk
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	if len(c.readBuf) == 0 && c.readBufPB != nil {
		pool.Put(c.readBufPB)
		c.readBufPB = nil
	}
	return n, nil
}

func (c *stream) nextChunkLocked() (pool.PB, error) {
	for {
		select {
		case chunk := <-c.inbound:
			return chunk, nil
		default:
		}
		if c.closed.Load() {
			// A close may race an enqueue admitted before the close signal.
			c.enqueueMu.Lock()
			c.enqueueMu.Unlock()
			select {
			case chunk := <-c.inbound:
				return chunk, nil
			default:
				return nil, c.closedError()
			}
		}

		deadline := unixNanoToTime(c.readDeadline.Load())
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(remaining)
			select {
			case chunk := <-c.inbound:
				stopTimer(timer)
				return chunk, nil
			case <-c.closeCh:
				stopTimer(timer)
				continue
			case <-c.deadlineChanged:
				stopTimer(timer)
				continue
			case <-timer.C:
				return nil, os.ErrDeadlineExceeded
			}
		}

		select {
		case chunk := <-c.inbound:
			return chunk, nil
		case <-c.closeCh:
			continue
		case <-c.deadlineChanged:
			continue
		}
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (c *stream) remoteClose() error {
	c.markClosed(io.EOF)
	c.removeStream(c.id)
	return nil
}

func (c *stream) Close() error {
	return c.closeLocal(true, net.ErrClosed)
}

func (c *stream) CloseWrite() error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	if !c.writeClosed.CompareAndSwap(false, true) {
		return nil
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.session.closed.Load() {
		return net.ErrClosed
	}
	frame := newFrame(cmdFIN, c.id)
	_, err := writeFrame(c.session, frame)
	return err
}

// markClosed stops new I/O but leaves received buffers owned by the reader.
// Only local Close discards unread data; remote and session closes allow draining.
func (c *stream) markClosed(err error) bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if !c.closed.CompareAndSwap(false, true) {
		return false
	}
	c.closeErr = err
	close(c.closeCh)
	return true
}

func (c *stream) closeLocal(sendFIN bool, err error) error {
	firstClose := c.markClosed(err)

	// Closing closeCh releases blocked enqueues. Wait for every admitted
	// enqueue before taking readMutex, which readers hold while draining.
	c.enqueueMu.Lock()
	c.enqueueMu.Unlock()
	c.readMutex.Lock()
	if c.readBufPB != nil {
		pool.Put(c.readBufPB)
		c.readBufPB = nil
		c.readBuf = nil
	}

drainLoop:
	for {
		select {
		case chunk := <-c.inbound:
			pool.Put(chunk)
		default:
			break drainLoop
		}
	}
	c.readMutex.Unlock()

	// A locally generated FIN must follow every write that started before Close.
	// Session and remote closes skip this lock so a blocked transport write cannot
	// prevent the underlying connection from being closed.
	if sendFIN && firstClose {
		c.writeMutex.Lock()
		if c.writeClosed.CompareAndSwap(false, true) && !c.session.closed.Load() {
			frame := newFrame(cmdFIN, c.id)
			_, _ = writeFrame(c.session, frame)
		}
		c.writeMutex.Unlock()
	}
	c.removeStream(c.id)
	return nil
}

func (c *stream) closedError() error {
	if !c.closed.Load() {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return net.ErrClosed
}

func (c *stream) LocalAddr() net.Addr {
	return c.session.conn.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.session.conn.RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *stream) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(timeToUnixNano(t))
	select {
	case c.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(timeToUnixNano(t))
	return nil
}

type packetStream struct {
	*stream

	addr string
	// addrPort is addr parsed once at construction: the per-datagram read
	// path used to re-run netip.ParseAddrPort on every ReadFrom for an
	// address that never changes.
	addrPort     netip.AddrPort
	udpWriteAddr atomic.Bool
}

func (ps *packetStream) TransportDone() <-chan struct{} {
	return ps.closeCh
}

func (ps *packetStream) Read(p []byte) (n int, err error) {
	n, _, err = ps.ReadFrom(p)
	return n, err
}

func (ps *packetStream) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	ps.readMutex.Lock()
	defer ps.readMutex.Unlock()

	addr := ps.addrPort
	var length uint16
	var lengthBuf [2]byte
	if err := ps.readFullLocked(lengthBuf[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length = binary.BigEndian.Uint16(lengthBuf[:])
	if len(p) < int(length) {
		if err := ps.drainLocked(int(length)); err != nil {
			return 0, addr, err
		}
		return 0, addr, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	if err := ps.readFullLocked(p[:length]); err != nil {
		return 0, addr, err
	}
	return int(length), addr, nil
}

func (ps *packetStream) readFullLocked(p []byte) error {
	for len(p) > 0 {
		n, err := ps.stream.readLocked(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (ps *packetStream) drainLocked(n int) error {
	buf := pool.Get(min(n, 2048))
	defer pool.Put(buf)
	for n > 0 {
		chunk := buf
		if len(chunk) > n {
			chunk = chunk[:n]
		}
		if err := ps.readFullLocked(chunk); err != nil {
			return err
		}
		n -= len(chunk)
	}
	return nil
}

func (ps *packetStream) Write(p []byte) (n int, err error) {
	return ps.WriteTo(p, ps.addr)
}

func (ps *packetStream) WriteTo(p []byte, addr string) (n int, err error) {
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > maxUDPPayloadSize {
		return 0, fmt.Errorf("anytls udp payload too large: %d > %d", len(p), maxUDPPayloadSize)
	}
	ps.writeMutex.Lock()
	defer ps.writeMutex.Unlock()
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}

	// The first datagram of the stream teaches the server the target
	// address (connected framing); every later one is unconnected framing
	// that carries no address. Only a first datagram needs the address to
	// parse, and it must parse before the mode flips: a malformed address
	// fails that write without pinning the stream to unconnected framing,
	// which the server could never parse.
	var tgtAddr []byte
	sendAddr := !ps.udpWriteAddr.Load()
	if sendAddr {
		tgtAddr, err = socks.ParseAddr(addr)
		if err != nil {
			return 0, err
		}
		ps.udpWriteAddr.Store(true)

		data := pool.Get(1 + len(tgtAddr) + 2 + len(p))
		defer pool.Put(data)
		// connected mode
		data[0] = 1
		copy(data[1:], tgtAddr)
		binary.BigEndian.PutUint16(data[1+len(tgtAddr):], uint16(len(p)))
		copy(data[1+len(tgtAddr)+2:], p)

		if _, err := writeDataFrames(ps.session, ps.id, data, unixNanoToTime(ps.writeDeadline.Load())); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	data := pool.Get(2 + len(p))
	defer pool.Put(data)
	binary.BigEndian.PutUint16(data, uint16(len(p)))
	copy(data[2:], p)

	if _, err := writeDataFrames(ps.session, ps.id, data, unixNanoToTime(ps.writeDeadline.Load())); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteBatch implements netproxy.PacketBatchWriter: several datagrams for
// the same target leave in one framed write burst (one TLS record batch,
// one socket write). Callers aggregate by endpoint, so every item shares
// ps.addr; the first item carries the address header when this stream has
// not announced it yet. Pre-send validation is all-or-nothing per the
// interface contract (n == 0 on validation failure).
func (ps *packetStream) WriteBatch(items []netproxy.BatchItem) (n int, err error) {
	if len(items) == 0 {
		return 0, nil
	}
	for _, item := range items {
		if len(item.Data) > maxUDPPayloadSize {
			return 0, fmt.Errorf("anytls udp payload too large: %d > %d", len(item.Data), maxUDPPayloadSize)
		}
	}
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}
	ps.writeMutex.Lock()
	defer ps.writeMutex.Unlock()
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}

	// Same contract as WriteTo: decide the addressing mode for this batch
	// before building any frame, and only after the first address parses,
	// so a malformed address cannot pin the stream to unconnected framing.
	sendAddr := !ps.udpWriteAddr.Load()
	var firstTgtAddr []byte
	if sendAddr {
		firstAddr := ps.addr
		if items[0].Addr != "" {
			firstAddr = items[0].Addr
		}
		firstTgtAddr, err = socks.ParseAddr(firstAddr)
		if err != nil {
			return 0, err
		}
		ps.udpWriteAddr.Store(true)
	}
	datas := make([][]byte, 0, len(items))
	for i, item := range items {
		var data []byte
		if i == 0 && sendAddr {
			data = pool.Get(1 + len(firstTgtAddr) + 2 + len(item.Data))
			// connected mode
			data[0] = 1
			copy(data[1:], firstTgtAddr)
			binary.BigEndian.PutUint16(data[1+len(firstTgtAddr):], uint16(len(item.Data)))
			copy(data[1+len(firstTgtAddr)+2:], item.Data)
		} else {
			data = pool.Get(2 + len(item.Data))
			binary.BigEndian.PutUint16(data, uint16(len(item.Data)))
			copy(data[2:], item.Data)
		}
		datas = append(datas, data)
	}
	defer func() {
		for _, data := range datas {
			pool.Put(data)
		}
	}()
	if _, err := writeDataFramesBatch(ps.session, ps.id, datas, unixNanoToTime(ps.writeDeadline.Load())); err != nil {
		return 0, err
	}
	return len(items), nil
}

func timeToUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func unixNanoToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
