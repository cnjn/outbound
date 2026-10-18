// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// PktConn .
type PktConn struct {
	netproxy.PacketConn
	ctrlConn  netproxy.Conn // tcp control conn
	target    string
	proxyAddr string
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	addrCache common.LastStringValue[socks.Addr]
}

var _ netproxy.PacketReceiver = (*PktConn)(nil)

func (pc *PktConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := pc.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, pc.mapReceivedPacket)
}

// parseSocksUdpPayload splits one decoded SOCKS UDP datagram into the reply
// payload and its source address. Shared by the polling readFrom and the
// push-mode receiver so the two decode paths cannot drift.
func parseSocksUdpPayload(data []byte) (payload []byte, from netip.AddrPort, err error) {
	// Every failure below is a per-datagram event: the datagram was already
	// drained from the socket and the session stays usable. The typed
	// datagram-dropped contract tells consumers to drop this one datagram
	// instead of retiring the endpoint an untyped error would imply.
	if len(data) < 3 {
		return nil, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	if data[2] != 0 {
		// FRAG != 0 means a fragmented datagram; we never fragment and the
		// payload of a fragment is not a self-contained datagram, so reject
		// instead of misparsing the shifted address header.
		return nil, netip.AddrPort{}, netproxy.DatagramDropped(errors.New("fragmented SOCKS UDP datagrams are not supported"))
	}
	tgtAddr := socks.SplitAddr(data[3:])
	if tgtAddr == nil {
		return nil, netip.AddrPort{}, netproxy.DatagramDropped(errors.New("can not get target addr"))
	}
	addrPort, ok := tgtAddr.AddrPort()
	if !ok {
		// Domain-shaped reply: keep the legacy resolution path.
		target, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			return nil, netip.AddrPort{}, netproxy.DatagramDropped(errors.New("wrong target addr"))
		}
		addrPort = target.AddrPort()
	}
	return data[3+len(tgtAddr):], addrPort, nil
}

func (pc *PktConn) mapReceivedPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	payload, from, err := parseSocksUdpPayload(packet.Data)
	if err != nil {
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	packet.Data = payload
	packet.From = from
	return packet, true
}

var parseSocksAddr = socks.ParseAddr

// NewPktConn returns a PktConn, the writeAddr must be *net.UDPAddr or *net.UnixAddr.
func NewPktConn(c netproxy.PacketConn, proxyAddr string, targetAddr string, ctrlConn netproxy.Conn) *PktConn {
	ctx, cancel := context.WithCancel(context.Background())
	pc := &PktConn{
		PacketConn: c,
		target:     targetAddr,
		proxyAddr:  proxyAddr,
		ctrlConn:   ctrlConn,
		cancel:     cancel,
	}
	if ctrlConn != nil {
		pc.done = make(chan struct{})
	}

	if ctrlConn != nil {
		go func() {
			buf := pool.Get(1)
			defer pool.Put(buf)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, err := ctrlConn.Read(buf)
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				_ = pc.Close()
				return
			}
		}()
	}

	return pc
}

// ReadFrom overrides the original function from transport.PacketConn.
func (pc *PktConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, _, target, err := pc.readFrom(b)
	return n, target, err
}

func (pc *PktConn) readFrom(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	n, raddr, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return n, raddr, netip.AddrPort{}, err
	}

	// https://www.rfc-editor.org/rfc/rfc1928#section-7
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+
	payload, target, err := parseSocksUdpPayload(b[:n])
	if err != nil {
		return n, raddr, netip.AddrPort{}, err
	}
	n = copy(b, payload)
	return n, raddr, target, nil
}

// WriteTo overrides the original function from transport.PacketConn.
func (pc *PktConn) WriteTo(b []byte, addr string) (int, error) {
	target, err := pc.targetAddr(addr)

	if err != nil {
		return 0, fmt.Errorf("invalid addr: %w", err)
	}

	tgtLen := len(target)
	buf := pool.Get(3 + tgtLen + len(b))
	defer pool.Put(buf)

	copy(buf, []byte{0, 0, 0})
	copy(buf[3:], target)
	copy(buf[3+tgtLen:], b)

	n, err := pc.PacketConn.WriteTo(buf, pc.proxyAddr)
	if n > tgtLen+3 {
		return n - tgtLen - 3, err
	}

	return 0, err
}

// WriteBatch implements netproxy.PacketBatchWriter: encapsulate every
// datagram with its SOCKS5 UDP header (RSV FRAG ATYP DST.ADDR DST.PORT) and
// hand the whole batch to the underlying transport's batched writer in one
// call. The encapsulation copies per item exactly like WriteTo; only the
// syscall is amortized.
func (pc *PktConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	bw, ok := pc.PacketConn.(netproxy.PacketBatchWriter)
	if !ok {
		// Underlying transport has no batched writer: fall back to per-item
		// synchronous writes, preserving ordering. n is a datagram count,
		// matching PacketBatchWriter / dae's aggregator contract.
		sent := 0
		for _, it := range items {
			if _, err := pc.WriteTo(it.Data, it.Addr); err != nil {
				return sent, err
			}
			sent++
		}
		return sent, nil
	}
	enc := make([]netproxy.BatchItem, len(items))
	releaseEnc := func() {
		for _, it := range enc {
			if it.Data != nil {
				pool.Put(it.Data)
			}
		}
	}
	for i, it := range items {
		target, err := pc.targetAddr(it.Addr)
		if err != nil {
			releaseEnc()
			return 0, fmt.Errorf("invalid addr: %w", err)
		}
		tgtLen := len(target)
		buf := pool.Get(3 + tgtLen + len(it.Data))
		copy(buf, []byte{0, 0, 0})
		copy(buf[3:], target)
		copy(buf[3+tgtLen:], it.Data)
		enc[i] = netproxy.BatchItem{Data: buf, Addr: pc.proxyAddr}
	}
	n, err := bw.WriteBatch(enc)
	releaseEnc()
	return n, err
}

func (pc *PktConn) targetAddr(addr string) (socks.Addr, error) {
	if cached, ok := pc.addrCache.Load(addr); ok {
		return cached, nil
	}
	target, err := parseSocksAddr(addr)
	if err != nil {
		return nil, err
	}
	target = append(socks.Addr(nil), target...)
	pc.addrCache.Store(addr, target)
	return target, nil
}

// TransportDone implements netproxy.TransportLifecycle.
// The returned channel is closed when the SOCKS5 UDP association control
// channel terminates and the UDP relay becomes unusable.
func (pc *PktConn) TransportDone() <-chan struct{} {
	return pc.done
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped transport: SetWriteDeadline is
// delegated to the underlying PacketConn unchanged, so the semantics — and
// the declaration — belong to that transport, not to this wrapper.
func (pc *PktConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(pc.PacketConn)
}

// Close .
func (pc *PktConn) Close() error {
	pc.closeOnce.Do(func() {
		if pc.cancel != nil {
			pc.cancel()
		}
		if pc.done != nil {
			close(pc.done)
		}
		if pc.ctrlConn != nil {
			_ = pc.ctrlConn.Close()
		}
		if pc.PacketConn != nil {
			pc.closeErr = pc.PacketConn.Close()
		}
	})
	return pc.closeErr
}

func (c *PktConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *PktConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.target)
}

var _ netproxy.TransportLifecycle = (*PktConn)(nil)
