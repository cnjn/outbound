package direct

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

var resolveUDPAddr = common.ResolveUDPAddr

type directPacketConn struct {
	*net.UDPConn
	FullCone           bool
	dialTgt            string
	receiver           *packetReceiverRegistry
	receiverMu         sync.Mutex
	receiverStop       func()
	receiverGeneration uint64
	cachedDialTgt      atomic.Value // stores netip.AddrPort
	// writeTgtCache remembers resolved non-dial targets so a FullCone socket
	// relaying to several peers does not re-resolve on every datagram. It is
	// bounded: a pathological many-peer relay must not grow it without limit,
	// and eviction only costs one re-resolve.
	writeTgtCache map[string]netip.AddrPort
	cacheMu       sync.Mutex // guards the bounded target cache; never held across a resolve
	resolver      *net.Resolver
	batchOnce     sync.Once
	batchWriter   packetBatchWriter
}

// writeTgtCacheCapacity bounds the resolved-target cache on one FullCone
// socket; realistic relays stay well below it.
const writeTgtCacheCapacity = 8

// Close unregisters the socket from the shared packet receiver before closing
// its underlying UDP descriptor.
func (c *directPacketConn) Close() error {
	c.stopPacketReceiver()
	if c.UDPConn == nil {
		return nil
	}
	return c.UDPConn.Close()
}

func (c *directPacketConn) stopPacketReceiver() {
	c.receiverMu.Lock()
	stop := c.receiverStop
	c.receiverStop = nil
	c.receiverMu.Unlock()
	if stop != nil {
		stop()
	}
}

func (c *directPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return c.ReadFromUDPAddrPort(p)
}

func (c *directPacketConn) WriteTo(b []byte, addr string) (int, error) {
	if !c.FullCone {
		// FIXME: check the addr
		return c.Write(b)
	}

	target, err := c.writeTargetAddrPort(addr)
	if err != nil {
		return 0, err
	}

	return c.WriteToUDPAddrPort(b, target)
}

func (c *directPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	// Always forward to the real WriteMsgUDP. The previous symmetric-mode
	// shortcut (plain Write on the connected socket) silently dropped the
	// OOB control messages, which discards UDP_SEGMENT for QUIC GSO batches:
	// a batch of N segments then leaves as one oversized datagram that QUIC
	// receivers discard (>3x max_udp_payload, RFC 9000 s14.4.1), blackholing
	// a large fraction of packets. In symmetric mode the socket is
	// pre-connected to the single peer, and Go's net package rejects an
	// explicit destination on a pre-connected UDP socket, so pass nil (the
	// connected destination) there.
	if !c.FullCone {
		return c.UDPConn.WriteMsgUDP(b, oob, nil)
	}
	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *directPacketConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.FullCone {
		return c.Write(b)
	}

	return c.UDPConn.WriteToUDP(b, addr)
}

// directBatchScratch holds reusable per-batch scratch storage for
// WriteBatch. Pooled because hot relays flush many batches per second and
// the msgs array plus the per-message iovec slice would otherwise be two
// heap allocations per datagram (the iovec literal escapes).
type directBatchScratch struct {
	msgs []ipv6.Message
	iovs [][]byte
}

var directBatchScratchPool = sync.Pool{
	New: func() any {
		return &directBatchScratch{
			msgs: make([]ipv6.Message, udpBatchScratchCapacity),
			iovs: make([][]byte, udpBatchScratchCapacity),
		}
	},
}

const udpBatchScratchCapacity = 32

type packetBatchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func (c *directPacketConn) getBatchWriter() packetBatchWriter {
	c.batchOnce.Do(func() {
		if ua, ok := c.UDPConn.LocalAddr().(*net.UDPAddr); ok && ua.IP.To4() != nil {
			c.batchWriter = ipv4.NewPacketConn(c.UDPConn)
			return
		}
		c.batchWriter = ipv6.NewPacketConn(c.UDPConn)
	})
	return c.batchWriter
}

func resetDirectBatchScratch(scratch *directBatchScratch, n int) {
	clear(scratch.msgs[:n])
	clear(scratch.iovs[:n])
}

func releaseDirectBatchScratch(scratch *directBatchScratch, n int) {
	resetDirectBatchScratch(scratch, n)
	directBatchScratchPool.Put(scratch)
}

// WriteBatch implements netproxy.PacketBatchWriter: several datagrams in one
// sendmmsg syscall. On a connected (non-FullCone) socket every datagram goes
// to the connected peer (Addr left nil); on a FullCone socket each item
// carries its own destination. Data slices must stay valid until return.
func (c *directPacketConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	if len(items) > udpBatchScratchCapacity {
		// Oversized batch: allocate directly (rare).
		return c.writeBatchAlloc(items)
	}
	scratch := directBatchScratchPool.Get().(*directBatchScratch)
	defer releaseDirectBatchScratch(scratch, len(items))
	msgs := scratch.msgs[:len(items)]
	iovs := scratch.iovs[:len(items)]
	for i, it := range items {
		var addr net.Addr
		if c.FullCone {
			target, err := c.writeTargetAddrPort(it.Addr)
			if err != nil {
				// Nothing has been handed to sendmmsg yet, so n=0.
				return 0, err
			}
			addr = net.UDPAddrFromAddrPort(target)
		}
		iovs[i] = it.Data
		// Sub-slicing the pooled iovs array avoids the escaping literal.
		msgs[i] = ipv6.Message{Buffers: iovs[i : i+1], Addr: addr}
	}
	return c.getBatchWriter().WriteBatch(msgs, 0)
}

func (c *directPacketConn) writeBatchAlloc(items []netproxy.BatchItem) (int, error) {
	msgs := make([]ipv6.Message, len(items))
	for i, it := range items {
		var addr net.Addr
		if c.FullCone {
			target, err := c.writeTargetAddrPort(it.Addr)
			if err != nil {
				// Nothing has been handed to sendmmsg yet, so n=0.
				return 0, err
			}
			addr = net.UDPAddrFromAddrPort(target)
		}
		msgs[i] = ipv6.Message{Buffers: [][]byte{it.Data}, Addr: addr}
	}
	return c.getBatchWriter().WriteBatch(msgs, 0)
}

func (c *directPacketConn) resolveTarget() error {
	// Retryable by design: a failure must not be memoized for the lifetime
	// of the conn (fullcone UDP relays live for hours — a transient resolver
	// outage at first write would otherwise fail every later write).
	//
	// The check and the publication below are two phases around the
	// resolution, which can block for the resolver timeout: holding cacheMu
	// across it stalled every lookup of the bounded target cache — and
	// therefore every write to any other peer — for as long as one lookup
	// took. Two writers that miss the same brand-new target may now resolve
	// it concurrently; they publish the same address, so the duplicate only
	// costs one lookup.
	if c.cachedDialTgt.Load() != nil {
		return nil
	}
	ua, err := resolveUDPAddr(c.resolver, c.dialTgt)
	if err != nil {
		return err
	}
	// Store the value directly, not a pointer to a stack variable.
	// atomic.Value stores the value on heap, ensuring memory safety.
	resolved := ua.AddrPort()
	ap := netip.AddrPortFrom(resolved.Addr().Unmap(), resolved.Port())
	c.cachedDialTgt.Store(ap)
	return nil
}

func (c *directPacketConn) writeTargetAddrPort(addr string) (netip.AddrPort, error) {
	if addr == c.dialTgt {
		if c.cachedDialTgt.Load() == nil {
			if err := c.resolveTarget(); err != nil {
				return netip.AddrPort{}, err
			}
		}
		return c.cachedDialTgt.Load().(netip.AddrPort), nil
	}
	c.cacheMu.Lock()
	cached, ok := c.writeTgtCache[addr]
	c.cacheMu.Unlock()
	if ok {
		return cached, nil
	}
	uAddr, err := resolveUDPAddr(c.resolver, addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	resolved := uAddr.AddrPort()
	target := netip.AddrPortFrom(resolved.Addr().Unmap(), resolved.Port())
	c.cacheMu.Lock()
	c.storeWriteTgtLocked(addr, target)
	c.cacheMu.Unlock()
	return target, nil
}

// storeWriteTgtLocked inserts into the bounded target cache, evicting an
// arbitrary entry when full (map iteration order); the caller holds cacheMu.
func (c *directPacketConn) storeWriteTgtLocked(addr string, target netip.AddrPort) {
	if c.writeTgtCache == nil {
		c.writeTgtCache = make(map[string]netip.AddrPort, writeTgtCacheCapacity)
	}
	if len(c.writeTgtCache) >= writeTgtCacheCapacity {
		for victim := range c.writeTgtCache {
			delete(c.writeTgtCache, victim)
			break
		}
	}
	c.writeTgtCache[addr] = target
}

func (c *directPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Write(b)
	}

	target, err := c.writeTargetAddrPort(c.dialTgt)
	if err != nil {
		return 0, err
	}
	// No lock needed: Go's net.UDPConn.WriteToUDPAddrPort() is thread-safe.
	// From Go's net package documentation:
	// "Multiple goroutines may invoke methods on a PacketConn simultaneously."
	return c.WriteToUDPAddrPort(b, target)
}

func (c *directPacketConn) Read(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Read(b)
	}
	n, _, err := c.UDPConn.ReadFrom(b)
	return n, err
}

var _ interface {
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
} = &directPacketConn{}
