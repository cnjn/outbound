package vmess

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	if !c.metadata.IsPacketAddr() {
		// Fixed target: read the datagram straight into the caller's
		// buffer instead of bouncing through a pooled MaxUDPSize copy.
		n, err = c.read(p)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		tgt, err := c.dialTargetAddrPort()
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, tgt, nil
	}
	// Read the datagram straight into the caller's buffer. Staging it through a
	// pooled MaxUDPSize (2048) frame buffer capped every packetaddr datagram at
	// 2048 bytes regardless of the caller's capacity, so larger replies (for
	// example EDNS0 DNS answers) were drained and reported as dropped. c.read
	// already reports a caller-side short buffer as a typed datagram-dropped
	// error, so no copy or cap is needed here.
	n, err = c.read(p)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n == 0 {
		return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
	}
	addrTyp, address, err := ExtractPacketAddr(p[:n])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	// ExtractPacketAddr rejects a datagram shorter than its own packet address,
	// so addrLen <= n here. The address is a prefix of the datagram; compacting
	// it out is a forward-overlapping copy, which copy handles correctly.
	addrLen := PacketAddrLength(addrTyp)
	return copy(p, p[addrLen:n]), address, nil
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		// VMess packet addr does not support domain.
		address, err := c.writeTargetAddrPort(addr)
		if err != nil {
			return 0, err
		}
		packetAddrLen := UDPAddrToPacketAddrLength(address)
		buf := pool.Get(packetAddrLen + len(p))
		defer pool.Put(buf)

		err = PutPacketAddr(buf, address)
		if err != nil {
			return 0, err
		}
		copy(buf[packetAddrLen:], p)
		return c.write(buf)
	}

	return c.write(p)
}

func (c *Conn) writeTargetAddrPort(addr string) (*net.UDPAddr, error) {
	if addr == c.dialTgt {
		target, err := c.dialTargetAddrPort()
		if err != nil {
			return nil, err
		}
		return net.UDPAddrFromAddrPort(target), nil
	}
	if cached, ok := c.writeCache.Load(addr); ok {
		return net.UDPAddrFromAddrPort(cached), nil
	}
	target, err := resolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	addrPort := unmapAddrPort(target.AddrPort())
	c.writeCache.Store(addr, addrPort)
	return net.UDPAddrFromAddrPort(addrPort), nil
}

// WriteBatch implements netproxy.PacketBatchWriter: seal several datagrams
// (each as its own AEAD chunk, with its own nonce and padding, exactly like
// WriteTo) and push them with one underlying write. Packet-addr mode
// prepends each datagram's destination, so full-cone Addr alternation keeps
// working. Every destination is resolved before the first byte is written,
// so an address failure is all-or-nothing (n == 0).
func (c *Conn) WriteBatch(items []netproxy.BatchItem) (n int, err error) {
	if len(items) == 0 {
		return 0, nil
	}
	if c.metadata.Network != "udp" {
		return 0, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, c.metadata.Network)
	}
	datas := make([][]byte, 0, len(items))
	var release []pool.PB
	if c.metadata.IsPacketAddr() {
		release = make([]pool.PB, 0, len(items))
		for _, item := range items {
			address, err := c.writeTargetAddrPort(item.Addr)
			if err != nil {
				for _, b := range release {
					pool.Put(b)
				}
				return 0, err
			}
			packetAddrLen := UDPAddrToPacketAddrLength(address)
			buf := pool.Get(packetAddrLen + len(item.Data))
			if err := PutPacketAddr(buf, address); err != nil {
				pool.Put(buf)
				for _, b := range release {
					pool.Put(b)
				}
				return 0, err
			}
			copy(buf[packetAddrLen:], item.Data)
			datas = append(datas, buf)
			release = append(release, buf)
		}
	} else {
		// Fixed target: the destination lives in the request header, so the
		// plaintext is the payload itself and stays caller-owned.
		for _, item := range items {
			datas = append(datas, item.Data)
		}
	}
	return c.writePackets(datas, release)
}
