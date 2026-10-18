package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	// FIXME: a compromise on Symmetric NAT
	addr = c.cachedProxyAddrIpIP

	var bLen [2]byte
	if _, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, bLen[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length := int(binary.BigEndian.Uint16(bLen[:]))
	if len(p) < length {
		if _, discardErr := io.CopyN(io.Discard, &netproxy.ReadWrapper{ReadFunc: c.read}, int64(length)); discardErr != nil {
			return 0, netip.AddrPort{}, discardErr
		}
		return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	n, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, p[:length])
	return n, addr, err
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	var bLen [2]byte
	binary.BigEndian.PutUint16(bLen[:], uint16(len(p)))
	if _, err = c.write(bLen[:]); err != nil {
		return 0, err
	}
	return c.write(p)
}

// WriteBatch implements netproxy.PacketBatchWriter: several datagrams leave
// as one framed write burst (one TLS record batch / one socket write) instead
// of one write pair per datagram. Like WriteTo, the item address is ignored:
// the target is fixed in the request header, so every item must share it
// (dae's aggregator groups by endpoint). Length validation is all-or-nothing
// per the interface contract: a pre-send failure reports n == 0.
func (c *Conn) WriteBatch(items []netproxy.BatchItem) (n int, err error) {
	if len(items) == 0 {
		return 0, nil
	}
	total := 0
	for _, item := range items {
		if len(item.Data) > 0xffff {
			return 0, fmt.Errorf("vless udp payload too large: %d > %d", len(item.Data), 0xffff)
		}
		total += 2 + len(item.Data)
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	buf := pool.Get(total)
	defer pool.Put(buf)
	offset := 0
	var bLen [2]byte
	for _, item := range items {
		binary.BigEndian.PutUint16(bLen[:], uint16(len(item.Data)))
		copy(buf[offset:], bLen[:])
		offset += 2
		offset += copy(buf[offset:], item.Data)
	}
	if _, err = c.write(buf); err != nil {
		// The framed blob is one stream write: a failed write leaves an
		// unknown number of complete datagrams on the wire, so report none
		// rather than guess.
		return 0, err
	}
	return len(items), nil
}
