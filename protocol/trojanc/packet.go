package trojanc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

type PacketConn struct {
	*Conn
	domainIpMapping sync.Map
	writeTarget     common.LastStringValue[protocol.Metadata]
}

var parseMetadata = protocol.ParseMetadata

func (c *PacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	m := Metadata{}
	if _, err = m.Unpack(c.Conn); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Consume the whole frame before resolving the reported address. Resolving
	// can fail (a peer-supplied domain that does not resolve in time), and
	// returning with the body still unread would leave the next Unpack parsing
	// payload bytes as metadata. Reading first keeps every error at a frame
	// boundary, which is what lets the caller drop one datagram and keep the
	// session instead of tearing it down.
	var lengthAndCRLF [4]byte
	if _, err = io.ReadFull(c.Conn, lengthAndCRLF[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if lengthAndCRLF[2] != '\r' || lengthAndCRLF[3] != '\n' {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid trojan UDP CRLF")
	}
	length := int(binary.BigEndian.Uint16(lengthAndCRLF[:2]))
	if length > len(p) {
		// Caller buffer too small: fill it and discard the remainder of the
		// datagram so the stream stays framed, then surface the drop —
		// delivering the truncated bytes as success would corrupt the
		// datagram silently.
		if n, err = io.ReadFull(c.Conn, p); err != nil {
			return 0, netip.AddrPort{}, err
		}
		_, _ = io.CopyN(io.Discard, c.Conn, int64(length-len(p)))
		if addr, err = m.DomainIpMapping(&c.domainIpMapping); err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, addr, netproxy.DatagramDropped(io.ErrShortBuffer)
	} else if n, err = io.ReadFull(c.Conn, p[:length]); err != nil {
		return 0, netip.AddrPort{}, err
	}

	if addr, err = m.DomainIpMapping(&c.domainIpMapping); err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, addr, nil
}

func (c *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	_metadata, err := c.metadataForAddr(addr)
	if err != nil {
		return 0, err
	}
	metadata := Metadata{
		Metadata: _metadata,
		Network:  "udp",
	}
	c.Conn.writeMutex.Lock()
	defer c.Conn.writeMutex.Unlock()
	buf := c.Conn.borrowPacketWriteBuffer(metadata.Len() + 4 + len(p))
	SealUDP(metadata, buf, p)
	if _, err = c.Conn.writeLocked(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteBatch implements netproxy.PacketBatchWriter: seal every datagram with
// its own trojan UDP frame (metadata, length, CRLF) and push the whole batch
// through one underlying write. Each frame carries its destination address,
// so full-cone Addr alternation keeps working. Addresses are resolved for
// every item before the first byte is written, so a parse failure is
// all-or-nothing (n == 0).
func (c *PacketConn) WriteBatch(items []netproxy.BatchItem) (n int, err error) {
	if len(items) == 0 {
		return 0, nil
	}
	metadatas := make([]Metadata, 0, len(items))
	total := 0
	for _, item := range items {
		if len(item.Data) > 0xffff {
			return 0, fmt.Errorf("trojan udp payload too large: %d > %d", len(item.Data), 0xffff)
		}
		_metadata, err := c.metadataForAddr(item.Addr)
		if err != nil {
			return 0, err
		}
		metadata := Metadata{
			Metadata: _metadata,
			Network:  "udp",
		}
		metadatas = append(metadatas, metadata)
		total += metadata.Len() + 4 + len(item.Data)
	}
	c.Conn.writeMutex.Lock()
	defer c.Conn.writeMutex.Unlock()
	buf := pool.Get(total)
	defer pool.Put(buf)
	offset := 0
	for i, item := range items {
		offset += len(SealUDP(metadatas[i], buf[offset:], item.Data))
	}
	if _, err = c.Conn.writeLocked(buf); err != nil {
		// One stream write carries every frame; a failure cannot be split
		// per datagram, so report none instead of guessing.
		return 0, err
	}
	return len(items), nil
}

func (c *PacketConn) metadataForAddr(addr string) (protocol.Metadata, error) {
	if cached, ok := c.writeTarget.Load(addr); ok {
		return cached, nil
	}
	mdata, err := parseMetadata(addr)
	if err != nil {
		return protocol.Metadata{}, err
	}
	c.writeTarget.Store(addr, mdata)
	return mdata, nil
}

func SealUDP(metadata Metadata, dst []byte, data []byte) []byte {
	n := metadata.Len()
	// copy first to allow overlap
	copy(dst[n+4:], data)
	metadata.PackTo(dst)
	binary.BigEndian.PutUint16(dst[n:], uint16(len(data)))
	copy(dst[n+2:], CRLF)
	return dst[:n+4+len(data)]
}
