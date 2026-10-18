package vision

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

var _ netproxy.PacketConn = (*PacketConn)(nil)

var parseAddrPort = netip.ParseAddrPort

type PacketConn struct {
	*Conn
	network string
	addr    string
	target  common.LastStringValue[netip.AddrPort]
}

func (c *PacketConn) Read(b []byte) (n int, err error) {
	switch c.network {
	case "tcp":
		return c.Conn.Read(b)
	case "udp":
		n, _, err = c.ReadFrom(b)
		return n, err
	default:
		return 0, fmt.Errorf("unsupported network: %s", c.network)
	}
}

func (c *PacketConn) Write(b []byte) (n int, err error) {
	switch c.network {
	case "tcp":
		return c.Conn.Write(b)
	case "udp":
		return c.WriteTo(b, c.addr)
	default:
		return 0, fmt.Errorf("unsupported network: %s", c.network)
	}
}

// +-------------------+-------------------+
// | Frame Length (2B) | Frame Header (4B) |
// +-------------------+-------------------+
// |Net Type (1B) | PORT (2B)  | IP Type (1B) | IP Address |
// +-------------------+-------------------+
// |   Length Data     |     Payload      |
// +-------------------+-------------------+
func (c *PacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	for {
		// Read frame length (2 bytes)
		var frameLengthBytes [2]byte
		if _, err = io.ReadFull(c.Conn, frameLengthBytes[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		frameLength := binary.BigEndian.Uint16(frameLengthBytes[:])

		// Read frame header (4 bytes)
		var frameHeaderBytes [4]byte
		if _, err = io.ReadFull(c.Conn, frameHeaderBytes[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}

		addr = netip.AddrPort{}
		switch frameHeaderBytes[2] {
		case 0x01:
			return 0, netip.AddrPort{}, fmt.Errorf("unexpected frame new")
		case 0x02:
			// Keep
			if frameLength > 4 {
				addrData := make([]byte, frameLength-4)
				if _, err = io.ReadFull(c.Conn, addrData); err != nil {
					return 0, netip.AddrPort{}, err
				}
				addr, err = ReadPacketAddr(addrData)
				if err != nil {
					return 0, netip.AddrPort{}, err
				}
			}
		case 0x03:
			return 0, netip.AddrPort{}, io.EOF
		case 0x04:
			// KeepAlive
		default:
			return 0, netip.AddrPort{}, fmt.Errorf("unsupported frame header: %x", frameHeaderBytes[2])
		}

		if frameHeaderBytes[3]&1 != 1 {
			continue
		}

		// Read length and payload
		var lengthBytes [2]byte
		if _, err = io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		length := binary.BigEndian.Uint16(lengthBytes[:])

		// Compare in int: casting len(p) to uint16 wraps any buffer of
		// 65536 bytes (dae's full-range DNS forward buffer, and the pool's
		// largest bucket) to 0, which would classify every datagram as
		// oversized and drop the whole UDP path of the connection.
		if int(length) > len(p) {
			if _, discardErr := io.CopyN(io.Discard, c.Conn, int64(length)); discardErr != nil {
				return 0, netip.AddrPort{}, discardErr
			}
			return 0, netip.AddrPort{}, netproxy.DatagramDropped(io.ErrShortBuffer)
		}

		n, err = io.ReadFull(c.Conn, p[:length])
		return n, addr, err
	}
}

// +------------------------+------------------------+
// |  Metadata Length (2B)  |    Session ID (2B)    |
// +------------------------+------------------------+
// |    Type (1B)          |    Options (1B)        |
// |    (New=1/Keep=2)     |                        |
// +------------------------+------------------------+
// |  Protocol Type (1B)    |                       |
// +------------------------+                       |
// |     Target Address     |       Port            |
// |     (Variable)         |                       |
// +------------------------+------------------------+
// |     Global ID (8B)     |                       |
// |     (Optional)         |                       |
// +------------------------+------------------------+
// |   Data Length (2B)     |      Payload          |
// +------------------------+------------------------+
func (pc *PacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	pc.muWrite.Lock()
	defer pc.muWrite.Unlock()

	dataLen := len(p)
	prefix, err := pc.prefixPacketLocked(addr)
	if err != nil {
		return 0, err
	}
	defer prefix.Put()
	_, err = iout.MultiWrite(pc.writer, prefix, []byte{byte(dataLen >> 8), byte(dataLen)}, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteBatch implements netproxy.PacketBatchWriter: encode every datagram as
// its own XUDP frame (each frame carries its destination address, so
// full-cone Addr alternation keeps working) and push the whole batch through
// one underlying write. The first frame of the session still carries the
// "new" handshake header. Address resolution happens for every item before
// the first byte is written, so a parse failure is all-or-nothing (n == 0).
func (pc *PacketConn) WriteBatch(items []netproxy.BatchItem) (n int, err error) {
	if len(items) == 0 {
		return 0, nil
	}
	for _, item := range items {
		if len(item.Data) > 0xffff {
			return 0, fmt.Errorf("vision udp payload too large: %d > %d", len(item.Data), 0xffff)
		}
	}
	// Resolve every destination up front: a failure must not leave the
	// handshake flag flipped or earlier frames on the wire.
	for _, item := range items {
		if _, err := pc.addrPortForWrite(item.Addr); err != nil {
			return 0, err
		}
	}
	pc.muWrite.Lock()
	defer pc.muWrite.Unlock()

	total := 0
	prefixes := make([]pool.PB, 0, len(items))
	defer func() {
		for _, prefix := range prefixes {
			prefix.Put()
		}
	}()
	for _, item := range items {
		prefix, err := pc.prefixPacketLocked(item.Addr)
		if err != nil {
			// prefixPacketLocked returns its (already pooled) buffer together
			// with the error; release it instead of leaking.
			if prefix != nil {
				prefix.Put()
			}
			return 0, err
		}
		prefixes = append(prefixes, prefix)
		total += len(prefix) + 2 + len(item.Data)
	}
	buf := pool.Get(total)
	defer pool.Put(buf)
	offset := 0
	for i, item := range items {
		offset += copy(buf[offset:], prefixes[i])
		buf[offset] = byte(len(item.Data) >> 8)
		buf[offset+1] = byte(len(item.Data))
		offset += 2
		offset += copy(buf[offset:], item.Data)
	}
	if _, err := pc.writer.Write(buf); err != nil {
		// One stream write carries every frame; a failure cannot be split
		// per datagram, so report none instead of guessing.
		return 0, err
	}
	return len(items), nil
}

func (pc *PacketConn) prefixPacketLocked(addr string) (pool.PB, error) {
	address, err := pc.addrPortForWrite(addr)
	if err != nil {
		return nil, err
	}
	packetAddrLen := IPAddrToPacketAddrLength(address)
	prefix := pool.Get(7 + packetAddrLen)
	l := len(prefix) - 2
	err = PutPacketAddr(prefix[7:], address)
	if err != nil {
		return nil, err
	}
	if pc.needHandshake {
		pc.needHandshake = false
		prefix[0] = byte(l >> 8)
		prefix[1] = byte(l)
		prefix[2] = 0
		prefix[3] = 0
		prefix[4] = 1 // new
		prefix[5] = 1 // option
		prefix[6] = 2 // udp
	} else {
		prefix[0] = byte(l >> 8)
		prefix[1] = byte(l)
		prefix[2] = 0
		prefix[3] = 0
		prefix[4] = 2 // keep
		prefix[5] = 1 // option
		prefix[6] = 2 // udp
	}

	return prefix, err
}

func (pc *PacketConn) addrPortForWrite(addr string) (netip.AddrPort, error) {
	if cached, ok := pc.target.Load(addr); ok {
		return cached, nil
	}
	address, err := parseAddrPort(addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	pc.target.Store(addr, address)
	return address, nil
}

func IPAddrToPacketAddrLength(addr netip.AddrPort) int {
	nip, ok := netip.AddrFromSlice(addr.Addr().AsSlice())
	if !ok {
		return 0
	}

	if nip.Is4() {
		return 1 + 4 + 2
	} else {
		return 1 + 16 + 2
	}
}

func PutPacketAddr(src []byte, addr netip.AddrPort) error {
	nip, ok := netip.AddrFromSlice(addr.Addr().AsSlice())
	if !ok {
		return errors.New("invalid IP")
	}

	if nip.Is4() {
		binary.BigEndian.PutUint16(src[0:2], addr.Port())
		src[2] = 1
		copy(src[3:7], nip.AsSlice())
	} else {
		binary.BigEndian.PutUint16(src[0:2], addr.Port())
		src[2] = 3
		copy(src[3:19], nip.AsSlice())
	}

	return nil
}

// ReadPacketAddr parses a packet address block laid out as one skipped byte,
// a 2-byte port, a 1-byte IP type and a 4- or 16-byte IP. The block comes
// from the server with an attacker-controlled length; every slice below must
// be bounds-checked against what was actually received.
func ReadPacketAddr(p []byte) (addr netip.AddrPort, err error) {
	const ipv4Len, ipv6Len = 4, 16
	if len(p) < 1+2+1+ipv4Len {
		return netip.AddrPort{}, io.ErrUnexpectedEOF
	}
	p = p[1:]
	port := binary.BigEndian.Uint16(p[0:2])
	ipType := p[2]
	ip := p[3:]
	if ipType == 1 {
		if len(ip) < ipv4Len {
			return netip.AddrPort{}, io.ErrUnexpectedEOF
		}
		ip = ip[:ipv4Len]
	} else {
		if len(ip) < ipv6Len {
			return netip.AddrPort{}, io.ErrUnexpectedEOF
		}
		ip = ip[:ipv6Len]
	}
	ipAddr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, errors.New("invalid IP")
	}
	return netip.AddrPortFrom(ipAddr, port), nil
}
