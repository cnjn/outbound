package tuic

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/google/uuid"
	"github.com/olicesx/quic-go"
)

type BufferedReader interface {
	io.Reader
	io.ByteReader
}

type BufferedWriter interface {
	io.Writer
	io.ByteWriter
}

type CommandType byte

const (
	AuthenticateType = CommandType(0x00)
	ConnectType      = CommandType(0x01)
	PacketType       = CommandType(0x02)
	DissociateType   = CommandType(0x03)
	HeartbeatType    = CommandType(0x04)
)

func (c CommandType) String() string {
	switch c {
	case AuthenticateType:
		return "Authenticate"
	case ConnectType:
		return "Connect"
	case PacketType:
		return "Packet"
	case DissociateType:
		return "Dissociate"
	case HeartbeatType:
		return "Heartbeat"
	default:
		return fmt.Sprintf("UnknowCommand: %#x", byte(c))
	}
}

func (c CommandType) BytesLen() int {
	return 1
}

type CommandHead struct {
	VER  byte
	TYPE CommandType
}

func NewCommandHead(TYPE CommandType, VER byte) *CommandHead {
	return &CommandHead{
		VER:  VER,
		TYPE: TYPE,
	}
}

func ReadCommandHead(reader BufferedReader) (c *CommandHead, err error) {
	var _c CommandHead
	_c.VER, err = reader.ReadByte()
	if err != nil {
		return nil, err
	}
	TYPE, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	_c.TYPE = CommandType(TYPE)
	return &_c, nil
}

func (c CommandHead) WriteTo(writer BufferedWriter) (err error) {
	err = writer.WriteByte(c.VER)
	if err != nil {
		return
	}
	err = writer.WriteByte(byte(c.TYPE))
	if err != nil {
		return
	}
	return
}

func (c CommandHead) WriteToBytes(buf []byte) (n int) {
	buf[0] = c.VER
	buf[1] = byte(c.TYPE)
	return 2
}

func (c CommandHead) BytesLen() int {
	return 1 + c.TYPE.BytesLen()
}

type Authenticate struct {
	*CommandHead
	UUID  uuid.UUID
	TOKEN [32]byte
	VER   byte
}

func NewAuthenticate(UUID [16]byte, TOKEN [32]byte, VER byte) *Authenticate {
	return &Authenticate{
		CommandHead: NewCommandHead(AuthenticateType, VER),
		UUID:        UUID,
		TOKEN:       TOKEN,
		VER:         VER,
	}
}

func ReadAuthenticateWithHead(head *CommandHead, reader BufferedReader) (c *Authenticate, err error) {
	var _c Authenticate
	_c.CommandHead = head
	if _c.TYPE != AuthenticateType {
		return nil, fmt.Errorf("error command type: %s", _c.TYPE)
	}
	_, err = io.ReadFull(reader, _c.UUID[:])
	if err != nil {
		return nil, fmt.Errorf("read uuid: %w", err)
	}
	_, err = io.ReadFull(reader, _c.TOKEN[:])
	if err != nil {
		return nil, fmt.Errorf("read token: %w", err)
	}
	return &_c, nil
}

func GenToken(state quic.ConnectionState, uuid [16]byte, password string) (token [32]byte, err error) {
	var tokenBytes []byte
	tokenBytes, err = state.TLS.ExportKeyingMaterial(string(uuid[:]), []byte(password), 32)
	if err != nil {
		return
	}
	copy(token[:], tokenBytes)
	return
}

func (c Authenticate) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	_, err = writer.Write(c.UUID[:])
	if err != nil {
		return
	}
	_, err = writer.Write(c.TOKEN[:])
	if err != nil {
		return
	}
	return
}

func (c Authenticate) BytesLen() int {
	return c.CommandHead.BytesLen() + 16 + 32
}

type Connect struct {
	*CommandHead
	ADDR *Address
}

func NewConnect(ADDR *Address, VER byte) *Connect {
	return &Connect{
		CommandHead: NewCommandHead(ConnectType, VER),
		ADDR:        ADDR,
	}
}

func ReadConnectWithHead(head *CommandHead, reader BufferedReader) (c *Connect, err error) {
	var _c Connect
	_c.CommandHead = head
	if _c.TYPE != ConnectType {
		err = fmt.Errorf("error command type: %s", _c.TYPE)
		return nil, err
	}
	_c.ADDR, err = ReadAddress(reader)
	if err != nil {
		return nil, err
	}
	return &_c, nil
}

func (c Connect) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = c.ADDR.WriteTo(writer)
	if err != nil {
		return
	}
	return
}

func (c Connect) WriteToBytes(b []byte) (n int) {
	n += c.CommandHead.WriteToBytes(b)
	n += c.ADDR.WriteToBytes(b[2:])
	return n
}

func (c Connect) BytesLen() int {
	return c.CommandHead.BytesLen() + c.ADDR.BytesLen()
}

type packetDataOwner struct {
	once sync.Once
}

type Packet struct {
	*CommandHead
	ASSOC_ID   uint16
	PKT_ID     uint16
	FRAG_TOTAL uint8
	FRAG_ID    uint8
	SIZE       uint16
	ADDR       *Address
	DATA       []byte

	// dataOwner is present only for parsed pool-backed DATA. Keeping sync.Once
	// behind a pointer makes outgoing Packet value copies safe.
	dataOwner *packetDataOwner
}

// releaseData returns DATA to the pool if pool-backed; no-op otherwise and on
// repeat calls. Call once the consumer is done with DATA.
func (p *Packet) releaseData() {
	if p == nil || p.dataOwner == nil {
		return
	}
	p.dataOwner.once.Do(func() {
		pool.Put(p.DATA)
		p.DATA = nil
	})
}

func NewPacket(ASSOC_ID uint16, PKT_ID uint16, FRGA_TOTAL uint8, FRAG_ID uint8, SIZE uint16, ADDR *Address, DATA []byte, VER byte) *Packet {
	return &Packet{
		CommandHead: NewCommandHead(PacketType, VER),
		ASSOC_ID:    ASSOC_ID,
		PKT_ID:      PKT_ID,
		FRAG_ID:     FRAG_ID,
		FRAG_TOTAL:  FRGA_TOTAL,
		SIZE:        SIZE,
		ADDR:        ADDR,
		DATA:        DATA,
	}
}

func ReadPacketWithHead(head *CommandHead, reader BufferedReader) (c *Packet, err error) {
	var _c Packet
	_c.CommandHead = head
	if _c.TYPE != PacketType {
		err = fmt.Errorf("error command type: %s", _c.TYPE)
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.ASSOC_ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.PKT_ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.FRAG_TOTAL)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.FRAG_ID)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &_c.SIZE)
	if err != nil {
		return nil, err
	}
	_c.ADDR, err = ReadAddress(reader)
	if err != nil {
		return nil, err
	}
	_c.DATA = make([]byte, _c.SIZE)
	_, err = io.ReadFull(reader, _c.DATA)
	if err != nil {
		return nil, err
	}
	return &_c, nil
}

func (c Packet) WriteTo(writer BufferedWriter) (err error) {
	// Serialize straight into the writer's tail when it supports Extend
	// (pool/bytes.Buffer), skipping the intermediate heap buffer and extra
	// copy of the scratch path. BytesLen is exact, so the extended region
	// needs no truncation.
	if ext, ok := writer.(interface {
		Extend(n int)
		Len() int
		Bytes() []byte
	}); ok {
		start := ext.Len()
		ext.Extend(c.BytesLen())
		_ = c.WriteToBytes(ext.Bytes()[start:])
		return nil
	}
	buf := make([]byte, c.BytesLen())
	n := c.WriteToBytes(buf)
	_, err = writer.Write(buf[:n])
	return
}

// WriteToBytes serializes the Packet into a caller-provided buffer using
// direct binary.BigEndian writes, avoiding the per-field binary.Write
// reflection allocations of WriteTo. The buffer must be at least
// c.BytesLen() bytes long.
func (c Packet) WriteToBytes(b []byte) (n int) {
	n += c.CommandHead.WriteToBytes(b)
	binary.BigEndian.PutUint16(b[n:], c.ASSOC_ID)
	n += 2
	binary.BigEndian.PutUint16(b[n:], c.PKT_ID)
	n += 2
	b[n] = c.FRAG_TOTAL
	n += 1
	b[n] = c.FRAG_ID
	n += 1
	binary.BigEndian.PutUint16(b[n:], c.SIZE)
	n += 2
	n += c.ADDR.WriteToBytes(b[n:])
	n += copy(b[n:], c.DATA)
	return n
}

func (c Packet) BytesLen() int {
	// Fixed fields: ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2) = 8
	return c.CommandHead.BytesLen() + 8 + c.ADDR.BytesLen() + len(c.DATA)
}

type Dissociate struct {
	*CommandHead
	ASSOC_ID uint16
}

func NewDissociate(ASSOC_ID uint16, VER byte) *Dissociate {
	return &Dissociate{
		CommandHead: NewCommandHead(DissociateType, VER),
		ASSOC_ID:    ASSOC_ID,
	}
}

func (c Dissociate) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.ASSOC_ID)
	if err != nil {
		return
	}
	return
}

func (c Dissociate) BytesLen() int {
	return c.CommandHead.BytesLen() + 4
}

// Addr types
const (
	AtypDomainName byte = 0
	AtypIPv4       byte = 1
	AtypIPv6       byte = 2
	AtypNone       byte = 255 // Address type None is used in Packet commands that is not the first fragment of a UDP packet.
)

type Address struct {
	TYPE byte
	ADDR []byte
	PORT uint16
}

func NewAddress(metadata *protocol.Metadata) *Address {
	var addrType byte
	var addr []byte
	switch metadata.Type {
	case protocol.MetadataTypeIPv4:
		addrType = AtypIPv4
		if metadata.IP.Is4() {
			ip4 := metadata.IP.As4()
			addr = ip4[:]
		} else {
			addr = net.ParseIP(metadata.Hostname).To4()
		}
	case protocol.MetadataTypeIPv6:
		addrType = AtypIPv6
		if metadata.IP.IsValid() && !metadata.IP.Is4() {
			ip16 := metadata.IP.As16()
			addr = ip16[:]
		} else {
			addr = net.ParseIP(metadata.Hostname).To16()
		}
	case protocol.MetadataTypeDomain:
		addrType = AtypDomainName
		addr = make([]byte, len(metadata.Hostname)+1)
		addr[0] = byte(len(metadata.Hostname))
		copy(addr[1:], metadata.Hostname)
	}

	return &Address{
		TYPE: addrType,
		ADDR: addr,
		PORT: metadata.Port,
	}
}

func NewAddressAddrPort(addrPort netip.AddrPort) *Address {
	var addrType byte
	port := addrPort.Port()
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		addrType = AtypIPv4
	} else {
		addrType = AtypIPv6
	}
	return &Address{
		TYPE: addrType,
		ADDR: addr.AsSlice(),
		PORT: port,
	}
}

func ReadAddress(reader BufferedReader) (c *Address, err error) {
	var _c Address
	_c.TYPE, err = reader.ReadByte()
	if err != nil {
		return
	}
	switch _c.TYPE {
	case AtypIPv4:
		_c.ADDR = make([]byte, net.IPv4len)
		_, err = io.ReadFull(reader, _c.ADDR)
		if err != nil {
			return
		}
	case AtypIPv6:
		_c.ADDR = make([]byte, net.IPv6len)
		_, err = io.ReadFull(reader, _c.ADDR)
		if err != nil {
			return
		}
	case AtypDomainName:
		var addrLen byte
		addrLen, err = reader.ReadByte()
		if err != nil {
			return
		}
		_c.ADDR = make([]byte, addrLen+1)
		_c.ADDR[0] = addrLen
		_, err = io.ReadFull(reader, _c.ADDR[1:])
		if err != nil {
			return
		}
	}

	if _c.TYPE == AtypNone {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &_c.PORT)
	if err != nil {
		return
	}
	return &_c, nil
}

func (c Address) WriteTo(writer BufferedWriter) (err error) {
	err = writer.WriteByte(c.TYPE)
	if err != nil {
		return
	}
	if c.TYPE == AtypNone {
		return
	}
	_, err = writer.Write(c.ADDR[:])
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.PORT)
	if err != nil {
		return
	}
	return
}

func (c Address) WriteToBytes(b []byte) (n int) {
	b[0] = c.TYPE
	if c.TYPE == AtypNone {
		// The type byte alone is serialized; returning 0 here would make
		// the caller lay the payload over it and shift the frame.
		return 1
	}
	n = copy(b[1:], c.ADDR)
	binary.BigEndian.PutUint16(b[1+n:], c.PORT)
	return 3 + n
}

func (c Address) String() string {
	switch c.TYPE {
	case AtypDomainName:
		return net.JoinHostPort(string(c.ADDR[1:]), strconv.Itoa(int(c.PORT)))
	default:
		addr, _ := netip.AddrFromSlice(c.ADDR)
		addrPort := netip.AddrPortFrom(addr, c.PORT)
		return addrPort.String()
	}
}

func (c Address) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   c.ADDR,
		Port: int(c.PORT),
		Zone: "",
	}
}

// UDPAddrPort returns the address as a netip.AddrPort without the
// intermediate net.UDPAddr allocation, for per-datagram receive paths.
// Domain-typed addresses fall back to UDPAddr and yield an invalid AddrPort,
// exactly like the previous UDPAddr().AddrPort() chain.
func (c Address) UDPAddrPort() netip.AddrPort {
	if addr, ok := netip.AddrFromSlice(c.ADDR); ok {
		return netip.AddrPortFrom(addr, c.PORT)
	}
	return c.UDPAddr().AddrPort()
}

func (c Address) BytesLen() int {
	if c.TYPE == AtypNone {
		// Mirror the serializers: only the type byte goes on the wire.
		return 1
	}
	return 1 + len(c.ADDR) + 2
}

const (
	ProtocolError         = quic.ApplicationErrorCode(0xfffffff0)
	AuthenticationFailed  = quic.ApplicationErrorCode(0xfffffff1)
	AuthenticationTimeout = quic.ApplicationErrorCode(0xfffffff2)
	BadCommand            = quic.ApplicationErrorCode(0xfffffff3)
)
