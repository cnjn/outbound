package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	disk_bloom "github.com/mzz2017/disk-bloom"
)

// [LEGACY] Global switch for UDP cipher cache optimization (kept for reference):
// This optimization is now always enabled for 5x+ performance improvement.
// var enableUDPCipherCache int32 = 1 // enabled by default
//
// func EnableUDPCipherCache(enable bool) {
//     if enable {
//         atomic.StoreInt32(&enableUDPCipherCache, 1)
//     } else {
//         atomic.StoreInt32(&enableUDPCipherCache, 0)
//     }
// }
//
// func isUDPCipherCacheEnabled() bool {
//     return atomic.LoadInt32(&enableUDPCipherCache) == 1
// }

type UdpConn struct {
	netproxy.PacketConn

	proxyAddress string

	metadata   protocol.Metadata
	cipherConf *ciphers.CipherConf
	masterKey  []byte
	bloom      *disk_bloom.FilterGroup
	sg         *RandomSaltGenerator

	tgtAddr string
	target  common.LastStringValue[protocol.Metadata]
}

var _ netproxy.PacketReceiver = (*UdpConn)(nil)

func (c *UdpConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := c.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, c.mapReceivedPacket)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped transport: SetWriteDeadline is
// delegated to the underlying PacketConn unchanged, so the semantics — and
// the declaration — belong to that transport, not to this wrapper.
func (c *UdpConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.PacketConn)
}

func (c *UdpConn) mapReceivedPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	key := &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}
	decoded := pool.Get(len(packet.Data))
	n, err := DecryptUDP(decoded[:0], key, packet.Data, ShadowsocksReusedInfo)
	if err != nil {
		decoded.Put()
		packet.Err = err
		packet.Data = nil
		return packet, true
	}

	if c.bloom != nil {
		if exist := c.bloom.ExistOrAdd(packet.Data[:c.cipherConf.SaltLen]); exist {
			decoded.Put()
			packet.Err = protocol.ErrReplayAttack
			packet.Data = nil
			return packet, true
		}
	}
	payload, from, err := splitDecryptedUdp(decoded[:n])
	if err != nil {
		decoded.Put()
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	return netproxy.NewReceivedPacket(
		payload,
		from,
		nil,
		func() { decoded.Put() },
	), true
}

var parseMetadata = protocol.ParseMetadata

// splitDecryptedUdp splits one decrypted legacy-SS UDP payload into the
// reply payload and its source address. Shared by the polling ReadFrom and
// the push-mode receiver so the two decode paths cannot drift.
func splitDecryptedUdp(plain []byte) (payload []byte, from netip.AddrPort, err error) {
	sizeMetadata, err := BytesSizeForMetadata(plain)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	mdata, err := NewMetadata(plain)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	switch mdata.Type {
	case protocol.MetadataTypeIPv4, protocol.MetadataTypeIPv6:
		if !mdata.IP.IsValid() {
			return nil, netip.AddrPort{}, fmt.Errorf("ip metadata without a parsed address (type %v)", mdata.Type)
		}
	default:
		return nil, netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", mdata.Type)
	}
	return plain[sizeMetadata:], netip.AddrPortFrom(mdata.IP, mdata.Port), nil
}

func NewUdpConn(conn netproxy.PacketConn, proxyAddress string, metadata protocol.Metadata, masterKey []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	conf := ciphers.AeadCiphersConf[metadata.Cipher]
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	sg := NewRandomSaltGenerator(conf.SaltLen)
	c := &UdpConn{
		PacketConn:   conn,
		proxyAddress: proxyAddress,
		metadata:     metadata,
		cipherConf:   conf,
		masterKey:    key,
		bloom:        bloom,
		sg:           sg,
		tgtAddr:      net.JoinHostPort(metadata.Hostname, strconv.Itoa(int(metadata.Port))),
	}
	return c, nil
}

func (c *UdpConn) Close() error {
	return c.PacketConn.Close()
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.tgtAddr)
}

// maxMetadataLen returns the maximum possible metadata length for pre-allocation.
// IPv6 (1 + 16 + 2) = 19 bytes is the maximum.

// metadataForWrite resolves the per-datagram destination into the session's
// write metadata. Shared by WriteTo and WriteBatch so the two send paths
// cannot drift.
func (c *UdpConn) metadataForWrite(addr string) (Metadata, error) {
	metadata := Metadata{
		Metadata: c.metadata,
	}
	mdata, err := c.metadataForAddr(addr)
	if err != nil {
		return Metadata{}, err
	}
	metadata.Hostname = mdata.Hostname
	metadata.Port = mdata.Port
	metadata.Type = mdata.Type
	metadata.IP = mdata.IP

	if metadata.Type == protocol.MetadataTypeDomain && len(metadata.Hostname) > 255 {
		// Reject rather than truncate: a silently shortened domain would send
		// the datagram to the wrong host.
		return Metadata{}, fmt.Errorf("domain name too long: %d", len(metadata.Hostname))
	}
	return metadata, nil
}

// sealToPool seals one datagram (salt + metadata + payload, AEAD tag) into a
// pool buffer that the caller owns and must pool.Put. Shared by WriteTo and
// WriteBatch.
func (c *UdpConn) sealToPool(metadata *Metadata, b []byte) (out pool.PB, err error) {
	// Layout: [salt][metadata][payload][tag]
	prefixLen := metadataLen(metadata.Type)
	totalLen := c.cipherConf.SaltLen + prefixLen + len(b) + c.cipherConf.TagLen
	buf := pool.Get(totalLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()

	// Write salt at the beginning
	salt := c.sg.Get()
	copy(buf, salt)
	pool.Put(salt)

	// Write metadata inline after salt
	offset := c.cipherConf.SaltLen
	offset += writeMetadataInline(buf[offset:], metadata)

	// Write payload
	copy(buf[offset:], b)
	payloadEnd := offset + len(b)

	// Encrypt in-place
	key := &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}
	toWrite, err := encryptUDPInPlace(key, buf, payloadEnd, ShadowsocksReusedInfo)
	if err != nil {
		return nil, err
	}
	return toWrite, nil
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	metadata, err := c.metadataForWrite(addr)
	if err != nil {
		return 0, err
	}
	toWrite, err := c.sealToPool(&metadata, b)
	if err != nil {
		return 0, err
	}
	defer pool.Put(toWrite)

	if c.bloom != nil {
		c.bloom.ExistOrAdd(toWrite[:c.cipherConf.SaltLen])
	}
	return c.PacketConn.WriteTo(toWrite, c.proxyAddress)
}

// WriteBatch implements netproxy.PacketBatchWriter: seal every datagram
// independently (each is its own UDP datagram with its own salt) and hand the
// sealed batch to the underlying transport's batched writer in one call,
// amortizing the per-item syscall the same way the socks5 wrapper does. When
// the underlay has no batched writer the items fall back to sequential
// synchronous sends, preserving order. Every destination is resolved and
// sealed before anything is sent, so a pre-send failure is all-or-nothing
// (n == 0).
func (c *UdpConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	metadatas := make([]Metadata, len(items))
	for i, item := range items {
		metadata, err := c.metadataForWrite(item.Addr)
		if err != nil {
			return 0, err
		}
		metadatas[i] = metadata
	}
	sealed := make([]pool.PB, len(items))
	for i, item := range items {
		s, err := c.sealToPool(&metadatas[i], item.Data)
		if err != nil {
			for _, prev := range sealed[:i] {
				pool.Put(prev)
			}
			return 0, err
		}
		sealed[i] = s
	}
	if bw, ok := c.PacketConn.(netproxy.PacketBatchWriter); ok {
		defer func() {
			for _, s := range sealed {
				pool.Put(s)
			}
		}()
		if c.bloom != nil {
			for _, s := range sealed {
				c.bloom.ExistOrAdd(s[:c.cipherConf.SaltLen])
			}
		}
		enc := make([]netproxy.BatchItem, len(items))
		for i, s := range sealed {
			enc[i] = netproxy.BatchItem{Data: s, Addr: c.proxyAddress}
		}
		return bw.WriteBatch(enc)
	}
	// No batched underlay: sequential synchronous sends in order. Each sealed
	// datagram returns to the pool right after its send.
	sent := 0
	for i := range items {
		if c.bloom != nil {
			c.bloom.ExistOrAdd(sealed[i][:c.cipherConf.SaltLen])
		}
		_, err := c.PacketConn.WriteTo(sealed[i], c.proxyAddress)
		pool.Put(sealed[i])
		sealed[i] = nil
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (c *UdpConn) metadataForAddr(addr string) (protocol.Metadata, error) {
	if cached, ok := c.target.Load(addr); ok {
		return cached, nil
	}
	mdata, err := parseMetadata(addr)
	if err != nil {
		return protocol.Metadata{}, err
	}
	c.target.Store(addr, mdata)
	return mdata, nil
}

// metadataLen returns the length of metadata for a given type.
func metadataLen(typ protocol.MetadataType) int {
	switch typ {
	case protocol.MetadataTypeIPv4:
		return 1 + 4 + 2 // type + ipv4 + port
	case protocol.MetadataTypeIPv6:
		return 1 + 16 + 2 // type + ipv6 + port
	case protocol.MetadataTypeDomain:
		return 1 + 1 + 255 + 2 // type + len + max domain + port (will be truncated)
	case protocol.MetadataTypeMsg:
		return 1 + 1 + 4 // type + cmd + len
	default:
		return 19 // max possible
	}
}

// writeMetadataInline writes metadata directly to the buffer without extra allocation.
func writeMetadataInline(buf []byte, meta *Metadata) int {
	buf[0] = MetadataTypeToByte(meta.Type)
	switch meta.Type {
	case protocol.MetadataTypeIPv4:
		if meta.IP.Is4() {
			ip4 := meta.IP.As4()
			copy(buf[1:], ip4[:])
		} else if ip := net.ParseIP(meta.Hostname); ip != nil {
			copy(buf[1:], ip.To4()[:4])
		}
		binary.BigEndian.PutUint16(buf[5:], meta.Port)
		return 7
	case protocol.MetadataTypeIPv6:
		if meta.IP.IsValid() && !meta.IP.Is4() {
			ip16 := meta.IP.As16()
			copy(buf[1:], ip16[:])
		} else if ip := net.ParseIP(meta.Hostname); ip != nil {
			copy(buf[1:], ip[:16])
		}
		binary.BigEndian.PutUint16(buf[17:], meta.Port)
		return 19
	case protocol.MetadataTypeDomain:
		hostname := []byte(meta.Hostname)
		lenDN := len(hostname)
		if lenDN > 255 {
			lenDN = 255
		}
		buf[1] = uint8(lenDN)
		copy(buf[2:], hostname[:lenDN])
		binary.BigEndian.PutUint16(buf[2+lenDN:], meta.Port)
		return 4 + lenDN
	case protocol.MetadataTypeMsg:
		buf[1] = uint8(meta.Cmd)
		binary.BigEndian.PutUint32(buf[2:], meta.LenMsgBody)
		return 6
	default:
		return 0
	}
}

// encryptUDPInPlace encrypts the buffer in place, returning the final packet.
func encryptUDPInPlace(key *Key, buf []byte, payloadLen int, reusedInfo []byte) (pool.PB, error) {
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)

	deriveSubKey(subKey, key.MasterKey, buf[:key.CipherConf.SaltLen], reusedInfo)

	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}

	// Seal in-place: we need space for tag at the end
	// Input is buf[saltLen:payloadLen], output goes to buf[saltLen:payloadLen+tagLen]
	encrypted := ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen],
		ciphers.ZeroNonce[:key.CipherConf.NonceLen],
		buf[key.CipherConf.SaltLen:payloadLen],
		nil)

	return buf[:key.CipherConf.SaltLen+len(encrypted)], nil
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	enc := pool.Get(len(b) + c.cipherConf.SaltLen)
	defer pool.Put(enc)
	n, addr, err = c.PacketConn.ReadFrom(enc)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	key := &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
	}

	n, err = DecryptUDP(b, key, enc[:n], ShadowsocksReusedInfo)

	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.bloom != nil {
		if exist := c.bloom.ExistOrAdd(enc[:c.cipherConf.SaltLen]); exist {
			err = protocol.ErrReplayAttack
			return
		}
	}
	payload, addr, err := splitDecryptedUdp(b[:n])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n = copy(b, payload)
	return n, addr, nil
}
