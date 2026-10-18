package shadowsocks_2022

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20poly1305"
)

// UdpConn represents a Shadowsocks 2022 UDP connection.
// Design follows sing-box: cipher is created once at session initialization.
type UdpConn struct {
	*SS2022Core

	net.Conn

	sessionID [8]byte
	packetID  atomic.Uint64

	// cipher is derived from the local session ID and reused for outbound
	// packets. Inbound packets must decrypt against the remote session ID
	// carried in each packet, so they use decryptCiphers instead.
	cipher     cipher.AEAD
	cipherOnce sync.Once
	cipherErr  error

	// decryptCiphersMu guards decryptCiphers to allow bounded eviction
	// without the race-prone sync.Map Range+Delete pattern.
	decryptCiphersMu sync.Mutex
	// decryptCiphers caches inbound AEAD instances by remote session ID.
	// Keeping this per-UdpConn avoids the old process-wide cache while
	// preserving the protocol requirement that receive-side decryption uses
	// the sender's session ID, not the local one.
	decryptCiphers map[[8]byte]cipher.AEAD

	bloom *disk_bloom.FilterGroup

	replayWindow sync.Map
	replayCount  atomic.Int64

	cleanupCounter atomic.Int64
	targetCache    common.LastStringValue[socks5.AddressInfo]
}

var parseAddressInfo = socks5.AddressFromString

const (
	udpPacketReplayWindowSize = 1024
	maxTrackedUdpSessions     = 128
	udpPacketNonceSize        = 24
	maxDecryptCipherEntries   = 64
	decryptCipherLowWatermark = maxDecryptCipherEntries / 2
)

type udpSessionReplayState struct {
	filter   *ciphers.SlidingWindowFilter
	lastSeen atomic.Int64
}

// NewUdpConn creates a new UDP connection bound to a shared SS2022 profile.
// The connection is not bound to the dial context: UDP sessions are
// long-lived and must not be torn down by the dial's timeout or cancellation.
func NewUdpConn(conn net.Conn, core *SS2022Core, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := &UdpConn{
		SS2022Core:     core,
		Conn:           conn,
		bloom:          bloom,
		decryptCiphers: make(map[[8]byte]cipher.AEAD, 16),
	}

	// Generate session ID
	_, _ = fastrand.Read(u.sessionID[:])
	return u, nil
}

func (c *UdpConn) ensureCipher() error {
	c.cipherOnce.Do(func() {
		if !c.IsUsingBlockCipher() {
			c.cipher, c.cipherErr = chacha20poly1305.NewX(c.UPSK())
		} else {
			c.cipher, c.cipherErr = CreateCipher(c.UPSK(), c.sessionID[:], c.CipherConf())
		}
		if c.cipherErr != nil {
			c.cipherErr = fmt.Errorf("failed to create session cipher: %w", c.cipherErr)
		}
	})
	return c.cipherErr
}

func (c *UdpConn) decryptCipherFor(sessionID [8]byte) (cipher.AEAD, error) {
	c.decryptCiphersMu.Lock()
	defer c.decryptCiphersMu.Unlock()

	if cached, ok := c.decryptCiphers[sessionID]; ok {
		return cached, nil
	}

	sessionCipher, err := CreateCipher(c.UPSK(), sessionID[:], c.CipherConf())
	if err != nil {
		return nil, fmt.Errorf("failed to create decrypt cipher for remote session: %w", err)
	}

	// Trim the cache back to a lower watermark once it reaches the cap so a
	// burst of new remote sessions does not pay an eviction penalty on every
	// subsequent miss while still keeping the memory usage bounded.
	if len(c.decryptCiphers) >= maxDecryptCipherEntries {
		// Map iteration order is intentionally unspecified, which is good enough
		// for approximate eviction because remote sessions rotate frequently.
		toDelete := len(c.decryptCiphers) - decryptCipherLowWatermark + 1
		for k := range c.decryptCiphers {
			delete(c.decryptCiphers, k)
			toDelete--
			if toDelete == 0 {
				break
			}
		}
	}

	c.decryptCiphers[sessionID] = sessionCipher
	return sessionCipher, nil
}

func (c *UdpConn) nextPacketID() uint64 {
	return c.packetID.Add(1)
}

func (c *UdpConn) checkAndUpdateReplay(sessionID [8]byte, packetID uint64, now time.Time) bool {
	nowNano := now.UnixNano()
	expireNano := ciphers.SaltStorageDuration.Nanoseconds()

	if v, ok := c.replayWindow.Load(sessionID); ok {
		state := v.(*udpSessionReplayState)
		lastSeen := state.lastSeen.Load()
		if nowNano-lastSeen > expireNano {
			if c.replayWindow.CompareAndDelete(sessionID, v) {
				c.replayCount.Add(-1)
			}
		} else {
			state.lastSeen.Store(nowNano)
			return state.filter.CheckAndUpdate(packetID)
		}
	}

	if c.cleanupCounter.Add(1)%cleanupInterval == 0 {
		go c.cleanupExpiredSessions(nowNano, expireNano)
	}

	newState := &udpSessionReplayState{
		filter: ciphers.NewSlidingWindowFilter(udpPacketReplayWindowSize),
	}
	newState.lastSeen.Store(nowNano)

	actual, loaded := c.replayWindow.LoadOrStore(sessionID, newState)
	state := actual.(*udpSessionReplayState)

	if loaded {
		state.lastSeen.Store(nowNano)
	} else {
		c.replayCount.Add(1)
		c.evictOldestIfNeeded()
	}

	return state.filter.CheckAndUpdate(packetID)
}

const cleanupInterval = 1000

func (c *UdpConn) cleanupExpiredSessions(nowNano, expireNano int64) {
	c.replayWindow.Range(func(key, value interface{}) bool {
		state := value.(*udpSessionReplayState)
		if nowNano-state.lastSeen.Load() > expireNano {
			if c.replayWindow.CompareAndDelete(key, value) {
				c.replayCount.Add(-1)
			}
		}
		return true
	})
}

// evictOldestIfNeeded trims the replay-session table back to its cap, but only
// ever removes sessions that are already past SaltStorageDuration.
//
// The cap alone was the wrong-only criterion: SIP022 requires a session's
// replay window to be retained for SaltStorageDuration (60s), and a burst of
// new remote sessions could evict a session that is still inside that window.
// The evicted session's window would be rebuilt empty on its next packet,
// which re-admits every packet ID already seen for it - a deduplication
// downgrade. Sessions that are too young to remove are deliberately left
// tracked: exceeding the cap is a memory concern, losing replay protection is
// a security one, and the excess is bounded by the arrival rate over one
// SaltStorageDuration.
func (c *UdpConn) evictOldestIfNeeded() {
	nowNano := time.Now().UnixNano()
	expireNano := ciphers.SaltStorageDuration.Nanoseconds()

	for c.replayCount.Load() > maxTrackedUdpSessions {
		var (
			found      bool
			oldestKey  [8]byte
			oldestVal  any
			oldestNano = ^int64(0)
		)

		c.replayWindow.Range(func(key, value interface{}) bool {
			state := value.(*udpSessionReplayState)
			seen := state.lastSeen.Load()
			// Age filter: only sessions already past the required retention
			// period are candidates.
			if nowNano-seen <= expireNano {
				return true
			}
			if !found || seen < oldestNano {
				found = true
				oldestKey = key.([8]byte)
				oldestVal = value
				oldestNano = seen
			}
			return true
		})

		if !found {
			// Every tracked session is still inside its retention window.
			// Stop rather than evicting one early; the periodic
			// cleanupExpiredSessions sweep will collect them once they age
			// out.
			return
		}
		if c.replayWindow.CompareAndDelete(oldestKey, oldestVal) {
			c.replayCount.Add(-1)
			continue
		}
		// Retry if the oldest entry changed concurrently.
	}
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	if err := c.ensureCipher(); err != nil {
		return 0, err
	}
	addrInfo, err := c.targetAddrInfo(addr)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to parse target address")
	}
	packetID := c.nextPacketID()
	var packet pool.PB
	if c.IsUsingBlockCipher() {
		packet, err = c.sealBlockPacket(b, &addrInfo, packetID)
	} else {
		packet, err = c.sealChachaPacket(b, &addrInfo, packetID)
	}
	if err != nil {
		return 0, err
	}
	defer pool.Put(packet)

	n, err := c.Write(packet)
	if err != nil {
		return 0, err
	}
	if n < len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

// sealBlockPacket seals one datagram for the AES-based ciphers into a pool
// buffer owned by the caller. Shared by WriteTo and WriteBatch so the two
// send paths cannot drift.
func (c *UdpConn) sealBlockPacket(b []byte, addrInfo *socks5.AddressInfo, packetID uint64) (out pool.PB, err error) {
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return nil, oops.Wrapf(err, "fail to calculate address length")
	}

	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	c.BlockCipherEncrypt().Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	messageLen := 1 + 8 + 2 + addrLen + len(b)
	totalPacketLen := len(separateHeaderEncrypted) + c.IdentityHeaderLen() + messageLen + c.CipherConf().TagLen
	packet := pool.Get(totalPacketLen)
	defer func() {
		if err != nil {
			pool.Put(packet)
		}
	}()
	offset := 0
	copy(packet[offset:], separateHeaderEncrypted[:])
	offset += len(separateHeaderEncrypted)

	identityHeaderLen, err := c.WriteIdentityHeader(packet[offset:], separateHeader[:])
	if err != nil {
		return nil, oops.Wrapf(err, "fail to write identity header")
	}
	offset += identityHeaderLen

	messageOffset := offset
	message := packet[messageOffset : messageOffset+messageLen]
	message[0] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(message[9:11], 0)
	addrWritten, err := writeAddrInfoTo(message[11:], addrInfo)
	if err != nil {
		return nil, oops.Wrapf(err, "fail to encode request address")
	}
	copy(message[11+addrWritten:], b)

	// Use session-level cipher (no cache lookup needed)
	return c.cipher.Seal(packet[:messageOffset], separateHeader[4:16], message, nil), nil
}

// sealChachaPacket seals one datagram for the chacha-based ciphers into a
// pool buffer owned by the caller. Shared by WriteTo and WriteBatch so the
// two send paths cannot drift.
func (c *UdpConn) sealChachaPacket(b []byte, addrInfo *socks5.AddressInfo, packetID uint64) (out pool.PB, err error) {
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return nil, oops.Wrapf(err, "fail to calculate address length")
	}

	// Packet structure: nonce + message. EIH never applies here: multi-PSK is
	// only constructed with an AES cipher, which WriteTo routes to the block
	// path, so this chacha path is always single-PSK.
	messageLen := 16 + 1 + 8 + 2 + addrLen + len(b)
	totalPacketLen := udpPacketNonceSize + messageLen + c.CipherConf().TagLen
	packet := pool.Get(totalPacketLen)
	defer func() {
		if err != nil {
			pool.Put(packet)
		}
	}()

	nonce := packet[:udpPacketNonceSize]
	_, _ = fastrand.Read(nonce)

	message := packet[udpPacketNonceSize : udpPacketNonceSize+messageLen]
	copy(message[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(message[8:16], packetID)
	message[16] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(message[17:25], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(message[25:27], 0)

	addrWritten, err := writeAddrInfoTo(message[27:], addrInfo)
	if err != nil {
		return nil, oops.Wrapf(err, "fail to encode request address")
	}
	copy(message[27+addrWritten:], b)

	// Seal the entire message
	return c.cipher.Seal(packet[:udpPacketNonceSize], nonce, message, nil), nil
}

// WriteBatch implements netproxy.PacketBatchWriter: seal every datagram
// independently (each is its own UDP datagram with its own packet ID or
// nonce) and hand the sealed batch to the underlay's batched writer when it
// has one (sendmmsg on a direct UDP socket), else send them sequentially.
// Every destination is resolved and sealed before anything is sent, so a
// pre-send failure is all-or-nothing (n == 0). Items leave with an empty
// Addr on the batched underlay path, matching WriteTo's connected write.
func (c *UdpConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	if err := c.ensureCipher(); err != nil {
		return 0, err
	}
	addrInfos := make([]socks5.AddressInfo, len(items))
	for i, item := range items {
		addrInfo, err := c.targetAddrInfo(item.Addr)
		if err != nil {
			return 0, oops.Wrapf(err, "fail to parse target address")
		}
		addrInfos[i] = addrInfo
	}
	packets := make([]pool.PB, len(items))
	for i, item := range items {
		packetID := c.nextPacketID()
		var packet pool.PB
		var err error
		if c.IsUsingBlockCipher() {
			packet, err = c.sealBlockPacket(item.Data, &addrInfos[i], packetID)
		} else {
			packet, err = c.sealChachaPacket(item.Data, &addrInfos[i], packetID)
		}
		if err != nil {
			for _, prev := range packets[:i] {
				pool.Put(prev)
			}
			return 0, err
		}
		packets[i] = packet
	}
	if bw, ok := c.Conn.(netproxy.PacketBatchWriter); ok {
		defer func() {
			for _, packet := range packets {
				pool.Put(packet)
			}
		}()
		enc := make([]netproxy.BatchItem, len(items))
		for i, packet := range packets {
			enc[i] = netproxy.BatchItem{Data: packet}
		}
		return bw.WriteBatch(enc)
	}
	// No batched underlay: sequential synchronous sends in order. Each sealed
	// datagram returns to the pool right after its send.
	sent := 0
	for i := range items {
		packet := packets[i]
		n, err := c.Write(packet)
		if err == nil && n < len(packet) {
			err = io.ErrShortWrite
		}
		pool.Put(packet)
		packets[i] = nil
		if err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func (c *UdpConn) targetAddrInfo(addr string) (socks5.AddressInfo, error) {
	if cached, ok := c.targetCache.Load(addr); ok {
		return cached, nil
	}
	addrInfo, err := parseAddressInfo(addr)
	if err != nil {
		return socks5.AddressInfo{}, err
	}
	c.targetCache.Store(addr, *addrInfo)
	return *addrInfo, nil
}

var _ netproxy.PacketReceiver = (*UdpConn)(nil)

func (c *UdpConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := c.Conn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, c.mapReceivedPacket)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn: the exported
// SetWriteDeadline is the promoted delegate of the embedded net.Conn, so the
// semantics — and the declaration — belong to that conn. A plain UDP socket
// reports false; a marker-bearing wrapper in its place reports true.
func (c *UdpConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *UdpConn) mapReceivedPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	var payload []byte
	var addr netip.AddrPort
	var err error
	if c.IsUsingBlockCipher() {
		payload, addr, err = c.decodeBlockPacket(packet.Data, time.Now())
	} else {
		payload, addr, err = c.decodeChachaPacket(packet.Data, time.Now())
	}
	if err != nil {
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	packet.Data = payload
	packet.From = addr
	return packet, true
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	if !c.IsUsingBlockCipher() {
		return c.readFromChacha(b)
	}

	buf := pool.Get(len(b) + 16 + c.CipherConf().TagLen)
	defer pool.Put(buf)
	n, err = c.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, addr, err := c.decodeBlockPacket(buf[:n], time.Now())
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return copy(b, payload), addr, nil
}

func (c *UdpConn) decodeBlockPacket(buf []byte, now time.Time) ([]byte, netip.AddrPort, error) {
	if len(buf) < 16 {
		return nil, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}
	c.BlockCipherDecrypt().Decrypt(buf[:16], buf[:16])
	var sessionID [8]byte
	copy(sessionID[:], buf[:8])
	packetID := binary.BigEndian.Uint64(buf[8:16])

	// Authenticate before committing anti-replay state (the same order the
	// chacha path below uses): the separate header carries no integrity of
	// its own, so committing the replay window first would let anyone who
	// knows a session ID push the window forward and permanently reject the
	// victim's later legitimate packets.
	payload := buf[16:]
	sessionCipher, err := c.decryptCipherFor(sessionID)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	payload, err = sessionCipher.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	// Validate the whole payload (header type + timestamp) before committing
	// the replay window, so this path holds the same "authenticate before
	// committing anti-replay state" line as the Open above and as the chacha
	// path. Committing on a packet that then fails validation would burn the
	// packet ID of a packet that was never delivered.
	out, addr, err := c.decodePacketPayload(payload, now)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return nil, netip.AddrPort{}, protocol.ErrReplayAttack
	}
	return out, addr, nil
}

func (c *UdpConn) readFromChacha(b []byte) (n int, addr netip.AddrPort, err error) {
	if err := c.ensureCipher(); err != nil {
		return 0, netip.AddrPort{}, err
	}

	buf := pool.Get(len(b) + udpPacketNonceSize + c.CipherConf().TagLen + 320)
	defer pool.Put(buf)
	n, err = c.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, addr, err := c.decodeChachaPacket(buf[:n], time.Now())
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if len(payload) > len(b) {
		// The decrypted datagram does not fit the caller's buffer. The read
		// buffer's slack (+320) lets the wire datagram arrive and
		// authenticate fully, so the oversize is known exactly here:
		// surface it as a dropped datagram per the typed read contract
		// instead of silently truncating a successful return.
		return 0, addr, netproxy.DatagramDropped(io.ErrShortBuffer)
	}
	return copy(b, payload), addr, nil
}

func (c *UdpConn) decodeChachaPacket(buf []byte, now time.Time) ([]byte, netip.AddrPort, error) {
	if err := c.ensureCipher(); err != nil {
		return nil, netip.AddrPort{}, err
	}
	if len(buf) < udpPacketNonceSize+c.CipherConf().TagLen+16 {
		return nil, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}
	nonce := buf[:udpPacketNonceSize]
	payload := buf[udpPacketNonceSize:]
	var err error
	payload, err = c.cipher.Open(payload[:0], nonce, payload, nil)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	// No EIH skip here: multi-PSK is only constructed with an AES cipher,
	// which WriteTo routes to the block path, so this chacha path always
	// carries a single-PSK datagram.
	var sessionID [8]byte
	copy(sessionID[:], payload[:8])
	packetID := binary.BigEndian.Uint64(payload[8:16])
	// Validate the whole payload (header type + timestamp) before committing
	// the replay window: a packet that decrypts but is malformed or stale must
	// not burn its ID in the window, and a forged-but-decryptable packet must
	// not advance it.
	out, addr, err := c.decodePacketPayload(payload[16:], now)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return nil, netip.AddrPort{}, protocol.ErrReplayAttack
	}
	return out, addr, nil
}

// decodePacketPayload validates the decrypted server datagram header and
// splits off the reply body. It parses by offset directly instead of through
// a bytes.Reader: this is the UDP receive hot path, and the shadowsocks
// legacy decoder (splitDecryptedUdp) already established the zero-alloc
// slicing pattern.
func (c *UdpConn) decodePacketPayload(payload []byte, now time.Time) ([]byte, netip.AddrPort, error) {
	// Fixed header: type(1) + timestamp(8) + session ID(8) + padding length(2).
	const fixedHeaderLen = 19
	if len(payload) < fixedHeaderLen {
		return nil, netip.AddrPort{}, fmt.Errorf("failed to read fixed header: %w", io.ErrUnexpectedEOF)
	}
	typ := payload[0]
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(payload[1:9])), 0)
	paddingLength := binary.BigEndian.Uint16(payload[17:19])
	offset := fixedHeaderLen + int(paddingLength)
	if offset > len(payload) {
		return nil, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", io.ErrUnexpectedEOF)
	}
	if typ != HeaderTypeServerStream {
		return nil, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}
	if err := validateTimestamp(timestamp, now); err != nil {
		return nil, netip.AddrPort{}, err
	}
	addr, addrLen, err := parseAddrPort(payload[offset:])
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	// A server datagram whose header and address consumed the whole payload
	// is legitimate: the address itself is the message (e.g. some
	// DNS/IP-ECHO style services reply with an empty body), so an empty
	// result is returned as-is rather than as an error.
	return payload[offset+addrLen:], addr, nil
}

// parseAddrPort reads the SOCKS-style address prefix of a decrypted server
// datagram and reports how many bytes it consumed. Server replies carry an
// IP address; a domain or other type is a protocol violation on this path.
func parseAddrPort(b []byte) (addr netip.AddrPort, n int, err error) {
	if len(b) < 1 {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: too short", socks5.ErrInvalidAddress)
	}
	switch socks5.AddressType(b[0]) {
	case socks5.AddressTypeIPv4:
		if len(b) < 1+4+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: too short", socks5.ErrInvalidAddress)
		}
		addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[1:5])), binary.BigEndian.Uint16(b[5:7]))
		return addr, 7, nil
	case socks5.AddressTypeIPv6:
		if len(b) < 1+16+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: too short", socks5.ErrInvalidAddress)
		}
		addr = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[1:17])), binary.BigEndian.Uint16(b[17:19]))
		return addr, 19, nil
	default:
		return netip.AddrPort{}, 0, fmt.Errorf("unsupported address type for UDP: %v", socks5.AddressType(b[0]))
	}
}
