package shadowsocks_2022

import (
	"encoding/binary"
	stderrors "errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"golang.org/x/crypto/chacha20poly1305"
)

type udpReadBufferConn struct {
	packet []byte
	read   bool
}

type udpReceiverConn struct {
	*udpReadBufferConn
	handler netproxy.PacketReceiveHandler
}

func (c *udpReceiverConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	c.handler = handler
	return func() { c.handler = nil }, true
}

func (c *udpReceiverConn) emit(packet *netproxy.ReceivedPacket) bool {
	if c.handler == nil {
		return false
	}
	return c.handler(packet)
}

func (c *udpReadBufferConn) Read(p []byte) (int, error) {
	if c.read {
		return 0, io.EOF
	}
	c.read = true
	copy(p, c.packet)
	return len(c.packet), nil
}

func (c *udpReadBufferConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *udpReadBufferConn) Close() error                       { return nil }
func (c *udpReadBufferConn) LocalAddr() net.Addr                { return udpConnTestAddr("local") }
func (c *udpReadBufferConn) RemoteAddr() net.Addr               { return udpConnTestAddr("remote") }
func (c *udpReadBufferConn) SetDeadline(_ time.Time) error      { return nil }
func (c *udpReadBufferConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *udpReadBufferConn) SetWriteDeadline(_ time.Time) error { return nil }

type udpConnTestAddr string

func (a udpConnTestAddr) Network() string { return "udp-test" }
func (a udpConnTestAddr) String() string  { return string(a) }

func buildServerPacket(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte) []byte {
	t.Helper()

	var separateHeader [16]byte
	copy(separateHeader[:8], serverSessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	core.BlockCipherDecrypt().Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString: %v", err)
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		t.Fatalf("addrInfoEncodedLen: %v", err)
	}

	messageLen := 1 + 8 + 8 + 2 + addrLen + len(payload)
	message := make([]byte, messageLen)
	message[0] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	copy(message[9:17], clientSessionID[:])
	addrWritten, err := writeAddrInfoTo(message[19:], addrInfo)
	if err != nil {
		t.Fatalf("writeAddrInfoTo: %v", err)
	}
	copy(message[19+addrWritten:], payload)

	sessionCipher, err := CreateCipher(core.UPSK(), serverSessionID[:], core.CipherConf())
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}
	return sessionCipher.Seal(separateHeaderEncrypted[:], separateHeader[4:16], message, nil)
}

func buildServerPacketChacha(t *testing.T, core *SS2022Core, serverSessionID, clientSessionID [8]byte, packetID uint64, addr string, payload []byte) []byte {
	t.Helper()

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		t.Fatalf("AddressFromString: %v", err)
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		t.Fatalf("addrInfoEncodedLen: %v", err)
	}

	messageLen := 16 + 1 + 8 + 8 + 2 + addrLen + len(payload)
	message := make([]byte, messageLen)
	copy(message[:8], serverSessionID[:])
	binary.BigEndian.PutUint64(message[8:16], packetID)
	message[16] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(message[17:25], uint64(time.Now().Unix()))
	copy(message[25:33], clientSessionID[:])
	addrWritten, err := writeAddrInfoTo(message[35:], addrInfo)
	if err != nil {
		t.Fatalf("writeAddrInfoTo: %v", err)
	}
	copy(message[35+addrWritten:], payload)

	udpCipher, err := chacha20poly1305.NewX(core.UPSK())
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}

	nonce := make([]byte, udpPacketNonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}

	packet := make([]byte, udpPacketNonceSize, udpPacketNonceSize+messageLen+core.CipherConf().TagLen)
	copy(packet, nonce)
	return udpCipher.Seal(packet, nonce, message, nil)
}

func TestValidateTimestamp(t *testing.T) {
	now := time.Now()
	if err := validateTimestamp(now, now); err != nil {
		t.Fatalf("now should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance-time.Millisecond), now); err != nil {
		t.Fatalf("near-future timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance+time.Millisecond), now); err != nil {
		t.Fatalf("near-past timestamp should pass: %v", err)
	}
	if err := validateTimestamp(now.Add(ciphers.TimestampTolerance+time.Millisecond), now); err != protocol.ErrTimestampExpired {
		t.Fatalf("too-far future timestamp should fail with an expired timestamp, got: %v", err)
	}
	if err := validateTimestamp(now.Add(-ciphers.TimestampTolerance-time.Millisecond), now); err != protocol.ErrTimestampExpired {
		t.Fatalf("too-old timestamp should fail with an expired timestamp, got: %v", err)
	}
}

// TestTimestampExpiryIsDistinguishableFromReplay pins the classification split:
// a rejected timestamp reports its own cause, and a replayed packet ID keeps
// reporting a replay. A consumer that reacts to one of them must therefore say
// so explicitly instead of inheriting the other's behaviour.
func TestTimestampExpiryIsDistinguishableFromReplay(t *testing.T) {
	now := time.Now()
	stale := validateTimestamp(now.Add(-ciphers.TimestampTolerance-time.Second), now)
	if stale == nil {
		t.Fatal("a stale timestamp must be rejected")
	}
	if !stderrors.Is(stale, protocol.ErrTimestampExpired) {
		t.Fatalf("stale timestamp error = %v, want ErrTimestampExpired", stale)
	}
	if stderrors.Is(stale, protocol.ErrReplayAttack) {
		t.Fatalf("stale timestamp error = %v, must not be classified as a replay", stale)
	}

	replay := protocol.ErrReplayAttack
	if !stderrors.Is(replay, protocol.ErrReplayAttack) || stderrors.Is(replay, protocol.ErrTimestampExpired) {
		t.Fatalf("replay error = %v, want it classified as a replay only", replay)
	}

	// The UDP replay window keeps reporting a plain replay: the split moved the
	// timestamp rejection out of ErrReplayAttack and left this decision intact.
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}
	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x11
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	conn, err := NewUdpConn(&udpReadBufferConn{}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.checkAndUpdateReplay(sessionID, 7, now) {
		t.Fatal("the first packet of a session must be accepted")
	}
	if conn.checkAndUpdateReplay(sessionID, 7, now) {
		t.Fatal("a repeated packet ID must be rejected")
	}
}

func TestUdpConn_NextPacketID_ConcurrentUnique(t *testing.T) {
	u := &UdpConn{}
	const n = 2000

	ids := make(chan uint64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids <- u.nextPacketID()
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[uint64]struct{}, n)
	var minID = ^uint64(0)
	var maxID uint64
	for id := range ids {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate packetID: %d", id)
		}
		seen[id] = struct{}{}
		if id < minID {
			minID = id
		}
		if id > maxID {
			maxID = id
		}
	}

	if len(seen) != n {
		t.Fatalf("unexpected unique count: got %d, want %d", len(seen), n)
	}
	if minID != 1 {
		t.Fatalf("unexpected min packetID: got %d, want 1", minID)
	}
	if maxID != n {
		t.Fatalf("unexpected max packetID: got %d, want %d", maxID, n)
	}
}

func TestUdpConn_ReplayWindow_PerSessionAndExpiry(t *testing.T) {
	u := &UdpConn{}
	now := time.Now()

	var sid1 [8]byte
	copy(sid1[:], []byte{1, 1, 1, 1, 1, 1, 1, 1})
	var sid2 [8]byte
	copy(sid2[:], []byte{2, 2, 2, 2, 2, 2, 2, 2})

	if !u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 packet 1 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 duplicate packet 1 should fail")
	}
	if !u.checkAndUpdateReplay(sid1, 2, now) {
		t.Fatalf("sid1 packet 2 should pass")
	}
	if !u.checkAndUpdateReplay(sid2, 1, now) {
		t.Fatalf("sid2 packet 1 should pass independently")
	}

	if !u.checkAndUpdateReplay(sid1, 5000, now) {
		t.Fatalf("sid1 packet 5000 should pass")
	}
	if u.checkAndUpdateReplay(sid1, 1, now) {
		t.Fatalf("sid1 old packet should fail after large jump")
	}

	future := now.Add(ciphers.SaltStorageDuration + time.Second)
	if !u.checkAndUpdateReplay(sid1, 1, future) {
		t.Fatalf("sid1 should reset after expiry and accept packet 1")
	}
}

func TestUdpConn_ReadFromUsesRemoteSessionCipher(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x23
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteSessionID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	wantAddr := netip.MustParseAddrPort("203.0.113.9:853")
	wantPayload := []byte("ss2022-udp-remote-session")

	packet := buildServerPacket(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), wantPayload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}

func TestUdpConn_ReadFromChacha2022(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-chacha20-poly1305"]
	if conf == nil {
		t.Fatal("missing ss2022 chacha cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x31
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 3, 5, 7, 9, 11, 13, 15}
	remoteSessionID := [8]byte{2, 4, 6, 8, 10, 12, 14, 16}
	wantAddr := netip.MustParseAddrPort("198.51.100.7:443")
	wantPayload := []byte("ss2022-chacha-udp")

	packet := buildServerPacketChacha(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), wantPayload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
	if got := string(buf[:n]); got != string(wantPayload) {
		t.Fatalf("unexpected payload: got %q want %q", got, string(wantPayload))
	}
}

func TestUdpConnPacketReceiverDecodesBlockAndChachaPackets(t *testing.T) {
	tests := []struct {
		name       string
		cipherName string
		serverID   [8]byte
		clientID   [8]byte
		addr       string
		payload    []byte
		build      func(*testing.T, *SS2022Core, [8]byte, [8]byte, uint64, string, []byte) []byte
	}{
		{
			name:       "block",
			cipherName: "2022-blake3-aes-256-gcm",
			serverID:   [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
			clientID:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
			addr:       "203.0.113.9:853",
			payload:    []byte("receiver-block"),
			build:      buildServerPacket,
		},
		{
			name:       "chacha",
			cipherName: "2022-blake3-chacha20-poly1305",
			serverID:   [8]byte{2, 4, 6, 8, 10, 12, 14, 16},
			clientID:   [8]byte{1, 3, 5, 7, 9, 11, 13, 15},
			addr:       "198.51.100.7:443",
			payload:    []byte("receiver-chacha"),
			build:      buildServerPacketChacha,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := ciphers.Aead2022CiphersConf[tc.cipherName]
			if conf == nil {
				t.Fatalf("missing cipher config %q", tc.cipherName)
			}
			psk := make([]byte, conf.KeyLen)
			for i := range psk {
				psk[i] = byte(i + 0x20)
			}
			core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
			if err != nil {
				t.Fatal(err)
			}
			packet := tc.build(t, core, tc.serverID, tc.clientID, 1, tc.addr, tc.payload)
			receiver := &udpReceiverConn{udpReadBufferConn: &udpReadBufferConn{}}
			conn, err := NewUdpConn(receiver, core, nil)
			if err != nil {
				t.Fatal(err)
			}
			conn.sessionID = tc.clientID

			var got *netproxy.ReceivedPacket
			stop, ok := conn.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
				got = packet
				return true
			})
			if !ok || stop == nil {
				t.Fatal("RegisterPacketReceiver() did not register")
			}
			var released atomic.Int32
			if !receiver.emit(netproxy.NewReceivedPacket(append([]byte(nil), packet...), netip.AddrPort{}, nil, func() {
				released.Add(1)
			})) {
				t.Fatal("receiver did not consume packet")
			}
			if got == nil || string(got.Data) != string(tc.payload) || got.From != netip.MustParseAddrPort(tc.addr) {
				t.Fatalf("decoded packet = %+v, want payload %q from %s", got, tc.payload, tc.addr)
			}
			got.Release()
			if released.Load() != 1 {
				t.Fatalf("raw release count = %d, want 1", released.Load())
			}
			stop()
		})
	}
}

func TestUdpConn_DecryptCipherCacheDropsToLowWatermarkAfterBurst(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x42
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := NewUdpConn(&udpReadBufferConn{}, core, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i <= maxDecryptCipherEntries; i++ {
		var sessionID [8]byte
		sessionID[0] = byte(i)
		sessionID[1] = byte(i >> 8)
		if _, err := conn.decryptCipherFor(sessionID); err != nil {
			t.Fatalf("decryptCipherFor(%d): %v", i, err)
		}
	}

	if got := len(conn.decryptCiphers); got > decryptCipherLowWatermark {
		t.Fatalf("decrypt cipher cache size = %d, want <= %d after burst trimming", got, decryptCipherLowWatermark)
	}
}

// TestUdpConn_ReadFromChachaSurfacesOversizeAsDropped pins the typed
// datagram-dropped contract on the chacha read path: the read buffer carries
// +320 bytes of headroom, so a wire datagram that decodes to more than the
// caller's buffer is received and authenticated in full — and must surface as
// a dropped datagram (session stays usable) instead of a silently truncated
// successful read.
func TestUdpConn_ReadFromChachaSurfacesOversizeAsDropped(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-chacha20-poly1305"]
	if conf == nil {
		t.Fatal("missing ss2022 chacha cipher config")
	}
	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x41
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 3, 5, 7, 9, 11, 13, 15}
	remoteSessionID := [8]byte{2, 4, 6, 8, 10, 12, 14, 16}
	wantAddr := netip.MustParseAddrPort("198.51.100.7:443")
	// 1700 decoded bytes > the 1500-byte caller buffer, while the wire packet
	// still fits the len(b)+nonce+tag+320 read buffer.
	payload := make([]byte, 1700)
	for i := range payload {
		payload[i] = byte(i)
	}

	packet := buildServerPacketChacha(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), payload)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 1500)
	n, addr, err := conn.ReadFrom(buf)
	if err == nil {
		t.Fatalf("expected the oversize datagram to surface as dropped, got a silent success with n=%d (want the drop, not a truncated copy)", n)
	}
	if !stderrors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("error should unwrap to io.ErrShortBuffer: %v", err)
	}
	var dropped *netproxy.ErrDatagramDropped
	if !stderrors.As(err, &dropped) {
		t.Fatalf("error should carry the typed datagram-dropped contract: %v", err)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr on the dropped datagram: got %v want %v", addr, wantAddr)
	}
}

// TestUdpConn_ReadFromEmptyPayloadIsADatagram pins the empty-body contract: a
// server datagram whose framing header and address consumed the entire
// payload decodes as a zero-length datagram with its address, not as an
// error. io.EOF from the empty read used to retire the whole UDP endpoint.
func TestUdpConn_ReadFromEmptyPayloadIsADatagram(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}

	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x23
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}

	localSessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteSessionID := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	wantAddr := netip.MustParseAddrPort("203.0.113.9:853")

	packet := buildServerPacket(t, core, remoteSessionID, localSessionID, 1, wantAddr.String(), nil)
	conn, err := NewUdpConn(&udpReadBufferConn{packet: packet}, core, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.sessionID = localSessionID

	buf := make([]byte, 128)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom of an empty-payload datagram: %v", err)
	}
	if n != 0 {
		t.Fatalf("payload length = %d, want 0", n)
	}
	if addr != wantAddr {
		t.Fatalf("unexpected addr: got %v want %v", addr, wantAddr)
	}
}
