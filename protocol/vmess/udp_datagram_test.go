package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*bufferConn)(nil)

// framePacketAddrDatagram builds the wire chunk for one packetaddr datagram: a
// two-byte big-endian size followed by the packet address and its payload.
func framePacketAddrDatagram(t *testing.T, addr *net.UDPAddr, payload []byte) ([]byte, netip.AddrPort) {
	t.Helper()
	addrLen := UDPAddrToPacketAddrLength(addr)
	buf := make([]byte, addrLen+len(payload))
	if err := PutPacketAddr(buf, addr); err != nil {
		t.Fatal(err)
	}
	copy(buf[addrLen:], payload)
	framed := make([]byte, 2+len(buf))
	framed[0] = byte(len(buf) >> 8)
	framed[1] = byte(len(buf))
	copy(framed[2:], buf)
	return framed, addr.AddrPort()
}

// newDirectReadPacketAddrConn wires a Conn whose next read returns framed with
// the identity cipher, so a test can drive ReadFrom without a real peer.
func newDirectReadPacketAddrConn(framed []byte) *Conn {
	c := &Conn{
		Conn: &bufferConn{Buffer: bytes.NewBuffer(framed)},
		metadata: Metadata{
			Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: SeqPacketMagicAddress},
			Network:  "udp",
		},
		dialTgt:         "203.0.113.10:53",
		dialTgtAddrPort: netip.MustParseAddrPort("203.0.113.10:53"),
	}
	c.initRead.Do(func() {})
	c.readChunkSizeParser = PlainChunkSizeParser{}
	c.readPaddingGenerator = PlainPaddingGenerator{}
	c.readNonceGenerator = func() []byte { return make([]byte, 12) }
	c.readBodyCipher = identityAEAD{}
	return c
}

// TestReadFromDropsDatagramWhenCallerBufferTooSmall pins the datagram-dropped
// contract on the packetaddr path: a caller buffer that cannot hold the whole
// datagram must not receive a truncated payload, and the typed short-buffer
// error must survive for consumers that classify it.
func TestReadFromDropsDatagramWhenCallerBufferTooSmall(t *testing.T) {
	addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.10:53"))
	framed, _ := framePacketAddrDatagram(t, addr, []byte("0123456789"))
	c := newDirectReadPacketAddrConn(framed)

	small := make([]byte, 4)
	n, _, err := c.ReadFrom(small)
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0: a truncated datagram must not be delivered", n)
	}
}

// TestReadFromDeliversDatagramLargerThanMaxUDPSize is the regression for the
// packetaddr path staging every datagram through a pooled MaxUDPSize (2048)
// frame buffer: any datagram larger than that was drained and reported as
// dropped even when the caller's buffer could hold it, which broke EDNS0-sized
// DNS replies over VMess.
func TestReadFromDeliversDatagramLargerThanMaxUDPSize(t *testing.T) {
	addr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.10:53"))
	for _, payloadLen := range []int{2048, 2049, 4096} {
		payload := bytes.Repeat([]byte{0xAB}, payloadLen)
		framed, wantAddr := framePacketAddrDatagram(t, addr, payload)
		c := newDirectReadPacketAddrConn(framed)

		out := make([]byte, 65536)
		n, gotAddr, err := c.ReadFrom(out)
		if err != nil {
			t.Fatalf("payload %d: ReadFrom = %v, want the datagram to be delivered", payloadLen, err)
		}
		if n != len(payload) {
			t.Fatalf("payload %d: n = %d, want %d", payloadLen, n, len(payload))
		}
		if !bytes.Equal(out[:n], payload) {
			t.Fatalf("payload %d: delivered bytes differ from the payload", payloadLen)
		}
		if gotAddr != wantAddr {
			t.Fatalf("payload %d: addr = %v, want %v", payloadLen, gotAddr, wantAddr)
		}
	}
}

func TestReadFromDoesNotSplitLeftoverAsSecondDatagram(t *testing.T) {
	chunk := []byte("abcdefghij")
	c := &Conn{
		Conn: &bufferConn{Buffer: bytes.NewBuffer(nil)},
		metadata: Metadata{
			Metadata: protocol.Metadata{},
			Network:  "udp",
		},
		leftToRead:         chunk,
		readNonceGenerator: func() []byte { return make([]byte, 12) },
		dialTgt:            "203.0.113.10:53",
		dialTgtAddrPort:    netip.MustParseAddrPort("203.0.113.10:53"),
	}
	c.initRead.Do(func() {})
	first := make([]byte, 4)
	n, _, err := c.ReadFrom(first)
	// Both matching styles must hold: the typed datagram-dropped contract and
	// the legacy io.ErrShortBuffer sentinel it unwraps to.
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("first ReadFrom err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("truncated datagram delivered: n=%d %q", n, first[:n])
	}
	second := make([]byte, 16)
	n, _, err = c.ReadFrom(second)
	if err != io.EOF && err != nil {
		t.Fatalf("second ReadFrom: %v", err)
	}
	if n != 0 {
		t.Fatalf("leftover delivered as second datagram: %q", second[:n])
	}
}

type identityAEAD struct{}

func (identityAEAD) NonceSize() int { return 12 }
func (identityAEAD) Overhead() int  { return 0 }
func (identityAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	out := make([]byte, len(dst)+len(plaintext))
	copy(out, dst)
	copy(out[len(dst):], plaintext)
	return out
}
func (identityAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	out := make([]byte, len(dst)+len(ciphertext))
	copy(out, dst)
	copy(out[len(dst):], ciphertext)
	return out, nil
}

// TestWritePacketRejectsDatagramBeyondChunkLengthField pins the write-side
// mirror of the read-side datagram contract: the two-byte chunk length field
// covers payload + AEAD overhead + padding, so a datagram that would wrap the
// uint16 must fail the write instead of emitting a bogus frame length that
// desyncs the stream.
func TestWritePacketRejectsDatagramBeyondChunkLengthField(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	shake := NewShakeSizeParser(make([]byte, 16))
	newWriteTestConn := func() *Conn {
		return &Conn{
			Conn:                  &bufferConn{Buffer: bytes.NewBuffer(nil)},
			writeBodyCipher:       aead,
			writeNonceGenerator:   GenerateChunkNonce(make([]byte, aead.NonceSize()), uint32(aead.NonceSize())),
			writeChunkSizeParser:  shake,
			writePaddingGenerator: shake,
		}
	}

	// One byte past the field's reach: len(b)+overhead+maxPadding = 0x10000.
	oversize := make([]byte, 0xFFFF-aead.Overhead()-int(shake.MaxPaddingLen())+1)
	_, err = newWriteTestConn().writePacket(oversize, nil)
	if err == nil {
		t.Fatal("expected the oversize datagram to be rejected before framing")
	}
	if got := fmt.Sprint(err); !bytes.Contains([]byte(got), []byte("16-bit chunk length")) {
		t.Fatalf("unexpected error: %v", err)
	}

	// Exactly at the field's reach still frames and writes.
	fit := make([]byte, 0xFFFF-aead.Overhead()-int(shake.MaxPaddingLen()))
	n, err := newWriteTestConn().writePacket(fit, nil)
	if err != nil {
		t.Fatalf("boundary datagram should write: %v", err)
	}
	if n != len(fit) {
		t.Fatalf("n = %d, want %d", n, len(fit))
	}
}

// TestWritePacketRejectionIsDatagramDropped pins the typed contract of the
// oversize rejection: the endpoint must read it as one dropped datagram with
// the session still usable, not as a session failure that retires it.
func TestWritePacketRejectionIsDatagramDropped(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	shake := NewShakeSizeParser(make([]byte, 16))
	c := &Conn{
		Conn:                  &bufferConn{Buffer: bytes.NewBuffer(nil)},
		writeBodyCipher:       aead,
		writeNonceGenerator:   GenerateChunkNonce(make([]byte, aead.NonceSize()), uint32(aead.NonceSize())),
		writeChunkSizeParser:  shake,
		writePaddingGenerator: shake,
	}

	oversize := make([]byte, 0xFFFF-aead.Overhead()-int(shake.MaxPaddingLen())+1)
	_, err = c.writePacket(oversize, nil)
	if err == nil {
		t.Fatal("expected the oversize datagram to be rejected")
	}
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) {
		t.Fatalf("oversize rejection must carry the datagram-dropped contract, got %T: %v", err, err)
	}
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("legacy io.ErrShortBuffer consumers must still match the rejection")
	}
	// The session stays usable: the next, small enough datagram writes.
	small := make([]byte, 64)
	n, werr := c.writePacket(small, nil)
	if werr != nil || n != len(small) {
		t.Fatalf("session unusable after a dropped datagram: n=%d err=%v", n, werr)
	}
}
