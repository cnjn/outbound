package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return nil }
func (c *bufferConn) RemoteAddr() net.Addr             { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*bufferConn)(nil)

// frameVisionUDPDatagram builds the direct-read vision frame that carries one
// UDP datagram: [frame length][4-byte frame header][command][packet addr]
// [payload length][payload].
func frameVisionUDPDatagram(t *testing.T, addr netip.AddrPort, payload []byte) []byte {
	t.Helper()
	packetAddrLen := IPAddrToPacketAddrLength(addr)
	headerLen := 4 + 1 + packetAddrLen
	var framed bytes.Buffer
	var fl [2]byte
	binary.BigEndian.PutUint16(fl[:], uint16(headerLen))
	framed.Write(fl[:])
	framed.Write([]byte{0, 0, 0x02, 0x01})
	framed.WriteByte(2)
	addrBytes := make([]byte, packetAddrLen)
	if err := PutPacketAddr(addrBytes, addr); err != nil {
		t.Fatal(err)
	}
	framed.Write(addrBytes)
	var ll [2]byte
	binary.BigEndian.PutUint16(ll[:], uint16(len(payload)))
	framed.Write(ll[:])
	framed.Write(payload)
	return framed.Bytes()
}

// newDirectReadVisionPacketConn wires a direct-read vision PacketConn over the
// given raw stream bytes and returns the underlying stream for alignment
// assertions.
func newDirectReadVisionPacketConn(framed []byte) (*PacketConn, *bufferConn) {
	underlay := &bufferConn{Buffer: bytes.NewBuffer(framed)}
	vc := &Conn{Conn: underlay, toReadDirect: true}
	vc.reader = &readWrapper{directRead: true, vision: vc}
	return &PacketConn{Conn: vc}, underlay
}

func TestReadFromDrainsOversizedPayload(t *testing.T) {
	payload := []byte("0123456789")
	addr := netip.MustParseAddrPort("203.0.113.10:53")
	framed := append(frameVisionUDPDatagram(t, addr, payload), "NEXT"...)

	pc, underlay := newDirectReadVisionPacketConn(framed)
	n, _, err := pc.ReadFrom(make([]byte, 4))
	// The drained oversized datagram must surface as the typed
	// datagram-dropped contract (unwrapping to io.ErrShortBuffer), never as
	// an untyped error or a session-fatal condition.
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	rest := make([]byte, 4)
	if _, err := io.ReadFull(underlay, rest); err != nil {
		t.Fatalf("remaining stream: %v", err)
	}
	if string(rest) != "NEXT" {
		t.Fatalf("remaining = %q, want NEXT", rest)
	}
}

// TestReadFromAcceptsDatagramWithFullRangeBuffer pins the buffer arithmetic of
// the vision UDP read path. dae sizes its DNS forward read buffer with
// pool.GetFullCap(65536), and the pool's largest bucket is exactly 65536 bytes
// (pool maxsize == 1<<16), so len(p) reaches 65536. The size check cast len(p)
// to uint16, which wraps 65536 to 0 and makes every non-empty datagram look
// oversized: every UDP response travelling through an XTLS/Vision node is then
// drained and dropped, and DNS over that node fails on every query.
func TestReadFromAcceptsDatagramWithFullRangeBuffer(t *testing.T) {
	addr := netip.MustParseAddrPort("203.0.113.10:53")
	payload := bytes.Repeat([]byte{0xAB}, 100)
	for _, bufLen := range []int{1500, 65535, 65536} {
		pc, _ := newDirectReadVisionPacketConn(frameVisionUDPDatagram(t, addr, payload))
		buf := make([]byte, bufLen)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom with len(p)=%d: err = %v, want nil", bufLen, err)
		}
		if n != len(payload) {
			t.Fatalf("ReadFrom with len(p)=%d: n = %d, want %d", bufLen, n, len(payload))
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("ReadFrom with len(p)=%d: payload mismatch", bufLen)
		}
	}
}
