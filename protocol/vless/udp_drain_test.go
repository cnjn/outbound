package vless

import (
	"bytes"
	"encoding/binary"
	stderrors "errors"
	"io"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

func TestUDPReadFromDrainsOversizedDatagram(t *testing.T) {
	payload := []byte("0123456789")
	var framed bytes.Buffer
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	framed.Write(hdr[:])
	framed.Write(payload)
	framed.WriteString("NEXT")

	c := &Conn{
		Conn: &bufferConn{Buffer: &framed},
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{IsClient: true},
			Network:  "udp",
		}},
		cmdKey:              testKey(t),
		cachedProxyAddrIpIP: netip.MustParseAddrPort("203.0.113.10:53"),
		readHeaderDone:      true,
	}
	small := make([]byte, 4)
	n, _, err := c.ReadFrom(small)
	// The drained oversized datagram must surface as the typed
	// datagram-dropped contract (unwrapping to io.ErrShortBuffer), never as
	// an untyped error or a session-fatal condition.
	var dropped *netproxy.ErrDatagramDropped
	if !stderrors.As(err, &dropped) || !stderrors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	rest := make([]byte, 4)
	got, err := io.ReadFull(c.Conn, rest)
	if err != nil {
		t.Fatalf("remaining stream: %v", err)
	}
	if got != 4 || string(rest) != "NEXT" {
		t.Fatalf("remaining = %q, want NEXT (frame was not drained)", rest[:got])
	}
}

func TestUDPReadDrainsOversizedDatagram(t *testing.T) {
	payload := []byte("0123456789")
	var framed bytes.Buffer
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	framed.Write(hdr[:])
	framed.Write(payload)
	framed.WriteString("NEXT")

	c := &Conn{
		Conn: &bufferConn{Buffer: &framed},
		metadata: Metadata{Metadata: vmess.Metadata{
			Metadata: protocol.Metadata{IsClient: true},
			Network:  "udp",
		}},
		cmdKey:         testKey(t),
		readHeaderDone: true,
	}
	_, err := c.Read(make([]byte, 4))
	var dropped *netproxy.ErrDatagramDropped
	if !stderrors.As(err, &dropped) || !stderrors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	rest := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, rest); err != nil {
		t.Fatalf("remaining stream: %v", err)
	}
	if string(rest) != "NEXT" {
		t.Fatalf("remaining = %q, want NEXT", rest)
	}
}
