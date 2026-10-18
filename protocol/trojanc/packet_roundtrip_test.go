package trojanc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type streamPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newStreamPipe() (*streamPipe, *streamPipe) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &streamPipe{r: ar, w: bw}, &streamPipe{r: br, w: aw}
}

func (p *streamPipe) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *streamPipe) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *streamPipe) Close() error {
	_ = p.r.Close()
	return p.w.Close()
}
func (p *streamPipe) SetDeadline(time.Time) error      { return nil }
func (p *streamPipe) SetReadDeadline(time.Time) error  { return nil }
func (p *streamPipe) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*streamPipe)(nil)

func trojanPacketConnPair(t *testing.T) (*PacketConn, *PacketConn) {
	t.Helper()
	a, b := newStreamPipe()
	md := Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "udp"}
	leftConn := &Conn{Conn: a, metadata: md}
	rightConn := &Conn{Conn: b, metadata: md}
	leftConn.onceWrite.Store(true)
	rightConn.onceWrite.Store(true)
	left := &PacketConn{Conn: leftConn}
	right := &PacketConn{Conn: rightConn}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	return left, right
}

func TestPacketConnRoundTripPreservesPayload(t *testing.T) {
	left, right := trojanPacketConnPair(t)
	payload := []byte("HELLO")
	const target = "203.0.113.10:443"

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := left.WriteTo(payload, target); err != nil {
			t.Errorf("WriteTo: %v", err)
		}
	}()

	buf := make([]byte, 64)
	n, addr, err := right.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	<-done
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q (CRLF must not be consumed as data)", buf[:n], payload)
	}
	if addr.String() != target {
		t.Fatalf("addr = %s, want %s", addr, target)
	}
}

func TestPacketConnRoundTripTwoDatagramsStayFramed(t *testing.T) {
	left, right := trojanPacketConnPair(t)
	first := []byte("one")
	second := []byte("two-two")
	const target = "192.0.2.8:53"

	go func() {
		if _, err := left.WriteTo(first, target); err != nil {
			t.Errorf("WriteTo first: %v", err)
		}
		if _, err := left.WriteTo(second, target); err != nil {
			t.Errorf("WriteTo second: %v", err)
		}
	}()

	buf := make([]byte, 64)
	n, _, err := right.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom first: %v", err)
	}
	if string(buf[:n]) != string(first) {
		t.Fatalf("first datagram = %q, want %q", buf[:n], first)
	}
	n, _, err = right.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom second: %v", err)
	}
	if string(buf[:n]) != string(second) {
		t.Fatalf("second datagram = %q, want %q", buf[:n], second)
	}
}

func TestPacketConnReadFromSmallBufferKeepsNextDatagram(t *testing.T) {
	left, right := trojanPacketConnPair(t)
	big := []byte("ABCDEFGHIJ")
	next := []byte("ok")
	const target = "198.51.100.9:9"

	go func() {
		if _, err := left.WriteTo(big, target); err != nil {
			t.Errorf("WriteTo big: %v", err)
		}
		if _, err := left.WriteTo(next, target); err != nil {
			t.Errorf("WriteTo next: %v", err)
		}
	}()

	small := make([]byte, 4)
	n, _, err := right.ReadFrom(small)
	// The oversized datagram is drained and reported as dropped — the typed
	// contract (which unwraps to io.ErrShortBuffer), never as silent
	// truncation or a session-fatal error.
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom truncated err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	if string(small[:n]) != "ABCD" {
		t.Fatalf("truncated prefix = %q, want ABCD", small[:n])
	}
	buf := make([]byte, 16)
	n, _, err = right.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom next: %v", err)
	}
	if string(buf[:n]) != string(next) {
		t.Fatalf("next datagram = %q, want %q", buf[:n], next)
	}
}

func TestPacketConnReadFromRejectsInvalidCRLF(t *testing.T) {
	raw := &bytes.Buffer{}
	md := Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: "203.0.113.10",
			Port:     443,
			IP:       netip.MustParseAddr("203.0.113.10"),
		},
		Network: "udp",
	}
	payload := []byte("HELLO")
	wire := make([]byte, md.Len()+4+len(payload))
	SealUDP(md, wire, payload)
	// Corrupt CRLF after the length field.
	wire[md.Len()+2] = 'X'
	wire[md.Len()+3] = 'Y'
	raw.Write(wire)

	rawConn := &Conn{
		Conn:     &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "udp"},
	}
	rawConn.onceWrite.Store(true)
	pc := &PacketConn{Conn: rawConn}
	_, _, err := pc.ReadFrom(make([]byte, 64))
	if err == nil {
		t.Fatal("expected invalid CRLF error")
	}
	if err.Error() != "invalid trojan UDP CRLF" {
		t.Fatalf("err = %v, want invalid trojan UDP CRLF", err)
	}
}

type bufferConn struct {
	*bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*bufferConn)(nil)

// TestPacketConnReadFromKeepsFramingWhenResolutionFails pins the read ordering
// that makes an unresolvable peer address survivable. The datagram body must be
// consumed before the resolution can fail: otherwise the next read starts inside
// the previous payload, and a caller that drops one datagram -- exactly what the
// ErrDomainResolution sentinel exists to let it do -- would silently desync the
// session. The read loop is per association, so that desync would corrupt every
// destination sharing it.
func TestPacketConnReadFromKeepsFramingWhenResolutionFails(t *testing.T) {
	protocol.SetDatapathResolver(func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, errors.New("test resolver: no answer")
	})
	t.Cleanup(func() { protocol.SetDatapathResolver(nil) })

	badMD := Metadata{
		Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "unresolvable.invalid", Port: 53},
		Network:  "udp",
	}
	goodMD := Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeIPv4,
			Hostname: "192.0.2.8",
			Port:     53,
			IP:       netip.MustParseAddr("192.0.2.8"),
		},
		Network: "udp",
	}
	const dropped, kept = "dropped-payload", "kept-payload"
	raw := &bytes.Buffer{}
	bad := make([]byte, badMD.Len()+4+len(dropped))
	SealUDP(badMD, bad, []byte(dropped))
	good := make([]byte, goodMD.Len()+4+len(kept))
	SealUDP(goodMD, good, []byte(kept))
	raw.Write(bad)
	raw.Write(good)

	rawConn := &Conn{
		Conn:     &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "udp"},
	}
	rawConn.onceWrite.Store(true)
	pc := &PacketConn{Conn: rawConn}

	buf := make([]byte, 64)
	if _, _, err := pc.ReadFrom(buf); !errors.Is(err, protocol.ErrDomainResolution) {
		t.Fatalf("first ReadFrom err = %v, want it to wrap ErrDomainResolution", err)
	}

	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom: %v (the failed resolution desynced the stream)", err)
	}
	if string(buf[:n]) != kept {
		t.Fatalf("second payload = %q, want %q", buf[:n], kept)
	}
	if addr.String() != "192.0.2.8:53" {
		t.Fatalf("second addr = %s, want 192.0.2.8:53", addr)
	}
}
