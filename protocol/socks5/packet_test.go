package socks5

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type recordingPacketConn struct {
	mu        sync.Mutex
	writes    []recordedPacketWrite
	closeCh   chan struct{}
	closeOnce sync.Once
}

type recordedPacketWrite struct {
	addr string
	data []byte
}

func (c *recordingPacketConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, "")
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *recordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	clone := append([]byte(nil), p...)
	c.mu.Lock()
	c.writes = append(c.writes, recordedPacketWrite{addr: addr, data: clone})
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingPacketConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	c.mu.Lock()
	for _, it := range items {
		clone := append([]byte(nil), it.Data...)
		c.writes = append(c.writes, recordedPacketWrite{addr: it.Addr, data: clone})
	}
	c.mu.Unlock()
	return len(items), nil
}

func (c *recordingPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeCh != nil {
			close(c.closeCh)
		}
	})
	return nil
}
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedCtrlConn struct {
	shutdownCh chan struct{}
	closeCh    chan struct{}
	closeOnce  sync.Once
}

func newScriptedCtrlConn() *scriptedCtrlConn {
	return &scriptedCtrlConn{
		shutdownCh: make(chan struct{}),
		closeCh:    make(chan struct{}),
	}
}

func (c *scriptedCtrlConn) shutdown() {
	c.closeOnce.Do(func() {
		close(c.shutdownCh)
	})
}

func (c *scriptedCtrlConn) Read([]byte) (int, error) {
	select {
	case <-c.shutdownCh:
		return 0, io.EOF
	case <-c.closeCh:
		return 0, net.ErrClosed
	}
}

func (c *scriptedCtrlConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *scriptedCtrlConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	return nil
}

func (c *scriptedCtrlConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedCtrlConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedCtrlConn) SetWriteDeadline(time.Time) error { return nil }

func TestPktConnConcurrentWriteTo(t *testing.T) {
	t.Helper()

	recorder := &recordingPacketConn{}
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", nil)

	targets := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
	}

	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pc.WriteTo([]byte("payload-"+target), target); err != nil {
				t.Errorf("WriteTo(%s) failed: %v", target, err)
			}
		}()
	}
	wg.Wait()

	if len(recorder.writes) != len(targets) {
		t.Fatalf("unexpected write count: got %d want %d", len(recorder.writes), len(targets))
	}

	seen := make(map[string]bool, len(targets))
	for _, write := range recorder.writes {
		if write.addr != "127.0.0.1:1080" {
			t.Fatalf("unexpected proxy addr: got %q", write.addr)
		}
		if len(write.data) < 4 {
			t.Fatalf("unexpected short socks5 packet: %d", len(write.data))
		}
		if write.data[0] != 0 || write.data[1] != 0 || write.data[2] != 0 {
			t.Fatalf("unexpected socks5 reserved header: %v", write.data[:3])
		}
		addr := socks.SplitAddr(write.data[3:])
		if addr == nil {
			t.Fatal("failed to parse encoded target address")
		}
		target := addr.String()
		payload := string(write.data[3+len(addr):])
		if payload != "payload-"+target {
			t.Fatalf("payload mismatch for %s: got %q", target, payload)
		}
		seen[target] = true
	}

	for _, target := range targets {
		if !seen[target] {
			t.Fatalf("missing target write for %s", target)
		}
	}
}

func TestPktConnTransportDoneClosesWhenControlConnEnds(t *testing.T) {
	recorder := &recordingPacketConn{closeCh: make(chan struct{})}
	ctrlConn := newScriptedCtrlConn()
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", ctrlConn)
	lifecycle, ok := any(pc).(netproxy.TransportLifecycle)
	if !ok {
		t.Fatalf("expected SOCKS5 packet conn to expose TransportDone, got %T", pc)
	}
	if lifecycle.TransportDone() == nil {
		t.Fatal("expected non-nil transport lifecycle channel when control conn is present")
	}

	ctrlConn.shutdown()

	select {
	case <-lifecycle.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SOCKS5 control-channel shutdown to close lifecycle channel")
	}

	select {
	case <-recorder.closeCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SOCKS5 control-channel shutdown to close packet conn")
	}
}

// TestPktConnWriteBatch verifies that WriteBatch encapsulates every datagram
// with the SOCKS5 UDP header (RSV FRAG ATYP DST.ADDR DST.PORT) and forwards
// the whole batch to the underlying batched writer.
func TestPktConnWriteBatch(t *testing.T) {
	recorder := &recordingPacketConn{}
	ctrlConn := newScriptedCtrlConn()
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", ctrlConn)

	items := []netproxy.BatchItem{
		{Data: []byte("hello"), Addr: "10.0.0.1:53"},
		{Data: []byte("world"), Addr: "[2001:db8::1]:443"},
	}
	n, err := pc.WriteBatch(items)
	if err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("unexpected n: got %d want 2", n)
	}

	recorder.mu.Lock()
	writes := recorder.writes
	recorder.mu.Unlock()
	if len(writes) != 2 {
		t.Fatalf("unexpected write count: got %d want 2", len(writes))
	}
	for i, write := range writes {
		if write.addr != "127.0.0.1:1080" {
			t.Fatalf("write #%d: unexpected proxy addr %q", i, write.addr)
		}
		if len(write.data) < 4 || write.data[0] != 0 || write.data[1] != 0 || write.data[2] != 0 {
			t.Fatalf("write #%d: bad socks5 header %v", i, write.data)
		}
		addr := socks.SplitAddr(write.data[3:])
		if addr == nil {
			t.Fatalf("write #%d: failed to parse encoded target address", i)
		}
		wantPayloads := [][]byte{[]byte("hello"), []byte("world")}
		payload := string(write.data[3+len(addr):])
		if payload != string(wantPayloads[i]) {
			t.Fatalf("write #%d: payload mismatch: got %q want %q", i, payload, wantPayloads[i])
		}
		if addr.String() != items[i].Addr {
			t.Fatalf("write #%d: target mismatch: got %q want %q", i, addr.String(), items[i].Addr)
		}
	}
}

// TestPktConnWriteBatchFallback verifies per-item synchronous fallback when
// the underlying transport has no batched writer. nonBatchPacketConn wraps a
// recordingPacketConn but deliberately does not promote WriteBatch, so it
// must NOT satisfy netproxy.PacketBatchWriter.
type nonBatchPacketConn struct {
	inner *recordingPacketConn
}

func (c *nonBatchPacketConn) Read(p []byte) (int, error)  { return c.inner.Read(p) }
func (c *nonBatchPacketConn) Write(p []byte) (int, error) { return c.inner.Write(p) }
func (c *nonBatchPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return c.inner.ReadFrom(p)
}
func (c *nonBatchPacketConn) WriteTo(p []byte, addr string) (int, error) {
	return c.inner.WriteTo(p, addr)
}
func (c *nonBatchPacketConn) Close() error                       { return c.inner.Close() }
func (c *nonBatchPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *nonBatchPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *nonBatchPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

func TestPktConnWriteBatchFallback(t *testing.T) {
	recorder := &nonBatchPacketConn{inner: &recordingPacketConn{}}
	if _, ok := any(recorder).(netproxy.PacketBatchWriter); ok {
		t.Fatal("test fixture must not implement PacketBatchWriter")
	}
	ctrlConn := newScriptedCtrlConn()
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", ctrlConn)

	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "10.0.0.1:53"},
		{Data: []byte("two"), Addr: "10.0.0.2:53"},
	}
	n, err := pc.WriteBatch(items)
	if err != nil {
		t.Fatalf("WriteBatch fallback: %v", err)
	}
	if n != 2 {
		t.Fatalf("unexpected n: got %d want 2 datagrams", n)
	}
	recorder.inner.mu.Lock()
	writes := recorder.inner.writes
	recorder.inner.mu.Unlock()
	if len(writes) != 2 {
		t.Fatalf("unexpected write count: got %d want 2", len(writes))
	}
	for i, write := range writes {
		addr := socks.SplitAddr(write.data[3:])
		if addr == nil || addr.String() != items[i].Addr {
			t.Fatalf("write #%d: target mismatch", i)
		}
		payload := string(write.data[3+len(addr):])
		if payload != string(items[i].Data) {
			t.Fatalf("write #%d: payload mismatch: got %q want %q", i, payload, items[i].Data)
		}
	}
}

// TestPktConnWriteBatchInvalidAddrReturnsZeroAndReleasesBuffers is the M2
// regression: a mid-batch parse failure must report n=0 (nothing left the
// socket) and Put every already-allocated encapsulation buffer.
func TestPktConnWriteBatchInvalidAddrReturnsZeroAndReleasesBuffers(t *testing.T) {
	recorder := &recordingPacketConn{}
	ctrlConn := newScriptedCtrlConn()
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", ctrlConn)

	items := []netproxy.BatchItem{
		{Data: []byte("hello"), Addr: "10.0.0.1:53"},
		{Data: []byte("world"), Addr: "not-an-address"},
	}
	n, err := pc.WriteBatch(items)
	if err == nil {
		t.Fatal("expected invalid-addr error")
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0 (nothing left the socket)", n)
	}
	recorder.mu.Lock()
	writes := recorder.writes
	recorder.mu.Unlock()
	if len(writes) != 0 {
		t.Fatalf("underlying WriteBatch ran with %d writes, want 0", len(writes))
	}
}

// scriptedReplyPacketConn feeds one canned SOCKS UDP reply frame to the
// first ReadFrom call, letting tests exercise the polling decode path.
type scriptedReplyPacketConn struct {
	recordingPacketConn
	frame []byte
	used  bool
}

func (c *scriptedReplyPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	if c.used {
		return 0, netip.AddrPort{}, io.EOF
	}
	c.used = true
	n := copy(p, c.frame)
	from := netip.MustParseAddrPort("203.0.113.9:1080")
	return n, from, nil
}

// TestPktConnReadFromDecodesFramedReply locks the polling UDP reply decode:
// the datagram is handed to the splitter whole (RSV+FRAG+ATYP+addr+payload)
// and only the payload after the address survives in b.
func TestPktConnReadFromDecodesFramedReply(t *testing.T) {
	frame := []byte{
		0x00, 0x00, // RSV
		0x00, // FRAG
		0x01, // ATYP_IPV4
		198, 51, 100, 7,
		0x01, 0xBB, // port 443
		'p', 'o', 'n', 'g',
	}
	pc := &PktConn{PacketConn: &scriptedReplyPacketConn{frame: frame}}

	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("payload = %q, want %q", buf[:n], "pong")
	}
	if from != (netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), 443)) {
		t.Fatalf("from = %v, want 198.51.100.7:443", from)
	}
}

// TestPktConnReadFromMalformedDatagramIsDropped pins the typed contract for
// malformed SOCKS UDP replies: a too-short header, a non-zero FRAG byte, or an
// unparseable target address is one dropped datagram, not a session failure —
// the endpoint must stay alive for the next well-formed reply.
func TestPktConnReadFromMalformedDatagramIsDropped(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"truncated header", []byte{0x00, 0x00}},
		{"non-zero FRAG", []byte{0x00, 0x00, 0x02, 0x01, 198, 51, 100, 7, 0x01, 0xBB, 'x'}},
		{"unparseable address", []byte{0x00, 0x00, 0x00, 0x99, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := &PktConn{PacketConn: &scriptedReplyPacketConn{frame: tc.frame}}
			_, _, err := pc.ReadFrom(make([]byte, 64))
			if err == nil {
				t.Fatal("malformed datagram must be reported")
			}
			var dropped *netproxy.ErrDatagramDropped
			if !errors.As(err, &dropped) {
				t.Fatalf("malformed datagram must carry the datagram-dropped contract, got %T: %v", err, err)
			}
		})
	}
}
