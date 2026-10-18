package tuic

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

// wbDatagramConn is a fake quic.Connection that records sent datagrams and
// can fail a chosen send to exercise partial-success semantics.
type wbDatagramConn struct {
	quic.Connection

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	datagrams [][]byte

	failAt  int
	failErr error
}

func newWbDatagramConn() *wbDatagramConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &wbDatagramConn{ctx: ctx, cancel: cancel, failAt: -1}
}

func (c *wbDatagramConn) Context() context.Context { return c.ctx }

func (c *wbDatagramConn) SendDatagram(b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.datagrams) == c.failAt {
		return c.failErr
	}
	c.datagrams = append(c.datagrams, append([]byte(nil), b...))
	return nil
}

func (c *wbDatagramConn) OpenUniStream() (quic.SendStream, error) {
	return nil, errors.New("quic relay mode not used by this test")
}

func (c *wbDatagramConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.datagrams)
}

func (c *wbDatagramConn) datagram(i int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.datagrams[i]
}

func newWriteBatchPacketConn(conn *wbDatagramConn) *quicStreamPacketConn {
	// A mode other than common.QUIC selects the native (RFC 9221 datagram)
	// relay path in WriteTo.
	return &quicStreamPacketConn{
		quicConn:              conn,
		incomingPackets:       NewPackets(),
		udpRelayMode:          common.NATIVE,
		maxUdpRelayPacketSize: 0,
	}
}

// TestWriteBatchSendsPerItemWithTargets verifies the wire format and full-cone
// Addr alternation: each item leaves as its own TUIC packet whose address and
// payload match the item, in order.
func TestWriteBatchSendsPerItemWithTargets(t *testing.T) {
	conn := newWbDatagramConn()
	q := newWriteBatchPacketConn(conn)

	addrA := netip.MustParseAddrPort("203.0.113.10:443")
	addrB := netip.MustParseAddrPort("198.51.100.20:53")
	items := []netproxy.BatchItem{
		{Data: []byte("to-a"), Addr: addrA.String()},
		{Data: []byte("to-b"), Addr: addrB.String()},
		{Data: []byte("to-a-again"), Addr: addrA.String()},
	}
	n, err := q.WriteBatch(items)
	if err != nil || n != len(items) {
		t.Fatalf("WriteBatch: n=%d err=%v", n, err)
	}
	if got := conn.count(); got != len(items) {
		t.Fatalf("transport sent %d datagrams, want %d", got, len(items))
	}
	for i, item := range items {
		// The active lineage only keeps ReadPacketWithHead; read the command
		// head off the same reader like the removed ReadPacket wrapper did.
		r := bytes.NewReader(conn.datagram(i))
		head, err := ReadCommandHead(r)
		if err != nil {
			t.Fatalf("datagram %d: ReadCommandHead: %v", i, err)
		}
		packet, err := ReadPacketWithHead(head, r)
		if err != nil {
			t.Fatalf("datagram %d: ReadPacketWithHead: %v", i, err)
		}
		if string(packet.DATA) != string(item.Data) {
			t.Fatalf("datagram %d payload = %q, want %q", i, packet.DATA, item.Data)
		}
		if packet.ADDR == nil {
			t.Fatalf("datagram %d has no address", i)
		}
		got := packet.ADDR.UDPAddrPort()
		want := netip.MustParseAddrPort(item.Addr)
		if got.Addr().Unmap() != want.Addr() || got.Port() != want.Port() {
			t.Fatalf("datagram %d addr = %v, want %v", i, got, want)
		}
	}
}

// TestWriteBatchPartialSuccessCountsPrefix pins the sequential-loop contract:
// a datagram send failing mid-batch reports the accepted prefix together
// with the error.
func TestWriteBatchPartialSuccessCountsPrefix(t *testing.T) {
	conn := newWbDatagramConn()
	conn.failAt = 2
	conn.failErr = errors.New("boom")
	q := newWriteBatchPacketConn(conn)
	items := []netproxy.BatchItem{
		{Data: []byte("one"), Addr: "203.0.113.10:443"},
		{Data: []byte("two"), Addr: "203.0.113.10:443"},
		{Data: []byte("three"), Addr: "203.0.113.10:443"},
		{Data: []byte("four"), Addr: "203.0.113.10:443"},
	}
	n, err := q.WriteBatch(items)
	if err == nil || n != 2 {
		t.Fatalf("want n=2 with error, got n=%d err=%v", n, err)
	}
	if got := conn.count(); got != 2 {
		t.Fatalf("transport sent %d datagrams, want 2", got)
	}
}

// TestWriteBatchEmptyIsNoOp verifies the interface convention for empty
// batches.
func TestWriteBatchEmptyIsNoOp(t *testing.T) {
	conn := newWbDatagramConn()
	q := newWriteBatchPacketConn(conn)
	n, err := q.WriteBatch(nil)
	if err != nil || n != 0 {
		t.Fatalf("want n=0 nil, got n=%d err=%v", n, err)
	}
	if got := conn.count(); got != 0 {
		t.Fatalf("transport sent %d datagrams, want 0", got)
	}
}
