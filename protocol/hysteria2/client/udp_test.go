package client

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

type noopUDPTestIO struct{}

func (noopUDPTestIO) ReceiveMessage() (*protocol.UDPMessage, error)  { return nil, nil }
func (noopUDPTestIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }

func TestUDPConnWriteToSerializesSendFunc(t *testing.T) {
	t.Helper()

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{}, 1)

	var active atomic.Int32
	var calls atomic.Int32

	u := &udpConn{
		ID:        1,
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		SendBuf:   make([]byte, protocol.MaxUDPSize),
		SendFunc: func(buf []byte, msg *protocol.UDPMessage) error {
			if len(buf) != protocol.MaxUDPSize {
				t.Fatalf("unexpected send buffer length: got %d want %d", len(buf), protocol.MaxUDPSize)
			}

			if active.Add(1) > 1 {
				select {
				case secondEntered <- struct{}{}:
				default:
				}
			}

			if calls.Add(1) == 1 {
				close(firstEntered)
				<-releaseFirst
			}

			active.Add(-1)
			return nil
		},
		CloseFunc: func() {},
		target:    "127.0.0.1:443",
	}

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := u.WriteTo([]byte("payload"), "127.0.0.1:443"); err != nil {
				t.Errorf("WriteTo returned error: %v", err)
			}
		}()
	}

	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first WriteTo did not enter SendFunc")
	}

	select {
	case <-secondEntered:
		t.Fatal("SendFunc entered concurrently for the same udpConn")
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseFirst)
	wg.Wait()

	if got := calls.Load(); got != 2 {
		t.Fatalf("unexpected SendFunc call count: got %d want 2", got)
	}
}

func TestUDPConnFeedMessageCloseBarrier(t *testing.T) {
	newFragment := func(released *atomic.Int32) *protocol.UDPMessage {
		return &protocol.UDPMessage{
			SessionID: 1,
			PacketID:  7,
			FragID:    0,
			FragCount: 2,
			Addr:      []byte("192.0.2.10:443"),
			Data:      []byte("partial"),
			Release:   func() { released.Add(1) },
		}
	}

	t.Run("close before feed", func(t *testing.T) {
		u := &udpConn{D: &frag.Defragger{}}
		var released atomic.Int32
		u.closed.Store(true)
		u.receiveMu.Lock()
		u.D.Close()
		u.receiveMu.Unlock()

		if got := u.feedMessage(newFragment(&released)); got != nil {
			t.Fatalf("feedMessage() = %v, want nil", got)
		}
		if got := released.Load(); got != 1 {
			t.Fatalf("fragment releases = %d, want 1", got)
		}
		u.D.Close()
		if got := released.Load(); got != 1 {
			t.Fatalf("fragment releases after Defragger.Close = %d, want 1", got)
		}
	})

	t.Run("feed before close", func(t *testing.T) {
		u := &udpConn{D: &frag.Defragger{}}
		var released atomic.Int32

		if got := u.feedMessage(newFragment(&released)); got != nil {
			t.Fatalf("feedMessage() = %v, want nil", got)
		}
		if got := released.Load(); got != 0 {
			t.Fatalf("fragment releases before close = %d, want 0", got)
		}
		u.closed.Store(true)
		u.receiveMu.Lock()
		u.D.Close()
		u.receiveMu.Unlock()
		if got := released.Load(); got != 1 {
			t.Fatalf("fragment releases after close = %d, want 1", got)
		}
	})
}

func TestUDPConnCloseConcurrentWrite(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.10:443")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)

	firstWrite := make(chan struct{})
	var firstWriteOnce sync.Once
	originalSend := u.SendFunc
	u.SendFunc = func(buf []byte, msg *protocol.UDPMessage) error {
		firstWriteOnce.Do(func() { close(firstWrite) })
		return originalSend(buf, msg)
	}

	u.receiverMu.Lock()
	var writers sync.WaitGroup
	for range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for {
				if _, err := u.WriteTo([]byte("payload"), u.target); err != nil {
					return
				}
			}
		}()
	}
	<-firstWrite

	closed := make(chan struct{})
	go func() {
		m.close(u)
		close(closed)
	}()
	u.receiverMu.Unlock()

	<-closed
	writers.Wait()
}

func TestUDPConnMessageAddrUsesDefaultCacheAndPerDatagramFallback(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	const target = "[2001:db8::1]:443"
	connRaw, err := m.NewUDP(target)
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)
	defer m.close(u)

	tests := []struct {
		name    string
		addr    string
		want    netip.AddrPort
		wantErr bool
	}{
		{
			name: "cached default target",
			addr: target,
			want: netip.MustParseAddrPort(target),
		},
		{
			name: "equivalent target spelling",
			addr: "[2001:db8:0:0:0:0:0:1]:443",
			want: netip.MustParseAddrPort(target),
		},
		{
			name: "alternate peer",
			addr: "198.51.100.8:8443",
			want: netip.MustParseAddrPort("198.51.100.8:8443"),
		},
		{
			name: "cached default after alternate peer",
			addr: target,
			want: netip.MustParseAddrPort(target),
		},
		{
			name:    "malformed peer",
			addr:    "not-an-addr-port",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.addrForMessage([]byte(tt.addr))
			if tt.wantErr {
				if err == nil {
					t.Fatal("addrForMessage() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("addrForMessage() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("addrForMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUDPConnReassembledPacketPreservesDefaultAddressAndRelease(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	const target = "192.0.2.10:5353"
	connRaw, err := m.NewUDP(target)
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)
	defer m.close(u)

	type received struct {
		data []byte
		from netip.AddrPort
	}
	receivedCh := make(chan received, 1)
	if _, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		receivedCh <- received{data: append([]byte(nil), packet.Data...), from: packet.From}
		packet.Release()
		return true
	}); !ok {
		t.Fatal("RegisterPacketReceiver() = false")
	}

	var released atomic.Int32
	for fragID, data := range [][]byte{[]byte("hello "), []byte("world")} {
		if !u.deliverMessage(&protocol.UDPMessage{
			SessionID: u.ID,
			PacketID:  7,
			FragID:    uint8(fragID),
			FragCount: 2,
			Addr:      []byte(target),
			Data:      data,
			Release:   func() { released.Add(1) },
		}) {
			t.Fatalf("deliverMessage(fragment %d) = false", fragID)
		}
	}

	got := <-receivedCh
	if string(got.data) != "hello world" {
		t.Fatalf("reassembled data = %q, want %q", got.data, "hello world")
	}
	if want := netip.MustParseAddrPort(target); got.from != want {
		t.Fatalf("reassembled address = %v, want %v", got.from, want)
	}
	if got := released.Load(); got != 2 {
		t.Fatalf("fragment releases = %d, want 2", got)
	}
}

func TestUDPConnReassembledPacketKeepsAddressAfterFragmentRelease(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	const target = "192.0.2.10:5353"
	connRaw, err := m.NewUDP(target)
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)
	defer m.close(u)

	type received struct {
		data []byte
		from netip.AddrPort
	}
	receivedCh := make(chan received, 1)
	if _, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		receivedCh <- received{data: append([]byte(nil), packet.Data...), from: packet.From}
		packet.Release()
		return true
	}); !ok {
		t.Fatal("RegisterPacketReceiver() = false")
	}

	newFragment := func(id uint8, payload []byte) *protocol.UDPMessage {
		backing := append([]byte(target), payload...)
		return &protocol.UDPMessage{
			SessionID: u.ID,
			PacketID:  7,
			FragID:    id,
			FragCount: 2,
			Addr:      backing[:len(target)],
			Data:      backing[len(target):],
			Release: func() {
				for i := range backing {
					backing[i] = 'x'
				}
			},
		}
	}
	if !u.deliverMessage(newFragment(0, []byte("hello "))) {
		t.Fatal("deliverMessage(fragment 0) = false")
	}
	if !u.deliverMessage(newFragment(1, []byte("world"))) {
		t.Fatal("deliverMessage(fragment 1) = false")
	}

	got := <-receivedCh
	if string(got.data) != "hello world" {
		t.Fatalf("reassembled data = %q, want %q", got.data, "hello world")
	}
	if want := netip.MustParseAddrPort(target); got.from != want {
		t.Fatalf("reassembled address = %v, want %v", got.from, want)
	}
}

func TestUDPConnReadFromReportsPerDatagramMessageAddress(t *testing.T) {
	targetAddr := netip.MustParseAddrPort("192.0.2.10:5353")
	messageAddrs := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.8:443"),
		netip.MustParseAddrPort("203.0.113.9:8443"),
	}
	var released atomic.Int32
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, len(messageAddrs)),
		target:    targetAddr.String(),
	}
	for _, messageAddr := range messageAddrs {
		u.ReceiveCh <- &protocol.UDPMessage{
			SessionID: 1,
			FragCount: 1,
			Addr:      []byte(messageAddr.String()),
			Data:      []byte(messageAddr.String()),
			Release:   func() { released.Add(1) },
		}
	}

	buf := make([]byte, 64)
	for _, want := range messageAddrs {
		n, from, err := u.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() error = %v", err)
		}
		if got := string(buf[:n]); got != want.String() {
			t.Fatalf("ReadFrom() data = %q, want %q", got, want)
		}
		if from != want {
			t.Fatalf("ReadFrom() address = %v, want message address %v", from, want)
		}
	}
	if got, want := released.Load(), int32(len(messageAddrs)); got != want {
		t.Fatalf("Release calls = %d, want %d", got, want)
	}
}

// TestUDPConnReadFromSurfacesOversizedDatagramAsDropped pins the
// datagram-dropped contract: a datagram larger than the caller's buffer is
// consumed (released) and reported through the typed error unwrapping to
// io.ErrShortBuffer, so consumers keep the session instead of retiring it.
func TestUDPConnReadFromSurfacesOversizedDatagramAsDropped(t *testing.T) {
	var released atomic.Int32
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 2),
		target:    "192.0.2.10:5353",
	}
	push := func(data string) {
		u.ReceiveCh <- &protocol.UDPMessage{
			SessionID: 1,
			FragCount: 1,
			Addr:      []byte("198.51.100.8:443"),
			Data:      []byte(data),
			Release:   func() { released.Add(1) },
		}
	}
	push("0123456789abcdef")
	push("ok")

	small := make([]byte, 8)
	n, _, err := u.ReadFrom(small)
	var dropped *netproxy.ErrDatagramDropped
	if !errors.As(err, &dropped) || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("ReadFrom() err = %v, want datagram-dropped/ErrShortBuffer", err)
	}
	if n != len(small) {
		t.Fatalf("ReadFrom() n = %d, want %d (partial copy)", n, len(small))
	}

	// The session stays aligned: the next datagram arrives intact.
	buf := make([]byte, 16)
	n, _, err = u.ReadFrom(buf)
	if err != nil {
		t.Fatalf("next ReadFrom() error = %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("next datagram = %q, want ok", buf[:n])
	}
	if got, want := released.Load(), int32(2); got != want {
		t.Fatalf("Release calls = %d, want %d", got, want)
	}
}

func TestUDPConnReadFromMalformedAddressReleasesMessage(t *testing.T) {
	targetAddr := netip.MustParseAddrPort("192.0.2.10:5353")
	var released atomic.Int32
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		target:    targetAddr.String(),
	}
	u.ReceiveCh <- &protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		Addr:      []byte("not-an-addr-port"),
		Data:      []byte("malformed"),
		Release:   func() { released.Add(1) },
	}

	n, from, err := u.ReadFrom(make([]byte, 64))
	if err == nil {
		t.Fatal("ReadFrom() error = nil, want address parse error")
	}
	if n != 0 || from.IsValid() {
		t.Fatalf("ReadFrom() = (%d, %v), want zero values on malformed address", n, from)
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("Release calls = %d, want 1", got)
	}
}

func TestUDPConnPacketReceiverDrainsQueuedMessage(t *testing.T) {
	targetAddr := netip.MustParseAddrPort("192.0.2.10:5353")
	messageAddr := netip.MustParseAddrPort("198.51.100.8:443")
	var released atomic.Int32
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 2),
		target:    targetAddr.String(),
	}
	u.ReceiveCh <- &protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		Addr:      []byte(messageAddr.String()),
		Data:      []byte("queued"),
		Release:   func() { released.Add(1) },
	}

	packets := make(chan *netproxy.ReceivedPacket, 1)
	unregister, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packets <- packet
		return true
	})
	if !ok || unregister == nil {
		t.Fatal("expected packet receiver registration")
	}
	defer unregister()

	select {
	case packet := <-packets:
		if string(packet.Data) != "queued" {
			t.Fatalf("packet data = %q, want queued", packet.Data)
		}
		if packet.From != messageAddr {
			t.Fatalf("packet address = %v, want message address %v", packet.From, messageAddr)
		}
		packet.Release()
		if got := released.Load(); got != 1 {
			t.Fatalf("Release calls = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("packet receiver did not drain queued message")
	}
}

func TestUDPConnPacketReceiverMalformedAddressReleasesMessage(t *testing.T) {
	var delivered atomic.Int32
	var released atomic.Int32
	u := &udpConn{
		ID: 1,
		D:  &frag.Defragger{},
		receiver: func(packet *netproxy.ReceivedPacket) bool {
			delivered.Add(1)
			packet.Release()
			return true
		},
	}

	claimed := u.deliverMessage(&protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		Addr:      []byte("not-an-addr-port"),
		Data:      []byte("malformed"),
		Release:   func() { released.Add(1) },
	})
	if !claimed {
		t.Fatal("deliverMessage() = false, want malformed message claimed")
	}
	if got := delivered.Load(); got != 0 {
		t.Fatalf("handler calls = %d, want 0 for malformed address", got)
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("Release calls = %d, want 1", got)
	}
}

func TestUDPSessionManagerUsesPacketReceiverForNewMessages(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.20:443")
	if err != nil {
		t.Fatalf("NewUDP returned error: %v", err)
	}
	u := connRaw.(*udpConn)
	packets := make(chan *netproxy.ReceivedPacket, 1)
	unregister, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packets <- packet
		return true
	})
	if !ok {
		t.Fatal("expected packet receiver registration")
	}
	defer func() {
		unregister()
		_ = u.Close()
	}()

	var released atomic.Int32
	m.feed(&protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      []byte("198.51.100.8:443"),
		Data:      []byte("transport-owned"),
		Release:   func() { released.Add(1) },
	})
	select {
	case packet := <-packets:
		if string(packet.Data) != "transport-owned" {
			t.Fatalf("packet data = %q, want transport-owned", packet.Data)
		}
		if want := netip.MustParseAddrPort("198.51.100.8:443"); packet.From != want {
			t.Fatalf("packet address = %v, want message address %v", packet.From, want)
		}
		packet.Release()
		if got := released.Load(); got != 1 {
			t.Fatalf("Release calls = %d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("session manager did not use registered packet receiver")
	}
	if got := len(u.ReceiveCh); got != 0 {
		t.Fatalf("ReceiveCh length = %d, want 0 when receiver is registered", got)
	}
}

func TestUDPConnSetDeadlineZeroClearsTimer(t *testing.T) {
	var closes atomic.Int32
	u := &udpConn{
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		CloseFunc: func() { closes.Add(1) },
	}

	if err := u.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if err := u.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline(zero) error = %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	if got := closes.Load(); got != 0 {
		t.Fatalf("CloseFunc calls after clearing deadline = %d, want 0", got)
	}
}

func TestUDPConnCloseStopsDeadlineTimer(t *testing.T) {
	var closes atomic.Int32
	u := &udpConn{
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		CloseFunc: func() { closes.Add(1) },
	}

	if err := u.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	if got := closes.Load(); got != 1 {
		t.Fatalf("CloseFunc calls after Close() = %d, want 1", got)
	}
}

func TestUDPConnDeadlineClosesSession(t *testing.T) {
	var closes atomic.Int32
	var closeOnce sync.Once
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
	}
	u.CloseFunc = func() {
		closes.Add(1)
		closeOnce.Do(func() { close(u.ReceiveCh) })
	}

	if err := u.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}

	select {
	case msg := <-u.ReceiveCh:
		if msg != nil {
			t.Fatalf("ReceiveCh yielded %v, want closed channel", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not close UDP session")
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("CloseFunc calls after deadline = %d, want 1", got)
	}
}

func TestUDPConnDeadlineCanBeAppliedWhileReadIsPending(t *testing.T) {
	var closes atomic.Int32
	var closeOnce sync.Once
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
	}
	u.CloseFunc = func() {
		closes.Add(1)
		closeOnce.Do(func() { close(u.ReceiveCh) })
	}

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := u.ReadFrom(buf)
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := u.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err != io.EOF {
			t.Fatalf("ReadFrom() error = %T %v, want EOF after close", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock after deadline closed the session")
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("CloseFunc calls after pending read deadline = %d, want 1", got)
	}
}

func TestUDPSessionManagerTransportDoneClosesWithManager(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}

	connRaw, err := m.NewUDP("127.0.0.1:53")
	if err != nil {
		t.Fatalf("NewUDP returned error: %v", err)
	}
	conn, ok := connRaw.(*udpConn)
	if !ok {
		t.Fatalf("unexpected conn type: %T", connRaw)
	}
	if got := conn.TransportDone(); got != m.done {
		t.Fatal("expected UDP session to expose manager transport done channel")
	}

	m.closeCleanup()

	select {
	case <-conn.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("expected manager cleanup to close transport done channel")
	}
}

func TestUDPConnWriteToFragmentsWhenLocalSendBufferIsTooSmall(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 64)
	addr := "203.0.113.10:40000"

	var sent []protocol.UDPMessage
	u := &udpConn{
		ID:        7,
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		SendBuf:   make([]byte, 32),
		SendFunc: func(_ []byte, msg *protocol.UDPMessage) error {
			msgCopy := *msg
			msgCopy.Data = append([]byte(nil), msg.Data...)
			sent = append(sent, msgCopy)
			return nil
		},
		CloseFunc: func() {},
		target:    addr,
	}

	n, err := u.WriteTo(payload, addr)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo() n = %d, want %d", n, len(payload))
	}
	if len(sent) < 2 {
		t.Fatalf("expected fragmentation to emit multiple messages, got %d", len(sent))
	}

	var reassembled []byte
	for i, msg := range sent {
		if got := msg.Size(); got > len(u.SendBuf) {
			t.Fatalf("fragment %d size = %d, want <= %d", i, got, len(u.SendBuf))
		}
		reassembled = append(reassembled, msg.Data...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled payload mismatch: got %d bytes want %d", len(reassembled), len(payload))
	}
}

func TestUDPConnWriteToRejectsUnfragmentableDatagram(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 64)
	addr := "203.0.113.10:40000"
	u := &udpConn{
		ID:        7,
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		SendBuf:   make([]byte, 8),
		SendFunc: func(_ []byte, _ *protocol.UDPMessage) error {
			t.Fatal("SendFunc should not be called when fragmentation is impossible")
			return nil
		},
		CloseFunc: func() {},
		target:    addr,
	}

	n, err := u.WriteTo(payload, addr)
	if err == nil {
		t.Fatal("expected WriteTo to fail when the send buffer cannot hold a fragment header")
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

func TestUDPSessionManagerQueueAbsorbsModerateBurstWithoutDrop(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}

	connRaw, err := m.NewUDP("127.0.0.1:53")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	conn := connRaw.(*udpConn)

	// 3/4 of the queue depth: large enough to prove burst absorption, small
	// enough to leave headroom for the concurrent feed path.
	const burst = udpMessageChanSize * 3 / 4
	if burst >= udpMessageChanSize {
		t.Fatalf("burst = %d must stay below queue size %d", burst, udpMessageChanSize)
	}

	for i := 0; i < burst; i++ {
		m.feed(&protocol.UDPMessage{
			SessionID: conn.ID,
			PacketID:  uint16(i + 1),
			FragID:    0,
			FragCount: 1,
			Addr:      []byte("127.0.0.1:53"),
			Data:      []byte{byte(i)},
		})
	}

	if got := len(conn.ReceiveCh); got != burst {
		t.Fatalf("queued messages = %d, want %d", got, burst)
	}

	m.closeCleanup()
}

func TestUDPConnCloseReturnsSendBufAndRejectsWrite(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.1:443")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)
	if u.SendBuf == nil {
		t.Fatal("expected a pooled send buffer")
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if u.SendBuf != nil {
		t.Fatal("SendBuf must be returned to the pool and nilled")
	}
	if _, err := u.WriteTo([]byte("late"), "192.0.2.1:443"); err == nil {
		t.Fatal("WriteTo after Close must fail")
	} else if _, ok := err.(coreErrs.ClosedError); !ok {
		t.Fatalf("WriteTo after Close error = %T (%v), want ClosedError", err, err)
	}
}

func TestUDPConnCloseDrainsQueuedMessages(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.2:443")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)

	var released atomic.Int32
	queued := &protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      []byte("192.0.2.2:443"),
		Data:      []byte("queued"),
		Release:   func() { released.Add(1) },
	}
	u.ReceiveCh <- queued
	if err := u.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("queued message Release calls = %d, want 1", got)
	}
	if _, ok := <-u.ReceiveCh; ok {
		t.Fatal("ReceiveCh must be closed after Close")
	}
}

func TestUDPSessionManagerQueueIfNoReceiverReleasesOnClosed(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.3:443")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)
	if err := u.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	var released atomic.Int32
	late := &protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      []byte("192.0.2.3:443"),
		Data:      []byte("late"),
		Release:   func() { released.Add(1) },
	}
	if !u.queueIfNoReceiver(late) {
		t.Fatal("queueIfNoReceiver on a closed session must claim the message")
	}
	if got := released.Load(); got != 1 {
		t.Fatalf("closed-session Release calls = %d, want 1", got)
	}
}

func TestUDPConnRegisterPacketReceiverPreservesFIFOWithFeed(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.4:443")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	u := connRaw.(*udpConn)
	defer u.Close()

	u.ReceiveCh <- &protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      []byte("192.0.2.4:443"),
		Data:      []byte{0},
	}
	u.ReceiveCh <- &protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      []byte("192.0.2.4:443"),
		Data:      []byte{1},
	}

	var mu sync.Mutex
	var got []byte
	started := make(chan struct{})
	block := make(chan struct{})
	regDone := make(chan struct{})
	var unregister func()
	go func() {
		defer close(regDone)
		var ok bool
		unregister, ok = u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
			select {
			case <-started:
			default:
				close(started)
				<-block
			}
			mu.Lock()
			got = append(got, packet.Data[0])
			mu.Unlock()
			packet.Release()
			return true
		})
		if !ok {
			t.Error("expected packet receiver registration")
		}
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("drain did not start")
	}

	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		m.feed(&protocol.UDPMessage{
			SessionID: u.ID,
			FragCount: 1,
			Addr:      []byte("192.0.2.4:443"),
			Data:      []byte{2},
		})
	}()
	time.Sleep(20 * time.Millisecond)
	close(block)
	select {
	case <-regDone:
	case <-time.After(time.Second):
		t.Fatal("RegisterPacketReceiver did not finish drain")
	}
	if unregister != nil {
		defer unregister()
	}
	select {
	case <-feedDone:
	case <-time.After(time.Second):
		t.Fatal("feed blocked behind drain")
	}

	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		n := len(got)
		copyGot := append([]byte(nil), got...)
		mu.Unlock()
		if n == 3 {
			if copyGot[0] != 0 || copyGot[1] != 1 || copyGot[2] != 2 {
				t.Fatalf("delivery order = %v, want [0 1 2]", copyGot)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %v, want three in-order packets", copyGot)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
