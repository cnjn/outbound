package direct

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestDirectPacketConnWriteToUsesDialTargetCache(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().String()
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  target,
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		)), nil
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("ping"), target); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolveUDPAddr() call count = %d, want 1", got)
	}
}

func TestDirectPacketConnWriteToCachesAlternateTarget(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	target := serverConn.LocalAddr().String()
	conn := &directPacketConn{
		UDPConn:  clientConn,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(resolver *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{127, 0, 0, 1}),
			uint16(serverConn.LocalAddr().(*net.UDPAddr).Port),
		)), nil
	}

	for i := 0; i < 2; i++ {
		if _, err := conn.WriteTo([]byte("ping"), target); err != nil {
			t.Fatalf("WriteTo() error = %v", err)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("resolveUDPAddr() call count = %d, want 1", got)
	}
}

// TestDirectPacketConnWriteBatchAlternatingPeersResolveOnce pins the
// FullCone multi-peer contract: a relay whose client alternates between
// several non-dial targets must resolve each target exactly once, and every
// datagram must land on the server its address maps to.
func TestDirectPacketConnWriteBatchAlternatingPeersResolveOnce(t *testing.T) {
	const peers = 3
	servers := make([]*net.UDPConn, peers)
	targets := make([]string, peers)
	for i := range servers {
		server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("ListenUDP(server %d): %v", i, err)
		}
		t.Cleanup(func() { _ = server.Close() })
		servers[i] = server
		targets[i] = fmt.Sprintf("peer-%d.invalid:53", i)
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	var calls atomic.Int32
	resolveUDPAddr = func(_ *net.Resolver, hostport string) (*net.UDPAddr, error) {
		calls.Add(1)
		for i, target := range targets {
			if hostport == target {
				return (*net.UDPAddr)(servers[i].LocalAddr().(*net.UDPAddr)), nil
			}
		}
		return nil, fmt.Errorf("unexpected target %q", hostport)
	}

	payload := []byte("payload-0123456789")
	for round := 0; round < 16; round++ {
		items := make([]netproxy.BatchItem, peers)
		for i := range items {
			items[i] = netproxy.BatchItem{Data: payload, Addr: targets[i]}
		}
		if n, err := conn.WriteBatch(items); err != nil || n != peers {
			t.Fatalf("WriteBatch() = %d, %v; want %d, nil", n, err, peers)
		}
	}

	if got := calls.Load(); got != peers {
		t.Fatalf("resolveUDPAddr() call count = %d, want %d (one per peer)", got, peers)
	}

	// Every datagram must have landed on the peer its address resolved to.
	for i, server := range servers {
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(payload))
		for round := 0; round < 16; round++ {
			n, _, err := server.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("server %d round %d ReadFromUDP: %v", i, round, err)
			}
			if string(buf[:n]) != string(payload) {
				t.Fatalf("server %d round %d payload = %q", i, round, buf[:n])
			}
		}
	}
}

// TestDirectPacketConnWriteTgtCacheBounded pins the eviction contract: the
// resolved-target cache never exceeds its capacity no matter how many
// distinct peers the relay writes to.
func TestDirectPacketConnWriteTgtCacheBounded(t *testing.T) {
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	resolveUDPAddr = func(_ *net.Resolver, _ string) (*net.UDPAddr, error) {
		return (*net.UDPAddr)(server.LocalAddr().(*net.UDPAddr)), nil
	}

	for i := 0; i < writeTgtCacheCapacity+5; i++ {
		if _, err := conn.WriteTo([]byte("x"), fmt.Sprintf("peer-%d.invalid:53", i)); err != nil {
			t.Fatalf("WriteTo(peer %d): %v", i, err)
		}
	}

	conn.cacheMu.Lock()
	size := len(conn.writeTgtCache)
	conn.cacheMu.Unlock()
	if size > writeTgtCacheCapacity {
		t.Fatalf("writeTgtCache size = %d, want <= %d", size, writeTgtCacheCapacity)
	}
}

// TestDirectPacketConnSlowResolveDoesNotBlockOtherTargets pins the two-phase
// target-cache access: resolving the dial target can block for the resolver
// timeout (seconds), and that resolution must hold no cache lock, or a write
// to any other peer waits behind it for as long as one lookup takes. The
// injectable resolver parks the dial-target lookup while the other target is
// written, so the pre-fix code blocks here until the parked lookup is
// released instead of completing promptly.
func TestDirectPacketConnSlowResolveDoesNotBlockOtherTargets(t *testing.T) {
	const (
		slowTarget = "slow.example:53"
		fastTarget = "fast.example:53"
		// Generous against a loaded -race run: the pre-fix failure mode is a
		// block until the parked resolver is released, not a slow path.
		prompt = 2 * time.Second
	)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()

	resolving := make(chan struct{}, 1)
	// Buffered so the cleanup release cannot block when the resolver was never
	// entered, and one release can still be left over after the test used one.
	release := make(chan struct{}, 1)
	t.Cleanup(func() { release <- struct{}{} })

	resolveUDPAddr = func(_ *net.Resolver, hostport string) (*net.UDPAddr, error) {
		if hostport == slowTarget {
			select {
			case resolving <- struct{}{}:
			default:
			}
			<-release
		}
		return net.UDPAddrFromAddrPort(server.LocalAddr().(*net.UDPAddr).AddrPort()), nil
	}

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  slowTarget,
		resolver: net.DefaultResolver,
	}

	slowDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("slow"))
		slowDone <- err
	}()
	select {
	case <-resolving:
	case <-time.After(prompt):
		t.Fatal("the dial-target resolution never started")
	}

	fastDone := make(chan error, 1)
	go func() {
		_, err := conn.WriteTo([]byte("fast"), fastTarget)
		fastDone <- err
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("WriteTo(%s) error = %v, want nil", fastTarget, err)
		}
	case <-time.After(prompt):
		t.Fatal("WriteTo to an unrelated target blocked behind the parked dial-target resolution")
	}

	release <- struct{}{}
	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatalf("Write() to the dial target error = %v, want nil", err)
		}
	case <-time.After(prompt):
		t.Fatal("the dial-target write did not finish after the resolution was released")
	}
}

// BenchmarkDirectWriteBatchAlternatingPeers measures the FullCone write path
// with a realistic resolver stub (parsing only, no network): the metric that
// matters is resolutions per operation, which the bounded cache drops from
// one-per-datagram to one-per-target.
func BenchmarkDirectWriteBatchAlternatingPeers(b *testing.B) {
	for _, peers := range []int{2, 4} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				b.Fatalf("ListenUDP(client): %v", err)
			}
			defer func() { _ = client.Close() }()

			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				b.Fatalf("ListenUDP(server): %v", err)
			}
			defer func() { _ = server.Close() }()

			conn := &directPacketConn{
				UDPConn:  client,
				FullCone: true,
				dialTgt:  "127.0.0.1:1",
				resolver: net.DefaultResolver,
			}
			targets := make([]string, peers)
			for i := range targets {
				targets[i] = fmt.Sprintf("peer-%d.invalid:53", i)
			}

			oldResolve := resolveUDPAddr
			defer func() { resolveUDPAddr = oldResolve }()
			var calls atomic.Int64
			resolveUDPAddr = func(_ *net.Resolver, _ string) (*net.UDPAddr, error) {
				calls.Add(1)
				return (*net.UDPAddr)(server.LocalAddr().(*net.UDPAddr)), nil
			}

			payload := []byte("payload-0123456789")
			items := make([]netproxy.BatchItem, peers)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := range items {
					items[j] = netproxy.BatchItem{Data: payload, Addr: targets[j]}
				}
				if _, err := conn.WriteBatch(items); err != nil {
					b.Fatalf("WriteBatch: %v", err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(calls.Load())/float64(b.N), "resolves/op")
		})
	}
}

// TestDirectPacketConnSlowResolveDoesNotBlockManyTargets is the multi-peer
// version of TestDirectPacketConnSlowResolveDoesNotBlockOtherTargets: a
// full-cone relay serves one client per peer, so a parked dial-target lookup
// must not serialise the writes of every other peer behind it.
func TestDirectPacketConnSlowResolveDoesNotBlockManyTargets(t *testing.T) {
	const (
		slowTarget = "slow-many.example:53"
		prompt     = 2 * time.Second
		peers      = 8
	)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	serverAddr := server.LocalAddr().(*net.UDPAddr).AddrPort()

	oldResolve := resolveUDPAddr
	defer func() { resolveUDPAddr = oldResolve }()
	var parked sync.Once
	resolving, release := make(chan struct{}), make(chan struct{})
	resolveUDPAddr = func(_ *net.Resolver, hostport string) (*net.UDPAddr, error) {
		if host, _, _ := net.SplitHostPort(hostport); host == "slow-many.example" {
			parked.Do(func() { close(resolving) })
			<-release
		}
		return net.UDPAddrFromAddrPort(serverAddr), nil
	}

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  slowTarget,
		resolver: net.DefaultResolver,
	}
	slowDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("slow"))
		slowDone <- err
	}()
	select {
	case <-resolving:
	case <-time.After(prompt):
		t.Fatal("the dial-target resolution never started")
	}

	blocked := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		errs := make(chan error, peers)
		for i := range peers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := conn.WriteTo([]byte("peer"), fmt.Sprintf("peer-%d.example:53", i))
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Errorf("WriteTo(peer) error = %v, want nil", err)
			}
		}
		close(blocked)
	}()
	select {
	case <-blocked:
	case <-time.After(prompt):
		t.Fatal("peer writes blocked behind the parked dial-target resolution")
	}

	close(release)
	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatalf("Write() to the dial target error = %v, want nil", err)
		}
	case <-time.After(prompt):
		t.Fatal("the dial-target write did not finish after the resolution was released")
	}
}

// TestDirectPacketConnUsesProductionResolver keeps the injected-resolver tests
// honest: a hostname write must resolve through common.ResolveUDPAddr, the
// default value of resolveUDPAddr, and reach the peer. "localhost" comes from
// the host's own hosts file, so the test needs no network; the peer is bound on
// whichever loopback families the resolver can return.
func TestDirectPacketConnUsesProductionResolver(t *testing.T) {
	const payload = "hello-production-resolver"
	addrs, err := net.DefaultResolver.LookupNetIP(t.Context(), "ip", "localhost")
	if err != nil || len(addrs) == 0 {
		t.Skipf("cannot resolve localhost from the host's own name sources: %v (%v)", err, addrs)
	}
	var servers []*net.UDPConn
	port := 0
	for _, addr := range addrs {
		addr = addr.Unmap()
		network := "udp4"
		if addr.Is6() {
			network = "udp6"
		}
		server, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, uint16(port))))
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = server.Close() })
		servers = append(servers, server)
		port = server.LocalAddr().(*net.UDPAddr).Port
	}
	if len(servers) == 0 {
		t.Skipf("cannot bind a loopback peer for %v", addrs)
	}

	// The production write path resolves the name and sends to whatever
	// address the resolver returns first, so the client socket must be bound
	// on that family: on hosts where "localhost" resolves to ::1 first (the
	// GitHub runners), a udp4 socket cannot carry the write.
	clientNetwork, clientIP := "udp4", net.ParseIP("127.0.0.1")
	if first := addrs[0].Unmap(); first.Is6() {
		clientNetwork, clientIP = "udp6", net.ParseIP("::1")
	}
	client, err := net.ListenUDP(clientNetwork, &net.UDPAddr{IP: clientIP, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "127.0.0.1:1",
		resolver: net.DefaultResolver,
	}
	if _, err := conn.WriteTo([]byte(payload), fmt.Sprintf("localhost:%d", port)); err != nil {
		t.Fatalf("WriteTo(localhost:%d) error = %v; the production resolver path must resolve a hosts-file name", port, err)
	}

	received := make(chan string, len(servers))
	for _, server := range servers {
		go func(server *net.UDPConn) {
			_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 128)
			n, _, err := server.ReadFromUDP(buf)
			if err != nil {
				received <- ""
				return
			}
			received <- string(buf[:n])
		}(server)
	}
	for range servers {
		if got := <-received; got == payload {
			return
		}
	}
	t.Fatalf("no loopback peer received %q; the production resolver path did not deliver the datagram", payload)
}
