package vmess

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnDialTargetAddrPortConcurrentSafe(t *testing.T) {
	t.Helper()

	oldResolveUDPAddr := resolveUDPAddr
	defer func() {
		resolveUDPAddr = oldResolveUDPAddr
	}()

	resolved := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:8443"))
	var calls atomic.Int32
	resolveUDPAddr = func(network, address string) (*net.UDPAddr, error) {
		if network != "udp" {
			t.Fatalf("unexpected network: %q", network)
		}
		if address != "example.com:8443" {
			t.Fatalf("unexpected address: %q", address)
		}
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return resolved, nil
	}

	c := &Conn{dialTgt: "example.com:8443"}

	const goroutines = 8
	results := make(chan netip.AddrPort, goroutines)
	errs := make(chan error, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr, err := c.dialTargetAddrPort()
			if err != nil {
				errs <- err
				return
			}
			results <- addr
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("dialTargetAddrPort returned error: %v", err)
		}
	}

	for addr := range results {
		if addr != resolved.AddrPort() {
			t.Fatalf("unexpected resolved addr: got %v want %v", addr, resolved.AddrPort())
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("unexpected resolver call count: got %d want 1", got)
	}
}

func TestConnWriteTargetAddrPortMissPathUnmaps(t *testing.T) {
	t.Helper()

	oldResolveUDPAddr := resolveUDPAddr
	defer func() {
		resolveUDPAddr = oldResolveUDPAddr
	}()

	// net.ResolveUDPAddr keeps the 16-byte ::ffff: form for literal IPv4
	// targets; the miss path must return the unmapped form it caches, not
	// the resolver's address.
	v4mapped := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[::ffff:192.168.1.2]:53"))
	resolveUDPAddr = func(network, address string) (*net.UDPAddr, error) {
		return v4mapped, nil
	}

	c := &Conn{dialTgt: "example.com:8443"}

	got, err := c.writeTargetAddrPort("192.168.1.2:53")
	if err != nil {
		t.Fatalf("writeTargetAddrPort miss returned error: %v", err)
	}
	if want := netip.MustParseAddrPort("192.168.1.2:53"); got.AddrPort() != want {
		t.Fatalf("miss path returned %v, want unmapped %v", got.AddrPort(), want)
	}

	// The cache-hit path must observe the same normalized form.
	cached, err := c.writeTargetAddrPort("192.168.1.2:53")
	if err != nil {
		t.Fatalf("writeTargetAddrPort cache hit returned error: %v", err)
	}
	if cached.AddrPort() != got.AddrPort() {
		t.Fatalf("cache hit returned %v, want %v", cached.AddrPort(), got.AddrPort())
	}
}
