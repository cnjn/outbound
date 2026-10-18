//go:build linux

package direct

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// TestNewDirectDialerLaddrOmitsTypedNilLocalAddr locks the LocalAddr contract:
// without a bind address the dialer must leave the field a nil interface so
// dial errors render no source, and with a bind address the source must
// render. A typed-nil *net.TCPAddr in the net.Addr field used to produce
// "dial tcp <nil>->host:port: ..." on every unbound direct dial.
func TestNewDirectDialerLaddrOmitsTypedNilLocalAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listen unavailable: %v", err)
	}
	target := ln.Addr().String()
	_ = ln.Close()

	unbound := NewDirectDialerLaddr(netip.Addr{}, Option{})
	_, err = unbound.DialContext(context.Background(), "tcp", target)
	if err == nil {
		t.Fatal("expected dial to a closed port to fail")
	}
	if strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("dial error must not render a typed-nil source: %v", err)
	}

	bound := NewDirectDialerLaddr(netip.MustParseAddr("127.0.0.1"), Option{})
	_, err = bound.DialContext(context.Background(), "tcp", target)
	if err == nil {
		t.Fatal("expected dial to a closed port to fail")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:0->") {
		t.Fatalf("dial error must render the bound source: %v", err)
	}
}
