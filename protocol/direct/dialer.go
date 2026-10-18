package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
)

var (
	// SymmetricDirect and FullconeDirect are process-wide lazy views of the
	// latest published DirectDialers pair. They remain the compatibility
	// entry points; generation-scoped callers should use NewDirectDialers
	// instead of reading these globals.
	SymmetricDirect netproxy.Dialer = &lazyDirectDialer{fullcone: false}
	FullconeDirect  netproxy.Dialer = &lazyDirectDialer{fullcone: true}

	// globalDirectDialers holds one immutable Symmetric+Fullcone snapshot.
	// Readers load a single pointer so they never observe a mixed-generation pair.
	globalDirectDialers atomic.Pointer[DirectDialers]
)

// DirectDialers is an immutable Symmetric/Fullcone pair that shares the
// process-wide packetReceiver registry and does not publish process globals.
// kdae can keep one pair per generation without racing InitDirectDialers.
type DirectDialers struct {
	Symmetric netproxy.Dialer
	Fullcone  netproxy.Dialer
}

// NewDirectDialers builds a generation-scoped pair. It does not modify the
// exported globals; call InitDirectDialers to publish a pair process-wide.
func NewDirectDialers(fallbackDNS string) DirectDialers {
	return DirectDialers{
		Symmetric: NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: false, FallbackDNS: fallbackDNS}),
		Fullcone:  NewDirectDialerLaddr(netip.Addr{}, Option{FullCone: true, FallbackDNS: fallbackDNS}),
	}
}

func loadGlobalDirectDialers() *DirectDialers {
	for {
		if pair := globalDirectDialers.Load(); pair != nil {
			return pair
		}
		lazy := NewDirectDialers("")
		if globalDirectDialers.CompareAndSwap(nil, &lazy) {
			return &lazy
		}
	}
}

// lazyDirectDialer provides lazy initialization for the exported globals.
// It always reads from a single atomic snapshot.
type lazyDirectDialer struct {
	fullcone bool
}

func (d *lazyDirectDialer) getDialer() netproxy.Dialer {
	pair := loadGlobalDirectDialers()
	if d.fullcone {
		return pair.Fullcone
	}
	return pair.Symmetric
}

// InitDirectDialers publishes a new immutable global pair with optional
// fallback DNS. Later calls replace the snapshot atomically so a restart or
// config reload can publish a new fallback resolver. If never called, dialers
// are lazily initialized without fallback DNS on first use.
func InitDirectDialers(fallbackDNS string) {
	pair := NewDirectDialers(fallbackDNS)
	globalDirectDialers.Store(&pair)
}

func (d *lazyDirectDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return d.getDialer().DialContext(ctx, network, addr)
}

func (d *lazyDirectDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	if resolver, ok := d.getDialer().(interface {
		LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error)
	}); ok {
		return resolver.LookupIPAddr(ctx, network, host)
	}
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type Option struct {
	FullCone    bool
	FallbackDNS string
}

type directDialer struct {
	tcpDialer      *net.Dialer
	tcpDialerMptcp *net.Dialer
	udpLocalAddr   *net.UDPAddr
	receiver       *packetReceiverRegistry
	Option         Option
}

func NewDirectDialerLaddr(lAddr netip.Addr, option Option) netproxy.Dialer {
	var tcpLocalAddr *net.TCPAddr
	var udpLocalAddr *net.UDPAddr
	if lAddr.IsValid() {
		tcpLocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
		udpLocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(lAddr, 0))
	}
	tcpDialer := &net.Dialer{LocalAddr: tcpLocalAddrOrNil(tcpLocalAddr)}
	tcpDialerMptcp := &net.Dialer{LocalAddr: tcpLocalAddrOrNil(tcpLocalAddr)}
	tcpDialerMptcp.SetMultipathTCP(true)
	d := &directDialer{
		tcpDialer:      tcpDialer,
		tcpDialerMptcp: tcpDialerMptcp,
		udpLocalAddr:   udpLocalAddr,
		receiver:       newPacketReceiverRegistry(),
		Option:         option,
	}

	return d
}

// tcpLocalAddrOrNil and udpLocalAddrOrNil return the address as a net.Addr
// only when it holds a real value. Assigning a typed-nil *net.TCPAddr or
// *net.UDPAddr to net.Dialer.LocalAddr keeps the dial wildcard but makes
// dial errors render the source as "<nil>" ("dial tcp <nil>->host:port:
// ..."), so the unset case must stay a nil interface.
func tcpLocalAddrOrNil(addr *net.TCPAddr) net.Addr {
	if addr == nil {
		return nil
	}
	return addr
}

func udpLocalAddrOrNil(addr *net.UDPAddr) net.Addr {
	if addr == nil {
		return nil
	}
	return addr
}

func (d *directDialer) tryRetry(err error, addr string, callback func()) {
	host, _, _ := net.SplitHostPort(addr)
	// Check if the host is domain
	if _, e := netip.ParseAddr(host); e == nil {
		// addr is IP
		return
	}

	// addr is domain
	if err != nil {
		// The resolver surfaces *net.DNSError/*net.OpError, never the bare
		// sentinel; an identity comparison here would never fire and the
		// fallback-DNS retry would silently rot away.
		if outbounderrors.IsDNSTimeout(err) {
			callback()
		}
	}
}

func (d *directDialer) createResolver(mark int, fallback bool) *net.Resolver {
	if mark == 0 && !fallback {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			if mark != 0 {
				dialer.Control = func(network, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				}
			}
			if fallback {
				return dialer.DialContext(ctx, network, d.Option.FallbackDNS)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func preferredNetwork(baseNetwork, ipVersion string) string {
	switch ipVersion {
	case "4", "6":
		return baseNetwork + ipVersion
	default:
		return baseNetwork
	}
}

func (d *directDialer) dialUdp(ctx context.Context, addr string, mark int, ipVersion string, fallback bool) (c netproxy.PacketConn, err error) {
	network := preferredNetwork("udp", ipVersion)
	if d.Option.FallbackDNS != "" && !fallback {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, func() {
				c, err = d.dialUdp(ctx, addr, mark, ipVersion, true)
			})
		}()
	}
	resolver := d.createResolver(mark, fallback)
	if mark == 0 {
		if d.Option.FullCone {
			conn, err := net.ListenUDP(network, d.udpLocalAddr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn, FullCone: true, dialTgt: addr, resolver: resolver, receiver: d.receiver}, nil
		} else {
			dialer := net.Dialer{
				LocalAddr: udpLocalAddrOrNil(d.udpLocalAddr),
				Resolver:  resolver,
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &directPacketConn{UDPConn: conn.(*net.UDPConn), FullCone: false, dialTgt: addr, resolver: resolver, receiver: d.receiver}, nil
		}

	} else {
		var conn *net.UDPConn
		if d.Option.FullCone {
			c := net.ListenConfig{
				Control: func(network string, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
				KeepAlive: 0,
			}
			laddr := ""
			if d.udpLocalAddr != nil {
				laddr = d.udpLocalAddr.String()
			}
			_conn, err := c.ListenPacket(context.Background(), network, laddr)
			if err != nil {
				return nil, err
			}
			conn = _conn.(*net.UDPConn)
		} else {
			dialer := net.Dialer{
				Control: func(network, address string, c syscall.RawConn) error {
					return netproxy.SoMarkControl(c, mark)
				},
				LocalAddr: udpLocalAddrOrNil(d.udpLocalAddr),
				Resolver:  d.createResolver(mark, fallback),
			}
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn = c.(*net.UDPConn)
		}
		return &directPacketConn{UDPConn: conn, FullCone: d.Option.FullCone, dialTgt: addr, resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Control: func(network, address string, c syscall.RawConn) error {
						return netproxy.SoMarkControl(c, mark)
					},
					Resolver: resolver,
				}
				return dialer.DialContext(ctx, network, address)
			},
		}, receiver: d.receiver}, nil
	}
}

func (d *directDialer) dialTcp(ctx context.Context, addr string, mark int, ipVersion string, mptcp bool, fallback bool) (c net.Conn, err error) {
	network := preferredNetwork("tcp", ipVersion)
	if d.Option.FallbackDNS != "" && !fallback {
		defer func() { // don't remove func wrapper for d.tryRetry
			d.tryRetry(err, addr, func() {
				c, err = d.dialTcp(ctx, addr, mark, ipVersion, mptcp, true)
			})
		}()
	}
	var dialer net.Dialer
	if mptcp {
		dialer = *d.tcpDialerMptcp
	} else {
		dialer = *d.tcpDialer
	}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		return netproxy.TCPDialControl(c, mark, address)
	}
	dialer.Resolver = d.createResolver(mark, fallback)
	return dialer.DialContext(ctx, network, addr)
}

func (d *directDialer) lookupIPAddr(ctx context.Context, host string, mark int, fallback bool) ([]net.IPAddr, error) {
	resolver := d.createResolver(mark, fallback)
	if resolver == nil {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
	return resolver.LookupIPAddr(ctx, host)
}

func (d *directDialer) LookupIPAddr(ctx context.Context, network, host string) ([]net.IPAddr, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	ips, err := d.lookupIPAddr(ctx, host, int(magicNetwork.Mark), false)
	if err != nil && d.Option.FallbackDNS != "" && outbounderrors.IsDNSTimeout(err) {
		return d.lookupIPAddr(ctx, host, int(magicNetwork.Mark), true)
	}
	return ips, err
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		return d.dialTcp(ctx, addr, int(magicNetwork.Mark), magicNetwork.IPVersion, magicNetwork.Mptcp, false)
	case "udp":
		return d.dialUdp(ctx, addr, int(magicNetwork.Mark), magicNetwork.IPVersion, false)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
