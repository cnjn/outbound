package hysteria2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/daeuniverse/outbound/dialer/stickyip"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/client"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

func init() {
	protocol.Register("hysteria2", NewDialer)
}

type Dialer struct {
	client   client.Client
	metadata protocol.Metadata
}

type Feature1 struct {
	BandwidthConfig client.BandwidthConfig
	UDPHopInterval  time.Duration
	ObfsPassword    string
}

func toClientTLSConfig(config *tls.Config) client.TLSConfig {
	return client.TLSConfig{
		ServerName:                     config.ServerName,
		InsecureSkipVerify:             config.InsecureSkipVerify,
		VerifyPeerCertificate:          config.VerifyPeerCertificate,
		RootCAs:                        config.RootCAs,
		EncryptedClientHelloConfigList: config.EncryptedClientHelloConfigList,
	}
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	host, port, hostPort := parseServerAddrString(header.ProxyAddress)

	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}

	config := &client.Config{
		TLSConfig: toClientTLSConfig(header.TlsConfig),
		Auth:      header.User,
		FastOpen:  true,
	}
	if header.SNI == "" {
		config.TLSConfig.ServerName = host
	}
	if header.Password != "" {
		config.Auth = header.User + ":" + header.Password
	}
	if feature := header.Feature1; feature != nil {
		// protocol.Header is an exported API, so an external caller can hand
		// this dialer any value. A bare type assertion would panic inside
		// NewDialer; a configuration error must come back as an error.
		typed, ok := feature.(*Feature1)
		if !ok {
			return nil, fmt.Errorf("hysteria2: unexpected Feature1 type %T, want *Feature1", feature)
		}
		config.BandwidthConfig = typed.BandwidthConfig
		config.UDPHopInterval = typed.UDPHopInterval
		config.ObfsPassword = typed.ObfsPassword
	}
	// The override is client-local and never reaches the server. Validate it
	// here so a typo fails at dialer construction, like tuic and juicity,
	// instead of failing every connection at handshake time.
	config.CCOverride = header.CongestionOverride
	if err := client.ValidateCongestionOverride(config.CCOverride); err != nil {
		return nil, err
	}

	var err error
	if !isPortHoppingPort(port) {
		if ip := net.ParseIP(host); ip != nil {
			config.ServerAddr, err = net.ResolveUDPAddr("udp", hostPort)
		} else {
			config.ServerAddr = hostnameUDPAddr(hostPort)
		}
	} else {
		config.ServerAddr, err = udphop.ParseUDPHopAddr(hostPort)
	}
	if err != nil {
		return nil, err
	}

	if config.ServerAddr.Network() == "udphop" {
		config.ConnFactory = &client.UdpConnFactory{
			NewFunc: func(ctx context.Context) (net.PacketConn, error) {
				dialFunc := func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
					return dialWrappedUDPConn(ctx, nextDialer, addr)
				}
				return udphop.NewUDPHopPacketConnContext(ctx, config.ServerAddr.(*udphop.UDPHopAddr), config.UDPHopInterval, dialFunc)
			},
		}
	} else {
		config.ConnFactory = &client.UdpConnFactory{
			NewFunc: func(ctx context.Context) (net.PacketConn, error) {
				return dialWrappedUDPConn(ctx, nextDialer, config.ServerAddr)
			},
		}
	}

	client, err := client.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Dialer{
		client:   client,
		metadata: metadata,
	}, nil
}

// parseServerAddrString parses server address string.
// Server address can be in either "host:port" or "host" format (in which case we assume port 443).
func parseServerAddrString(addrStr string) (host, port, hostPort string) {
	h, p, err := stickyip.SplitHostPort(addrStr)
	if err != nil {
		return addrStr, "443", net.JoinHostPort(addrStr, "443")
	}
	return h, p, addrStr
}

// isPortHoppingPort returns whether the port string is a port hopping port.
// We consider a port string to be a port hopping port if it contains "-" or ",".
func isPortHoppingPort(port string) bool {
	return strings.Contains(port, "-") || strings.Contains(port, ",")
}

type hostnameUDPAddr string

func (a hostnameUDPAddr) Network() string {
	return "udp"
}

func (a hostnameUDPAddr) String() string {
	return string(a)
}

func remoteAddrOf(conn netproxy.Conn) net.Addr {
	type remoteAddrConn interface {
		RemoteAddr() net.Addr
	}
	if c, ok := conn.(remoteAddrConn); ok {
		return c.RemoteAddr()
	}
	return nil
}

// dialWrappedUDPConn dials the server over UDP through nextDialer and wraps
// the resulting conn in a FakeNetPacketConn with a unique fake local address.
// The conn's actual remote address is preferred over the requested one.
func dialWrappedUDPConn(ctx context.Context, nextDialer netproxy.Dialer, addr net.Addr) (net.PacketConn, error) {
	conn, err := nextDialer.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, err
	}
	remoteAddr := addr
	if actualAddr := remoteAddrOf(conn); actualAddr != nil {
		remoteAddr = actualAddr
	}
	return netproxy.NewFakeNetPacketConn(
		conn.(netproxy.PacketConn),
		net.UDPAddrFromAddrPort(common.GetUniqueFakeAddrPort()),
		remoteAddr,
	), nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}

	switch magicNetwork.Network {
	case "tcp":
		return d.client.TCP(address, ctx)
	case "udp":
		return d.client.UDP(address, ctx)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

func (d *Dialer) Close() error {
	if d == nil || d.client == nil {
		return nil
	}
	return d.client.Close()
}
