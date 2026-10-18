package shadowsocks_2022

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

const maxPSKListLength = 8

// FakeNetPacketConn wraps a PacketConn to override the target address.
// It embeds netproxy.PacketConn directly, so it implements the interface correctly.
// The Addr field is used by UdpConn.WriteTo to determine the actual target.
type FakeNetPacketConn struct {
	netproxy.PacketConn
	Addr string
}

func (c *FakeNetPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.Addr)
}

func (c *FakeNetPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped transport: SetWriteDeadline is
// delegated to the underlying PacketConn unchanged, so the semantics — and
// the declaration — belong to that transport, not to this wrapper.
func (c *FakeNetPacketConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.PacketConn)
}

// WriteBatch forwards the optional batched writer through this net.Conn
// compatibility wrapper: embedding the netproxy.PacketConn interface does
// not promote methods the dynamic type has beyond it, so without this
// forward the dae aggregator would not see the capability. A wrapped conn
// without the capability falls back to ordered synchronous sends.
func (c *FakeNetPacketConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	bw, ok := c.PacketConn.(netproxy.PacketBatchWriter)
	if !ok {
		sent := 0
		for _, item := range items {
			if _, err := c.WriteTo(item.Data, item.Addr); err != nil {
				return sent, err
			}
			sent++
		}
		return sent, nil
	}
	return bw.WriteBatch(items)
}

func init() {
	protocol.Register("shadowsocks_2022", NewDialer)
}

type Dialer struct {
	parentDialer netproxy.Dialer
	proxyAddress string
	core         *SS2022Core
	sg           *shadowsocks.RandomSaltGenerator
}

func NewDialer(parentDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	conf := ciphers.Aead2022CiphersConf[header.Cipher]
	if conf == nil {
		return nil, fmt.Errorf("unsupported shadowsocks 2022 cipher: %s", header.Cipher)
	}
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid shadowsocks 2022 cipher config: %s", header.Cipher)
	}
	keyStrList := strings.Split(header.Password, ":")
	if len(keyStrList) > maxPSKListLength {
		return nil, fmt.Errorf("too many PSKs: got %d, max %d", len(keyStrList), maxPSKListLength)
	}
	pskList := make([][]byte, len(keyStrList))
	for i, keyStr := range keyStrList {
		key, err := ciphers.ValidateBase64PSK(keyStr, conf.KeyLen)
		if err != nil {
			return nil, err
		}
		pskList[i] = key
	}
	uPSK := pskList[len(pskList)-1]
	core, err := NewSS2022Core(conf, pskList, uPSK)
	if err != nil {
		return nil, err
	}
	sg := shadowsocks.NewRandomSaltGenerator(conf.SaltLen)
	return &Dialer{
		parentDialer: parentDialer,
		proxyAddress: header.ProxyAddress,
		core:         core,
		sg:           sg,
	}, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.parentDialer
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	// Extract base protocol from network string (handles "udp", "udp4", "udp6", "udp4(DNS)", etc.)
	proto := magicNetwork.Network
	if len(proto) >= 3 && (proto[0:3] == "tcp" || proto[0:3] == "udp") {
		proto = proto[0:3]
	}
	switch proto {
	case "tcp":
		addrInfo, err := socks5.AddressFromString(addr)
		if err != nil {
			return nil, err
		}
		// Shadowsocks transfer TCP traffic via TCP tunnel.
		conn, err := d.parentDialer.DialContext(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		// Wrap with a buffered reader so the salt/header/payload reads done
		// via io.ReadFull do not each trigger their own syscall.
		if npc, ok := conn.(netproxy.Conn); ok {
			conn = netproxy.NewBufferedReaderConn(npc, 0)
		}
		// TCPConn embeds net.Conn. BufferedReaderConn carries the address
		// accessors for exactly this assertion; turn a future wrapper that
		// drops them into a dial error instead of a panic.
		netConn, ok := conn.(net.Conn)
		if !ok {
			_ = conn.Close()
			return nil, fmt.Errorf("shadowsocks_2022: TCP underlay does not implement net.Conn: %T", conn)
		}
		return NewTCPConn(netConn, d.core, d.sg, addrInfo, nil), nil
	case "udp":
		conn, err := d.ListenPacket(ctx, network, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &FakeNetPacketConn{
			PacketConn: conn,
			Addr:       addr,
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, network string, addr string) (netproxy.PacketConn, error) {
	// Parse magic network to preserve Mark and Mptcp settings
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	// Shadowsocks transfer UDP traffic via UDP tunnel.
	magicNetwork.Network = "udp"
	network = magicNetwork.Encode()
	conn, err := d.parentDialer.DialContext(ctx, network, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	// UdpConn embeds net.Conn; a future parent wrapper that does not carry
	// the address accessors must surface as a dial error, not a panic (the
	// TCP branch above turns the same condition into an error).
	netConn, ok := conn.(net.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("shadowsocks_2022: UDP underlay does not implement net.Conn: %T", conn)
	}
	return NewUdpConn(netConn, d.core, nil)
}
