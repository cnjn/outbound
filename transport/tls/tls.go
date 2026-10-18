package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
)

// Tls is a base Tls struct
type Tls struct {
	dialer              netproxy.Dialer
	addr                string
	serverName          string
	skipVerify          bool
	tlsImplentation     string
	utlsImitate         string
	passthroughUdp      bool
	fragmentation       bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64

	tlsConfig *tls.Config
}

func (s *Tls) UnwrapDialer() netproxy.Dialer {
	return s.dialer
}

// NewTls returns a Tls infra.
func NewTls(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewTls: %w", err)
	}

	query := u.Query()

	tlsImplentation := u.Scheme
	utlsImitate := query.Get("utlsImitate")
	if (tlsImplentation == "tls" || tlsImplentation == "") && option.TlsImplementation != "" {
		tlsImplentation = option.TlsImplementation
		utlsImitate = option.UtlsImitate
	}
	t := &Tls{
		dialer:          nextDialer,
		addr:            u.Host,
		tlsImplentation: tlsImplentation,
		utlsImitate:     utlsImitate,
		serverName:      query.Get("sni"),
	}
	if t.tlsImplentation == "utls" {
		// Fail an unknown fingerprint at construction time instead of on
		// every dial, after the underlay connection was already established.
		if _, err := nameToUtlsClientHelloID(utlsImitate); err != nil {
			return nil, nil, fmt.Errorf("NewTls: %w", err)
		}
	}
	if t.serverName == "" {
		t.serverName = u.Hostname()
	}
	t.passthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	// skipVerify
	allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
	}
	t.skipVerify = allowInsecure || option.AllowInsecure
	t.tlsConfig = &tls.Config{
		ServerName:         t.serverName,
		InsecureSkipVerify: t.skipVerify,
	}
	if len(query.Get("alpn")) > 0 {
		t.tlsConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
	}

	if option.TlsFragment {
		t.fragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinLength = minLen
		t.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return nil, nil, err
		}
		t.fragmentMinInterval = minInterval
		t.fragmentMaxInterval = maxInterval
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.addr,
		Protocol: tlsImplentation,
		Link:     link,
	}, nil
}

func (s *Tls) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		rc, err := s.dialer.DialContext(ctx, network, s.addr)
		if err != nil {
			return nil, fmt.Errorf("[Tls]: dial to %s: %w", s.addr, err)
		}

		if s.fragmentation {
			rc = NewFragmentConn(rc, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
		}

		var tlsConn interface {
			netproxy.Conn
			Handshake() error
		}

		// No write shaping here, by contract: crypto/tls and utls issue one
		// underlying Write per TLS record, and that per-record granularity is
		// the camouflage this transport owes its users. Coalescing the
		// records of a burst into one socket write changes the wire pattern
		// into a shape no browser produces, and pattern-classifying filters
		// (observed in production, 2026-10: whole flows blackholed while
		// small flows passed) punish exactly that. Throughput-class
		// protocols that own their wire pattern (anytls) apply coalescing
		// themselves around their TLS conn; see pkg/coalesce. The
		// wire_shape_test pins the invariant: no underlying write may exceed
		// one TLS record.
		raw := &netproxy.FakeNetConn{
			Conn:  rc,
			LAddr: nil,
			RAddr: nil,
		}

		switch s.tlsImplentation {
		case "tls":
			tlsConn = tls.Client(raw, s.tlsConfig)

		case "utls":
			clientHelloID, err := nameToUtlsClientHelloID(s.utlsImitate)
			if err != nil {
				// rc was dialed above and is owned by this call.
				_ = rc.Close()
				return nil, err
			}

			tlsConn = utls.UClient(raw, uTLSConfigFromTLSConfig(s.tlsConfig), *clientHelloID)

		default:
			_ = rc.Close()
			return nil, fmt.Errorf("unknown tls implementation: %v", s.tlsImplentation)
		}

		if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		// The forwarder keeps the raw socket reachable for UnwrapTCPConn:
		// TLS conns are opaque to unwrapping, and copy loops above need the
		// kernel receive-queue state to decide whether another read
		// completes immediately (write batching).
		return netproxy.NewUnderlyingConnForwarder(
			tlsConn, func() net.Conn {
				// rc is a netproxy.Conn; peel it through the same
				// FakeNetConn adapter used for the TLS conn above.
				if u, ok := rc.(interface{ UnderlyingConn() net.Conn }); ok {
					return u.UnderlyingConn()
				}
				if nc, ok := rc.(net.Conn); ok {
					return nc
				}
				return nil
			}), nil
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: tls+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
