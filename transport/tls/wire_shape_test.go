/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
	tlstransport "github.com/daeuniverse/outbound/transport/tls"
)

// maxTLSWriteBound is the ceiling a single underlying write may reach while
// remaining one TLS record: 16KB payload + record header + AEAD tag and
// content-type byte with slack. Anything larger means records were
// accumulated across writes - exactly the wire-pattern change the camouflage
// contract forbids.
const maxTLSWriteBound = 16384 + 5 + 64

// recordingDialer wraps the raw underlay and records the size of every
// write the TLS layer issues.
type recordingDialer struct {
	maxWrite atomic.Int64
	inner    netproxy.Dialer
}

type recordingConn struct {
	netproxy.Conn
	rec *recordingDialer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n := len(p)
	if int64(n) > c.rec.maxWrite.Load() {
		c.rec.maxWrite.Store(int64(n))
	}
	return c.Conn.Write(p)
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	c, err := d.inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: c, rec: d}, nil
}

// TestWireShapeOneRecordPerWrite pins the transport's camouflage contract:
// during a bulk application write burst, no underlying write may exceed one
// TLS record. crypto/tls and utls natively issue one write per record -
// browser-shaped pacing; a record coalescer folds a burst into giant writes,
// a pattern no browser produces, and production filters were observed
// (2026-10) blackholing exactly those flows while small flows passed. Any
// future write shaping under this transport must prove it stays inside this
// bound.
func TestWireShapeOneRecordPerWrite(t *testing.T) {
	cases := []struct {
		name string
		impl string
	}{
		{"crypto/tls", "tls"},
		{"utls", "utls"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = listener.Close() }()

			serverReady := make(chan struct{})
			go func() {
				close(serverReady)
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				cert, err := selfSignedCert()
				if err != nil {
					_ = raw.Close()
					return
				}
				srv := tls.Server(raw, &tls.Config{
					Certificates: []tls.Certificate{cert},
				})
				_ = srv.Handshake()
				// Drain until the client closes so its writes all land.
				buf := make([]byte, 32*1024)
				for {
					_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
					if _, err := srv.Read(buf); err != nil {
						_ = srv.Close()
						return
					}
				}
			}()
			<-serverReady

			rec := &recordingDialer{inner: direct.SymmetricDirect}
			option := &dialer.ExtraOption{
				TlsImplementation: tc.impl,
				UtlsImitate:       "chrome_auto",
				AllowInsecure:     true,
			}
			u := "tls://" + listener.Addr().String() + "/?sni=underlay.test&allowInsecure=true"
			d, _, err := tlstransport.NewTls(option, rec, u)
			if err != nil {
				t.Fatalf("NewTls: %v", err)
			}
			conn, err := d.DialContext(context.Background(), "tcp", "test.invalid:443")
			if err != nil {
				t.Fatalf("dial through transport: %v", err)
			}
			defer func() { _ = conn.Close() }()

			// A burst far larger than one record: without coalescing this
			// resolves into per-record writes; with it, into writes of
			// whole bursts.
			burst := make([]byte, 128*1024)
			deadline := time.Now().Add(5 * time.Second)
			_ = conn.SetWriteDeadline(deadline)
			total := 0
			for total < 512*1024 {
				n, err := conn.Write(burst)
				total += n
				if err != nil {
					t.Fatalf("bulk write failed at %d bytes: %v", total, err)
				}
			}
			if got := rec.maxWrite.Load(); got > maxTLSWriteBound {
				t.Fatalf("underlying write reached %d bytes (> %d): records were accumulated across writes - "+
					"the one-record-per-write camouflage contract is violated", got, maxTLSWriteBound)
			}
		})
	}
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"underlay.test"},
		Subject:               pkix.Name{CommonName: "underlay.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
