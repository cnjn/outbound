package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
)

// authStreamConn fakes the two quic.Connection methods sendAuthentication
// uses and embeds the interface for everything else, so an unexpected call
// panics instead of silently faking a behavior this test did not pin.
type authStreamConn struct {
	quic.Connection
	stream quic.SendStream
	state  quic.ConnectionState
}

func (c *authStreamConn) OpenUniStream() (quic.SendStream, error) { return c.stream, nil }
func (c *authStreamConn) ConnectionState() quic.ConnectionState   { return c.state }

// authStreamSendStream fakes the write side of the Authenticate uni stream.
type authStreamSendStream struct {
	quic.SendStream
	writeErr error
	closeErr error
	closed   bool
}

func (s *authStreamSendStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(p), nil
}

func (s *authStreamSendStream) Close() error {
	s.closed = true
	return s.closeErr
}

// authTestTLSConfig builds an in-memory ECDSA certificate: the shared RSA
// helper costs a multi-second keygen per call, and this test only needs a
// completed handshake so the exporter secret exists.
func authTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}
}

// authTestConnState runs a real TLS 1.3 handshake so GenToken's
// ExportKeyingMaterial sees the exporter secret a live connection would have.
func authTestConnState(t *testing.T) quic.ConnectionState {
	t.Helper()

	clientRaw, serverRaw := net.Pipe()
	server := tls.Server(serverRaw, authTestTLSConfig(t))
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	})
	// Close the raw pipes rather than the tls.Conns: tls.Conn.Close waits up
	// to five seconds for the peer to read its close_notify, and net.Pipe has
	// no reader here.
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.HandshakeContext(context.Background()) }()
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return quic.ConnectionState{TLS: client.ConnectionState()}
}

// TestSendAuthenticationToleratesPeerStopSending pins the ordering that a
// contended runner loses: a v5 server stops reading the one-shot Authenticate
// uni stream as soon as it has consumed the command (sing-quic's service does
// `defer stream.CancelRead(0)`, and this repository's e2e server mirrors it),
// and when that STOP_SENDING reaches the client before its FIN, quic-go
// refuses Close with "close called for canceled stream N" and skips the FIN.
// The command was written in full and a server that rejects the credentials
// closes the connection with an auth error instead, so the FIN is best effort:
// the dial must survive the peer's ordering, not fail on it.
func TestSendAuthenticationToleratesPeerStopSending(t *testing.T) {
	// One handshake state is enough: both subtests only need GenToken's
	// exporter secret to be real.
	state := authTestConnState(t)

	t.Run("peer stopped reading the auth stream", func(t *testing.T) {
		stream := &authStreamSendStream{
			closeErr: fmt.Errorf("close called for canceled stream %d", 2),
		}
		c := &clientImpl{ClientOption: &ClientOption{Uuid: [16]byte{7}, Password: "pw"}}
		conn := &authStreamConn{stream: stream, state: state}

		if err := c.sendAuthentication(conn); err != nil {
			t.Fatalf("sendAuthentication() = %v, want nil: the peer stopping the one-shot auth stream must not fail the handshake", err)
		}
		if !stream.closed {
			t.Fatal("sendAuthentication() never closed the auth stream")
		}
	})

	t.Run("write failure still fails the handshake", func(t *testing.T) {
		wantErr := errors.New("write refused by the transport")
		stream := &authStreamSendStream{writeErr: wantErr}
		c := &clientImpl{ClientOption: &ClientOption{Uuid: [16]byte{7}, Password: "pw"}}
		conn := &authStreamConn{stream: stream, state: state}

		if err := c.sendAuthentication(conn); !errors.Is(err, wantErr) {
			t.Fatalf("sendAuthentication() = %v, want the write error %v", err, wantErr)
		}
	})
}
