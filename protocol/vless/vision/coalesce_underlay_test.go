package vision_test

import (
	gotls "crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/vless/vision"
)

// tlsStageConn stands in for the raw underlay below the TLS layer. The chain
// below never handshakes (no I/O is driven), so the TLS config is inert; a
// plain config with a server name keeps certificate verification enabled.
type tlsStageConn struct{}

func (tlsStageConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (tlsStageConn) Write(p []byte) (int, error)      { return len(p), nil }
func (tlsStageConn) Close() error                     { return nil }
func (tlsStageConn) LocalAddr() net.Addr              { return nil }
func (tlsStageConn) RemoteAddr() net.Addr             { return nil }
func (tlsStageConn) SetDeadline(time.Time) error      { return nil }
func (tlsStageConn) SetReadDeadline(time.Time) error  { return nil }
func (tlsStageConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = tlsStageConn{}

// TestNewConnAcceptsTransportTLSChain builds the exact conn shapes
// transport/tls returns - the TLS conn over the raw underlay, the
// UnderlyingConnForwarder it is wrapped in, then the read buffering layer
// the vless dialer adds - and requires Vision to accept the chain. A wrapper
// that hides IntrinsicConn makes visionIntrinsicConn stop at the wrapper and
// reject the underlay outright, so no vless+tls+xtls-rprx-vision node can be
// dialed.
func TestNewConnAcceptsTransportTLSChain(t *testing.T) {
	tlsConn := gotls.Client(&netproxy.FakeNetConn{Conn: tlsStageConn{}},
		&gotls.Config{ServerName: "underlay.test"})
	fwd := netproxy.NewUnderlyingConnForwarder(tlsConn, func() net.Conn {
		return nil
	})
	wrapped := netproxy.NewBufferedReaderConn(fwd, 0)

	// The chain must still resolve to the TLS conn: that is what Vision
	// reflects on for the record-buffer splice.
	peeled := wrapped.(interface {
		IntrinsicConn() netproxy.Conn
	}).IntrinsicConn()
	if _, ok := peeled.(*gotls.Conn); !ok {
		t.Fatalf("intrinsic conn = %T, want *tls.Conn", peeled)
	}

	c, err := vision.NewConn(wrapped, make([]byte, 16))
	if err != nil {
		t.Fatalf("vision.NewConn over the transport/tls chain: %v", err)
	}
	if c == nil {
		t.Fatal("vision.NewConn returned a nil conn and no error")
	}
	_ = c.Close()
}
