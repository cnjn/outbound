package common

import (
	"context"
	"net"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
)

var (
	ErrClientClosed       = outbounderrors.ErrClientClosed
	ErrTooManyOpenStreams = outbounderrors.ErrStreamExhausted
	ErrHoldOn             = outbounderrors.ErrOperationHold
)

type DialFunc func(ctx context.Context, dialer netproxy.Dialer) (transport *quic.Transport, addr net.Addr, err error)

type UdpRelayMode uint8

const (
	QUIC UdpRelayMode = iota
	NATIVE
)
