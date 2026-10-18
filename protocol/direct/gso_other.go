//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package direct

import (
	"errors"
	"net/netip"

	"github.com/daeuniverse/outbound/netproxy"
)

var _ netproxy.PacketGSOWriter = (*directPacketConn)(nil)

func (c *directPacketConn) WriteGSO(payload []byte, segmentSize uint16, addr netip.AddrPort) (int, error) {
	return 0, errors.New("write gso not supported on non-linux")
}
