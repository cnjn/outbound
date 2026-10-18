//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package direct

import (
	"net/netip"
	"syscall"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

var _ netproxy.PacketGSOWriter = (*directPacketConn)(nil)

// WriteGSO implements netproxy.PacketGSOWriter for Linux by issuing a single
// sendmsg with UDP_SEGMENT control message for kernel/NIC segmentation.
func (c *directPacketConn) WriteGSO(payload []byte, segmentSize uint16, addr netip.AddrPort) (int, error) {
	if c.UDPConn == nil {
		return 0, syscall.EINVAL
	}
	rawConn, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var sa unix.Sockaddr
	if c.FullCone {
		if !addr.IsValid() {
			return 0, syscall.EINVAL
		}
		sa = netproxy.SockaddrFromAddrPort(addr).(unix.Sockaddr)
	}
	return netproxy.WriteUDPGSO(rawConn, payload, segmentSize, sa)
}
