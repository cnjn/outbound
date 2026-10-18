//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netproxy

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

var errGSONotSupported = errors.New("udp gso/gro not supported on non-linux platforms")

func EnableUDPGRO(conn *net.UDPConn) error {
	return errGSONotSupported
}

func ProbeUDPGSO(conn *net.UDPConn) bool {
	return false
}

func BuildUDPGSOControlMsg(segmentSize uint16) []byte {
	return nil
}

func WriteUDPGSO(rawConn syscall.RawConn, payload []byte, segmentSize uint16, to any) (int, error) {
	return 0, errGSONotSupported
}

func SockaddrFromAddrPort(ap netip.AddrPort) any {
	return nil
}
