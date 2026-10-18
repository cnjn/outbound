//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netproxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// SolUDP is the socket level for UDP (IPPROTO_UDP = 17).
	SolUDP = 17

	// UDPGRO is the socket option (SOL_UDP, 104) to enable UDP Generic Receive Offload.
	UDPGRO = 104

	// UDPSEGMENT is the socket option / cmsg type (SOL_UDP, 103) for Generic Segmentation Offload.
	UDPSEGMENT = 103

	// MaxUDPGSOAggregateSize defines the Linux maximum theoretical aggregate size (64 KiB - 1).
	// Aggregated UDP packets exceeding 65535 bytes cannot be processed by the kernel UDP stack.
	MaxUDPGSOAggregateSize = 65535
)

// EnableUDPGRO enables UDP Generic Receive Offload on the given UDP socket.
func EnableUDPGRO(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw conn for UDP_GRO: %w", err)
	}

	var sockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), SolUDP, UDPGRO, 1)
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	if sockErr != nil {
		return fmt.Errorf("setsockopt UDP_GRO: %w", sockErr)
	}
	return nil
}

// ProbeUDPGSO checks whether the Linux kernel supports UDP Generic Segmentation Offload on the socket.
func ProbeUDPGSO(conn *net.UDPConn) bool {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return false
	}

	var supported bool
	_ = rawConn.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), SolUDP, UDPSEGMENT)
		supported = (err == nil)
	})
	return supported
}

// BuildUDPGSOControlMsg builds a control message (cmsg) containing the UDP_SEGMENT header.
func BuildUDPGSOControlMsg(segmentSize uint16) []byte {
	cmsgLen := unix.CmsgSpace(2)
	oob := make([]byte, cmsgLen)
	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	cmsg.Level = SolUDP
	cmsg.Type = UDPSEGMENT
	cmsg.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.SizeofCmsghdr:], segmentSize)
	return oob
}

// WriteUDPGSO sends an aggregated buffer composed of multiple logical UDP datagrams
// using a single sendmsg system call with UDP_SEGMENT.
//
// If payload exceeds MaxUDPGSOAggregateSize (65535 bytes), unix.EMSGSIZE is returned.
func WriteUDPGSO(rawConn syscall.RawConn, payload []byte, segmentSize uint16, to unix.Sockaddr) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if len(payload) > MaxUDPGSOAggregateSize {
		return 0, unix.EMSGSIZE
	}

	if segmentSize == 0 || len(payload) <= int(segmentSize) {
		var n int
		var sockErr error
		err := rawConn.Write(func(fd uintptr) bool {
			n, sockErr = unix.SendmsgN(int(fd), payload, nil, to, 0)
			return sockErr != unix.EAGAIN && sockErr != unix.EWOULDBLOCK
		})
		if err != nil {
			return 0, err
		}
		if sockErr != nil {
			return n, sockErr
		}
		if n < len(payload) {
			return n, io.ErrShortWrite
		}
		return n, nil
	}

	oob := BuildUDPGSOControlMsg(segmentSize)

	var n int
	var sockErr error
	err := rawConn.Write(func(fd uintptr) bool {
		n, sockErr = unix.SendmsgN(int(fd), payload, oob, to, 0)
		return sockErr != unix.EAGAIN && sockErr != unix.EWOULDBLOCK
	})
	if err != nil {
		return 0, err
	}
	if sockErr != nil {
		return n, sockErr
	}
	if n < len(payload) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

// SockaddrFromAddrPort converts netip.AddrPort to a unix.Sockaddr, preserving IPv6 ZoneId.
func SockaddrFromAddrPort(ap netip.AddrPort) unix.Sockaddr {
	if !ap.IsValid() {
		return nil
	}
	port := int(ap.Port())
	if ap.Addr().Is4() {
		return &unix.SockaddrInet4{
			Port: port,
			Addr: ap.Addr().As4(),
		}
	}

	var zoneId uint32
	if zone := ap.Addr().Zone(); zone != "" {
		if ifi, err := net.InterfaceByName(zone); err == nil {
			zoneId = uint32(ifi.Index)
		}
	}

	return &unix.SockaddrInet6{
		Port:   port,
		Addr:   ap.Addr().As16(),
		ZoneId: zoneId,
	}
}
