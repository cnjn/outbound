//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2023, v2rayA Organization <team@v2raya.org>
 */

package netproxy

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// fwmarkIoctl is SO_MARK on Linux; dae targets the Linux eBPF datapath only,
// so the BSD/android branches of the former switch are intentionally dropped.
var fwmarkIoctl = 36 /* unix.SO_MARK */

// SoMarkControl is replacable. Replacibility is useful for Android.
var SoMarkControl = func(c syscall.RawConn, mark int) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, fwmarkIoctl, mark)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

// SoMark is replacable. Replacibility is useful for Android.
var SoMark = func(fd int, mark int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, fwmarkIoctl, mark); err != nil {
		return err
	}
	return nil
}

const (
	// SafeTCPMaxSeg defines a conservative TCP MSS (1380 bytes) to prevent
	// packet drops caused by PMTU black holes when packets are encapsulated
	// inside proxy or tunnel protocols (WireGuard, Shadowsocks, Trojan, TLS).
	// Note: On typical Linux TCP connections with 12-byte TCP timestamp options enabled,
	// setting TCP_MAXSEG to 1380 results in an effective payload MSS of 1368 bytes.
	SafeTCPMaxSeg = 1380
)

// TCPMaxSegOverride allows fine-tuning or disabling TCP MSS clamping.
// A value > 0 clamps the TCP MSS to the specified threshold.
// A value <= 0 disables MSS clamping completely.
var TCPMaxSegOverride = SafeTCPMaxSeg

func isLoopbackTarget(address string) bool {
	if address == "" {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// TCPDialControl applies performance and MTU safety socket options before connect:
// 1. fwmark if mark != 0
// 2. TCP_NODELAY = 1
// 3. TCP_MAXSEG = TCPMaxSegOverride (if > 0 and non-loopback)
// 4. TCP_FASTOPEN_CONNECT = 1 (best effort on Linux 4.11+)
var TCPDialControl = func(c syscall.RawConn, mark int, address ...string) error {
	var sockOptErr error
	isLoopback := len(address) > 0 && isLoopbackTarget(address[0])
	controlErr := c.Control(func(fd uintptr) {
		intFd := int(fd)
		if mark != 0 {
			if err := unix.SetsockoptInt(intFd, unix.SOL_SOCKET, fwmarkIoctl, mark); err != nil {
				sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
				return
			}
		}
		_ = unix.SetsockoptInt(intFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		if !isLoopback && TCPMaxSegOverride > 0 {
			_ = unix.SetsockoptInt(intFd, unix.IPPROTO_TCP, unix.TCP_MAXSEG, TCPMaxSegOverride)
		}
		_ = unix.SetsockoptInt(intFd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}
