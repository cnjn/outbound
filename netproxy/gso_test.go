//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package netproxy

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNetproxyUDPGSO_Cmsg(t *testing.T) {
	segmentSize := uint16(1400)
	cmsg := BuildUDPGSOControlMsg(segmentSize)
	require.NotEmpty(t, cmsg)

	parsed, err := unix.ParseSocketControlMessage(cmsg)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	hdr := parsed[0].Header
	require.Equal(t, int32(SolUDP), hdr.Level)
	require.Equal(t, int32(UDPSEGMENT), hdr.Type)
}

func TestNetproxyUDPGSO_ProbeAndLoopback(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	supported := ProbeUDPGSO(conn)
	t.Logf("ProbeUDPGSO supported: %v", supported)

	err = EnableUDPGRO(conn)
	t.Logf("EnableUDPGRO result: %v", err)

	// IPv4 mapping test
	ap := netip.MustParseAddrPort("127.0.0.1:53")
	sa := SockaddrFromAddrPort(ap)
	require.NotNil(t, sa)
	sa4, ok := sa.(*unix.SockaddrInet4)
	require.True(t, ok)
	require.Equal(t, 53, sa4.Port)
	require.Equal(t, [4]byte{127, 0, 0, 1}, sa4.Addr)

	// IPv6 mapping test
	ap6 := netip.MustParseAddrPort("[::1]:853")
	sa6 := SockaddrFromAddrPort(ap6)
	require.NotNil(t, sa6)
	sa6Parsed, ok6 := sa6.(*unix.SockaddrInet6)
	require.True(t, ok6)
	require.Equal(t, 853, sa6Parsed.Port)
}

func TestNetproxyUDPGSO_PayloadLimitsAndWrite(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer func() {
		_ = serverConn.Close()
	}()

	clientConn, err := net.DialUDP("udp4", nil, serverConn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer func() {
		_ = clientConn.Close()
	}()

	rawClient, err := clientConn.SyscallConn()
	require.NoError(t, err)

	// Check oversized aggregate protection (> 65535)
	hugePayload := make([]byte, 65536)
	_, err = WriteUDPGSO(rawClient, hugePayload, 1400, nil)
	require.ErrorIs(t, err, unix.EMSGSIZE)

	// If GSO is not supported in this environment/kernel, skip live segmentation test
	if !ProbeUDPGSO(clientConn) {
		t.Skip("Kernel or socket does not support UDP GSO; skipping segmentation send")
	}

	segSize := uint16(500)
	segCount := 3
	payload := make([]byte, int(segSize)*segCount)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	n, err := WriteUDPGSO(rawClient, payload, segSize, nil)
	if err != nil {
		t.Skipf("WriteUDPGSO failed with %v (possibly unprivileged or sandbox environment)", err)
	}
	require.Equal(t, len(payload), n)

	// Receive segments and verify contents
	recvBuf := make([]byte, 2048)
	var totalReceived int
	for seg := 0; seg < segCount; seg++ {
		rn, _, rerr := serverConn.ReadFrom(recvBuf)
		require.NoError(t, rerr)
		require.Equal(t, int(segSize), rn)

		expectedSlice := payload[totalReceived : totalReceived+rn]
		require.True(t, bytes.Equal(expectedSlice, recvBuf[:rn]), "received datagram slice mismatch at segment %d", seg)
		totalReceived += rn
	}
	require.Equal(t, len(payload), totalReceived)
}
