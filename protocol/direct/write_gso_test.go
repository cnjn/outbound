//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package direct

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/stretchr/testify/require"
)

func TestDirectPacketConnWriteGSO_Connected(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer server.Close()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer client.Close()

	conn := &directPacketConn{UDPConn: client, FullCone: false}

	// Verify interface satisfaction
	var gsoWriter netproxy.PacketGSOWriter = conn
	require.NotNil(t, gsoWriter)

	segSize := uint16(1200)
	payload := bytes.Repeat([]byte("G"), int(segSize)*2) // 2 segments = 2400 bytes

	n, err := conn.WriteGSO(payload, segSize, netip.AddrPort{})
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	// Read on server side
	buf := make([]byte, 65535)
	rn, _, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Positive(t, rn)
}

func TestDirectPacketConnWriteGSO_FullCone(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer server.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer client.Close()

	conn := &directPacketConn{UDPConn: client, FullCone: true}

	targetAP := server.LocalAddr().(*net.UDPAddr).AddrPort()
	segSize := uint16(1000)
	payload := bytes.Repeat([]byte("F"), int(segSize)*3)

	n, err := conn.WriteGSO(payload, segSize, targetAP)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	buf := make([]byte, 65535)
	rn, _, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Positive(t, rn)
}
