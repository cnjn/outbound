package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/outbound/pool"
)

type AddressType uint8

// Address type constants for the SOCKS-style address codec. The encode side
// consumed by shadowsocks_2022 lives in that package (writeAddrInfoTo); this
// file provides the decode side (ReadAddr/ReadAddrInfo) and AddressFromString.
const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 3
	AddressTypeIPv6   AddressType = 4
)

var (
	ErrInvalidAddress = fmt.Errorf("invalid address")
)

// AddressInfo represents decoded address information
type AddressInfo struct {
	Type     AddressType
	Hostname string
	IP       netip.Addr
	Port     uint16
}

func ReadAddr(data io.Reader) (net.Addr, error) {
	addressInfo, err := ReadAddrInfo(data)
	if err != nil {
		return nil, err
	}

	// Create address object (only support IP addresses for UDP)
	switch addressInfo.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port)), nil
	default:
		return nil, fmt.Errorf("unsupported address type for UDP: %v", addressInfo.Type)
	}
}

// ReadAddr reads address from buffer
func ReadAddrInfo(data io.Reader) (*AddressInfo, error) {
	var typ uint8
	if err := binary.Read(data, binary.BigEndian, &typ); err != nil {
		return nil, fmt.Errorf("%w: too short", ErrInvalidAddress)
	}

	info := &AddressInfo{Type: AddressType(typ)}

	switch info.Type {
	case AddressTypeIPv4:
		ip := pool.Get(4)
		defer pool.Put(ip)
		if _, err := io.ReadFull(data, ip); err != nil {
			return nil, fmt.Errorf("failed to read IP: %w", err)
		}
		info.IP = netip.AddrFrom4([4]byte(ip))
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	case AddressTypeIPv6:
		ip := pool.Get(16)
		defer pool.Put(ip)
		if _, err := io.ReadFull(data, ip); err != nil {
			return nil, fmt.Errorf("failed to read IP: %w", err)
		}
		info.IP = netip.AddrFrom16([16]byte(ip))
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	case AddressTypeDomain:
		var domainLen uint8
		if err := binary.Read(data, binary.BigEndian, &domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := pool.Get(int(domainLen))
		defer pool.Put(domain)
		if _, err := io.ReadFull(data, domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
		}
		info.Hostname = string(domain)
		if err := binary.Read(data, binary.BigEndian, &info.Port); err != nil {
			return nil, fmt.Errorf("failed to read port: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: invalid type: %v", ErrInvalidAddress, info.Type)
	}
	return info, nil
}

func AddressFromString(addr string) (*AddressInfo, error) {
	hostname, port_, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(port_, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", port_)
	}

	info := &AddressInfo{Port: uint16(port)}

	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		info.Type = AddressTypeDomain
		info.Hostname = hostname
	} else {
		info.IP = ip
		if ip.Is4() {
			info.Type = AddressTypeIPv4
		} else {
			info.Type = AddressTypeIPv6
		}
	}
	return info, nil
}
