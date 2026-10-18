package vless

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

// domainFirst4 builds the leading four bytes consumed before
// CompleteMetadataFromReader: network byte (tcp), big-endian port 80, and
// the domain address type.
func domainFirst4() []byte {
	return []byte{0x01, 0x00, 0x50, vmess.MetadataTypeToByte(protocol.MetadataTypeDomain)}
}

func TestCompleteMetadataFromReaderDomain(t *testing.T) {
	domain := "example.dae"
	stream := append([]byte{byte(len(domain))}, domain...)
	// Trailing sentinel byte: the domain branch must consume exactly
	// 1 + len(domain) bytes and leave the sentinel unread.
	stream = append(stream, 0xEE)

	r := bytes.NewReader(stream)
	m := &Metadata{}
	if err := CompleteMetadataFromReader(m, domainFirst4(), r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Hostname != domain {
		t.Fatalf("hostname = %q, want %q", m.Hostname, domain)
	}
	if m.Port != 80 {
		t.Fatalf("port = %v, want 80", m.Port)
	}
	if m.Network != "tcp" {
		t.Fatalf("network = %q, want tcp", m.Network)
	}
	if got := r.Len(); got != 1 {
		t.Fatalf("reader has %v unread bytes, want 1 (sentinel only)", got)
	}
}

func TestCompleteMetadataFromReaderDomainMaxLength(t *testing.T) {
	domain := bytes.Repeat([]byte("a"), 255)
	stream := append([]byte{255}, domain...)

	r := bytes.NewReader(stream)
	m := &Metadata{}
	if err := CompleteMetadataFromReader(m, domainFirst4(), r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Hostname != string(domain) {
		t.Fatalf("hostname length = %v, want 255", len(m.Hostname))
	}
	if got := r.Len(); got != 0 {
		t.Fatalf("reader has %v unread bytes, want 0", got)
	}
}

func TestCompleteMetadataFromReaderDomainZeroLength(t *testing.T) {
	r := bytes.NewReader([]byte{0})
	err := CompleteMetadataFromReader(&Metadata{}, domainFirst4(), r)
	if err == nil {
		t.Fatal("expected error for zero domain length")
	}
}

// TestCompleteMetadataFromReaderDomainPooledResidue ensures the domain bytes
// come only from the wire: the pooled buffer may still hold stale bytes from
// a previous request past the wire-supplied length.
func TestCompleteMetadataFromReaderDomainPooledResidue(t *testing.T) {
	// Poison the pool bucket the domain branch uses so the next buffer is
	// likely to carry residue. Even if a fresh buffer is returned, the exact
	// hostname assertion below still catches an off-by-one read.
	dirty := pool.Get(1 + 255)
	for i := range dirty {
		dirty[i] = 0xAA
	}
	dirty.Put()

	domain := "abc"
	stream := append([]byte{byte(len(domain))}, domain...)

	r := bytes.NewReader(stream)
	m := &Metadata{}
	if err := CompleteMetadataFromReader(m, domainFirst4(), r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Hostname != domain {
		t.Fatalf("hostname = %q, want %q (pooled residue leaked in)", m.Hostname, domain)
	}
	if got := r.Len(); got != 0 {
		t.Fatalf("reader has %v unread bytes, want 0", got)
	}
}
