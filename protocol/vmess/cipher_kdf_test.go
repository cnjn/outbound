package vmess

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestKDFMatchesReference pins the allocation-free KDF evaluator to the
// original nested-hmac construction byte for byte. Both are deterministic,
// so random vectors over every reachable chain depth plus the long-key
// branches give full-path coverage.
func TestKDFMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	keySizes := []int{16, 32, 48, 64, 65, 100, kdfMaxKeyLen, kdfMaxKeyLen + 1}
	elemSizes := []int{0, 1, 8, 16, 31, 64, 65, 200, kdfMaxPathElemLen + 1, 1024}
	for depth := 1; depth < kdfMaxChainLen; depth++ {
		for i := 0; i < 200; i++ {
			key := make([]byte, keySizes[rng.Intn(len(keySizes))])
			rng.Read(key)
			path := make([][]byte, depth)
			for j := range path {
				path[j] = make([]byte, elemSizes[rng.Intn(len(elemSizes))])
				rng.Read(path[j])
			}
			want := kdfReference(key, path...)
			got := KDF(key, path...)
			if !bytes.Equal(want, got) {
				t.Fatalf("KDF mismatch at depth=%d keyLen=%d: want %x got %x", depth, len(key), want, got)
			}
		}
	}
	// The exact production shapes, with the real salt constants.
	prodKey := make([]byte, 16)
	rng.Read(prodKey)
	shapes := [][][]byte{
		{[]byte(KDFSaltConstAuthIDEncryptionKey)},
		{[]byte(KDFSaltConstAEADRespHeaderLenKey)},
		{[]byte(KDFSaltConstAEADRespHeaderPayloadIV)},
		{[]byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), prodKey[:16], prodKey[:8]},
		{[]byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), prodKey[:16], prodKey[:8]},
		{[]byte(KDFSaltConstVMessHeaderPayloadAEADKey), prodKey[:16], prodKey[:8]},
		{[]byte(KDFSaltConstVMessHeaderPayloadAEADIV), prodKey[:16], prodKey[:8]},
	}
	for i, path := range shapes {
		want := kdfReference(prodKey, path...)
		got := KDF(prodKey, path...)
		if !bytes.Equal(want, got) {
			t.Fatalf("production shape %d mismatch: want %x got %x", i, want, got)
		}
	}
	// Path len 0 and >= kdfMaxChainLen must route through the reference.
	if !bytes.Equal(KDF(prodKey), kdfReference(prodKey)) {
		t.Fatal("empty path mismatch")
	}
	deep := make([][]byte, kdfMaxChainLen)
	for j := range deep {
		deep[j] = []byte{byte(j)}
	}
	if !bytes.Equal(KDF(prodKey, deep...), kdfReference(prodKey, deep...)) {
		t.Fatal("deep path mismatch")
	}
}

// TestKDFOverBudgetPathElements covers the inputs that must leave the
// stack-scratch fast path for the reference construction: an over-sized path
// element is RFC 2104 pre-hashed through the child chain, and before the
// kdfMaxPathElemLen routing that pre-hash sliced the fixed scratch past its
// end (slice bounds out of range) instead of deriving a key.
func TestKDFOverBudgetPathElements(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	key := make([]byte, 16)
	rng.Read(key)
	sizes := []int{kdfMaxPathElemLen + 1, 1024, 8192}
	for idx := 0; idx < kdfMaxChainLen-1; idx++ {
		for _, size := range sizes {
			path := make([][]byte, idx+1)
			for j := range path {
				path[j] = []byte{byte(j)}
			}
			path[idx] = make([]byte, size)
			rng.Read(path[idx])
			want := kdfReference(key, path...)
			got := KDF(key, path...)
			if !bytes.Equal(want, got) {
				t.Fatalf("oversized element at index %d (len %d) mismatch: want %x got %x", idx, size, want, got)
			}
		}
	}
	// The key budget has the same shape.
	longKey := make([]byte, kdfMaxKeyLen+1)
	rng.Read(longKey)
	if !bytes.Equal(KDF(longKey, []byte(KDFSaltConstAuthIDEncryptionKey)), kdfReference(longKey, []byte(KDFSaltConstAuthIDEncryptionKey))) {
		t.Fatal("over-sized key mismatch")
	}
	// Every element at the budget limit still takes the fast path and must
	// stay byte-identical, including the one whose pre-hash reaches the
	// deepest node.
	maxPath := make([][]byte, kdfMaxChainLen-1)
	for j := range maxPath {
		maxPath[j] = make([]byte, kdfMaxPathElemLen)
		rng.Read(maxPath[j])
	}
	maxKey := make([]byte, kdfMaxKeyLen)
	rng.Read(maxKey)
	if !bytes.Equal(KDF(maxKey, maxPath...), kdfReference(maxKey, maxPath...)) {
		t.Fatal("budget-limit chain mismatch")
	}
}

func BenchmarkKDF(b *testing.B) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	eAuthID := make([]byte, 16)
	nonce := make([]byte, 8)
	path := [][]byte{[]byte(KDFSaltConstVMessHeaderPayloadAEADKey), eAuthID, nonce}
	b.Run("reference", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = kdfReference(key, path...)
		}
	})
	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = KDF(key, path...)
		}
	})
}
