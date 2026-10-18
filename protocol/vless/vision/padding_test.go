package vision

import (
	"testing"

	"github.com/daeuniverse/outbound/pool"
)

func poisonPoolBucket(size int) {
	b := pool.Get(size)
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0xAA
	}
	pool.Put(b)
}

func TestApplyPaddingFromPoolFillsPooledSuffix(t *testing.T) {
	// longPadding for "hi" yields paddingLen in [898,1397], which hits
	// pool buckets 1024 and 2048 — poison both, not a smaller unused bucket.
	poisonPoolBucket(1000)
	poisonPoolBucket(1100)

	userUUID := make([]byte, 16)
	payload := []byte("hi")
	frame := ApplyPaddingFromPool(payload, commandPaddingContinue, userUUID, true)
	defer pool.Put(frame)
	suffix := frame[PaddingHeaderLen+len(payload):]
	if len(suffix) < 16 {
		t.Fatalf("suffix too short to judge fill: %d", len(suffix))
	}
	aa := 0
	for _, b := range suffix {
		if b == 0xAA {
			aa++
		}
	}
	if aa == len(suffix) {
		t.Fatal("suffix is unfilled pool memory")
	}
}
