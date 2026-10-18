package anytls

import (
	"runtime"
	"testing"

	"github.com/daeuniverse/outbound/protocol/infra/bench"
)

// TestAnytlsWriteNoAllocCliff guards against the 64KB write allocation cliff
// fixed by capping maxFramePayloadSize within pool range. The cliff's signature
// is a large B/op (TotalAlloc per write), not the alloc count: pre-fix emitted
// ~73832 B/op because the encoded frame overflowed the pool and forced a heap
// allocation per write; post-fix is ~48 B/op. TotalAlloc is deterministic and
// machine-independent, so this assertion is not fragile like a ns/op threshold.
func TestAnytlsWriteNoAllocCliff(t *testing.T) {
	sess := newSession(bench.NewNetDiscardConn(), 0)
	stream, err := sess.newStream("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("newStream: %v", err)
	}
	payload := make([]byte, 65536)
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("warmup write: %v", err)
	}

	const runs = 100
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	for i := 0; i < runs; i++ {
		if _, err := stream.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	runtime.ReadMemStats(&m2)

	bytesPerOp := int(m2.TotalAlloc-m1.TotalAlloc) / runs
	const budget = 4096
	if bytesPerOp > budget {
		t.Fatalf("anytls 64KB write alloc cliff regressed: %d B/op (budget %d); "+
			"check maxFramePayloadSize stays within pool's largest bucket", bytesPerOp, budget)
	}
}
