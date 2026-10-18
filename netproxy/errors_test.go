package netproxy

import (
	stderrors "errors"
	"fmt"
	"io"
	"testing"
)

// TestErrDatagramDroppedContract locks the compatibility contract of the
// typed datagram-dropped error: a consumer on an older pin that only matches
// the stdlib sentinel must keep classifying it as a droppable datagram.
func TestErrDatagramDroppedContract(t *testing.T) {
	err := DatagramDropped(io.ErrShortBuffer)

	if !stderrors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("errors.Is(err, io.ErrShortBuffer) = false, want true (legacy matching)")
	}
	var dropped *ErrDatagramDropped
	if !stderrors.As(err, &dropped) {
		t.Fatalf("errors.As(err, *ErrDatagramDropped) = false, want true (typed matching)")
	}
	if !stderrors.Is(dropped.Cause, io.ErrShortBuffer) {
		t.Fatalf("Cause = %v, want io.ErrShortBuffer", dropped.Cause)
	}
	if msg := err.Error(); msg == "" || msg == io.ErrShortBuffer.Error() {
		t.Fatalf("Error() = %q, want a datagram-dropped flavored message", msg)
	}

	// Wrapped through another layer, both matching styles must still work.
	wrapped := fmt.Errorf("read udp: %w", err)
	if !stderrors.Is(wrapped, io.ErrShortBuffer) {
		t.Fatalf("errors.Is(wrapped, io.ErrShortBuffer) = false, want true")
	}
	if !stderrors.As(wrapped, &dropped) {
		t.Fatalf("errors.As(wrapped, *ErrDatagramDropped) = false, want true")
	}

	// The wrapper must not accidentally masquerade as unrelated sentinels.
	if stderrors.Is(err, io.EOF) {
		t.Fatalf("errors.Is(err, io.EOF) = true, want false")
	}
}
