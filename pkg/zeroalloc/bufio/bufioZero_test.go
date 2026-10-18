package bufio

import (
	stdbufio "bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

// sameReadErr compares a forked ReadSlice error with the standard library's.
// ErrBufferFull is a package-level sentinel in both packages, so identity
// cannot be compared across them; the class and the message can.
func sameReadErr(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	if errors.Is(want, stdbufio.ErrBufferFull) != errors.Is(got, ErrBufferFull) {
		return false
	}
	return got.Error() == want.Error()
}

// ReadSlice carries the response-header parse in transport/httpheader and was
// taken from the standard library, so it must behave exactly like the method
// it was copied from: a found delimiter consumes through it, a pending error
// returns the rest of the window (consumed) together with that error, and a
// buffer that fills without a delimiter reports ErrBufferFull. The parity
// harness drives both readers with the same input and compares the returned
// line, the error and the buffered window after every call.
func TestReadSliceMatchesStdlib(t *testing.T) {
	// 16 is the minimum buffer size both implementations accept, which makes
	// ErrBufferFull reachable with small deterministic inputs.
	const bufSize = 16
	cases := []struct {
		name  string
		input string
	}{
		{"response header", "HTTP/1.1 200 OK\r\nHost: example\r\n\r\nbody"},
		{"no delimiter", "no-delimiter-here"},
		{"bare newline", "\n"},
		{"blank lines", "\r\n\r\n"},
		{"delimited lines", "line\nline\nline"},
		{"empty input", ""},
		{"full window without delimiter", strings.Repeat("x", 40)},
		{"delimiter right after full window", strings.Repeat("x", bufSize) + "\ntail"},
		{"delimiter split across windows", strings.Repeat("x", bufSize-1) + "\nrest\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			std := stdbufio.NewReaderSize(strings.NewReader(tc.input), bufSize)
			fork := NewReaderSize(strings.NewReader(tc.input), bufSize)
			if std.Size() != fork.Size() {
				t.Fatalf("buffer size = %d, want %d", fork.Size(), std.Size())
			}
			// A few extra steps keep both readers walking the same path after
			// the input is exhausted (each must keep reporting io.EOF).
			for step := 0; step < 8; step++ {
				wantLine, wantErr := std.ReadSlice('\n')
				gotLine, gotErr := fork.ReadSlice('\n')
				if string(gotLine) != string(wantLine) {
					t.Fatalf("step %d: line = %q, want %q", step, gotLine, wantLine)
				}
				if !sameReadErr(gotErr, wantErr) {
					t.Fatalf("step %d: err = %v, want %v", step, gotErr, wantErr)
				}
				if got, want := fork.Buffered(), std.Buffered(); got != want {
					t.Fatalf("step %d: Buffered() = %d, want %d", step, got, want)
				}
			}
		})
	}
}

// The pending-error branch must hand back a partial line exactly once and
// leave the reader reporting the error afterwards, since that is what the
// header parser's timeout-retry path observes.
func TestReadSlicePendingErrorConsumesPartialLine(t *testing.T) {
	r := NewReaderSize(strings.NewReader("partial"), 16)
	line, err := r.ReadSlice('\n')
	if string(line) != "partial" || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadSlice = %q, %v; want \"partial\", io.EOF", line, err)
	}
	if n := r.Buffered(); n != 0 {
		t.Fatalf("Buffered() after the error = %d, want 0 (the partial line is consumed)", n)
	}
	if line, err := r.ReadSlice('\n'); len(line) != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("second ReadSlice = %q, %v; want empty, io.EOF", line, err)
	}
}
