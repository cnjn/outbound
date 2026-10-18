/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package errors

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

// ============================================================================
// Unit Tests
// ============================================================================

func TestIsDNSTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "resolve timeout via net.Error",
			// The shape the resolver actually returns: *net.DNSError
			// satisfies net.Error and Timeout() reports true.
			err:  &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true},
			want: true,
		},
		{
			name: "plain string that merely looks like a DNS timeout",
			// Deliberately false: the deprecated substring shim matched this
			// without any evidence that the error was a timeout, and it
			// allocated on every failed dial. Only a net.Error that reports
			// Timeout()==true (or the sentinel) counts now.
			err:  fmt.Errorf("lookup example.com on 127.0.0.53:53: i/o timeout"),
			want: false,
		},
		{
			name: "standard DNS timeout error",
			err:  ErrDNSTimeout,
			want: true,
		},
		{
			name: "wrapped DNS timeout",
			err:  fmt.Errorf("operation failed: %w", ErrDNSTimeout),
			want: true,
		},
		{
			name: "net.Error with timeout and lookup",
			err:  &testNetError{timeout: true, msg: "lookup example.com: i/o timeout"},
			want: true,
		},
		{
			name: "non-DNS timeout",
			err:  fmt.Errorf("i/o timeout"),
			want: false,
		},
		{
			name: "lookup without timeout",
			err:  fmt.Errorf("lookup example.com: no such host"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "other error",
			err:  errors.New("some other error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDNSTimeout(tt.err); got != tt.want {
				t.Errorf("IsDNSTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsStreamExhausted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "too many open streams error",
			err:  errors.New("too many open streams"),
			want: true,
		},
		{
			name: "wrapped stream exhausted error",
			err:  fmt.Errorf("operation failed: too many open streams"),
			want: true,
		},
		{
			name: "other stream error",
			err:  errors.New("stream reset"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsStreamExhausted(tt.err); got != tt.want {
				t.Errorf("IsStreamExhausted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkIsDNSTimeout_StringMatch(b *testing.B) {
	err := fmt.Errorf("lookup example.com on 127.0.0.53:53: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Old approach: string matching
		errStr := err.Error()
		_ = strings.Contains(errStr, "i/o timeout") && strings.Contains(errStr, "lookup")
	}
}

func BenchmarkIsDNSTimeout_TypeSafe(b *testing.B) {
	err := fmt.Errorf("lookup example.com on 127.0.0.53:53: i/o timeout")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// New approach: type-safe check
		_ = IsDNSTimeout(err)
	}
}

func BenchmarkIsDNSTimeout_TypeSafeWrapped(b *testing.B) {
	err := fmt.Errorf("operation failed: %w", ErrDNSTimeout)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsDNSTimeout(err)
	}
}

func BenchmarkIsStreamExhausted_StringMatch(b *testing.B) {
	err := errors.New("too many open streams")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Old approach: string matching
		_ = strings.Contains(err.Error(), "too many open streams")
	}
}

func BenchmarkIsStreamExhausted_TypeSafe(b *testing.B) {
	err := errors.New("too many open streams")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// New approach: type-safe check
		_ = IsStreamExhausted(err)
	}
}

// testNetError is a minimal net.Error stand-in for table tests.
type testNetError struct {
	msg       string
	timeout   bool
	temporary bool
}

func (e *testNetError) Error() string   { return e.msg }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return e.temporary }
