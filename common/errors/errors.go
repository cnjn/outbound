/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package errors provides error handling utilities for the outbound module.
// This package maintains interface consistency with dae/common/errors while
// allowing independent evolution of the outbound module.
package errors

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/olicesx/quic-go"
)

// ============================================================================
// Standard Error Definitions (Sentinel Errors)
//
// These are exported for direct comparison in hot paths (1.19 ns/op).
// Usage: if err == ErrDNSTimeout { ... }
// ============================================================================

var (
	// DNS Errors
	ErrDNSTimeout          = errors.New("i/o timeout on DNS lookup")
	ErrDNSTemporaryFailure = errors.New("temporary DNS failure")

	// Stream Errors
	ErrStreamExhausted = errors.New("too many open streams")
	ErrClientClosed    = errors.New("client closed")
	ErrClientClosing   = errors.New("client closing")
	ErrOperationHold   = errors.New("hold on")
)

// ============================================================================
// DNS and Timeout Error Detection
// ============================================================================

// IsDNSTimeout checks if the error is a DNS timeout.
//
// The call sites run on every failed direct dial (protocol/direct/dialer.go),
// so the fast paths are ordered by cost and do not allocate:
//
//  1. identity comparison against the sentinel;
//  2. errors.As into net.Error plus Timeout() - this covers every real Go
//     network timeout, including *net.DNSError, and is the only structurally
//     sound interface check.
//
// The former second branch asserted `interface{ IsTimeout() bool }`, which no
// error in the standard library or in this tree implements: net.Error's method
// is Timeout(), not IsTimeout(), so that branch was unreachable dead code.
// The trailing substring match was a deprecated compatibility shim that
// allocated on every call; it is gone, and an error that is neither the
// sentinel nor a net.Error with Timeout()==true is reported as not-a-timeout.
func IsDNSTimeout(err error) bool {
	if err == nil {
		return false
	}

	// Fast path: identity comparison. errors.Is also unwraps, so a sentinel
	// wrapped by %w is still recognised (the bare `==` the previous version
	// used did not, which is why the wrapped case was untested).
	if errors.Is(err, ErrDNSTimeout) {
		return true
	}

	// Structurally correct interface check: net.Error.Timeout().
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

// IsStreamExhausted checks if the error indicates no more streams available.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrStreamExhausted { ... }
func IsStreamExhausted(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrStreamExhausted {
		return true
	}
	return strings.Contains(err.Error(), "too many open streams")
}

// IsTemporaryError checks if an error is temporary and should not close the connection.
// This is used to distinguish between fatal and non-fatal network/context errors.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// Context timeout/cancelled are temporary
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}

	// A full DATAGRAM send queue drops the current datagram and keeps the
	// QUIC connection alive. Closing the shared tunnel here would replay the
	// HY2 game-disconnect failure on TUIC.
	if errors.Is(err, quic.ErrDatagramQueueFullTimeout) {
		return true
	}

	// Net temporary errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() { // nolint:staticcheck
		return true
	}

	return false
}
