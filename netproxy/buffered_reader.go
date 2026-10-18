package netproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	zbufio "github.com/daeuniverse/outbound/pkg/zeroalloc/bufio"
)

// BufferedReaderConn wraps a Conn with a bufio.Reader so that callers using
// io.ReadFull on small, frequent reads (chunk headers, nonces, length prefixes)
// do not each incur their own syscall. Without this wrapper, every protocol
// that frames data into chunks (shadowsocks, vmess, trojan, vless, ...) ends
// up doing at least two reads per chunk: one for the 2-byte length+tag and one
// for the payload. On a raw TCP socket each Read may hit the kernel, doubling
// the syscall count compared to what dae's relay loop issues on the write side.
//
// The default buffer is sized to hold a full protocol decryption chunk so
// io.ReadFull(header) plus io.ReadFull(payload) complete from one underlying
// read once data is flowing. Shadowsocks AEAD max chunk is ~16.1 KiB
// (16383 B payload + length + two AEAD tags); VMess MaxChunkSize is 16 KiB.
// 16 KiB is just short of a max SS chunk. 32 KiB matches dae's relay copy
// unit and leaves slack for tags. SS2022's theoretical 64 KiB-1 max is rare;
// the relay writes 32 KiB, so a typical encrypted chunk still fits.
//
// This buffer is per proxied raw-TCP session, not per node. TLS-like
// underlays (*tls.Conn, *utls.UConn, and any Conn that already exposes a
// TLS record buffer) already coalesce small io.ReadFull calls from their
// decrypted record buffer (maxPlaintext = 16 KiB). Wrapping those again
// would hold an extra live allocation for the connection lifetime and add
// a memcpy without reducing syscalls. NewBufferedReaderConn therefore
// returns such conns unchanged.
const defaultReadBufferSize = 32 << 10

// AlreadyReadBuffered is implemented by connections whose Read already
// coalesces from an internal buffer (typically a TLS record layer). Protocol
// dialers wrap every underlay with NewBufferedReaderConn; implement this on
// a new transport instead of teaching netproxy another concrete type.
type AlreadyReadBuffered interface {
	AlreadyReadBuffered()
}

// BufferedReaderConn embeds the original Conn and routes Read through a
// per-connection pooled buffered reader. All other Conn methods (Write,
// deadlines) pass straight through to the underlying Conn, so Write
// semantics and any SO_MARK / socket options set on the raw fd are
// preserved unchanged.
//
// Buffer lifecycle: the backing array comes from the shared byte pool and is
// returned exactly once, by whichever of two paths finds the read loop over
// with no reader left inside reader.Read:
//
//   - Read observed a terminal error (EOF, net.ErrClosed, cancellation) and
//     the buffered window is drained: the read loop's own exit path;
//   - Close ran with no read in flight and nothing buffered: a connection
//     torn down without a draining read.
//
// Retryable errors (notably read-deadline timeouts) release nothing, so
// timeout-retry loops keep their buffer. A connection abandoned without Close
// or a terminal read keeps its buffer for GC, which is the pre-pooling
// behavior. Every release requires an empty buffered window, so no readable
// byte is ever discarded. A panic raised inside reader.Read by a misbehaving
// underlay counts like any other exit: the read is dropped from the in-flight
// count, but nothing is released until a terminal state exists (a terminal
// error or Close) with a drained window, so a window the panic left behind is
// never recycled - not even by a later Close.
//
// Read and ReadBuffered share the connection's reader side — bufio.Reader
// itself is not safe for concurrent use — while Close may be called from any
// goroutine, including one racing a blocked read: it only closes the underlay
// and leaves the release to the unblocked reader.
type BufferedReaderConn struct {
	Conn
	reader *zbufio.Reader

	// mu guards the lifecycle fields below. It is never held across a read,
	// so a blocked read can never stall Close.
	mu sync.Mutex
	// readers counts Read calls currently inside reader.Read; the pooled
	// buffer is only returned once it is zero.
	readers int
	// released records that the pooled buffer has gone back to the pool.
	released bool
	// termErr is the terminal error observed by the read path (or net.ErrClosed
	// recorded by Close). Reads after the release return it unchanged.
	termErr error
}

// WriteDeadlineClosesSession forwards the optional destructive write-deadline
// declaration of the wrapped Conn. Embedding the Conn interface promotes
// SetWriteDeadline but not this optional method, so without the forward a
// session-closing inner conn is invisible to deadline-arming callers - the
// exact case the type's own documentation calls "pass straight through".
func (c *BufferedReaderConn) WriteDeadlineClosesSession() bool {
	return WriteDeadlineClosesSession(c.Conn)
}

// NewBufferedReaderConn wraps c with a bufio.Reader of the given size.
// Pass 0 to use the default (32 KiB). If c already coalesces reads (TLS
// record layer, or AlreadyReadBuffered), c is returned unchanged so the
// extra read buffer is not allocated. Callers that need a wrapper even
// on TLS (Vision regression tests) should use ForceBufferedReaderConn.
func NewBufferedReaderConn(c Conn, size int) Conn {
	if alreadyHasReadBuffer(c) {
		return c
	}
	return ForceBufferedReaderConn(c, size)
}

// ForceBufferedReaderConn always allocates the bufio wrapper. Used by
// tests that must exercise IntrinsicConn peeling through the wrap.
func ForceBufferedReaderConn(c Conn, size int) *BufferedReaderConn {
	if size <= 0 {
		size = defaultReadBufferSize
	}
	return &BufferedReaderConn{
		Conn:   c,
		reader: zbufio.NewReaderSize(readerOf{c}, size),
	}
}

func alreadyHasReadBuffer(c Conn) bool {
	if c == nil {
		return false
	}
	switch c.(type) {
	case *tls.Conn, *utls.UConn, *BufferedReaderConn:
		return true
	}
	if _, ok := c.(AlreadyReadBuffered); ok {
		return true
	}
	return false
}

// Read drains buffered bytes first, then refills from the underlying Conn.
// The pooled reader handles partial reads internally, so io.ReadFull callers
// see a single logical read even when the kernel only delivered part of the
// chunk. A terminal error ends the stream: it is recorded, and the pooled
// buffer is returned as soon as no other read is still inside the reader (see
// the type comment for the full lifecycle contract).
func (b *BufferedReaderConn) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.released {
		err := b.termErr
		b.mu.Unlock()
		return 0, err
	}
	b.readers++
	b.mu.Unlock()

	// The exit is deferred so that a panic from the underlying reader cannot
	// leave the count raised: the count describes reads still inside
	// reader.Read, and an unwound stack is not one. A stale count would make
	// every later release impossible (Close included), so restoring it is
	// correctness, not bookkeeping. The release itself still goes through the
	// full gate, so the deferred call can only return a drained connection.
	defer b.exitRead()

	n, err := b.reader.Read(p)
	if IsTerminalReadErr(err) {
		b.mu.Lock()
		if b.termErr == nil {
			b.termErr = err
		}
		b.mu.Unlock()
	}
	return n, err
}

// exitRead drops one in-flight read and re-runs the release gate. It is
// deferred from Read, so it also runs while a panic unwinds; the gate short
// circuits on the unset terminal error before it touches the reader, which
// keeps an unwinding reader's window out of the decision.
func (b *BufferedReaderConn) exitRead() {
	b.mu.Lock()
	b.readers--
	b.releaseIfDrainedLocked()
	b.mu.Unlock()
}

// Close closes the underlying Conn and returns the pooled buffer when the
// connection is already drained and idle. A blocked read is never interrupted
// for the release: the underlying Close unblocks it and the read path returns
// the buffer on its way out. If readable bytes are still buffered, the buffer
// stays with the connection, exactly as the pre-pooling wrapper served them;
// draining them releases it.
func (b *BufferedReaderConn) Close() error {
	b.mu.Lock()
	if b.termErr == nil {
		// Reads after the release must report the closed connection, not EOF.
		b.termErr = net.ErrClosed
	}
	b.releaseIfDrainedLocked()
	b.mu.Unlock()
	return b.Conn.Close()
}

// releaseIfDrainedLocked returns the pooled buffer to the pool exactly once,
// and only when the stream has reached a terminal state, no Read is still
// inside reader.Read, and no readable byte remains buffered. Checking the
// reader count before touching the reader keeps Buffered() from racing a
// goroutine that is mutating the reader's window. The caller must hold mu.
func (b *BufferedReaderConn) releaseIfDrainedLocked() {
	if b.released || b.readers != 0 || b.termErr == nil || b.reader.Buffered() != 0 {
		return
	}
	b.released = true
	b.reader.Put()
}

// IsTerminalReadErr reports whether err ends a connection's read side, so no
// future read can still want the read buffer. It is deliberately
// conservative: deadline-exceeded and other temporary errors are retryable
// by net.Conn semantics and must not release anything, and a terminal error
// outside this set (for example ECONNRESET) still releases from Close once
// the read loop has exited. Transport wrappers that own a pooled read buffer
// share this classification so their release gates cannot drift apart.
func IsTerminalReadErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled)
}

// ReadBuffered reports how many decrypted bytes the buffered layer already
// holds: every buffered byte is returned by a subsequent Read without
// touching the network or the wrapped stream, which is exactly the
// "more data has already arrived" signal write-batching copy loops need.
// Layers below the buffer (kernel socket) are not this wrapper's to observe;
// callers combine this with their own socket-state checks. It reports zero
// once the buffer has been released, and while a read is in flight, when the
// count could not be read without racing the reader's window.
func (b *BufferedReaderConn) ReadBuffered() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.released || b.readers != 0 {
		return 0
	}
	return b.reader.Buffered()
}

// SetReadDeadline is forwarded to the underlying Conn. Note that bufio may
// have already buffered data that will be returned before the deadline takes
// effect on the next kernel read; this matches the semantics users expect
// from a buffered connection (deadline applies to new data, not buffered).
func (b *BufferedReaderConn) SetReadDeadline(t time.Time) error {
	return b.Conn.SetReadDeadline(t)
}

// LocalAddr exposes the underlying connection's local address so that
// BufferedReaderConn satisfies the net.Conn interface. Callers such as the
// Shadowsocks-2022 dialer type-assert the wrapped connection to net.Conn
// (its TCPConn embeds net.Conn); without these accessors the assertion
// panics even though the underlying socket carries the address. If the
// wrapped Conn does not expose address information, nil is returned.
func (b *BufferedReaderConn) LocalAddr() net.Addr {
	if a, ok := b.Conn.(interface{ LocalAddr() net.Addr }); ok {
		return a.LocalAddr()
	}
	return nil
}

// RemoteAddr exposes the underlying connection's remote address. See
// LocalAddr for the rationale.
func (b *BufferedReaderConn) RemoteAddr() net.Addr {
	if a, ok := b.Conn.(interface{ RemoteAddr() net.Addr }); ok {
		return a.RemoteAddr()
	}
	return nil
}

// IntrinsicConn unwraps the buffered layer so callers that need direct
// access to the underlying TLS/REALITY connection (notably XTLS/Vision,
// which reflects on *tls.Conn / *utls.UConn / *RealityUConn fields) can
// reach it. Without this method, Vision's intrinsicConn type assertion
// fails with "XTLS only supports TLS and REALITY directly for now".
// If the underlying Conn is itself a wrapper exposing IntrinsicConn,
// forward to it so nested wrappers compose correctly.
func (b *BufferedReaderConn) IntrinsicConn() Conn {
	if ic, ok := b.Conn.(interface{ IntrinsicConn() Conn }); ok {
		return ic.IntrinsicConn()
	}
	return b.Conn
}

// UnderlyingConn returns the wrapped Conn for callers (e.g. dae's relay
// unwrap path) that need direct access to the raw socket. Do not fall back
// to b.Conn itself: splicing through a bufio.Reader would skip unread bytes.
func (b *BufferedReaderConn) UnderlyingConn() net.Conn {
	if u, ok := b.Conn.(interface{ UnderlyingConn() net.Conn }); ok {
		return u.UnderlyingConn()
	}
	return nil
}

// CloseWrite forwards half-close to the inner conn. WriteCloser is not on
// the Conn interface, so embedding does not promote it; without this method
// protocol CloseWrite adapters stop at the buffered layer on plain TCP.
func (b *BufferedReaderConn) CloseWrite() error {
	return ForwardCloseWrite(b.Conn)
}

// readerOf adapts a netproxy.Conn to an io.Reader for bufio by stripping the
// deadline-bearing Read signature. We do NOT implement SetReadDeadline on this
// adapter: deadline control stays on the outer BufferedReaderConn so callers
// keep working with the wrapper, not the inner reader.
type readerOf struct{ c Conn }

func (r readerOf) Read(p []byte) (int, error) { return r.c.Read(p) }
