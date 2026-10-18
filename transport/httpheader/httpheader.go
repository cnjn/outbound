package httpheader

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	zbufio "github.com/daeuniverse/outbound/pkg/zeroalloc/bufio"
)

const (
	defaultHost       = "www.baidu.com"
	defaultUserAgent  = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
	maxResponseHeader = 8192

	// bufioBufferSize is the read buffer size for the wrapped connection.
	// It is decoupled from maxResponseHeader (which only bounds the HTTP
	// response header parsing) because downstream protocols (e.g. vmess)
	// issue io.ReadFull calls of up to ~16KB per chunk. A small bufio buffer
	// splits those reads into multiple syscalls, inflating write count in the
	// relay loop by ~1.5x and wasting CPU on syscall overhead.
	bufioBufferSize = 32 << 10
)

var errResponseHeaderTooLarge = errors.New("HTTP response header is too large")

// Dialer implements the legacy V2Ray TCP HTTP header transport.
type Dialer struct {
	nextDialer netproxy.Dialer
	host       string
	path       string
}

func NewDialer(nextDialer netproxy.Dialer, host, path string) (*Dialer, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		host = defaultHost
	}

	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if _, err := http.NewRequest(http.MethodGet, path, nil); err != nil {
		return nil, fmt.Errorf("httpheader: invalid path: %w", err)
	}

	return &Dialer{
		nextDialer: nextDialer,
		host:       host,
		path:       path,
	}, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network != "tcp" {
		return nil, fmt.Errorf("%w: httpheader+%s", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}

	conn, err := d.nextDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return newConn(conn, d.host, d.path), nil
}

// conn carries the HTTP request/response header transport on top of the
// underlying proxy connection. Its reads go through a pooled buffered reader
// (pkg/zeroalloc/bufio) so the response-header parse and the downstream
// protocol's small io.ReadFull calls coalesce into single socket reads without
// allocating a fresh 32 KiB array per connection.
//
// Buffer lifecycle: the backing array comes from the shared byte pool and is
// returned exactly once, by whichever of two paths finds the read side over
// with no reader left inside reader.Read:
//
//   - Read observed a terminal state (EOF, net.ErrClosed, cancellation, or a
//     non-retryable response-header error) and the buffered window is empty:
//     the read loop's own exit path;
//   - Close ran with no read in flight and nothing buffered: a connection
//     torn down without a draining read.
//
// Retryable errors - notably read-deadline timeouts, which the header parse
// leaves retryable - release nothing, so a timeout-retry loop keeps its buffer
// and the bytes already buffered in it. Every release requires an empty
// buffered window, so no readable byte is ever discarded. A panic raised
// inside reader.Read by a misbehaving underlay counts like any other exit: the
// read is dropped from the in-flight count, but nothing is released until a
// terminal state exists with a drained window.
//
// Read holds readMu, so the reader side stays single-goroutine, exactly as the
// pre-pooling conn required (bufio.Reader is not safe for concurrent use).
// Close may be called from any goroutine, including one racing a blocked read:
// it only closes the underlay and leaves the release to the unblocked reader.
type conn struct {
	netproxy.Conn
	reader *zbufio.Reader
	host   string
	path   string

	readMu  sync.Mutex
	writeMu sync.Mutex

	// mu guards the pooled-reader lifecycle fields below. It is never held
	// across a read, so a blocked read can never stall Close.
	mu sync.Mutex
	// readers counts Read calls currently inside reader.Read; the pooled
	// buffer is only returned once it is zero.
	readers int
	// released records that the pooled buffer has gone back to the pool.
	released bool
	// termErr is the first state that ended the read side: a sticky
	// response-header failure, a terminal body read error, or the
	// net.ErrClosed recorded by Close. It gates the release and is what reads
	// report once the buffer is gone.
	termErr error

	headerRead bool
	headerSent bool
	readErr    error
	writeErr   error
}

func newConn(raw netproxy.Conn, host, path string) *conn {
	return &conn{
		Conn:   raw,
		reader: zbufio.NewReaderSize(raw, bufioBufferSize),
		host:   host,
		path:   path,
	}
}

func (c *conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	c.mu.Lock()
	if c.released {
		err := c.termErr
		c.mu.Unlock()
		return 0, err
	}
	c.readers++
	c.mu.Unlock()

	// The exit is deferred so that a panic from the underlying reader cannot
	// leave the count raised: the count describes reads still inside
	// reader.Read, and an unwound stack is not one. A stale count would make
	// every later release impossible (Close included), so restoring it is
	// correctness, not bookkeeping.
	defer c.exitRead()

	if !c.headerRead {
		if err := discardResponseHeader(c.reader); err != nil {
			if isRetryableHeaderErr(err) {
				return 0, err
			}
			// A non-retryable header error is sticky: every later read returns
			// it without touching the reader, so the session is terminal for
			// the buffer lifecycle as well.
			c.headerRead = true
			c.readErr = err
			c.recordTerminalErr(err)
			return 0, err
		}
		c.headerRead = true
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	n, err := c.reader.Read(p)
	if netproxy.IsTerminalReadErr(err) {
		c.recordTerminalErr(err)
	}
	return n, err
}

// isRetryableHeaderErr reports whether a response-header read error leaves the
// parse retryable: net.Conn semantics let a deadline expire without ending the
// stream, so the reader, its buffered bytes and the header state all stay as
// they were and the next Read resumes the parse.
func isRetryableHeaderErr(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var to interface{ Timeout() bool }
	return errors.As(err, &to) && to.Timeout()
}

// recordTerminalErr records the first state that ended this conn's read side.
// The release gate only needs to know that a terminal state exists; the first
// one is the one reported to reads that arrive after the buffer is gone.
func (c *conn) recordTerminalErr(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.mu.Unlock()
}

// exitRead drops one in-flight read and re-runs the release gate. It is
// deferred from Read, so it also runs while a panic unwinds; the gate short
// circuits on the unset terminal error before it touches the reader, which
// keeps an unwinding reader's window out of the decision.
func (c *conn) exitRead() {
	c.mu.Lock()
	c.readers--
	c.releaseIfDrainedLocked()
	c.mu.Unlock()
}

// releaseIfDrainedLocked returns the pooled buffer to the pool exactly once,
// and only when the read side has reached a terminal state, no Read is still
// inside reader.Read, and no readable byte remains buffered. Checking the
// reader count before touching the reader keeps Buffered() from racing a
// goroutine that is mutating the reader's window. The caller must hold mu.
func (c *conn) releaseIfDrainedLocked() {
	if c.released || c.readers != 0 || c.termErr == nil || c.reader.Buffered() != 0 {
		return
	}
	c.released = true
	c.reader.Put()
}

// Close closes the underlying Conn and returns the pooled buffer when the
// connection is already drained and idle. A blocked read is never interrupted
// for the release: the underlying Close unblocks it and the read path returns
// the buffer on its way out. If readable bytes are still buffered, the buffer
// stays with the connection, exactly as the pre-pooling conn served them;
// draining them releases it.
func (c *conn) Close() error {
	c.mu.Lock()
	if c.termErr == nil {
		// Reads after the release must report the closed connection.
		c.termErr = net.ErrClosed
	}
	c.releaseIfDrainedLocked()
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *conn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. This type embeds
// netproxy.Conn, which promotes SetWriteDeadline but not this optional method,
// so without the forward a session-closing inner conn (TUIC, hysteria2) would
// be invisible to deadline-arming callers.
func (c *conn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.headerSent {
		c.headerSent = true
		c.writeErr = c.writeRequestHeader()
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}

func (c *conn) writeRequestHeader() error {
	req, err := http.NewRequest(http.MethodGet, c.path, nil)
	if err != nil {
		return err
	}
	req.Host = c.host
	// Do not advertise gzip/deflate: the server's compressed response would
	// make every connection allocate a flate decoder (compress/flate + gzip
	// Reader per handshake), which shows up as ~4k allocs/10s under
	// connection-storm workloads (speedtests) and feeds the GC loop. The
	// handshake response header is tiny; compression saves nothing here.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("User-Agent", defaultUserAgent)
	return req.Write(c.Conn)
}

func discardResponseHeader(reader *zbufio.Reader) error {
	total := 0
	for {
		line, err := reader.ReadSlice('\n')
		total += len(line)
		if total > maxResponseHeader || errors.Is(err, zbufio.ErrBufferFull) {
			return errResponseHeaderTooLarge
		}
		if err != nil {
			return fmt.Errorf("httpheader: read response header: %w", err)
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return nil
		}
	}
}
