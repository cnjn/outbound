// protocol spec:
// https://trojan-gfw.github.io/trojan/protocol

package trojanc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

var (
	CRLF        = []byte{13, 10}
	FailAuthErr = fmt.Errorf("incorrect password") // nolint:staticcheck

	// passwordHashCache caches SHA224 hash results of passwords
	passwordHashCache sync.Map
)

type Conn struct {
	netproxy.Conn
	metadata Metadata
	pass     [56]byte

	writeMutex sync.Mutex
	headerOnce sync.Once
	headerErr  error
	onceWrite  atomic.Bool

	// packetWriteBuf is the reusable sealed-datagram scratch, guarded by
	// writeMutex (see borrowPacketWriteBuffer).
	packetWriteBuf []byte
}

// getPasswordHash retrieves the SHA224 hash of a password (with caching)
// Optimization: Uses sync.Map to cache hash results, avoiding repeated computation
func getPasswordHash(password string) [56]byte {
	// Try to get from cache
	if cached, ok := passwordHashCache.Load(password); ok {
		return cached.([56]byte)
	}

	// Cache miss, calculate hash
	hash := sha256.New224()
	hash.Write([]byte(password))
	var result [56]byte
	hex.Encode(result[:], hash.Sum(nil))

	// Store in cache
	passwordHashCache.Store(password, result)
	return result
}

func NewConn(conn netproxy.Conn, metadata Metadata, password string) (c *Conn, err error) {
	// Use cached password hash for ~6x performance improvement
	pass := getPasswordHash(password)

	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		pass:     pass,
	}
	return c, nil
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped stream conn: SetWriteDeadline is
// delegated to the underlying netproxy.Conn unchanged, so the semantics —
// and the declaration — belong to that conn. The UDP PacketConn embeds
// *Conn and inherits this forward.
func (c *Conn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *Conn) reqHeaderFromPool() (buf []byte) {
	reqLen := c.metadata.Len()
	buf = pool.Get(56 + 2 + 1 + reqLen + 2)
	copy(buf, c.pass[:])
	copy(buf[56:], CRLF)
	buf[58] = NetworkToByte(c.metadata.Network)
	c.metadata.PackTo(buf[59:])
	copy(buf[59+reqLen:], CRLF)

	return buf
}

func (c *Conn) writeRequestHeader(payload []byte) (n int, err error) {
	header := c.reqHeaderFromPool()
	defer pool.Put(header)

	buffers := net.Buffers{header}
	if len(payload) > 0 {
		buffers = append(buffers, payload)
	}
	written, err := buffers.WriteTo(c.Conn)
	if err != nil {
		if written <= int64(len(header)) {
			return 0, fmt.Errorf("write header: %w", err)
		}
		return int(written) - len(header), fmt.Errorf("write header: %w", err)
	}
	if written < int64(len(header)) {
		return 0, fmt.Errorf("write header: %w", io.ErrShortWrite)
	}
	return int(written) - len(header), nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeLocked(b)
}

// writeLocked writes with writeMutex already held, so packet framing that
// borrows the reusable scratch buffer can seal and send under one lock.
func (c *Conn) writeLocked(b []byte) (n int, err error) {
	if !c.onceWrite.Load() {
		if c.metadata.IsClient {
			n, err = c.writeRequestHeader(b)
			if err != nil {
				return n, err
			}
			c.onceWrite.Store(true)
			return n, nil
		}
	}
	return c.Conn.Write(b)
}

// maxReusablePacketWriteBufferSize caps the growth of the reusable UDP
// write buffer; larger one-shot frames allocate instead of pinning memory.
// Kept byte-identical with juicity's stream_conn.go copy: the two Conns were
// assessed for a type-level merge (round 8) and rejected — their transports,
// auth headers, and QUIC-specific lifecycles differ enough that a shared
// base would be hook-shaped inheritance, not deduplication.
const maxReusablePacketWriteBufferSize = 128 << 10

// borrowPacketWriteBuffer returns a scratch buffer for one sealed datagram.
// Callers must hold writeMutex; the buffer is reused across datagrams so the
// steady-state UDP send path stops touching the shared pool per packet.
func (c *Conn) borrowPacketWriteBuffer(size int) []byte {
	if size <= maxReusablePacketWriteBufferSize {
		if cap(c.packetWriteBuf) < size {
			c.packetWriteBuf = make([]byte, size)
		}
		return c.packetWriteBuf[:size]
	}
	return make([]byte, size)
}

func (c *Conn) ensureRequestHeader() error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.onceWrite.Load() || !c.metadata.IsClient {
		return nil
	}
	if _, err := c.writeRequestHeader(nil); err != nil {
		return err
	}
	c.onceWrite.Store(true)
	return nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.metadata.IsClient && c.metadata.Network == "tcp" && !c.onceWrite.Load() {
		if err = c.ensureRequestHeader(); err != nil {
			return 0, err
		}
	}
	if !c.metadata.IsClient {
		c.headerOnce.Do(func() {
			c.headerErr = c.ReadReqHeader()
		})
		if c.headerErr != nil {
			return 0, c.headerErr
		}
	}
	return c.Conn.Read(b)
}

func (c *Conn) ReadReqHeader() (err error) {
	buf := pool.Get(56)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if !bytes.Equal(c.pass[:], buf[:56]) {
		_ = c.Conn.Close()
		return FailAuthErr
	}
	var crlf [2]byte
	if _, err = io.ReadFull(c.Conn, crlf[:]); err != nil {
		return err
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return fmt.Errorf("invalid trojan header CRLF")
	}
	if _, err = io.ReadFull(c.Conn, buf[:1]); err != nil {
		return err
	}
	c.metadata.Network = ParseNetwork(buf[0])
	n := c.metadata.Len()
	if n < 2 {
		return fmt.Errorf("invalid trojan header")
	}
	if _, err = c.metadata.Unpack(c.Conn); err != nil {
		return err
	}
	if _, err = io.ReadFull(c.Conn, crlf[:]); err != nil {
		return err
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return fmt.Errorf("invalid trojan header CRLF")
	}
	return nil
}

// ReadBuffered reports immediately-readable plaintext bytes by delegating
// to the wrapped conn (the bufio layer owns the userspace queue for TLS
// transports). It backs write-batching copy loops that must not issue
// speculative reads or arm deadlines on record-framed streams.
func (c *Conn) ReadBuffered() int {
	return netproxy.ReadBuffered(c.Conn)
}

// UnderlyingConn peels to the wrapped conn so unwrap walks reach the
// transport socket through the protocol layer.
func (c *Conn) UnderlyingConn() net.Conn {
	if u, ok := c.Conn.(netproxy.UnderlyingConnProvider); ok {
		return u.UnderlyingConn()
	}
	return nil
}
