package juicity

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/olicesx/quic-go"
)

type Conn struct {
	quic.Stream
	Metadata *trojanc.Metadata

	writeMutex     sync.Mutex
	onceWrite      bool
	packetWriteBuf []byte
	headerOnce     sync.Once
	headerErr      error

	closeDeferFn  func()
	transportDone <-chan struct{}

	closeOnce sync.Once
	closeErr  error
}

// reqHeader builds the request header into a small pooled buffer. The payload
// is written separately via net.Buffers so a large payload cannot inflate this
// buffer past the pool's largest bucket (same cliff as vless/anytls).
func (c *Conn) reqHeader() (buf []byte) {
	addrLen := c.Metadata.Len()
	buf = pool.Get(1 + addrLen)
	buf[0] = trojanc.NetworkToByte(c.Metadata.Network)
	c.Metadata.PackTo(buf[1:])
	return buf
}

func (c *Conn) readReqHeader() (err error) {
	buf := pool.Get(1)
	defer buf.Put()
	if _, err = io.ReadFull(c.Stream, buf[:1]); err != nil {
		return err
	}
	c.Metadata.Network = trojanc.ParseNetwork(buf[0])
	n := c.Metadata.Len()
	if n < 2 {
		_ = c.Stream.Close()
		return fmt.Errorf("invalid juicity header")
	}
	if _, err = c.Metadata.Unpack(c.Stream); err != nil {
		return err
	}
	return nil
}

const maxReusablePacketWriteBufferSize = 128 << 10

func (c *Conn) borrowPacketWriteBuffer(size int) []byte {
	if size <= maxReusablePacketWriteBufferSize {
		if cap(c.packetWriteBuf) < size {
			c.packetWriteBuf = make([]byte, size)
		}
		return c.packetWriteBuf[:size]
	}
	return make([]byte, size)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	return c.writeLocked(b)
}

func (c *Conn) writeLocked(b []byte) (n int, err error) {
	if !c.onceWrite {
		if c.Metadata.IsClient {
			header := c.reqHeader()
			defer pool.Put(header)
			buffers := net.Buffers{header}
			if len(b) > 0 {
				buffers = append(buffers, b)
			}
			if _, err = buffers.WriteTo(c.Stream); err != nil {
				return 0, fmt.Errorf("write header: %w", err)
			}
			c.onceWrite = true
			return len(b), nil
		}
	}
	return c.Stream.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.Metadata != nil && !c.Metadata.IsClient {
		c.headerOnce.Do(func() {
			c.headerErr = c.readReqHeader()
		})
		if c.headerErr != nil {
			return 0, c.headerErr
		}
	}
	return c.Stream.Read(b)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.close()
	})
	return c.closeErr
}

func (c *Conn) CloseWrite() error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// As documented by the quic-go library, this doesn't actually close the entire stream.
	// It prevents further writes, which in turn will result in an EOF signal being sent the other side of stream when
	// reading.
	// We can still read from this stream.
	return c.Stream.Close()
}

func (c *Conn) close() error {
	if c.closeDeferFn != nil {
		defer c.closeDeferFn()
	}

	// https://github.com/cloudflare/cloudflared/commit/ed2bac026db46b239699ac5ce4fcf122d7cab2cd
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = c.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to writes.
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	c.packetWriteBuf = nil

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	c.CancelRead(0)
	return c.Stream.Close()
}

var _ netproxy.Conn = &Conn{}

func (c *Conn) TransportDone() <-chan struct{} {
	return c.transportDone
}

func NewConn(stream quic.Stream, mdata *trojanc.Metadata, closeDeferFn func(), transportDone <-chan struct{}) *Conn {
	if mdata == nil {
		mdata = &trojanc.Metadata{}
	}
	return &Conn{
		Stream:        stream,
		Metadata:      mdata,
		closeDeferFn:  closeDeferFn,
		transportDone: transportDone,
	}
}

// ReadBuffered reports immediately-readable stream bytes from the QUIC
// receive path. It backs write-batching copy loops that must not issue
// speculative reads or arm deadlines on streams.
func (c *Conn) ReadBuffered() int {
	if rb, ok := c.Stream.(interface{ ReadBuffered() int }); ok {
		return rb.ReadBuffered()
	}
	return 0
}
