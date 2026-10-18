// protocol spec:
// https://trojan-gfw.github.io/trojan/protocol

package vless

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/vmess"
	"google.golang.org/protobuf/proto"
)

var (
	FailAuthErr = fmt.Errorf("incorrect UUID") // nolint:staticcheck
)

type Metadata struct {
	vmess.Metadata
	Flow string
	Mux  bool
}

type Conn struct {
	netproxy.Conn
	metadata            Metadata
	cmdKey              []byte
	cachedProxyAddrIpIP netip.AddrPort

	writeMutex     sync.Mutex
	readMutex      sync.Mutex
	readHeaderDone bool
	headerErr      error
	onceWrite      bool

	addonsBytes []byte
}

func NewConn(conn netproxy.Conn, metadata Metadata, cmdKey []byte) (c *Conn, err error) {

	// DO NOT use pool here because Close() cannot interrupt the reading or writing, which will modify the value of the pool buffer.
	key := make([]byte, len(cmdKey))
	copy(key, cmdKey)
	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		cmdKey:   key,
	}
	if metadata.Network == "udp" {
		proxyAddrIp, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port))))
		if err != nil {
			// NewConn owns conn from here on; close it on every failure or
			// the dialed underlay leaks.
			_ = conn.Close()
			return nil, err
		}
		c.cachedProxyAddrIpIP = proxyAddrIp.AddrPort()
	}
	// Vision streams must open with a padded Vision frame carrying the user
	// UUID; a raw empty write here would emit an unpadded VLESS header alone,
	// so vision.NewPacketConn owns the 100ms handshake-flush timer when a
	// flow is active.
	if metadata.Network == "tcp" && metadata.IsClient && metadata.Flow == "" {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first.
			// Use a local error: capturing the named return here would race
			// with the caller's frame after NewConn returns.
			if _, werr := c.Write(nil); werr != nil {
				return
			}
		})
	}
	if metadata.Flow != "" {
		c.addonsBytes, err = proto.Marshal(&Addons{
			Flow: metadata.Flow,
		})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *Conn) IntrinsicConn() netproxy.Conn {
	return c.Conn
}

func (c *Conn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// reqHeader builds the request header into a small pooled buffer. The payload
// is written separately via net.Buffers so a large payload cannot inflate this
// buffer past the pool's largest bucket (the same cliff anytls hit).
func (c *Conn) reqHeader() (buf []byte) {
	addrLen := c.metadata.AddrLen()
	if !c.metadata.Mux {
		buf = pool.Get(1 + 16 + len(c.addonsBytes) + 1 + 1 + 2 + 1 + addrLen)
	} else {
		buf = pool.Get(1 + 16 + len(c.addonsBytes) + 1 + 1)
	}
	start := 0
	buf[start] = 0 // version
	start += 1
	copy(buf[start:], c.cmdKey)
	start += 16
	buf[start] = byte(len(c.addonsBytes)) // length of addons
	start += 1
	copy(buf[start:], c.addonsBytes)
	start += len(c.addonsBytes)
	if !c.metadata.Mux {
		buf[start] = vmess.NetworkToByte(c.metadata.Network) // inst
		start += 1
		binary.BigEndian.PutUint16(buf[start:], c.metadata.Port) // port
		start += 2
		buf[start] = vmess.MetadataTypeToByte(c.metadata.Type) // addr type
		start += 1
		c.metadata.PutAddr(buf[start:])
	} else {
		buf[start] = vmess.NetworkToByte("mux") // inst
	}
	return buf
}

func (c *Conn) Write(b []byte) (n int, err error) {
	// logrus.Println("VLESS CONN WRITE", hex.EncodeToString(b))
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.metadata.Network == "udp" && c.metadata.Flow != XRV {
		// logrus.Println("!!!", "UDP, write")
		var bLen [2]byte
		binary.BigEndian.PutUint16(bLen[:], uint16(len(b)))
		if _, err = c.write(bLen[:]); err != nil {
			return 0, err
		}
	}
	return c.write(b)
}

func (c *Conn) write(b []byte) (n int, err error) {
	if !c.onceWrite {
		if c.metadata.IsClient {
			header := c.reqHeader()
			defer pool.Put(header)
			buffers := net.Buffers{header}
			if len(b) > 0 {
				buffers = append(buffers, b)
			}
			if _, err = buffers.WriteTo(c.Conn); err != nil {
				return 0, fmt.Errorf("write header: %w", err)
			}
			c.onceWrite = true
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	if c.metadata.Network == "udp" && c.metadata.Flow != XRV {
		// logrus.Println("!!!", "UDP, read")
		// defer func() {
		// 	logrus.Println("READ", n, err)
		// }()
		var bLen [2]byte
		if _, err = io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, bLen[:]); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(bLen[:]))
		if len(b) < length {
			if _, discardErr := io.CopyN(io.Discard, &netproxy.ReadWrapper{ReadFunc: c.read}, int64(length)); discardErr != nil && err == nil {
				err = discardErr
			}
			if err != nil {
				return 0, err
			}
			return 0, fmt.Errorf("buf size is not enough")
		}
		// Read exactly one framed datagram: a plain c.read(b) here could
		// return a partial or spanning chunk of the UDP-over-TCP stream.
		return io.ReadFull(&netproxy.ReadWrapper{ReadFunc: c.read}, b[:length])
	}

	return c.read(b)
}

func (c *Conn) read(b []byte) (n int, err error) {
	if c.headerErr != nil {
		return 0, c.headerErr
	}
	// Client reads the server's response header; server reads the client's
	// request header. A failed io.ReadFull cannot be retried: those bytes
	// are already gone, so the error is sticky.
	if !c.readHeaderDone {
		if c.metadata.IsClient {
			err = c.ReadRespHeader()
		} else {
			err = c.ReadReqHeader()
		}
		if err != nil {
			c.headerErr = err
			return 0, err
		}
		c.readHeaderDone = true
	}
	return c.Conn.Read(b)
}

func (c *Conn) ReadReqHeader() (err error) {
	buf := pool.Get(18)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		_ = c.Conn.Close()
		return fmt.Errorf("version %v is not supprted", buf[0])
	}
	if subtle.ConstantTimeCompare(c.cmdKey[:16], buf[1:17]) != 1 {
		_ = c.Conn.Close()
		return FailAuthErr
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(buf[17])); err != nil { // ignore addons
		return err
	}
	buf = pool.Get(4)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if err = CompleteMetadataFromReader(&c.metadata, buf, c.Conn); err != nil {
		return err
	}
	return nil
}

func (c *Conn) ReadRespHeader() (err error) {
	buf := pool.Get(2)
	defer pool.Put(buf)
	if _, err = io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	if buf[0] != 0 {
		_ = c.Conn.Close()
		return fmt.Errorf("version %v is not supprted", buf[0])
	}
	if _, err = io.CopyN(io.Discard, c.Conn, int64(buf[1])); err != nil {
		return err
	}
	return nil
}
