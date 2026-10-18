package shadowsocks

import (
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"golang.org/x/crypto/hkdf"
)

const (
	TCPChunkMaxLen = (1 << (16 - 2)) - 1
	// Cap matches ss2022/vmess: keep a per-conn write frame for the common
	// AEAD chunk sizes so steady-state Write does not pool.Get every call.
	// EncryptedPayloadLen(64KiB) overflows pool's 64KiB bucket; reuse avoids
	// that cliff without changing chunk semantics.
	maxReusableWriteFrameSize = 128 << 10
)

var (
	ErrFailInitCipher     = fmt.Errorf("fail to initiate cipher")
	ShadowsocksReusedInfo = []byte("ss-subkey")

	fnv32aPool = sync.Pool{New: func() any { return fnv.New32a() }}
	fnv32Pool  = sync.Pool{New: func() any { return fnv.New32() }}
)

type TCPConn struct {
	netproxy.Conn
	metadata   protocol.Metadata
	cipherConf *ciphers.CipherConf
	masterKey  []byte

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	writeBroken bool
	nonceRead   []byte
	nonceWrite  []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	leftToRead    []byte
	indexToRead   int
	readLengthBuf []byte
	readCipherBuf []byte

	writeFrame []byte

	bloom *disk_bloom.FilterGroup
	sg    *RandomSaltGenerator
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
}

func EncryptedPayloadLen(plainTextLen int, tagLen int) int {
	n := plainTextLen / TCPChunkMaxLen
	if plainTextLen%TCPChunkMaxLen > 0 {
		n++
	}
	return plainTextLen + n*(2+tagLen+tagLen)
}

func NewTCPConn(conn netproxy.Conn, metadata protocol.Metadata, masterKey []byte, bloom *disk_bloom.FilterGroup) (crw *TCPConn, err error) {
	conf := ciphers.AeadCiphersConf[metadata.Cipher]
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	sg := NewRandomSaltGenerator(conf.SaltLen)
	// Keep the key connection-owned because both directions use it for the
	// lifetime of the stream.
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	state := make([]byte, 2*conf.NonceLen+2+conf.TagLen)
	nonceWriteOffset := conf.NonceLen
	readLengthOffset := 2 * conf.NonceLen
	c := TCPConn{
		Conn:          conn,
		metadata:      metadata,
		cipherConf:    conf,
		masterKey:     key,
		nonceRead:     state[:nonceWriteOffset],
		nonceWrite:    state[nonceWriteOffset:readLengthOffset],
		readLengthBuf: state[readLengthOffset:],
		bloom:         bloom,
		sg:            sg,
	}
	if metadata.IsClient {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first.
			// Use a local error: capturing the named return here would race
			// with the caller's frame after NewTCPConn returns.
			if _, werr := c.Write(nil); werr != nil {
				return
			}
		})
	}
	return &c, nil
}

func (c *TCPConn) CloseWrite() error {
	return netproxy.ForwardCloseWrite(c.Conn)
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped conn. Embedding the conn interface
// promotes SetWriteDeadline but not this optional method, so without the
// forward a session-closing inner conn (TUIC, hysteria2) would be invisible to
// deadline-arming callers and they would arm a destructive timer believing it
// was an ordinary write deadline.
func (c *TCPConn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *TCPConn) Close() error {
	err := c.Conn.Close()

	c.readMutex.Lock()
	c.leftToRead = nil
	c.indexToRead = 0
	c.readLengthBuf = nil
	c.readCipherBuf = nil
	c.readMutex.Unlock()

	c.writeMutex.Lock()
	c.writeFrame = nil
	c.writeMutex.Unlock()
	return err
}

func (c *TCPConn) borrowWriteFrame(size int) []byte {
	if size <= maxReusableWriteFrameSize {
		if cap(c.writeFrame) < size {
			c.writeFrame = make([]byte, size)
		}
		return c.writeFrame[:size]
	}
	return make([]byte, size)
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if !c.onceRead {
		var salt = pool.Get(c.cipherConf.SaltLen)
		defer pool.Put(salt)
		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return
		}
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				err = protocol.ErrReplayAttack
				return
			}
		}
		subKey := getSubKey(c.cipherConf.KeyLen)
		defer putSubKey(subKey)
		kdf := hkdf.New(
			sha1.New,
			c.masterKey,
			salt,
			ShadowsocksReusedInfo,
		)
		_, err = io.ReadFull(kdf, subKey)
		if err != nil {
			return
		}
		c.cipherRead, err = c.cipherConf.NewCipher(subKey)
		if err != nil {
			return 0, fmt.Errorf("%v: %w", ErrFailInitCipher, err)
		}
		c.onceRead = true
	}
	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			c.leftToRead = nil
			c.indexToRead = 0
		}
		return n, nil
	}
	chunk, err := c.readChunk()
	if err != nil {
		return 0, err
	}
	n = copy(b, chunk)
	if n < len(chunk) {
		c.leftToRead = chunk
		c.indexToRead = n
	}
	return n, nil
}

func (c *TCPConn) borrowReadLengthFrame() []byte {
	size := 2 + c.cipherConf.TagLen
	if cap(c.readLengthBuf) < size {
		c.readLengthBuf = make([]byte, size)
	}
	return c.readLengthBuf[:size]
}

func (c *TCPConn) borrowReadCipherFrame(size int) []byte {
	if cap(c.readCipherBuf) < size {
		c.readCipherBuf = make([]byte, size)
	}
	return c.readCipherBuf[:size]
}

func (c *TCPConn) readChunk() ([]byte, error) {
	lengthFrame := c.borrowReadLengthFrame()
	if _, err := io.ReadFull(c.Conn, lengthFrame); err != nil {
		return nil, err
	}
	length, err := c.cipherRead.Open(lengthFrame[:0], c.nonceRead, lengthFrame, nil)
	if err != nil {
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)

	payloadSize := int(binary.BigEndian.Uint16(length)) + c.cipherConf.TagLen
	cipherFrame := c.borrowReadCipherFrame(payloadSize)
	if _, err := io.ReadFull(c.Conn, cipherFrame); err != nil {
		return nil, err
	}
	payload, err := c.cipherRead.Open(cipherFrame[:0], c.nonceRead, cipherFrame, nil)
	if err != nil {
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	return payload, nil
}

func (c *TCPConn) initWriteFromPool(b []byte) (buf []byte, offset int, toWrite []byte, err error) {
	var mdata = Metadata{
		Metadata: c.metadata,
	}
	var prefix, suffix []byte
	if c.metadata.Type == protocol.MetadataTypeMsg {
		mdata.LenMsgBody = uint32(len(b))
		suffix = pool.Get(CalcPaddingLen(c.masterKey, b, c.metadata.IsClient))
		defer pool.Put(suffix)
	}
	if c.metadata.IsClient || c.metadata.Type == protocol.MetadataTypeMsg {
		prefix, err = mdata.BytesFromPool()
		if err != nil {
			return nil, 0, nil, err
		}
		defer pool.Put(prefix)
	}
	toWrite = pool.Get(len(prefix) + len(b) + len(suffix))
	copy(toWrite, prefix)
	copy(toWrite[len(prefix):], b)
	copy(toWrite[len(prefix)+len(b):], suffix)

	buf = pool.Get(c.cipherConf.SaltLen + EncryptedPayloadLen(len(toWrite), c.cipherConf.TagLen))
	salt := c.sg.Get()
	copy(buf, salt)
	pool.Put(salt)
	subKey := getSubKey(c.cipherConf.KeyLen)
	defer putSubKey(subKey)
	kdf := hkdf.New(
		sha1.New,
		c.masterKey,
		buf[:c.cipherConf.SaltLen],
		ShadowsocksReusedInfo,
	)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		pool.Put(buf)
		pool.Put(toWrite)
		return nil, 0, nil, err
	}
	c.cipherWrite, err = c.cipherConf.NewCipher(subKey)
	if err != nil {
		pool.Put(buf)
		pool.Put(toWrite)
		return nil, 0, nil, err
	}
	offset += c.cipherConf.SaltLen
	if c.bloom != nil {
		c.bloom.ExistOrAdd(buf[:c.cipherConf.SaltLen])
	}
	return buf, offset, toWrite, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeBroken {
		return 0, net.ErrClosed
	}
	var buf []byte
	var toPack []byte
	var offset int
	firstWrite := !c.onceWrite
	if firstWrite {
		buf, offset, toPack, err = c.initWriteFromPool(b)
		if err != nil {
			return 0, err
		}
		defer pool.Put(toPack)
	}
	if buf == nil {
		buf = c.borrowWriteFrame(EncryptedPayloadLen(len(b), c.cipherConf.TagLen))
		toPack = b
	} else {
		defer pool.Put(buf)
	}
	if c.cipherWrite == nil {
		return 0, ErrFailInitCipher
	}
	sealed := c.seal(buf[offset:], toPack)
	if _, err = iout.WriteFull(c.Conn, buf[:offset+len(sealed)]); err != nil {
		c.writeBroken = true
		return 0, err
	}
	if firstWrite {
		c.onceWrite = true
	}
	return len(b), nil
}

func (c *TCPConn) seal(buf []byte, b []byte) []byte {
	offset := 0
	for i := 0; i < len(b); i += TCPChunkMaxLen {
		// write chunk
		var l = common.Min(TCPChunkMaxLen, len(b)-i)
		binary.BigEndian.PutUint16(buf[offset:], uint16(l))
		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, buf[offset:offset+2], nil)
		offset += 2 + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, b[i:i+l], nil)
		offset += l + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)
	}
	return buf[:offset]
}

func (c *TCPConn) ReadMetadata() (metadata Metadata, err error) {
	var firstTwoBytes = pool.Get(2)
	defer pool.Put(firstTwoBytes)
	if _, err = io.ReadFull(c, firstTwoBytes); err != nil {
		return Metadata{}, err
	}
	n, err := BytesSizeForMetadata(firstTwoBytes)
	if err != nil {
		return Metadata{}, err
	}
	var bytesMetadata = pool.Get(n)
	defer pool.Put(bytesMetadata)
	copy(bytesMetadata, firstTwoBytes)
	_, err = io.ReadFull(c, bytesMetadata[2:])
	if err != nil {
		return Metadata{}, err
	}
	mdata, err := NewMetadata(bytesMetadata)
	if err != nil {
		return Metadata{}, err
	}
	metadata = *mdata
	// complete metadata
	if !c.metadata.IsClient {
		c.metadata.Type = metadata.Type
		c.metadata.Hostname = metadata.Hostname
		c.metadata.Port = metadata.Port
		c.metadata.IP = metadata.IP
		if metadata.Type == protocol.MetadataTypeMsg {
			c.metadata.Cmd = protocol.MetadataCmdResponse
		} else {
			c.metadata.Cmd = metadata.Cmd
		}
	}
	return metadata, nil
}

func CalcPaddingLen(masterKey []byte, bodyWithoutAddr []byte, req bool) (length int) {
	maxPadding := common.Max(int(10*float64(len(bodyWithoutAddr))/(1+math.Log(float64(len(bodyWithoutAddr)))))-len(bodyWithoutAddr), 0)
	if maxPadding == 0 {
		return 0
	}
	var h hash.Hash32
	if req {
		h = fnv32aPool.Get().(hash.Hash32)
		defer fnv32aPool.Put(h)
	} else {
		h = fnv32Pool.Get().(hash.Hash32)
		defer fnv32Pool.Put(h)
	}
	h.Reset()
	h.Write(masterKey)
	h.Write(bodyWithoutAddr)
	return int(h.Sum32()) % maxPadding
}
