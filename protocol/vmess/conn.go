package vmess

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
)

var resolveUDPAddr = net.ResolveUDPAddr

const (
	MaxChunkSize = 1 << 14
	// MaxUDPSize is retained for API compatibility. It is NOT a read-path cap:
	// staging UDP reads through a buffer of this size silently dropped every
	// datagram larger than 2048 bytes regardless of the caller's capacity.
	// ReadFrom now reads into the caller's buffer instead.
	MaxUDPSize = 1 << 11

	maxReusableSealFrameSize = 128 << 10
)

type Conn struct {
	netproxy.Conn
	initRead        sync.Once
	initWrite       sync.Once
	metadata        Metadata
	cmdKey          []byte
	dialTgt         string
	dialTgtAddrPort netip.AddrPort // lazy resolve
	dialTgtMu       sync.Mutex
	writeCache      common.LastStringValue[netip.AddrPort]

	NewAEAD func(key []byte) (cipher.AEAD, error)

	writeMutex            sync.Mutex
	writeBodyCipher       cipher.AEAD
	writeNonceGenerator   BytesGenerator
	writeChunkSizeParser  ChunkSizeEncoder
	writePaddingGenerator PaddingLengthGenerator
	writeInitErr          error

	readBodyCipher       cipher.AEAD
	readNonceGenerator   BytesGenerator
	readChunkSizeParser  ChunkSizeDecoder
	readPaddingGenerator PaddingLengthGenerator

	requestBodyKey [16]byte
	requestBodyIV  [16]byte
	requestOptions byte

	responseBodyKey [16]byte
	responseBodyIV  [16]byte
	responseAuth    byte

	readMutex     sync.Mutex
	leftToRead    []byte
	indexToRead   int
	readSizeBuf   [2]byte
	readOpenFrame []byte

	writeSealFrame []byte
	writeClosed    bool
}

func NewConn(conn netproxy.Conn, metadata Metadata, dialTgt string, cmdKey []byte) (c *Conn, err error) {
	// DO NOT use pool here because Close() cannot interrupt the reading or writing, which will modify the value of the pool buffer.
	key := make([]byte, len(cmdKey))
	copy(key, cmdKey)
	c = &Conn{
		Conn:     conn,
		metadata: metadata,
		cmdKey:   key,
		dialTgt:  dialTgt,
	}
	if metadata.IsClient {
		if err = c.WriteReqHeader(); err != nil {
			// NewConn owns conn from here on; close it on every failure or
			// the dialed underlay leaks.
			_ = c.Conn.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *Conn) CloseWrite() error {
	if c.metadata.Network == "udp" || c.metadata.IsPacketAddr() {
		return nil
	}
	_, err := c.write(nil)
	return err
}

func (c *Conn) Close() error {
	err := c.Conn.Close()

	c.readMutex.Lock()
	c.leftToRead = nil
	c.indexToRead = 0
	c.readOpenFrame = nil
	c.readMutex.Unlock()

	c.writeMutex.Lock()
	c.writeSealFrame = nil
	c.writeMutex.Unlock()
	return err
}

// WriteDeadlineClosesSession implements netproxy.WriteDeadlineBehavior by
// forwarding the declaration of the wrapped stream conn: SetWriteDeadline is
// delegated to the underlying netproxy.Conn unchanged, so the semantics —
// and the declaration — belong to that conn (vmess UDP rides ReadFrom/Write
// on this conn).
func (c *Conn) WriteDeadlineClosesSession() bool {
	return netproxy.WriteDeadlineClosesSession(c.Conn)
}

func (c *Conn) dialTargetAddrPort() (netip.AddrPort, error) {
	c.dialTgtMu.Lock()
	defer c.dialTgtMu.Unlock()

	if c.dialTgtAddrPort.IsValid() {
		return c.dialTgtAddrPort, nil
	}

	tgt, err := resolveUDPAddr("udp", c.dialTgt)
	if err != nil {
		return netip.AddrPort{}, err
	}
	c.dialTgtAddrPort = unmapAddrPort(tgt.AddrPort())
	return c.dialTgtAddrPort, nil
}

// unmapAddrPort normalizes the v4-in-v6 form net.ResolveUDPAddr yields for
// literal IPv4 targets (its net.IP keeps the 16-byte ::ffff: representation
// and UDPAddr.AddrPort does not unmap it). Without this, the fixed-target
// ReadFrom reports datagram sources as [::ffff:a.b.c.d]:p instead of the
// canonical a.b.c.d:p, and packet-addr writes would encode IPv4 targets with
// the IPv6 address type. Unmap is the identity for IPv6 and clean IPv4
// addresses, so only the mapped form changes.
func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (c *Conn) chunks(size int) (payloadSize int, numChunks int) {
	payloadSize = MaxChunkSize - c.writeBodyCipher.Overhead() - int(c.writeChunkSizeParser.SizeBytes()) - int(c.writePaddingGenerator.MaxPaddingLen())
	if size%payloadSize == 0 {
		return payloadSize, size / payloadSize
	}
	return payloadSize, size/payloadSize + 1
}

func GenerateChunkNonce(nonce []byte, size uint32) BytesGenerator {
	c := make([]byte, size)
	copy(c[2:], nonce[2:])
	count := uint16(0)
	return func() []byte {
		binary.BigEndian.PutUint16(c, count)
		count++
		return c[:size]
	}
}

// initChunkCodecs derives the chunk-stream codec state shared by every
// connection direction: the size parser selected by the negotiated options
// (shake-masked under OptionChunkLengthMasking, plain otherwise), the padding
// generator (the shake parser under OptionGlobalPadding, plain otherwise),
// and the nonce generator seeded from the direction IV. The returned encoder
// and decoder are the same parser instance, so the caller keeps only the one
// its direction needs; each call yields fresh stateful parsers.
func initChunkCodecs(options byte, iv []byte, nonceSize int) (sizeEncoder ChunkSizeEncoder, sizeDecoder ChunkSizeDecoder, paddingGen PaddingLengthGenerator, nonceGen BytesGenerator) {
	if ContainOption(options, OptionChunkLengthMasking) {
		sizeParser := NewShakeSizeParser(iv)
		sizeEncoder = sizeParser
		sizeDecoder = sizeParser
		if ContainOption(options, OptionGlobalPadding) {
			paddingGen = sizeParser
		}
	} else {
		sizeEncoder = PlainChunkSizeParser{}
		sizeDecoder = PlainChunkSizeParser{}
	}
	if paddingGen == nil {
		paddingGen = PlainPaddingGenerator{}
	}
	nonceGen = GenerateChunkNonce(iv, uint32(nonceSize))
	return
}

// seal packs the b. The overhead is sizeParser.SizeBytes() + auth.Overhead() + paddingSize(no more than maxPadding).
func (c *Conn) sealFromPool(b []byte) (data []byte) {
	sizeSize := c.writeChunkSizeParser.SizeBytes()
	encryptedSize := int32(len(b) + c.writeBodyCipher.Overhead())
	paddingSize := int32(c.writePaddingGenerator.NextPaddingLen())
	totalSize := int(sizeSize + encryptedSize + paddingSize)

	if totalSize <= maxReusableSealFrameSize {
		if cap(c.writeSealFrame) < totalSize {
			c.writeSealFrame = make([]byte, totalSize)
		}
		data = c.writeSealFrame[:totalSize]
	} else {
		data = make([]byte, totalSize)
	}
	c.writeChunkSizeParser.Encode(uint16(encryptedSize+paddingSize), data)

	c.writeBodyCipher.Seal(data[sizeSize:sizeSize], c.writeNonceGenerator(), b, nil)
	_, _ = fastrand.Read(data[len(data)-int(paddingSize):])
	//log.Warn("write: size: %v, padding: %v", encryptedSize+paddingSize, paddingSize)
	return data
}

func (c *Conn) writeStream(b []byte, preWrite []byte) (n int, err error) {
	payloadSize, numChunks := c.chunks(len(b))
	var start = 0
	if preWrite != nil {
		start++
		data := c.sealFromPool(b[n:common.Min(n+payloadSize, len(b))])
		if _, err = iout.MultiWrite(c.Conn, preWrite, data); err != nil {
			return 0, err
		}
		n += payloadSize
	}
	for i := start; i < numChunks; i++ {
		data := c.sealFromPool(b[n:common.Min(n+payloadSize, len(b))])
		if _, err = c.Conn.Write(data); err != nil {
			return n, err
		}
		n += payloadSize
	}
	if n > len(b) {
		n = len(b)
	}
	return n, nil
}

func (c *Conn) writePacket(b []byte, preWrite []byte) (n int, err error) {
	// The two-byte chunk length field written in sealFromPool covers
	// len(b) + AEAD overhead + padding. A near-limit datagram (a jumbo one,
	// or a smaller one whose packetaddr prefix is already counted into b)
	// would wrap the uint16 and emit a bogus frame length that desyncs the
	// stream instead of failing the write; reject it up front, mirroring the
	// mux path's guard for the same field.
	if int64(len(b))+int64(c.writeBodyCipher.Overhead())+int64(c.writePaddingGenerator.MaxPaddingLen()) > 0xFFFF {
		// This one datagram cannot be serialized into the 16-bit chunk
		// length field, but the session itself stays usable. The typed
		// datagram-dropped contract (with io.ErrShortBuffer as the cause
		// for legacy errors.Is consumers) tells the endpoint to drop the
		// datagram and keep the session; an untyped error reads as a
		// session failure and retires the endpoint.
		return 0, fmt.Errorf("vmess: udp datagram of %d bytes exceeds the 16-bit chunk length field: %w",
			len(b), netproxy.DatagramDropped(io.ErrShortBuffer))
	}
	data := c.sealFromPool(b)
	if preWrite != nil {
		if _, err = iout.MultiWrite(c.Conn, preWrite, data); err != nil {
			return 0, err
		}
	} else {
		if _, err = c.Conn.Write(data); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// vmessInstructionDataFixedLen is the number of bytes InitContext reads from a
// request instruction block: 1 version byte + 16 IV + 16 key + 1 options byte
// + 1 security byte + 1 reserved byte, with the last fixed byte at index 35.
// The variable-length address, its padding and the trailing FNV1a checksum
// follow it.
const vmessInstructionDataFixedLen = 36

func (c *Conn) InitContext(instructionData []byte) error {
	// This path is reached from the server side with peer-supplied bytes, so
	// the length must be validated before any fixed offset is read: the
	// indexes below (up to 35) would otherwise panic on a short block, turning
	// a malformed request into a denial of service against the process.
	if len(instructionData) < vmessInstructionDataFixedLen {
		return fmt.Errorf("vmess: instruction data too short: %d bytes, need at least %d",
			len(instructionData), vmessInstructionDataFixedLen)
	}
	c.responseAuth = instructionData[33]
	copy(c.requestBodyIV[:], instructionData[1:])
	copy(c.requestBodyKey[:], instructionData[17:])
	tmp := sha256.Sum256(c.requestBodyIV[:])
	copy(c.responseBodyIV[:], tmp[:16])
	tmp = sha256.Sum256(c.requestBodyKey[:])
	copy(c.responseBodyKey[:], tmp[:16])
	if c.metadata.Cipher == "" {
		ciph, err := ParseCipherFromSecurity(instructionData[35] & 0xf)
		if err != nil {
			return err
		}
		c.metadata.Cipher = string(ciph)
	}
	newAEAD, ok := NewCipherMapper[Cipher(c.metadata.Cipher)]
	if !ok {
		return fmt.Errorf("unexpected cipher: %v", c.metadata.Cipher)
	}
	c.NewAEAD = newAEAD
	c.requestOptions = instructionData[34]
	return nil
}

func (c *Conn) WriteReqHeader() (err error) {
	c.initWrite.Do(func() {
		instructionData := ReqInstructionDataFromPool(c.metadata)
		defer pool.Put(instructionData)

		if err = c.InitContext(instructionData); err != nil {
			return
		}

		var header []byte
		if header, err = EncryptReqHeaderFromPool(instructionData, c.cmdKey); err != nil {
			return
		}
		defer pool.Put(header)
		if c.writeBodyCipher, err = c.NewAEAD(c.requestBodyKey[:]); err != nil {
			return
		}

		c.writeChunkSizeParser, _, c.writePaddingGenerator, c.writeNonceGenerator = initChunkCodecs(c.requestOptions, c.requestBodyIV[:], c.writeBodyCipher.NonceSize())
		_, err = c.Conn.Write(header)
	})
	return err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		tgt, err := c.dialTargetAddrPort()
		if err != nil {
			return 0, err
		}
		return c.WriteTo(b, tgt.String())
	} else {
		return c.write(b)
	}
}

// initWriteOnce performs the lazy first-write initialization (the server's
// encrypted response header plus the body cipher state). It returns the
// encrypted response header when one was produced; callers must release it
// with pool.Put. Callers must hold writeMutex.
func (c *Conn) initWriteOnce() (encRespHeader []byte, err error) {
	c.initWrite.Do(func() {
		if !c.metadata.IsClient {
			header := RespHeaderFromPool(c.responseAuth)
			defer pool.Put(header)
			encRespHeader, err = c.EncryptRespHeaderFromPool(header)
			if err != nil {
				c.writeInitErr = err
				return
			}
			if c.writeBodyCipher, err = c.NewAEAD(c.responseBodyKey[:]); err != nil {
				c.writeInitErr = err
				return
			}
			c.writeChunkSizeParser, _, c.writePaddingGenerator, c.writeNonceGenerator = initChunkCodecs(c.requestOptions, c.responseBodyIV[:], c.writeBodyCipher.NonceSize())
		}
	})
	if err == nil {
		// The once has already run: a failed init must surface on every
		// call, or later writes proceed with nil cipher state and panic.
		err = c.writeInitErr
	}
	if err != nil && encRespHeader != nil {
		// The caller returns on the error without adopting the header;
		// release the pool buffer here so it cannot leak.
		pool.Put(encRespHeader)
		encRespHeader = nil
	}
	return encRespHeader, err
}

// Writes data to the connection. Empty b should be written before closing the connection to indicate the terminal.
func (c *Conn) write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	encRespHeader, err := c.initWriteOnce()
	if err != nil {
		return 0, err
	}
	if len(encRespHeader) != 0 {
		defer pool.Put(encRespHeader)
	}
	if len(b) == 0 {
		c.writeClosed = true
		data := c.sealFromPool(nil)
		_, err = c.Conn.Write(data)
		return 0, err
	}
	//log.Trace("vmess: write len(b)=%v", len(b))
	switch c.metadata.Network {
	case "tcp":
		return c.writeStream(b, encRespHeader)
	case "udp":
		return c.writePacket(b, encRespHeader)
	default:
		return 0, fmt.Errorf("unsupported network (instruction cmd): %v", c.metadata.Network)
	}
}

// writePackets seals several UDP datagrams, each as its own AEAD chunk
// (nonce and padding are drawn per chunk), and pushes everything with a
// single underlying write. datas entries are the plaintext of one datagram
// each; entries in release are pool buffers returned on the way out.
func (c *Conn) writePackets(datas [][]byte, release []pool.PB) (n int, err error) {
	defer func() {
		for _, b := range release {
			pool.Put(b)
		}
	}()
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	encRespHeader, err := c.initWriteOnce()
	if err != nil {
		return 0, err
	}
	if len(encRespHeader) != 0 {
		defer pool.Put(encRespHeader)
	}
	sizeSize := int(c.writeChunkSizeParser.SizeBytes())
	overhead := c.writeBodyCipher.Overhead()
	maxPadding := int(c.writePaddingGenerator.MaxPaddingLen())
	total := len(encRespHeader)
	for _, d := range datas {
		if sizeSize+len(d)+overhead+maxPadding > 0xffff {
			// The chunk size parser encodes uint16 only; a larger datagram
			// would silently wrap and corrupt the stream.
			return 0, fmt.Errorf("vmess udp chunk too large: %d", len(d))
		}
		total += sizeSize + len(d) + overhead + maxPadding
	}
	buf := pool.Get(total)
	defer pool.Put(buf)
	offset := copy(buf, encRespHeader)
	for _, d := range datas {
		encryptedSize := len(d) + overhead
		paddingSize := int(c.writePaddingGenerator.NextPaddingLen())
		totalSize := sizeSize + encryptedSize + paddingSize
		chunk := buf[offset : offset+totalSize]
		c.writeChunkSizeParser.Encode(uint16(encryptedSize+paddingSize), chunk)
		c.writeBodyCipher.Seal(chunk[sizeSize:sizeSize], c.writeNonceGenerator(), d, nil)
		_, _ = fastrand.Read(chunk[len(chunk)-paddingSize:])
		offset += totalSize
	}
	if _, err = c.Conn.Write(buf[:offset]); err != nil {
		// One stream write carries every chunk; a failure cannot be split
		// per datagram, so report none instead of guessing.
		return 0, err
	}
	return len(datas), nil
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		n, _, err = c.ReadFrom(b)
		return n, err
	}
	if c.metadata.Network == "udp" {
		n, _, err = c.ReadFrom(b)
		return n, err
	}
	return c.read(b)
}

func (c *Conn) read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	c.initRead.Do(func() {
		if c.metadata.IsClient {
			bufSize := pool.Get(18) // 2+16
			defer pool.Put(bufSize)
			if _, err = io.ReadFull(c.Conn, bufSize); err != nil {
				err = fmt.Errorf("failed to read response header length: %w", err)
				return
			}
			var ciph cipher.AEAD
			if ciph, err = NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderLenKey))[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(bufSize[:0], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], bufSize, nil); err != nil {
				err = fmt.Errorf("failed to decrypt response header length: %w", err)
				return
			}
			headerSize := binary.BigEndian.Uint16(bufSize[:2])
			buf := pool.Get(int(headerSize) + 16)
			defer pool.Put(buf)
			if _, err = io.ReadFull(c.Conn, buf); err != nil {
				err = fmt.Errorf("failed to read response header: %w", err)
				return
			}
			if ciph, err = NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderPayloadKey))[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(buf[:0], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderPayloadIV))[:12], buf, nil); err != nil {
				err = fmt.Errorf("failed to decrypt response header: %w", err)
				return
			}
			if buf[0] != c.responseAuth {
				err = fmt.Errorf("unexpected response auth: %v, expect %v", buf[0], c.responseAuth)
				return
			}
			respCmd := buf[2]
			if respCmd != 0 {
				err = fmt.Errorf("unexpected response command: %v", respCmd)
				return
			}
			if c.readBodyCipher, err = c.NewAEAD(c.responseBodyKey[:]); err != nil {
				return
			}

			_, c.readChunkSizeParser, c.readPaddingGenerator, c.readNonceGenerator = initChunkCodecs(c.requestOptions, c.responseBodyIV[:], c.readBodyCipher.NonceSize())
		} else {
			// assume that EAuthID has been read
			buf := pool.Get(26) // len(2) + tag(16) + connection_nonce(8)
			defer pool.Put(buf)
			if _, err = io.ReadFull(c.Conn, buf); err != nil {
				err = fmt.Errorf("failed to read ALength and ConnectionNonce: %w", err)
				return
			}
			connectionNonce := buf[18:26]
			c.cmdKey = c.metadata.authedCmdKey[:]
			var ciph cipher.AEAD
			if ciph, err = NewAesGcm(KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADKey), c.metadata.authedEAuthID[:], connectionNonce)[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(buf[:0], KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadLengthAEADIV), c.metadata.authedEAuthID[:], connectionNonce)[:12], buf[:18], c.metadata.authedEAuthID[:]); err != nil {
				err = fmt.Errorf("failed to decrypt request header length: %w", err)
				return
			}
			lenInstruction := binary.BigEndian.Uint16(buf)

			instructionData := pool.Get(int(lenInstruction) + 16)
			defer pool.Put(instructionData)
			if _, err = io.ReadFull(c.Conn, instructionData); err != nil {
				err = fmt.Errorf("failed to read instruction data: %w", err)
				return
			}
			if ciph, err = NewAesGcm(KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADKey), c.metadata.authedEAuthID[:], connectionNonce)[:16]); err != nil {
				return
			}
			if _, err = ciph.Open(instructionData[:0], KDF(c.cmdKey, []byte(KDFSaltConstVMessHeaderPayloadAEADIV), c.metadata.authedEAuthID[:], connectionNonce)[:12], instructionData, c.metadata.authedEAuthID[:]); err != nil {
				err = fmt.Errorf("failed to decrypt request header: %w", err)
				return
			}
			if err = c.InitContext(instructionData[:lenInstruction]); err != nil {
				return
			}
			if err = c.metadata.CompleteFromInstructionData(instructionData[:lenInstruction]); err != nil {
				return
			}
			c.dialTgt = net.JoinHostPort(c.metadata.Hostname, strconv.Itoa(int(c.metadata.Port)))

			if c.readBodyCipher, err = c.NewAEAD(c.requestBodyKey[:]); err != nil {
				return
			}
			_, c.readChunkSizeParser, c.readPaddingGenerator, c.readNonceGenerator = initChunkCodecs(c.requestOptions, c.requestBodyIV[:], c.readBodyCipher.NonceSize())
		}
	})
	if err != nil {
		return 0, err
	}
	if b == nil {
		return 0, nil
	}
	if c.readNonceGenerator == nil {
		// did not initiate successfully
		return 0, net.ErrClosed
	}

	// dump unread data
	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		if c.metadata.Network == "udp" {
			c.leftToRead = nil
			c.indexToRead = 0
			return 0, netproxy.DatagramDropped(io.ErrShortBuffer)
		}
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
		if c.metadata.Network == "udp" {
			// Do not deliver a truncated datagram; dae treats the
			// datagram-dropped contract (and its io.ErrShortBuffer cause)
			// as a per-datagram event without retiring the UDP endpoint.
			c.leftToRead = nil
			c.indexToRead = 0
			return 0, netproxy.DatagramDropped(io.ErrShortBuffer)
		}
		c.leftToRead = chunk
		c.indexToRead = n
	}
	return n, nil
}

func (c *Conn) Metadata() Metadata {
	return c.metadata
}

// readSize reads the size and padding from Conn. size=encryptedSize+padding
func (c *Conn) readSize() (size uint16, padding uint16, err error) {
	// SizeBytes is always 2 (ShakeSizeParser/PlainChunkSizeParser). Keep the
	// scratch on Conn so passing it through the reader interface cannot make a
	// fresh stack array escape on every chunk.
	if _, err := io.ReadFull(c.Conn, c.readSizeBuf[:]); err != nil {
		return 0, 0, err
	}
	padding = c.readPaddingGenerator.NextPaddingLen()
	size, err = c.readChunkSizeParser.Decode(c.readSizeBuf[:])
	if err != nil {
		return size, padding, err
	}
	//log.Warn("read: size: %v, padding: %v", size, padding)
	return size, padding, nil
}

func (c *Conn) borrowReadOpenFrame(size int) []byte {
	if cap(c.readOpenFrame) < size {
		c.readOpenFrame = make([]byte, size)
	}
	return c.readOpenFrame[:size]
}

func (c *Conn) readChunk() ([]byte, error) {
	size, padding, err := c.readSize()
	if err != nil {
		return nil, err
	}
	// terminal signal
	if size == uint16(c.readBodyCipher.Overhead())+padding {
		return nil, io.EOF
	}
	// The unmasked size is server-controlled while the padding is negotiated
	// locally; a chunk smaller than its own padding would slice negatively
	// below, so reject the frame instead of panicking.
	if int(size) < int(padding) {
		return nil, fmt.Errorf("vmess: chunk size %d is smaller than its padding %d", size, padding)
	}
	frame := c.borrowReadOpenFrame(int(size))
	if _, err = io.ReadFull(c.Conn, frame); err != nil {
		return nil, err
	}
	return c.readBodyCipher.Open(frame[:0], c.readNonceGenerator(), frame[:len(frame)-int(padding)], nil)
}

func (c *Conn) EncryptRespHeaderFromPool(header []byte) (b []byte, err error) {
	buf := pool.Get(34 + len(header)) // length(2) + tag(16) + len(header) + tag(16)

	ciph, err := NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderLenKey))[:16])
	if err != nil {
		pool.Put(buf)
		return
	}
	binary.BigEndian.PutUint16(buf, uint16(len(header)))
	ciph.Seal(buf[:0], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderLenIV))[:12], buf[:2], nil)

	ciph, err = NewAesGcm(KDF(c.responseBodyKey[:], []byte(KDFSaltConstAEADRespHeaderPayloadKey))[:16])
	if err != nil {
		pool.Put(buf)
		return
	}
	ciph.Seal(buf[18:18], KDF(c.responseBodyIV[:], []byte(KDFSaltConstAEADRespHeaderPayloadIV))[:12], header, nil)

	return buf, nil
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
