package anytls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/common/iout"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

const (
	sessionStateActive uint32 = iota + 1
	sessionStateIdle
	sessionStateClosing
	sessionStateClosed
)

type readBufferReleaser interface {
	ReleaseReader()
}

type session struct {
	conn     net.Conn
	connLock sync.Mutex
	probeMu  sync.Mutex

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	padding     *atomic.Pointer[paddingFactory]
	sendPadding bool
	pktCounter  atomic.Uint32

	seq           uint64
	sid           atomic.Uint32
	state         atomic.Uint32
	activeStreams atomic.Int32
	idleAt        atomic.Int64
	closed        atomic.Bool
	done          chan struct{}

	closeStreamChan chan uint32
	heartResponseCh chan struct{}

	// writeBuf is a session-owned encode buffer used under connLock. Frames
	// stay within maxFramePayloadSize, so this avoids pool.Get/Put per write
	// without overflowing the pool cliff.
	writeBuf []byte

	// flusher drains the TLS record coalescing layer after each framed write
	// burst. Nil when the transport writes through directly (tests, non-TLS).
	flusher flusher
}

type flusher interface{ Flush() error }

func newSession(conn net.Conn, seq uint64) *session {
	padding := &atomic.Pointer[paddingFactory]{}
	padding.Store(DefaultPaddingFactory.Load())
	return newSessionWithPadding(conn, seq, padding)
}

func newSessionWithPadding(conn net.Conn, seq uint64, padding *atomic.Pointer[paddingFactory]) *session {
	s := &session{
		conn:            conn,
		streams:         map[uint32]*stream{},
		padding:         padding,
		seq:             seq,
		done:            make(chan struct{}),
		closeStreamChan: make(chan uint32, 2),
		heartResponseCh: make(chan struct{}, 1),
		sendPadding:     true,
	}
	s.state.Store(sessionStateActive)
	return s
}

func (s *session) newStream(addr string) (*stream, error) {
	if s.Closed() {
		return nil, net.ErrClosed
	}
	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}

	sid := s.sid.Add(1)
	stream := newStream(s, sid)
	if err := s.addStream(stream); err != nil {
		return nil, err
	}
	created := false
	defer func() {
		if !created {
			_ = stream.closeLocal(false, net.ErrClosed)
		}
	}()

	settings := newFrame(cmdSettings, 0)
	settings.data = settingsBytes(s.GetPadding())
	syn := newFrame(cmdSYN, sid)
	initialData := newFrame(cmdPSH, sid)
	initialData.data = tgtAddr

	if sid == 1 {
		if _, err := writeFrames(s, settings, syn, initialData); err != nil {
			return nil, err
		}
	} else {
		if _, err := writeFrame(s, syn); err != nil {
			return nil, err
		}
		if _, err := writeFrame(s, initialData); err != nil {
			return nil, err
		}
	}

	created = true
	return stream, nil
}

func (s *session) newPacketStream(addr, packetAddr string) (*packetStream, error) {
	stream, err := s.newStream(addr)
	if err != nil {
		return nil, err
	}
	// Lenient like the previous per-datagram parse: domain-shaped packet
	// addresses yield a zero AddrPort instead of failing the stream.
	addrPort, _ := netip.ParseAddrPort(packetAddr)
	return &packetStream{
		stream:   stream,
		addr:     packetAddr,
		addrPort: addrPort,
	}, nil
}

func (s *session) removeStream(sid uint32) {
	var removed bool
	var idle bool

	s.streamLock.Lock()
	if _, ok := s.streams[sid]; ok {
		delete(s.streams, sid)
		removed = true
		idle = len(s.streams) == 0
	}
	s.streamLock.Unlock()

	if !removed {
		return
	}
	if active := s.activeStreams.Add(-1); active < 0 {
		s.activeStreams.Store(0)
	}
	if !idle || s.closed.Load() {
		return
	}
	s.state.Store(sessionStateIdle)
	s.idleAt.Store(time.Now().UnixNano())

	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.closeStreamChan <- sid:
	case <-s.done:
	default:
	}
}

func (s *session) addStream(stream *stream) error {
	s.streamLock.Lock()
	defer s.streamLock.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.streams[stream.id] = stream
	s.activeStreams.Add(1)
	s.state.Store(sessionStateActive)
	s.idleAt.Store(0)
	return nil
}

func (s *session) run() error {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Panic]", slog.String("stack", string(debug.Stack())))
		}
	}()
	defer func() {
		if releaser, ok := s.conn.(readBufferReleaser); ok {
			releaser.ReleaseReader()
		}
	}()
	defer func() { _ = s.Close() }()

	var header rawHeader
	for {
		if s.Closed() {
			return net.ErrClosed
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		cmd := header.Cmd()
		if length != 0 {
			switch cmd {
			case cmdFIN, cmdHeartRequest, cmdHeartResponse:
				return fmt.Errorf("invalid payload length %d for cmd %d", length, cmd)
			}
		}
		switch cmd {
		case cmdWaste:
			if _, err := io.CopyN(io.Discard, s.conn, int64(length)); err != nil {
				return err
			}
		case cmdPSH:
			if length == 0 {
				continue
			}
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if !ok {
				pool.Put(buf)
				continue
			}
			// enqueue takes ownership of buf on every return path.
			if err := stream.enqueue(buf); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				return err
			}
		case cmdAlert:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			slog.Error("[Alert]", slog.String("msg", string(buf)))
			pool.Put(buf)
		case cmdFIN:
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				_ = stream.remoteClose()
			}
		case cmdUpdatePaddingScheme:
			if length > 0 {
				buf := pool.Get(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.Put(buf)
					return err
				}
				if padding := NewPaddingFactory(buf); padding != nil {
					s.SetPadding(padding)
				}
				pool.Put(buf)
			}
		case cmdSYNACK:
			if length > 0 {
				buf := pool.Get(length)
				if _, err := io.ReadFull(s.conn, buf); err != nil {
					pool.Put(buf)
					return err
				}
				s.streamLock.RLock()
				stream, ok := s.streams[sid]
				s.streamLock.RUnlock()
				if ok {
					_ = stream.Close()
				}
				pool.Put(buf)
			}
		case cmdServerSettings:
			if length > 0 {
				buffer := pool.Get(length)
				if _, err := io.ReadFull(s.conn, buffer); err != nil {
					pool.Put(buffer)
					return err
				}
				// The settings payload (a version map) must be drained to
				// keep the frame stream in sync, but the version itself is
				// not consumed anywhere yet.
				pool.Put(buffer)
			}

		case cmdHeartRequest:
			frame := newFrame(cmdHeartResponse, sid)
			if _, err := writeFrame(s, frame); err != nil {
				return err
			}
		case cmdHeartResponse:
			select {
			case s.heartResponseCh <- struct{}{}:
			default:
			}
		default:
			return fmt.Errorf("invalid cmd: %d", cmd)
		}
	}
}

func (s *session) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.state.Store(sessionStateClosing)
		close(s.done)
		s.streamLock.Lock()
		streams := make([]*stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		s.streams = make(map[uint32]*stream)
		s.activeStreams.Store(0)
		s.streamLock.Unlock()
		for _, stream := range streams {
			stream.markClosed(net.ErrClosed)
		}
		// Drain the coalescer before the raw close: Close itself no
		// longer flushes (a blocked flush must not delay teardown), so a
		// pending close_notify or final frame is pushed here instead.
		if s.flusher != nil {
			_ = s.flusher.Flush()
		}
		_ = s.conn.Close()
		s.connLock.Lock()
		s.writeBuf = nil
		s.connLock.Unlock()
		s.state.Store(sessionStateClosed)
		return nil
	}
	return nil
}

func (s *session) borrowWriteBuf(size int) []byte {
	if cap(s.writeBuf) < size {
		s.writeBuf = make([]byte, size)
	}
	return s.writeBuf[:size]
}

func (s *session) Closed() bool {
	return s.closed.Load()
}

func (s *session) Done() <-chan struct{} {
	return s.done
}

func (s *session) SetPadding(padding *paddingFactory) {
	s.padding.Store(padding)
}

func (s *session) GetPadding() *paddingFactory {
	return s.padding.Load()
}

func (s *session) isReusableIdle() bool {
	return !s.closed.Load() && s.state.Load() == sessionStateIdle && s.activeStreams.Load() == 0
}

func (s *session) idleTimedOut(now time.Time, timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	idleAt := s.idleAt.Load()
	return idleAt > 0 && !now.Before(time.Unix(0, idleAt).Add(timeout))
}

func (s *session) needsIdleProbe(now time.Time, threshold time.Duration) bool {
	if threshold <= 0 {
		return false
	}
	idleAt := s.idleAt.Load()
	return idleAt > 0 && !now.Before(time.Unix(0, idleAt).Add(threshold))
}

func (s *session) probeIdleHealth(timeout time.Duration) bool {
	if s.closed.Load() {
		return false
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()

	for {
		select {
		case <-s.heartResponseCh:
		default:
			goto drained
		}
	}

drained:
	if _, err := writeFrame(s, newFrame(cmdHeartRequest, 0)); err != nil {
		return false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-s.heartResponseCh:
		return true
	case <-s.done:
		return false
	case <-timer.C:
		return false
	}
}

// writeConnLockedWithDeadline applies an optional write deadline then writes.
// Caller must hold connLock.
func (s *session) writeConnLockedWithDeadline(b []byte, deadline time.Time) (n int, err error) {
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			return 0, os.ErrDeadlineExceeded
		}
		if err := s.conn.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
		defer func() { _ = s.conn.SetWriteDeadline(time.Time{}) }()
	}
	n, err = s.writeConnLocked(b)
	if err != nil {
		return n, err
	}
	// Drain the TLS record coalescer so the burst leaves in one socket write.
	// Without this the caller believes the data is out while records sit in
	// the coalescing buffer.
	if s.flusher != nil {
		if ferr := s.flusher.Flush(); ferr != nil {
			return n, ferr
		}
	}
	return n, nil
}

func (s *session) writeConnLocked(b []byte) (n int, err error) {
	// calculate and send padding
	if s.sendPadding {
		pkt := s.pktCounter.Add(1)
		paddingF := s.GetPadding()
		if pkt < paddingF.Stop {
			pktSizes := paddingF.GenerateRecordPayloadSizes(pkt)
			for _, l := range pktSizes {
				remainPayloadLen := len(b)
				if l == CheckMark {
					if remainPayloadLen == 0 {
						break
					} else {
						continue
					}
				}
				// logrus.Debugln(pkt, "write", l, "len", remainPayloadLen, "remain", remainPayloadLen-l)
				if remainPayloadLen > l { // this packet is all payload
					wn, err := iout.WriteFull(s.conn, b[:l])
					n += wn
					if err != nil {
						return n, err
					}
					b = b[l:]
				} else if remainPayloadLen > 0 { // this packet contains padding and the last part of payload
					paddingLen := l - remainPayloadLen - headerOverHeadSize
					if paddingLen > 0 {
						if paddingLen > maxFramePayloadSize {
							paddingLen = maxFramePayloadSize
						}
						combined := pool.Get(len(b) + headerOverHeadSize + paddingLen)
						copy(combined, b)
						fillWasteFrame(combined[len(b):], paddingLen)
						wn, err := iout.WriteFull(s.conn, combined)
						pool.Put(combined)
						if wn > remainPayloadLen {
							wn = remainPayloadLen
						}
						n += wn
						if err != nil {
							return n, err
						}
					} else {
						wn, err := iout.WriteFull(s.conn, b)
						n += wn
						if err != nil {
							return n, err
						}
					}
					b = nil
				} else { // this packet is all padding
					if l > maxFramePayloadSize {
						l = maxFramePayloadSize
					}
					padding := pool.Get(headerOverHeadSize + l)
					fillWasteFrame(padding, l)
					_, err = iout.WriteFull(s.conn, padding)
					pool.Put(padding)
					if err != nil {
						return n, err
					}
					b = nil
				}
			}
			// maybe still remain payload to write
			if len(b) == 0 {
				return
			}
			n2, err := iout.WriteFull(s.conn, b)
			return n + n2, err
		} else {
			s.sendPadding = false
		}
	}

	return iout.WriteFull(s.conn, b)
}

func fillWasteFrame(frame []byte, payloadLen int) {
	clear(frame)
	frame[0] = cmdWaste
	binary.BigEndian.PutUint32(frame[1:5], 0)
	binary.BigEndian.PutUint16(frame[5:7], uint16(payloadLen))
}
