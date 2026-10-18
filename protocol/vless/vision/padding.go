package vision

import (
	"bytes"
	"encoding/binary"

	"github.com/daeuniverse/outbound/pool"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/google/uuid"
)

const (
	PaddingHeaderLen = len(uuid.Nil) + 1 + 2 + 2 // =21

	commandPaddingContinue byte = 0x00
	commandPaddingEnd      byte = 0x01
	commandPaddingDirect   byte = 0x02

	BufferSize = 32 * 1024
)

// ApplyPaddingFromPool builds a complete Vision frame
// ([userUUID][command][contentLen(2B)][paddingLen(2B)][p][random padding])
// in a single pooled buffer so writePadding can emit the entire frame in one
// Write call (and therefore one outer TLS record).
func ApplyPaddingFromPool(p []byte, command byte, userUUID []byte, longPadding bool) (frame pool.PB) {
	contentLen := int32(len(p))
	var paddingLen int32
	if contentLen < 900 && longPadding {
		//logrus.Debugln("long padding")
		paddingLen = fastrand.Int31n(500) + 900 - contentLen
	} else {
		paddingLen = fastrand.Int31n(256)
	}

	headerLen := len(userUUID) + 1 + 2 + 2
	frame = pool.Get(headerLen + len(p) + int(paddingLen))
	start := 0
	if userUUID != nil {
		start += copy(frame, userUUID)
	}
	frame[start] = command
	start++
	binary.BigEndian.PutUint16(frame[start:], uint16(contentLen))
	start += 2
	binary.BigEndian.PutUint16(frame[start:], uint16(paddingLen))
	start += 2
	start += copy(frame[start:], p)
	if paddingLen > 0 {
		_, _ = fastrand.Read(frame[start:])
	}
	// logrus.Debugln("XTLS Vision write padding2: command=%d, payloadLen=%d, paddingLen=%d", command, contentLen, paddingLen)
	return frame
}

func ReshapeBytes(b []byte) (_ []byte, b2 []byte) {
	if len(b) < BufferSize-PaddingHeaderLen {
		return b, nil
	}
	index := bytes.LastIndex(b, tlsApplicationDataStart)
	if index < PaddingHeaderLen || index > BufferSize-PaddingHeaderLen {
		index = BufferSize / 2
	}
	b2 = b[index:]
	b = b[:index]
	return b, b2
}
