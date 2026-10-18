package vmess

import (
	"crypto/md5"

	"github.com/google/uuid"
)

const (
	IDBytesLen = 16
)

// The ID of en entity, in the form of a UUID.
type ID struct {
	uuid   uuid.UUID
	cmdKey [IDBytesLen]byte
}

func (id *ID) CmdKey() []byte {
	return id.cmdKey[:]
}

// NewID returns an ID with given UUID.
func NewID(uuid uuid.UUID) *ID {
	id := &ID{uuid: uuid}
	md5hash := md5.New()
	b, _ := uuid.MarshalBinary()
	md5hash.Write(b)
	md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	md5hash.Sum(id.cmdKey[:0])
	return id
}
