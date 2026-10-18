package shadowsocks

import (
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
)

// RandomSaltGenerator produces a fresh random salt for every request.
type RandomSaltGenerator struct {
	saltSize int
}

// NewRandomSaltGenerator returns a generator emitting salts of saltSize bytes.
func NewRandomSaltGenerator(saltSize int) *RandomSaltGenerator {
	return &RandomSaltGenerator{
		saltSize: saltSize,
	}
}

func (g *RandomSaltGenerator) Get() []byte {
	salt := pool.Get(g.saltSize)
	_, _ = fastrand.Read(salt)
	return salt
}
