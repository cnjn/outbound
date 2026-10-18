package shadowsocks_2022

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

type shortThenFailWriter struct {
	mu     sync.Mutex
	writes int
}

func (w *shortThenFailWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (w *shortThenFailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.writes == 1 {
		n := 1
		if n > len(p) {
			n = len(p)
		}
		return n, nil
	}
	return 0, io.ErrClosedPipe
}
func (w *shortThenFailWriter) Close() error                     { return nil }
func (w *shortThenFailWriter) LocalAddr() net.Addr              { return nil }
func (w *shortThenFailWriter) RemoteAddr() net.Addr             { return nil }
func (w *shortThenFailWriter) SetDeadline(time.Time) error      { return nil }
func (w *shortThenFailWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *shortThenFailWriter) SetWriteDeadline(time.Time) error { return nil }

func TestTCPConnFirstWriteDoesNotCommitOnShortWrite(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	if conf == nil {
		t.Fatal("missing ss2022 cipher config")
	}
	psk := make([]byte, conf.KeyLen)
	for i := range psk {
		psk[i] = 0x23
	}
	core, err := NewSS2022Core(conf, [][]byte{psk}, psk)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := socks5.AddressFromString("203.0.113.10:443")
	if err != nil {
		t.Fatal(err)
	}
	sg := shadowsocks.NewRandomSaltGenerator(conf.SaltLen)
	underlay := &shortThenFailWriter{}
	conn := NewTCPConn(underlay, core, sg, addr, nil).(*TCPConn)
	_, err = conn.Write([]byte("hello"))
	if err == nil {
		t.Fatal("expected first write to fail after incomplete underlay write")
	}
	if conn.onceWrite {
		t.Fatal("onceWrite committed despite failed first write")
	}
	if !conn.writeBroken {
		t.Fatal("expected writeBroken after incomplete sealed write")
	}
	_, err = conn.Write([]byte("world"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retry after partial first write: %v, want net.ErrClosed", err)
	}
}
