package ws

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type conn struct {
	*websocket.Conn

	readMu        sync.Mutex
	currentReader io.Reader

	writeMu sync.Mutex
}

func newConn(wsc *websocket.Conn) *conn {
	return &conn{
		Conn: wsc,
	}
}

func normalizeWebsocketError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, websocket.ErrCloseSent) ||
		websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		return io.EOF
	}
	return err
}

func (c *conn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.currentReader == nil {
			messageType, reader, err := c.NextReader()
			if err != nil {
				return 0, normalizeWebsocketError(err)
			}
			if messageType != websocket.BinaryMessage {
				_, _ = io.Copy(io.Discard, reader)
				continue
			}
			c.currentReader = reader
		}

		n, err = c.currentReader.Read(b)
		err = normalizeWebsocketError(err)
		if err == nil {
			return n, nil
		}
		if err == io.EOF {
			c.currentReader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}
func (c *conn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	writer, err := c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, normalizeWebsocketError(err)
	}
	n, err = writer.Write(b)
	err = normalizeWebsocketError(err)
	closeErr := normalizeWebsocketError(writer.Close())
	if err != nil {
		return n, err
	}
	if closeErr != nil {
		return n, closeErr
	}
	return n, nil
}

func (c *conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
