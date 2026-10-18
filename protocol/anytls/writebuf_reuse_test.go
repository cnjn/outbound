package anytls

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/outbound/protocol/infra/bench"
)

func TestSessionWriteBufReleasedOnClose(t *testing.T) {
	sess := newSession(bench.NewNetDiscardConn(), 0)
	stream, err := sess.newStream("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("newStream: %v", err)
	}
	payload := bytes.Repeat([]byte{0xab}, 1024)
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if cap(sess.writeBuf) == 0 {
		t.Fatal("expected session writeBuf after stream write")
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sess.writeBuf != nil {
		t.Fatal("expected writeBuf to be released on Close")
	}
}

func TestWriteFrameEncodingUnchanged(t *testing.T) {
	rec := &recordingConn{}
	sess := newSession(rec, 0)
	sess.sendPadding = false

	frame := newFrame(cmdPSH, 7)
	frame.data = []byte("hello-anytls")
	if _, err := writeFrame(sess, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(rec.writes))
	}
	got := rec.writes[0]
	want := make([]byte, headerOverHeadSize+len(frame.data))
	encodeFrame(want, frame)
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded frame mismatch\ngot  %x\nwant %x", got, want)
	}
}
