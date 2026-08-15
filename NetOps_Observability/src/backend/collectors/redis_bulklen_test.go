package collectors

// redis_bulklen_test.go — RESP wire-length cap. A bulk-string length header is
// attacker-influenced wire data; allocating it blindly (make([]byte, n+2)) was
// a makeslice panic that killed the calling collector goroutine for good. The
// reader must refuse an over-cap length with an error, not allocate it.

import (
	"net"
	"testing"
	"time"
)

func TestRedisCmdRejectsHugeBulkLength(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	go func() {
		// Consume the command bytes, then answer with an absurd bulk length —
		// far past Redis's own 512MB proto-max-bulk-len.
		buf := make([]byte, 256)
		_, _ = srv.Read(buf)
		_, _ = srv.Write([]byte("$99999999999\r\n"))
	}()
	if err := cli.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	// Without the cap this is a makeslice panic (test process dies), not an error.
	if _, err := redisCmd(cli, "GET", "k"); err == nil {
		t.Fatal("huge bulk length must be refused with an error")
	}

	// A sane bulk still round-trips (no false rejection).
	srv2, cli2 := net.Pipe()
	defer srv2.Close()
	defer cli2.Close()
	go func() {
		buf := make([]byte, 256)
		_, _ = srv2.Read(buf)
		_, _ = srv2.Write([]byte("$2\r\nok\r\n"))
	}()
	if err := cli2.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	got, err := redisCmd(cli2, "GET", "k")
	if err != nil || got != "ok" {
		t.Fatalf("sane bulk mis-read: %q, %v", got, err)
	}
}
