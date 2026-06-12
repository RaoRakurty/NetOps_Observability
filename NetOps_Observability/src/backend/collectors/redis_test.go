package collectors

import (
	"bufio"
	"context"
	"net"
	"testing"
)

func TestEncodeRESP(t *testing.T) {
	got := string(encodeRESP("SET", "k", "v"))
	want := "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n"
	if got != want {
		t.Fatalf("encodeRESP = %q, want %q", got, want)
	}
}

func TestTrimCRLF(t *testing.T) {
	if trimCRLF("OK\r\n") != "OK" || trimCRLF("x") != "x" {
		t.Fatal("trimCRLF wrong")
	}
}

// FetchProbePaths reads a RESP bulk string from the configured Redis. Stand up a
// fake RESP server that returns a bulk string and assert it round-trips.
func TestFetchProbePathsRESP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Consume the GET command line(s), then reply with a bulk string.
		_, _ = bufio.NewReader(c).ReadString('\n')
		_, _ = c.Write([]byte("$8\r\n[\"path\"]\r\n"))
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)

	got, err := FetchProbePaths(context.Background())
	if err != nil {
		t.Fatalf("FetchProbePaths: %v", err)
	}
	if got != `["path"]` {
		t.Fatalf("FetchProbePaths = %q, want %q", got, `["path"]`)
	}
}

// RedisAddr is empty when unconfigured (callers fall back).
func TestRedisAddrUnset(t *testing.T) {
	t.Setenv("REDIS_HOST", "")
	if RedisAddr() != "" {
		t.Fatal("RedisAddr should be empty when REDIS_HOST unset")
	}
}
