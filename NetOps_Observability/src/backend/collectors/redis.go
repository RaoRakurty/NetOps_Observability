package collectors

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// redis.go — a tiny, dependency-free RESP client (SET-with-TTL + GET only),
// used to share active-measurement results from the prober sidecar to the API
// per ADR 0001 (privileged ops isolated; workers communicate via Redis). The
// backend is stdlib-only by design, and we need just two commands, so a full
// Redis driver is unwarranted — this speaks RESP over a short-lived TCP conn.

const probePathsKey = "netops:probe:paths"

// RedisAddr returns host:port from REDIS_HOST/REDIS_PORT, or "" if unset — in
// which case callers fall back to file / in-process sharing.
func RedisAddr() string {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, os.Getenv("REDIS_PORT"))
}

func redisDial(ctx context.Context) (net.Conn, error) {
	addr := RedisAddr()
	if addr == "" {
		return nil, fmt.Errorf("redis not configured")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if pass := os.Getenv("REDIS_PASSWORD"); pass != "" {
		if _, err := redisCmd(c, "AUTH", pass); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

// encodeRESP renders a command as a RESP array of bulk strings.
func encodeRESP(args ...string) []byte {
	b := []byte("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b = append(b, '$')
		b = append(b, strconv.Itoa(len(a))...)
		b = append(b, '\r', '\n')
		b = append(b, a...)
		b = append(b, '\r', '\n')
	}
	return b
}

// redisCmd sends one command and reads a single reply line / bulk string.
func redisCmd(c net.Conn, args ...string) (string, error) {
	if _, err := c.Write(encodeRESP(args...)); err != nil {
		return "", err
	}
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) == 0 {
		return "", fmt.Errorf("empty redis reply")
	}
	switch line[0] {
	case '+': // simple string
		return trimCRLF(line[1:]), nil
	case '-': // error
		return "", fmt.Errorf("redis: %s", trimCRLF(line[1:]))
	case '$': // bulk string
		n, err := strconv.Atoi(trimCRLF(line[1:]))
		if err != nil {
			return "", err
		}
		if n < 0 {
			return "", nil // nil bulk → empty
		}
		buf := make([]byte, n+2) // payload + CRLF
		if _, err := readFull(r, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	default:
		return trimCRLF(line[1:]), nil
	}
}

func trimCRLF(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// redisSetEX writes key=val with a TTL (seconds) so stale data self-expires if a
// prober dies.
func redisSetEX(ctx context.Context, key, val string, ttlSec int) error {
	c, err := redisDial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = redisCmd(c, "SET", key, val, "EX", strconv.Itoa(ttlSec))
	return err
}

// FetchProbePaths reads the shared traceroute topology JSON published by the
// prober. Returns ("", nil) when the key is absent.
func FetchProbePaths(ctx context.Context) (string, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return redisCmd(c, "GET", probePathsKey)
}

// FetchTopologyLinks reads the raw LLDP neighbour records published by the LLDP
// collector (JSON array of LLDPNeighbor). Returns ("", nil) when the key is absent.
func FetchTopologyLinks(ctx context.Context) (string, error) {
	c, err := redisDial(ctx)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return redisCmd(c, "GET", topoLinksKey)
}
