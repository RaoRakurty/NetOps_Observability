// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// authRESP is a plaintext RESP server that refuses every command until the
// client authenticates with password, and records what it was sent.
type authRESP struct {
	password string
	mu       sync.Mutex
	vals     map[string]string
	cmds     []string
}

func (s *authRESP) serve(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func readRESPArray(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "*")))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := r.ReadString('\n'); err != nil { // $len
			return nil, err
		}
		arg, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		out = append(out, strings.TrimRight(arg, "\r\n"))
	}
	return out, nil
}

func (s *authRESP) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	authed := false
	for {
		args, err := readRESPArray(r)
		if err != nil || len(args) == 0 {
			return
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, strings.ToUpper(args[0]))
		s.mu.Unlock()
		var reply string
		switch strings.ToUpper(args[0]) {
		case "AUTH":
			if len(args) == 2 && args[1] == s.password {
				authed, reply = true, "+OK\r\n"
			} else {
				reply = "-WRONGPASS invalid username-password pair\r\n"
			}
		case "GET":
			switch {
			case !authed:
				reply = "-NOAUTH Authentication required.\r\n"
			default:
				s.mu.Lock()
				v, ok := s.vals[args[1]]
				s.mu.Unlock()
				if ok {
					reply = fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)
				} else {
					reply = "$-1\r\n"
				}
			}
		case "SET":
			if !authed {
				reply = "-NOAUTH Authentication required.\r\n"
			} else {
				s.mu.Lock()
				s.vals[args[1]] = args[2]
				s.mu.Unlock()
				reply = "+OK\r\n"
			}
		default:
			reply = "-ERR unknown\r\n"
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

// The prober-switch channel is the SEC-012.1 authenticated Valkey channel:
// ControlKV authenticates before every read and write, round-trips a value,
// reads an absent key as "" with no error, and a wrong password is an ERROR
// (which the prober reads as channel_unread → collectors off), never a
// silent empty answer.
func TestControlKVIsTheAuthenticatedChannel(t *testing.T) {
	srv := &authRESP{password: "s3cret", vals: map[string]string{}}
	port := srv.serve(t)
	t.Setenv("REDIS_HOST", "127.0.0.1")
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_TLS", "")
	t.Setenv("REDIS_PASSWORD", "s3cret")

	kv := ControlKV{}
	if !kv.Configured() {
		t.Fatal("REDIS_HOST set: the channel is configured")
	}
	ctx := context.Background()
	if v, err := kv.Get(ctx, "netops:prober:switches"); err != nil || v != "" {
		t.Fatalf("absent key: %q %v", v, err)
	}
	if err := kv.SetEX(ctx, "test-switch-channel", "netops:prober:switches", `{"v":1}`, 120); err != nil {
		t.Fatal(err)
	}
	if v, err := kv.Get(ctx, "netops:prober:switches"); err != nil || v != `{"v":1}` {
		t.Fatalf("round trip: %q %v", v, err)
	}
	srv.mu.Lock()
	cmds := strings.Join(srv.cmds, ",")
	srv.mu.Unlock()
	if cmds != "AUTH,GET,AUTH,SET,AUTH,GET" {
		t.Fatalf("every connection must authenticate first; commands = %s", cmds)
	}

	t.Setenv("REDIS_PASSWORD", "wrong")
	if _, err := kv.Get(ctx, "netops:prober:switches"); err == nil {
		t.Fatal("a refused AUTH must be an error, never an empty answer")
	}
	before := RedisPublishFailureCount("test-switch-channel")
	if err := kv.SetEX(ctx, "test-switch-channel", "netops:prober:switches", "x", 120); err == nil {
		t.Fatal("a refused AUTH must fail the write")
	}
	if RedisPublishFailureCount("test-switch-channel") != before+1 {
		t.Fatal("a failed publish must be counted under its channel")
	}

	t.Setenv("REDIS_HOST", "")
	if kv.Configured() {
		t.Fatal("no REDIS_HOST: no channel")
	}
}
