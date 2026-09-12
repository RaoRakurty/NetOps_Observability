// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// redis_drain_deadline_test.go — the two halves of 3.2-18 that the first fix
// left open.
//
// HALF ONE: the deadline. redisDial set ONE deadline for the whole connection,
// and every drain in this file walks up to 1024 vantage keys down that one
// connection. A healthy but slow drain therefore ran out of budget part-way
// through — and now that a transport failure is correctly reported instead of
// swallowed, that expired budget turns a good drain into a hard error every
// cycle. The fix gives each exchange its own budget; the test proves a drain
// that outlives the single connection-wide window still completes.
//
// HALF TWO: the same fold, the other function. FetchDEMRuns stopped treating a
// dead connection as an expired key; FetchProbePathsAll still did, one screen
// above it in the same file. A dead channel there returns the paths read so far
// with a nil error, so the path lane draws a partial topology and calls it the
// whole measurement.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func onePathBatch(t *testing.T, vantage string) string {
	t.Helper()
	raw, err := json.Marshal([]PathResult{{
		VantageID: vantage, Dst: "10.0.0.1", Method: "icmp", TS: time.Now().UTC(),
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return respBulk(string(raw))
}

// A connection that dies mid-drain must be REPORTED here exactly as it is in
// FetchDEMRuns. Before this fix the loop said "a dead vantage's key has expired
// — not an error" and returned a nil error over an unread channel.
func TestFetchProbePathsAllReportsABrokenConnection(t *testing.T) {
	fakeRedis(t,
		respArray("van-a", "van-b"), // SMEMBERS
		onePathBatch(t, "van-a"),    // GET van-a
		"",                          // GET van-b: the connection dies
	)
	paths, err := FetchProbePathsAll(context.Background())
	if err == nil {
		t.Fatal("a broken path channel returned a nil error — the path lane reads a partial measurement as the whole one")
	}
	if !errors.Is(err, errRedisTransport) {
		t.Errorf("a dead connection was not classified as a transport failure: %v", err)
	}
	if !strings.Contains(err.Error(), "van-b") {
		t.Errorf("the error does not name the vantage that could not be read: %v", err)
	}
	if !strings.Contains(err.Error(), "1 of 2 vantages") {
		t.Errorf("the error does not say how many vantages went unread: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("an unread channel still returned %d paths as if they were the answer", len(paths))
	}
}

// A per-key refusal from a LIVE server costs that vantage only, and the drain
// continues — the distinction the transport branch exists to preserve.
func TestFetchProbePathsAllKeepsDrainingPastOneVantageError(t *testing.T) {
	fakeRedis(t,
		respArray("van-a", "van-b"),   // SMEMBERS
		"-WRONGTYPE not a string\r\n", // GET van-a
		onePathBatch(t, "van-b"),      // GET van-b
	)
	paths, err := FetchProbePathsAll(context.Background())
	if err != nil {
		t.Fatalf("one vantage's error reply failed the whole drain: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("the healthy vantage contributed %d paths, want 1", len(paths))
	}
	if paths[0].VantageID != "van-b" {
		t.Fatalf("the surviving path came from %q, want van-b", paths[0].VantageID)
	}
}

// THE DEADLINE. Three exchanges, each comfortably inside one command's budget,
// whose SUM is longer than it. With one deadline set at dial for the whole
// connection the third one fails; with a per-command budget the drain completes.
//
// The numbers are the point: no single exchange is slow, the drain just is. A
// real one walks up to 1024 vantage keys.
func TestASlowDrainIsNotGuillotinedByOneConnectionWideDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("the stall is real time")
	}
	// Two stalls of 60 % of the per-command budget: each exchange is well
	// inside its own window, the pair is past a single connection-wide one.
	per := time.Duration(float64(redisCmdTimeout) * 0.6)
	fakeRedisSlow(t, map[int]time.Duration{1: per, 2: per},
		respArray("van-a", "van-b"), // SMEMBERS
		oneRunBatch(t, "van-a"),     // GET van-a, answered after a stall
		oneRunBatch(t, "van-b"),     // GET van-b, answered after another
	)
	runs, err := FetchDEMRuns(context.Background())
	if err != nil {
		t.Fatalf("a drain whose TOTAL outlived one connection-wide window failed, "+
			"though no single exchange came close to the budget: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("drained %d runs, want both vantages", len(runs))
	}
}

// fakeRedisSlow is fakeRedis with a per-reply delay: `delays[i]` is waited out
// before reply i is written. The server's own deadline is generous so the only
// thing under test is the CLIENT's.
func fakeRedisSlow(t *testing.T, delays map[int]time.Duration, replies ...string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_TLS", "")
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
		r := bufio.NewReader(c)
		for i, reply := range replies {
			hdr, rerr := r.ReadString('\n')
			if rerr != nil || len(hdr) == 0 || hdr[0] != '*' {
				return
			}
			n, cerr := strconv.Atoi(strings.TrimSpace(hdr[1:]))
			if cerr != nil {
				return
			}
			for j := 0; j < n*2; j++ {
				if _, rerr = r.ReadString('\n'); rerr != nil {
					return
				}
			}
			if d, ok := delays[i]; ok {
				time.Sleep(d)
			}
			if _, werr := c.Write([]byte(reply)); werr != nil {
				return
			}
		}
	}()
}
