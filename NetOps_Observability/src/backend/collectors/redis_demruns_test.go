// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// redis_demruns_test.go — a broken connection is not "no runs" (review
// 2026-09-08, 3.2-18).
//
// FetchDEMRuns folded a TRANSPORT error into the expired-key branch, so a
// connection that died mid-drain returned a short batch with a NIL error. The
// api's intake then counted nothing, logged nothing, and every synthetic check
// on the vantages it never reached graded `unknown` — the exact silent failure
// §10 forbids. The connection-wide 5-second deadline redisDial sets makes this
// the ORDINARY outcome of a slow drain, not an exotic one.

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

	"netops/backend/internal/dem"
)

// respArray renders a RESP array of bulk strings.
func respArray(items ...string) string {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(items)) + "\r\n")
	for _, s := range items {
		b.WriteString("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n")
	}
	return b.String()
}

// respBulk renders one RESP bulk string.
func respBulk(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }

// fakeRedis serves ONE connection with scripted replies, in order. A reply of
// "" means: close the connection without answering, which is what a dead
// Valkey, a dropped TCP session or the dial's own deadline looks like on the
// wire.
func fakeRedis(t *testing.T, replies ...string) {
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
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		for _, reply := range replies {
			// Read one RESP command: "*N\r\n" then N bulk strings.
			hdr, rerr := r.ReadString('\n')
			if rerr != nil || len(hdr) == 0 || hdr[0] != '*' {
				return
			}
			n, cerr := strconv.Atoi(strings.TrimSpace(hdr[1:]))
			if cerr != nil {
				return
			}
			for i := 0; i < n*2; i++ {
				if _, rerr = r.ReadString('\n'); rerr != nil {
					return
				}
			}
			if reply == "" {
				return // hang up mid-drain
			}
			if _, werr := c.Write([]byte(reply)); werr != nil {
				return
			}
		}
	}()
}

func oneRunBatch(t *testing.T, vantage string) string {
	t.Helper()
	now := time.Now().UTC()
	raw, err := json.Marshal([]dem.WireRun{{
		ID: "run-" + vantage, Tenant: "acme", TargetID: "dem-1", Kind: dem.KindICMP,
		Vantage: vantage, StartedAt: now.Add(-time.Second), EndedAt: now, Outcome: "ok",
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return respBulk(string(raw))
}

// A connection that dies mid-drain must be REPORTED, and the vantages that were
// never read must not be reported as having published nothing.
func TestFetchDEMRunsReportsABrokenConnection(t *testing.T) {
	fakeRedis(t,
		respArray("van-a", "van-b"), // SMEMBERS
		oneRunBatch(t, "van-a"),     // GET van-a
		"",                          // GET van-b: the connection dies
	)
	runs, err := FetchDEMRuns(context.Background())
	if err == nil {
		t.Fatal("a broken connection returned a nil error — the intake counts nothing, logs nothing, and every unread check grades unknown")
	}
	if !strings.Contains(err.Error(), "van-b") {
		t.Errorf("the error does not name the vantage that could not be read: %v", err)
	}
	// The count is vantages, not runs. Saying "1 of 2 vantages were not read"
	// is a measured number; the run total would be a different thing wearing
	// the same words.
	if !strings.Contains(err.Error(), "1 of 2 vantages") {
		t.Errorf("the error does not say how many vantages went unread: %v", err)
	}
	// The batch that WAS read is still returned: a partial drain is worth more
	// than nothing, as long as it is not reported as complete.
	if len(runs) != 1 {
		t.Errorf("the vantage that answered contributed %d runs, want 1", len(runs))
	}
}

// An EXPIRED (or never-written) vantage key is still an empty batch and still
// not an error: a prober that has not published yet is the ordinary state.
func TestFetchDEMRunsTreatsAnExpiredKeyAsEmpty(t *testing.T) {
	fakeRedis(t,
		respArray("van-a", "van-b"), // SMEMBERS
		"$-1\r\n",                   // GET van-a: nil bulk, the key expired
		oneRunBatch(t, "van-b"),     // GET van-b
	)
	runs, err := FetchDEMRuns(context.Background())
	if err != nil {
		t.Fatalf("an expired vantage key was reported as a failure: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("drained %d runs, want the 1 the live vantage published", len(runs))
	}
}

// A redis-side error reply for ONE key costs that vantage's batch and is
// reported, but the drain continues: one broken prober must not blind the api
// to every other one.
func TestFetchDEMRunsKeepsDrainingPastOneVantageError(t *testing.T) {
	fakeRedis(t,
		respArray("van-a", "van-b"),   // SMEMBERS
		"-WRONGTYPE not a string\r\n", // GET van-a
		oneRunBatch(t, "van-b"),       // GET van-b
	)
	runs, err := FetchDEMRuns(context.Background())
	if err == nil {
		t.Fatal("a redis error reply for one vantage was swallowed")
	}
	if errors.Is(err, errRedisTransport) {
		t.Errorf("a per-key error reply was classified as a dead connection: %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("the healthy vantage contributed %d runs, want 1", len(runs))
	}
}
