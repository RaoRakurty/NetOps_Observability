// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestLiveTraceDebug is a manual diagnostic, not CI: it runs a REAL traceroute to
// LIVE_TRACE_DST and prints the result or the exact error the collector would have
// swallowed into its status. Skipped unless LIVE_TRACE_DST is set.
func TestLiveTraceDebug(t *testing.T) {
	dst := os.Getenv("LIVE_TRACE_DST")
	if dst == "" {
		t.Skip("set LIVE_TRACE_DST to run")
	}
	sock := os.Getenv("LIVE_TRACE_SOCKET")
	if sock == "" {
		sock = "ip4:icmp"
	}
	cfg := traceConfig{
		maxHops:   10,
		probes:    1,
		timeout:   2 * time.Second,
		method:    "icmp",
		socketNet: sock,
		tcpPort:   443,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := traceOnce(ctx, dst, cfg)
	if err != nil {
		t.Fatalf("traceOnce(%s) error: %v", dst, err)
	}
	fmt.Printf("reached=%v hops=%d\n", res.Reached, len(res.Hops))
	for _, h := range res.Hops {
		fmt.Printf("  ttl=%d ip=%q rtt=%.2fms\n", h.TTL, h.IP, h.RTTms)
	}
}
