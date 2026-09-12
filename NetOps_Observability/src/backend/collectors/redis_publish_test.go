// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// SEC-012.1: a failed evidence publish must be COUNTED, never silent — the
// write-path fix that must land before Valkey auth (a wrong password would
// otherwise starve RCA of paths/topology with zero symptoms).

import (
	"context"
	"testing"
)

func TestRedisPublishSurfacesFailures(t *testing.T) {
	// Point at a port nothing listens on: every publish must fail AND count.
	t.Setenv("REDIS_HOST", "127.0.0.1")
	t.Setenv("REDIS_PORT", "1") // reserved port, nothing listens
	before := RedisPublishFailureCount("test-channel")
	redisPublish(context.Background(), "test-channel", "k", "v", 60)
	redisPublish(context.Background(), "test-channel", "k", "v", 60)
	if got := RedisPublishFailureCount("test-channel") - before; got != 2 {
		t.Fatalf("publish failures counted = %d, want 2", got)
	}
	if RedisPublishFailureCount("never-used") != 0 {
		t.Fatal("unknown channel must read 0")
	}
}
