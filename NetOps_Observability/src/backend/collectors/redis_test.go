// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
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

// With no vantage registered, the legacy single key is read — and verified like
// every other slot (tracker 475): a signed set round-trips over RESP.
func TestFetchProbePathsAllLegacyKeyRESP(t *testing.T) {
	raw := sealPathSet(t, "prober", []byte(`[{"dst":"10.0.0.9","method":"icmp","hops":[]}]`))
	fakeRedis(t,
		respArray(),   // SMEMBERS: no vantage registered
		respBulk(raw), // GET the legacy key
	)
	paths, err := FetchProbePathsAll(context.Background(), testPathVerifier(false))
	if err != nil {
		t.Fatalf("FetchProbePathsAll: %v", err)
	}
	if len(paths) != 1 || paths[0].Dst != "10.0.0.9" || paths[0].VantageID != "prober" {
		t.Fatalf("legacy key read = %+v, want the one signed path attributed to its vantage", paths)
	}
}

// RedisAddr is empty when unconfigured (callers fall back).
func TestRedisAddrUnset(t *testing.T) {
	t.Setenv("REDIS_HOST", "")
	if RedisAddr() != "" {
		t.Fatal("RedisAddr should be empty when REDIS_HOST unset")
	}
}
