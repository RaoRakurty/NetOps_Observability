// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"testing"
	"time"
)

// The in-memory store keeps the same overlay-read contract as Postgres:
// tenant-only, BFD rows with a tunnel identity, since-bounded, newest first,
// limited with a truncation flag.
func TestMemOverlaySessionsContract(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	t0 := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	tid := CanonicalTunnelID("10.0.0.1", "mpls", "10.0.0.2", "mpls")
	rec := func(key, kind, tunnel string, at time.Time) StateRecord {
		return StateRecord{EntityKey: key, StateKind: kind, CurrentState: "up", LastSeen: at, TunnelID: tunnel, LocalColor: "mpls"}
	}
	if err := st.UpsertStates(ctx, "t-a", "i-a", []StateRecord{
		rec("s1", "bfd", tid, t0), rec("s2", "bfd", tid, t0.Add(time.Second)),
		rec("r1", "reachability", "", t0), rec("s3", "bfd", "", t0),
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertStates(ctx, "t-b", "i-b", []StateRecord{rec("s1", "bfd", tid, t0)}); err != nil {
		t.Fatal(err)
	}
	got, truncated, err := st.OverlaySessions(ctx, "t-a", t0.Add(-time.Minute), 10)
	if err != nil || truncated || len(got) != 2 || got[0].EntityKey != "s2" || got[0].IntegrationID != "i-a" {
		t.Fatalf("t-a: err=%v truncated=%v %+v", err, truncated, got)
	}
	b, _, _ := st.OverlaySessions(ctx, "t-b", t0.Add(-time.Minute), 10)
	if len(b) != 1 || b[0].IntegrationID != "i-b" {
		t.Fatalf("CROSS-TENANT: t-b must read exactly its own session: %+v", b)
	}
	if one, tr, _ := st.OverlaySessions(ctx, "t-a", t0.Add(-time.Minute), 1); len(one) != 1 || !tr {
		t.Fatalf("limit must truncate and say so: %v %+v", tr, one)
	}
	if none, _, _ := st.OverlaySessions(ctx, "t-a", t0.Add(time.Hour), 10); len(none) != 0 {
		t.Fatalf("since must bound: %+v", none)
	}
	if zero, _, _ := st.OverlaySessions(ctx, "t-a", t0.Add(-time.Minute), 0); zero != nil {
		t.Fatalf("limit 0 reads nothing: %+v", zero)
	}
}

// Both transforms carry the two ends' colours, lower-cased.
func TestBFDTransformCarriesBothColours(t *testing.T) {
	for _, s := range loadBFD(t, "bfd_sessions_vedge20.json") {
		if s.LocalColor == "" || s.RemoteColor == "" || s.LocalColor != s.Data["local_color"] {
			t.Fatalf("colours missing: %+v", s)
		}
	}
}
