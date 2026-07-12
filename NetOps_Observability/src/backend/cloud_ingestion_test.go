package main

import (
	"testing"
	"time"
)

func TestIngestStatusFor(t *testing.T) {
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		volume   int64
		lastSeen time.Time
		want     string
	}{
		{"no data at all is off", 0, time.Time{}, "off"},
		{"volume but no timestamp is off", 42, time.Time{}, "off"},
		{"just arrived is flowing", 10, now.Add(-1 * time.Minute), "flowing"},
		{"inside the fresh window is flowing", 10, now.Add(-14 * time.Minute), "flowing"},
		{"past the fresh window is stale", 10, now.Add(-30 * time.Minute), "stale"},
		{"inside the stale horizon is stale", 10, now.Add(-23 * time.Hour), "stale"},
		{"beyond the stale horizon is off", 10, now.Add(-25 * time.Hour), "off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ingestStatusFor(tc.volume, tc.lastSeen, now); got != tc.want {
				t.Fatalf("ingestStatusFor(%d, %v) = %q, want %q", tc.volume, tc.lastSeen, got, tc.want)
			}
		})
	}
}

// A source with no producer must never report coverage we do not have.
func TestSourcesWithoutProducersHaveNoKinds(t *testing.T) {
	for _, src := range []string{"traces", "dns_logs", "firewall_logs", "nat_logs"} {
		if kinds, ok := cloudSourceKinds[src]; ok && len(kinds) > 0 {
			t.Fatalf("%s claims kinds %v but has no producer — it would report false coverage", src, kinds)
		}
	}
}

// Every source the UI renders must be present in the display order, or it would
// silently vanish from the matrix.
func TestSourceOrderCoversEveryMappedKind(t *testing.T) {
	inOrder := map[string]bool{}
	for _, s := range cloudSourceOrder {
		inOrder[s] = true
	}
	for src := range cloudSourceKinds {
		if !inOrder[src] {
			t.Fatalf("source %q has kinds mapped but is missing from cloudSourceOrder", src)
		}
	}
	for _, must := range []string{"inventory", "seam_data"} {
		if !inOrder[must] {
			t.Fatalf("source %q missing from cloudSourceOrder", must)
		}
	}
}
