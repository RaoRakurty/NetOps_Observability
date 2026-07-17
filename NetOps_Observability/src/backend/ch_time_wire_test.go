package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// S3 (log-time standard): every ClickHouse-backed SELECT renders datetimes as
// explicit-UTC RFC 3339 — never zone-less toString() strings a JS Date would
// parse as browser-local.

func TestChISOFragment(t *testing.T) {
	got := chISO("ts")
	want := "concat(replaceOne(toString(ts, 'UTC'), ' ', 'T'), 'Z')"
	if got != want {
		t.Fatalf("chISO(ts) = %q, want %q", got, want)
	}
	// Aggregates pass through as expressions.
	if !strings.Contains(chISO("max(fused_at)"), "toString(max(fused_at), 'UTC')") {
		t.Fatalf("chISO must accept aggregate expressions: %q", chISO("max(fused_at)"))
	}
}

// The server-side consumers of CH wire strings must accept BOTH the new RFC
// 3339 form and the legacy zone-less form (mixed fleets during rollout).
func TestCHWireParsersAcceptBothFormats(t *testing.T) {
	want := time.Date(2026, 7, 16, 21, 56, 3, 562_000_000, time.UTC)
	for _, s := range []string{
		"2026-07-16T21:56:03.562Z", // new wire format (chISO)
		"2026-07-16 21:56:03.562",  // legacy toString(DateTime64), UTC by contract
	} {
		if got := parseCHTime(s); !got.Equal(want) {
			t.Errorf("parseCHTime(%q) = %v, want %v", s, got, want)
		}
		if got, ok := parseChTS(s); !ok || !got.Equal(want) {
			t.Errorf("parseChTS(%q) = %v ok=%v, want %v", s, got, ok, want)
		}
	}
	// Second-precision variants (DateTime columns).
	wantSec := want.Truncate(time.Second)
	for _, s := range []string{"2026-07-16T21:56:03Z", "2026-07-16 21:56:03"} {
		if got := parseCHTime(s); !got.Equal(wantSec) {
			t.Errorf("parseCHTime(%q) = %v, want %v", s, got, wantSec)
		}
	}
}

// isoTS (cloud signals) must pass the new already-RFC-3339 strings through
// untouched while still upgrading any legacy zone-less string.
func TestIsoTSPassthroughAndLegacy(t *testing.T) {
	if got := isoTS("2026-07-16T21:56:03.562Z"); got != "2026-07-16T21:56:03.562Z" {
		t.Fatalf("isoTS RFC 3339 passthrough broken: %q", got)
	}
	if got := isoTS("2026-07-16 21:56:03.562"); got != "2026-07-16T21:56:03.562Z" {
		t.Fatalf("isoTS legacy upgrade broken: %q", got)
	}
}

// The window-bound round trip (loadCorrSlice) validates RFC 3339 tokens.
func TestIsDatetimeTokenAcceptsRFC3339(t *testing.T) {
	for _, s := range []string{"2026-07-16T21:56:03.562Z", "2026-07-16 21:56:03.562", "2026-07-16 21:56:03"} {
		if !isDatetimeToken(s) {
			t.Errorf("isDatetimeToken(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"2026-07-16T21:56:03.562Z'; DROP", "x", ""} {
		if isDatetimeToken(s) {
			t.Errorf("isDatetimeToken(%q) = true, want false", s)
		}
	}
}

// Regression guard: no ClickHouse SELECT may reintroduce a zone-less
// toString() around a datetime column. Comments are exempt; chISO is the only
// sanctioned wrapper (it embeds toString with an explicit 'UTC' zone).
func TestNoZonelessDatetimeToStringInSQL(t *testing.T) {
	re := regexp.MustCompile(`toString\((min\(|max\(|any\()?([a-z]+\.)?(ts|created_at|window_start|window_end|ingest_ts|fused_at|observed_at)[),]`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, "toString(") && strings.Contains(line, ", 'UTC')") {
				continue // chISO-generated shape
			}
			if re.MatchString(line) {
				t.Errorf("%s:%d: zone-less toString() around a datetime column — use chISO (log-time standard S3): %s", name, i+1, trimmed)
			}
		}
	}
}
