package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// S3 (log-time standard): every ClickHouse-backed SELECT renders datetimes as
// explicit-UTC RFC 3339 — never zone-less toString() strings a JS Date would
// parse as browser-local. The fragment itself (chschema.ISO) is tested in its
// package; these tests cover THIS package's consumers of the wire format.

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
// toString() around a datetime column. Comments are exempt; chschema.ISO is
// the only sanctioned wrapper (it embeds toString with an explicit 'UTC'
// zone). The walk is RECURSIVE (root + all subpackages, vendor excluded) —
// SQL-emitting code now lives under internal/ too, and a root-only scan is
// exactly the guard-scope mistake the 2026-07-27 audit documented.
func TestNoZonelessDatetimeToStringInSQL(t *testing.T) {
	re := regexp.MustCompile(`toString\((min\(|max\(|any\()?([a-z]+\.)?(ts|created_at|window_start|window_end|ingest_ts|fused_at|observed_at)[),]`)
	seen := 0
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "testdata" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		seen++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, "toString(") && strings.Contains(line, ", 'UTC')") {
				continue // chschema.ISO-generated shape
			}
			if re.MatchString(line) {
				t.Errorf("%s:%d: zone-less toString() around a datetime column — use chschema.ISO (log-time standard S3): %s", path, i+1, trimmed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Anti-vacuity: the recursive walk must cover more than the root package.
	if seen < 300 {
		t.Fatalf("guard walked only %d non-test .go files — the scan is not reaching the subpackages", seen)
	}
}
