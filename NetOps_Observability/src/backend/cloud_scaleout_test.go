package main

// cloud_scaleout_test.go — #10 "scale-out the tables": keyset cursor + server-side
// free-text search on the cloud signal surfaces. The cursor and the search needle
// both end up inside SQL literals, so the tests here are first about SAFETY
// (charset gates, escaping) and then about the keyset semantics.

import (
	"strings"
	"testing"

	"netops/backend/cloud"
)

func TestSignalCursorRoundTrip(t *testing.T) {
	ts, id := "2026-07-17 03:04:05.123", "9f0c2a4e-7b1d-4e2a-9d3c-000000000001"
	tok := cloud.EncodeSignalCursor(ts, id)
	gotTS, gotID, err := cloud.DecodeSignalCursor(tok)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if gotTS != ts || gotID != id {
		t.Fatalf("round-trip mangled: %q %q", gotTS, gotID)
	}
}

func TestSignalCursorFailsClosed(t *testing.T) {
	bad := []string{
		"not-base64!!!",
		"",                                 // empty
		cloud.EncodeSignalCursor("", "id"), // empty ts
		cloud.EncodeSignalCursor("2026-07-17", ""),                      // empty id
		cloud.EncodeSignalCursor("2026-07-17'; DROP", "x"),              // quote in ts
		cloud.EncodeSignalCursor("2026-07-17", "id' OR 1=1--"),          // quote in id
		cloud.EncodeSignalCursor(strings.Repeat("1", 41), "x"),          // ts too long
		cloud.EncodeSignalCursor("2026-07-17", strings.Repeat("a", 81)), // id too long
		"djF8YXxi", // "v1|a|b" — wrong version tag
	}
	for _, c := range bad {
		if _, _, err := cloud.DecodeSignalCursor(c); err == nil {
			t.Fatalf("cursor %q must fail closed", c)
		}
	}
}

func TestSignalSearchSQLEscapesNeedle(t *testing.T) {
	frag := cloud.SignalSearchSQL(`web'; DROP TABLE x; --\`)
	if !strings.Contains(frag, `positionCaseInsensitive`) {
		t.Fatalf("search must be a positionCaseInsensitive needle:\n%s", frag)
	}
	// The quote and backslash must be escaped so the term cannot close the literal.
	if !strings.Contains(frag, `web\'; DROP TABLE x; --\\`) {
		t.Fatalf("needle not escaped:\n%s", frag)
	}
	if cloud.SignalSearchSQL("") != "" {
		t.Fatal("empty search must add no predicate")
	}
}

func TestClampSignalQueryBounds(t *testing.T) {
	if got := cloud.ClampSignalQuery("  db-main  "); got != "db-main" {
		t.Fatalf("trim: %q", got)
	}
	if got := cloud.ClampSignalQuery("a\x00b\x1fc"); got != "abc" {
		t.Fatalf("control chars must be stripped: %q", got)
	}
	long := strings.Repeat("x", cloud.SignalQueryMaxLen+50)
	if got := cloud.ClampSignalQuery(long); len(got) != cloud.SignalQueryMaxLen {
		t.Fatalf("cap: %d", len(got))
	}
}

// The keyset fragments must express "strictly before the cursor position" with
// the signal id as tie-breaker, and the builders must order by the SAME total
// order — otherwise pages can skip or repeat rows.
func TestSignalKeysetMatchesOrder(t *testing.T) {
	pred := cloud.SignalCursorPredSQL("2026-07-17 01:02:03", "abc")
	for _, want := range []string{
		"ts < parseDateTime64BestEffort('2026-07-17 01:02:03')",
		"toString(signal_id) < 'abc'",
	} {
		if !strings.Contains(pred, want) {
			t.Fatalf("missing %q in:\n%s", want, pred)
		}
	}
	if cloud.SignalCursorPredSQL("", "") != "" {
		t.Fatal("no cursor must add no predicate")
	}

	health := cloud.HealthSQL(24, pred, 100, "acme")
	if !strings.Contains(health, "ORDER BY ts DESC, signal_id DESC") {
		t.Fatalf("health must order by the keyset total order:\n%s", health)
	}
	if !strings.Contains(health, "toString(signal_id)     AS signal_id_s") {
		t.Fatalf("health page must carry the id the next cursor needs:\n%s", health)
	}

	having := cloud.ChangesCursorHavingSQL("2026-07-17 01:02:03", "abc")
	if !strings.Contains(having, "HAVING min(ts) <") {
		t.Fatalf("changes keyset must run after the GROUP BY collapse:\n%s", having)
	}
	changes := cloud.ChangesSQL(24, "", having, 100, "acme")
	if !strings.Contains(changes, "ORDER BY ts_s DESC, signal_id_s DESC") {
		t.Fatalf("changes must order by the keyset total order:\n%s", changes)
	}
	if strings.Index(changes, "GROUP BY signal_id") > strings.Index(changes, "HAVING") {
		t.Fatalf("HAVING must follow GROUP BY:\n%s", changes)
	}

	evidence := cloud.EvidenceSignalsSQL(24, "'a'", pred, 100, "acme")
	if !strings.Contains(evidence, "ORDER BY ts DESC, signal_id DESC") {
		t.Fatalf("evidence must order by the keyset total order:\n%s", evidence)
	}
}

func TestNextSignalCursorOnlyOnFullPage(t *testing.T) {
	if got := cloud.NextSignalCursor("2026-07-17 01:02:03", "abc", 100, 100); got == "" {
		t.Fatal("full page must emit a next cursor")
	}
	if got := cloud.NextSignalCursor("2026-07-17 01:02:03", "abc", 40, 100); got != "" {
		t.Fatal("short page must not emit a next cursor")
	}
	if got := cloud.NextSignalCursor("", "", 100, 100); got != "" {
		t.Fatal("missing keys must not emit a cursor")
	}
}

// The scoped-query guarantee (§3a) must hold with the new fragments in place:
// search + cursor ride INSIDE the tenant-scoped, bounded query.
func TestScaleoutFragmentsStayInsideScopedQuery(t *testing.T) {
	pred := cloud.SignalSearchSQL("db") + cloud.SignalCursorPredSQL("2026-07-17 01:02:03", "abc")
	q := cloud.HealthSQL(24, pred, 100, "acme")
	if !strings.Contains(q, "SETTINGS tenant_scope = 'acme'") {
		t.Fatalf("scope lost:\n%s", q)
	}
	if !strings.Contains(q, "LIMIT") || !strings.Contains(q, "INTERVAL") {
		t.Fatalf("bounds lost:\n%s", q)
	}
}
