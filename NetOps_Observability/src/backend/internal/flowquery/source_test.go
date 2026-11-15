// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"strings"
	"testing"
	"time"
)

func utc(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

// A source with no rollup reads raw rows only; one whose rollup covers part of
// the scan reads rollup rows for exactly those received minutes and raw rows
// for the rest — never both for one minute.
func TestSourceSplitsReceivedMinutesBetweenRollupAndRaw(t *testing.T) {
	from, to := utc("2026-11-14T10:00:00Z"), utc("2026-11-14T11:00:00Z")
	raw := sourceSQL(Source{RawScope: " AND (tenant_id = 'acme')"}, from, to)
	if strings.Contains(raw, "flow_iface_1m") {
		t.Fatalf("no rollup configured, yet the rollup is read:\n%s", raw)
	}
	src := Source{
		RawScope: " AND (tenant_id = 'acme')", RollupScope: " AND (tenant_id = 'acme')",
		RollupLo: utc("2026-11-14T09:00:00Z"), RollupHi: utc("2026-11-14T10:30:00Z"), PlatformSig: 42,
	}
	sql := sourceSQL(src, from, to)
	for _, want := range []string{
		"FROM netops.flow_iface_1m FINAL",
		"WHERE platform_sig = 42",
		// Rollup: received minutes [window start, rollup end).
		"recv_minute >= toDateTime(1794650400, 'UTC') AND recv_minute < toDateTime(1794652200, 'UTC')",
		// Raw: from the rollup end to an hour and a minute past the window.
		"((ts >= toDateTime64(1794652200, 3, 'UTC') AND ts < toDateTime64(1794657660, 3, 'UTC')))",
		"UNION ALL",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("source missing %q:\n%s", want, sql)
		}
	}
	// A rollup that ends before the scan begins is not read at all.
	old := src
	old.RollupLo, old.RollupHi = utc("2026-11-13T00:00:00Z"), utc("2026-11-13T01:00:00Z")
	if strings.Contains(sourceSQL(old, from, to), "flow_iface_1m") {
		t.Error("a rollup outside the scan was read")
	}
}

// A minute belongs to a window when its START lies in [from, to): a window
// starting mid-minute begins at the next whole minute, so the current and the
// previous window never share one.
func TestWindowMinutesNeverOverlap(t *testing.T) {
	w := Window{From: utc("2026-11-14T10:00:30Z"), To: utc("2026-11-14T11:00:30Z")}
	if got := curCond(w); got != "minute >= toDateTime(1794650460, 'UTC')" {
		t.Errorf("curCond = %s", got)
	}
	sql := sourceSQL(Source{}, w.PrevFrom(), w.To)
	if !strings.Contains(sql, "minute >= toDateTime(1794646860, 'UTC') AND minute < toDateTime(1794654060, 'UTC')") {
		t.Errorf("window minutes:\n%s", sql)
	}
}

func TestDeclaredExprOnlyNamesItsKeys(t *testing.T) {
	if DeclaredExpr(nil) != "1" {
		t.Error("no declaration must read 1")
	}
	got := DeclaredExpr(map[DeclKey]uint32{{Tenant: "acme", Exporter: "10.0.0.1"}: 100, {Tenant: "globex", Exporter: "10.0.0.1"}: 0})
	want := "transform(concat(tid, '|', exporter), ['acme|10.0.0.1', 'globex|10.0.0.1'], [toUInt64(100), toUInt64(1)], toUInt64(1))"
	if got != want {
		t.Errorf("DeclaredExpr = %s", got)
	}
	// A hostile exporter string is quoted, never spliced.
	evil := DeclaredExpr(map[DeclKey]uint32{{Tenant: "a'b", Exporter: "x"}: 2})
	if strings.Contains(evil, "'a'b") {
		t.Errorf("unquoted key: %s", evil)
	}
}

func TestRollupInsertKeepsTheRowsTenantAndSplitsExactly(t *testing.T) {
	sql := RollupInsertSQL(utc("2026-11-14T10:00:20Z"), utc("2026-11-14T10:15:00Z"), "src_addr IN ('192.0.2.1')", 7)
	for _, want := range []string{
		"INSERT INTO netops.flow_iface_1m (" + RollupColumns + ")",
		"SELECT tid, minute, recv_minute, exporter, odid, ifx, dir, flow_type, rr, platform",
		"WHERE ts >= toDateTime64(1794650400, 3, 'UTC') AND ts < toDateTime64(1794651300, 3, 'UTC')",
		"tenant_id AS tid", // the row's own tenant, never a caller's
		"toUInt8(src_addr IN ('192.0.2.1')) AS pf",
		"GROUP BY tid, minute, recv_minute, exporter, odid, ifx, dir, flow_type, rr, platform",
		"toUInt64(7)",
		// The integer split: floor(total·cum(i)/dur) − floor(total·cum(i−1)/dur).
		"intDiv(toUInt128(sb) * toUInt128(least(e_ms, (m0 + toInt64(i) + 1) * 60000) - s_ms), toUInt128(dur_ms))",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("rollup insert missing %q:\n%s", want, sql)
		}
	}
	if strings.Contains(sql, "WITH FILL") || strings.Contains(sql, " AS bytes") || strings.Contains(sql, " AS ts") {
		t.Error("ClickHouse 24.8 traps: no WITH FILL, no alias shadowing bytes/ts")
	}
	if PlatformSignature("a") == PlatformSignature("b") || PlatformSignature(" a ") != PlatformSignature("a") {
		t.Error("platform signature must change with the condition and ignore surrounding space")
	}
}

func TestSamplingOfDeclared(t *testing.T) {
	for _, c := range []struct {
		fl, rr, decl float64
		want         string
	}{
		{0, 0, 0, SamplingNoFlows},
		{10, 0, 0, SamplingNotReported},
		{10, 10, 0, SamplingReported},
		{10, 0, 10, SamplingDeclared},
		{10, 4, 6, SamplingMixed},
		{10, 0, 4, SamplingMixed},
	} {
		if got := SamplingOfDeclared(c.fl, c.rr, c.decl); got != c.want {
			t.Errorf("SamplingOfDeclared(%v,%v,%v) = %s, want %s", c.fl, c.rr, c.decl, got, c.want)
		}
	}
}
