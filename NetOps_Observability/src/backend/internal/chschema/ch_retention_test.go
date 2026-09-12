// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ch_retention_test.go — F-58 guard tests.
//
// These are deliberately SOURCE-SCANNING (the architecture_guards_test.go
// family), because the defect was never in one table: it was that init.sql was
// the only place a TTL existed, so every table added afterwards inherited the
// same silence. A point assertion on `findings` would pass while the next
// table repeats the bug. These fail the build on the NEXT instance.

var (
	reCreateTable = regexp.MustCompile(`(?m)^CREATE TABLE IF NOT EXISTS netops\.(\w+)`)
	reTTLLine     = regexp.MustCompile(`(?m)^TTL\s+(.+?)\s*\+\s*INTERVAL\s+(\d+)\s+DAY`)
)

// initSQLTTLs parses init.sql into table -> (expr, days) for every TTL'd table.
func initSQLTTLs(t *testing.T) map[string]struct {
	Expr string
	Days int
} {
	t.Helper()
	path := repoFile(t, filepath.Join("deployment", "docker", "clickhouse", "init.sql"))
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative test fixture
	if err != nil {
		t.Fatalf("read init.sql: %v", err)
	}
	out := map[string]struct {
		Expr string
		Days int
	}{}
	// Walk the file linearly: a TTL line belongs to the most recent CREATE.
	var current string
	for _, line := range strings.Split(string(raw), "\n") {
		if m := reCreateTable.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if m := reTTLLine.FindStringSubmatch(line); m != nil && current != "" {
			days, err := strconv.Atoi(m[2])
			if err != nil {
				t.Fatalf("unparsable TTL interval for %s: %q", current, m[2])
			}
			out[current] = struct {
				Expr string
				Days int
			}{Expr: strings.TrimSpace(m[1]), Days: days}
			current = ""
		}
	}
	if len(out) < 10 {
		t.Fatalf("parsed only %d TTL'd tables from init.sql — the parser has drifted from the file", len(out))
	}
	return out
}

// corrOwned are the tables whose TTL belongs to corr_retention.go. Two owners
// for one TTL is how drift starts, so they must NOT appear in chRetentionTables.
var corrOwned = map[string]bool{
	"corr_objects":         true,
	"corr_edges":           true,
	"corr_evidence":        true,
	"corr_signals_archive": true,
	"corr_current":         true,
}

// TestEveryInitSQLTTLIsConverged is THE guard for F-58: a TTL that lives only
// in init.sql is a TTL that no existing installation has. Adding a TTL'd table
// without a converge entry fails here.
func TestEveryInitSQLTTLIsConverged(t *testing.T) {
	declared := initSQLTTLs(t)
	converged := map[string]chRetentionTable{}
	for _, ct := range chRetentionTables() {
		converged[ct.Table] = ct
	}
	for table := range declared {
		if corrOwned[table] {
			if _, dup := converged[table]; dup {
				t.Errorf("netops.%s has TWO retention owners (corr_retention.go and ch_retention.go)", table)
			}
			continue
		}
		if _, ok := converged[table]; !ok {
			t.Errorf("netops.%s carries a TTL in init.sql but nothing converges it — "+
				"a pre-existing install will never get it and will grow forever (F-58). "+
				"Add it to chRetentionTables().", table)
		}
	}
}

// TestConvergedTTLExpressionsMatchInitSQL: a MODIFY TTL over the wrong column
// silently reschedules deletion against a different clock (e.g. insert time
// instead of event time).
func TestConvergedTTLExpressionsMatchInitSQL(t *testing.T) {
	declared := initSQLTTLs(t)
	for _, ct := range chRetentionTables() {
		d, ok := declared[ct.Table]
		if !ok {
			t.Errorf("chRetentionTables() converges netops.%s, which has no TTL in init.sql — "+
				"a fresh install and an upgraded one would disagree", ct.Table)
			continue
		}
		if d.Expr != ct.Expr {
			t.Errorf("netops.%s TTL expression mismatch: init.sql %q vs converge %q",
				ct.Table, d.Expr, ct.Expr)
		}
	}
}

// TestNoConvergedDefaultShrinksRetention is the MIGRATION guard, and the one
// that matters most operationally: MODIFY TTL is a deletion schedule, so a
// default shorter than the declared value would destroy existing rows on the
// first boot after an upgrade — the F-63 lesson (a fix correct for a fresh
// install and destructive for an existing one).
func TestNoConvergedDefaultShrinksRetention(t *testing.T) {
	declared := initSQLTTLs(t)
	d := chRetentionDefaults()
	for _, ct := range chRetentionTables() {
		want, ok := declared[ct.Table]
		if !ok {
			continue // reported by TestConvergedTTLExpressionsMatchInitSQL
		}
		got := ct.Days(d)
		if got > 0 && got < want.Days {
			t.Errorf("netops.%s default retention %dd is SHORTER than the declared %dd — "+
				"the first boot after this change would delete %d days of data",
				ct.Table, got, want.Days, want.Days-got)
		}
	}
}

// TestCHRetentionDDLIsMetadataOnly: without materialize_ttl_after_modify=0 a
// MODIFY TTL launches a full-table mutation, which on netops.flows is a
// multi-million-row rewrite triggered by an ordinary API restart.
func TestCHRetentionDDLIsMetadataOnly(t *testing.T) {
	for _, s := range RetentionDDL(chRetentionDefaults()) {
		if !strings.Contains(s, "materialize_ttl_after_modify = 0") {
			t.Errorf("TTL statement is not metadata-only (would rewrite the table): %s", s)
		}
		if !strings.HasPrefix(s, "ALTER TABLE netops.") {
			t.Errorf("unexpected retention statement shape: %s", s)
		}
	}
}

// TestCHRetentionZeroDisablesRatherThanStrips: emitting a bare `MODIFY TTL`
// would REMOVE the table's TTL. "Keep forever" must mean "leave it alone",
// never "silently delete the retention policy".
func TestCHRetentionZeroDisablesRatherThanStrips(t *testing.T) {
	d := chRetentionDefaults()
	d.Flows = 0
	for _, s := range RetentionDDL(d) {
		if strings.Contains(s, "netops.flows ") {
			t.Fatalf("a zeroed knob must emit NO statement for that table, got: %s", s)
		}
	}
}

// TestCHRetentionFloorClampsUp: a typo must be able to slow retention down,
// never turn it into near-instant deletion.
func TestCHRetentionFloorClampsUp(t *testing.T) {
	t.Setenv("CH_FLOWS_RETENTION_DAYS", "1")
	if got := RetentionConfig().Flows; got != 7 {
		t.Errorf("sub-floor retention must clamp to the 7-day floor, got %d", got)
	}
	t.Setenv("CH_FLOWS_RETENTION_DAYS", "banana")
	if got := RetentionConfig().Flows; got != chRetentionDefaults().Flows {
		t.Errorf("invalid retention must fall back to the default, got %d", got)
	}
	t.Setenv("CH_FLOWS_RETENTION_DAYS", "0")
	if got := RetentionConfig().Flows; got != 0 {
		t.Errorf("0 must mean 'unmanaged', got %d", got)
	}
}

// TestRetentionRunsAfterSchemaCreation: an ALTER emitted before the CREATE of
// the SAME table fails on every fresh volume — and because chExecAll never
// stops at the first error, it fails quietly on every boot forever, which is
// how a retention policy ends up documented but not applied.
//
// Checked per table rather than globally: the converge list interleaves
// several schema families, so "no CREATE anywhere after any ALTER" would be
// both wrong and unmaintainable.
