// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// policies_test.go — guards for the statements ConvergeStmts emits itself
// (the per-family DDL is asserted next to its own builder).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findingsDedupALTER is the exact statement boot convergence must emit.
//
// netops.findings is created by init.sql, not by Go, so this ALTER is the ONLY
// thing that brings an existing install up to the dedup guarantee the
// correlation service's retry path now depends on: an insert whose outcome is
// UNKNOWN (a transport read error mid-flight — storm-s03, 2026-08-29) is
// re-sent under a deterministic insert_deduplication_token, and without the
// window the server has nothing to match that token against, so the retry
// appends a second row instead of being dropped. Before it, the correlation
// service could not retry findings at all and counted such a write LOST.
const findingsDedupALTER = "ALTER TABLE netops.findings MODIFY SETTING non_replicated_deduplication_window = 1000"

func TestFindingsDedupWindowIsConverged(t *testing.T) {
	stmts := ConvergeStmts()
	n := 0
	for _, s := range stmts {
		if s == findingsDedupALTER {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("boot converge list carries the findings dedup ALTER %d times, want exactly 1:\n\t%s",
			n, findingsDedupALTER)
	}
}

func TestFindingsDedupALTERIsIdempotentAndOrdered(t *testing.T) {
	stmts := ConvergeStmts()
	alterAt, createAt := -1, -1
	for i, s := range stmts {
		switch {
		case s == findingsDedupALTER:
			alterAt = i
		case strings.Contains(s, "CREATE TABLE IF NOT EXISTS netops.findings"):
			if createAt < 0 {
				createAt = i
			}
		}
	}
	if alterAt < 0 {
		t.Fatal("no findings dedup ALTER in the converge list")
	}
	// MODIFY SETTING writes a fixed value: re-running it is a no-op, which is
	// what makes it safe on every boot. It has no IF NOT EXISTS form, so the
	// idempotency has to come from the statement's own shape.
	if !strings.Contains(findingsDedupALTER, "MODIFY SETTING") ||
		strings.Contains(findingsDedupALTER, "ADD ") {
		t.Errorf("the findings dedup migration must be an idempotent MODIFY SETTING: %s", findingsDedupALTER)
	}
	// If netops.findings is ever CREATEd from Go too, the ALTER must follow it
	// — chExecAll continues past errors, so an ALTER before its CREATE fails
	// silently on every fresh volume (the F-58 ordering rule).
	if createAt >= 0 && createAt > alterAt {
		t.Errorf("findings dedup ALTER at index %d runs BEFORE its CREATE at index %d", alterAt, createAt)
	}
}

// TestFindingsDedupWindowInInitSQL keeps the fresh-install schema in lockstep
// with boot convergence: a fresh volume never runs the ALTER's remedial path,
// so if the CREATE lacks the setting, a brand-new install is the one place the
// findings retry is unsafe — the worst possible place for it to be missing.
func TestFindingsDedupWindowInInitSQL(t *testing.T) {
	path := repoFile(t, filepath.Join("deployment", "docker", "clickhouse", "init.sql"))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read init.sql: %v", err)
	}
	src := string(b)
	i := strings.Index(src, "CREATE TABLE IF NOT EXISTS netops.findings")
	if i < 0 {
		t.Fatal("init.sql no longer creates netops.findings")
	}
	// Strip line comments BEFORE looking for the terminator: init.sql's column
	// comments contain semicolons (the tenant_id note does), and splitting on
	// the raw text truncated the statement before its SETTINGS clause.
	var b2 strings.Builder
	for _, ln := range strings.Split(src[i:], "\n") {
		if c := strings.Index(ln, "--"); c >= 0 {
			ln = ln[:c]
		}
		b2.WriteString(ln)
		b2.WriteString("\n")
		if strings.Contains(ln, ";") {
			break
		}
	}
	stmt := b2.String()
	if !strings.Contains(stmt, "non_replicated_deduplication_window = 1000") {
		t.Errorf("netops.findings CREATE in init.sql is missing "+
			"non_replicated_deduplication_window = 1000 — a fresh install could not "+
			"safely retry an ambiguous findings insert:\n%s", stmt)
	}
}
