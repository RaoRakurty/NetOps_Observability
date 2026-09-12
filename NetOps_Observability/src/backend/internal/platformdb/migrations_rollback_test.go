// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

// migrations_rollback_test.go — a rollback that does not delete its own
// schema_migrations row leaves the database SILENTLY broken.
//
// Migrate() is forward-only: it records every applied file in schema_migrations
// and NEVER removes a row. So when an operator runs a .down.sql that drops the
// tables (or columns) a migration created, the version row survives, Migrate()
// skips that file on the next boot, and the API comes up reporting HEALTHY
// against a schema that no longer has the objects its queries name. The failure
// then arrives at the first request that touches the dropped table, in
// production, with nothing in the boot log to explain it.
//
// 0023 and 0024 got this right from the start. Twenty other rollbacks did not.
// This test is the guard: it fails on the twenty-first.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	rollbackDir    = "migrations/rollback"
	rollbackSuffix = ".down.sql"
)

// rollbackFiles lists the rollback scripts on disk. They are deliberately NOT
// embedded (the go:embed pattern is `migrations/*.sql`, which does not descend
// into this subdirectory), so nothing can run them automatically — they are an
// operator action, and this test reads them from the source tree.
func rollbackFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(rollbackDir)
	if err != nil {
		t.Fatalf("read %s: %v", rollbackDir, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), rollbackSuffix) {
			out = append(out, e.Name())
		}
	}
	if len(out) == 0 {
		t.Fatalf("no %s files under %s — this guard would pass vacuously", rollbackSuffix, rollbackDir)
	}
	return out
}

// migrationVersionFor maps a rollback file name to the schema_migrations
// version string it must remove: 0030_wireless_inventory.down.sql undoes the
// row recorded for 0030_wireless_inventory.sql. Migrate() records the FILE
// NAME, so the two must agree exactly.
func migrationVersionFor(name string) string {
	return strings.TrimSuffix(name, rollbackSuffix) + ".sql"
}

func TestEveryRollbackDeletesItsSchemaMigrationsRow(t *testing.T) {
	for _, name := range rollbackFiles(t) {
		version := migrationVersionFor(name)

		// The rollback must undo a migration this build actually applies —
		// otherwise it is dead text, and the version string below is a guess.
		if _, err := MigrationsFS.ReadFile("migrations/" + version); err != nil {
			t.Errorf("%s claims to roll back %q, which is not an embedded migration: %v", name, version, err)
			continue
		}

		body, err := os.ReadFile(filepath.Join(rollbackDir, name)) // #nosec G304 -- name came from the ReadDir above
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// The exact statement the two correct rollbacks (0023, 0024) already
		// carry. Matching on the literal keeps the guard honest: a DELETE that
		// names a DIFFERENT version would leave this migration's own row behind
		// and take an unrelated one with it.
		want := fmt.Sprintf("DELETE FROM schema_migrations WHERE version = '%s';", version)
		if !strings.Contains(string(body), want) {
			t.Errorf("%s drops schema objects but never removes its schema_migrations row.\n"+
				"  The migrator is forward-only and deletes no row itself, so after this rollback\n"+
				"  %q is still recorded as applied: it never re-applies and the API boots HEALTHY\n"+
				"  against the missing objects.\n"+
				"  Add, as 0023/0024 do:\n    %s",
				name, version, want)
		}
	}
}

// TestTheMigratorNeverRemovesAVersionRow pins the premise the test above rests
// on. If the RUNNER ever starts deleting rows itself, the rule changes and this
// failure is the prompt to revisit it rather than a silent divergence.
func TestTheMigratorNeverRemovesAVersionRow(t *testing.T) {
	src, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	if strings.Contains(string(src), "DELETE FROM schema_migrations") {
		t.Fatal("db.go now deletes schema_migrations rows itself — re-derive the rollback rule in " +
			"TestEveryRollbackDeletesItsSchemaMigrationsRow before relaxing it")
	}
}

// TestRollbacksAreNotEmbedded: a rollback must never be reachable by Migrate().
// The forward loop applies every embedded migrations/*.sql in lexical order, so
// an embedded .down.sql would be applied as if it were a migration.
func TestRollbacksAreNotEmbedded(t *testing.T) {
	entries, err := MigrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), rollbackSuffix) || e.Name() == "rollback" {
			t.Errorf("%q is embedded under migrations/ — Migrate() would apply it as a forward migration", e.Name())
		}
	}
}
