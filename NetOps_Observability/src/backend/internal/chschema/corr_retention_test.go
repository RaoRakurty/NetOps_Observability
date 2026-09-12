// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import (
	"strings"
	"testing"
)

// corr_retention_test.go — #101 retention contract guardrails. The retention
// layer must be (a) safe to re-run on every boot, (b) metadata-only on live
// multi-million-row tables, and (c) impossible to typo into instant deletion.

func TestCorrRetentionProfilesComplete(t *testing.T) {
	for _, p := range []string{"lab", "demo", "production", "extended"} {
		d, ok := corrRetentionProfiles[p]
		if !ok {
			t.Fatalf("missing retention profile %q", p)
		}
		// Every profile bounds every tier — "keep forever" is an explicit
		// per-knob override (0), never a profile default.
		if d.History <= 0 || d.Archive <= 0 || d.Closed <= 0 {
			t.Errorf("profile %q must bound every tier, got %+v", p, d)
		}
	}
}

func TestCorrRetentionEnvOverridesAndFloor(t *testing.T) {
	t.Setenv("CORR_RETENTION_PROFILE", "lab")
	t.Setenv("CORR_RETENTION_ARCHIVE_DAYS", "2") // below the 7-day safety floor
	t.Setenv("CORR_RETENTION_HISTORY_DAYS", "365")
	t.Setenv("CORR_RETENTION_CLOSED_DAYS", "0") // explicit keep-forever
	d := CorrRetentionConfig()
	if d.Archive != 7 {
		t.Errorf("sub-floor archive knob must clamp to 7, got %d", d.Archive)
	}
	if d.History != 365 {
		t.Errorf("history override not honored: %d", d.History)
	}
	if d.Closed != 0 {
		t.Errorf("0 must mean keep-forever (no TTL), got %d", d.Closed)
	}
	// 0 emits no corr_current TTL statement at all.
	for _, s := range CorrRetentionDDL(d) {
		if strings.Contains(s, "corr_current") {
			t.Errorf("Closed=0 must not emit a corr_current TTL: %s", s)
		}
	}
}

func TestCorrRetentionUnknownProfileFallsBack(t *testing.T) {
	t.Setenv("CORR_RETENTION_PROFILE", "yolo")
	if d := CorrRetentionConfig(); d != corrRetentionProfiles["production"] {
		t.Errorf("unknown profile must fall back to production, got %+v", d)
	}
}

func TestCorrRetentionDDLSafetyShape(t *testing.T) {
	stmts := CorrRetentionDDL(corrRetentionProfiles["production"])
	joined := strings.Join(stmts, "\n")
	// Every history/archive table gets part-level-only expiry (no TTL merges).
	for _, tbl := range []string{"corr_objects", "corr_edges", "corr_evidence", "corr_signals_archive"} {
		if !strings.Contains(joined, "ALTER TABLE netops."+tbl+" MODIFY SETTING ttl_only_drop_parts = 1") {
			t.Errorf("%s: missing ttl_only_drop_parts", tbl)
		}
		if !strings.Contains(joined, "ALTER TABLE netops."+tbl+" MODIFY TTL") {
			t.Errorf("%s: missing TTL", tbl)
		}
	}
	for _, s := range stmts {
		if strings.Contains(s, "MODIFY TTL") {
			// Metadata-only: a MODIFY TTL that materializes would rewrite a
			// 29.9M-row live table as a mutation storm.
			if !strings.Contains(s, "materialize_ttl_after_modify = 0") {
				t.Errorf("MODIFY TTL must not materialize: %s", s)
			}
		}
		if strings.Contains(s, "DROP") {
			t.Errorf("retention DDL must never DROP: %s", s)
		}
	}
	// corr_current expiry is row-level and only for rows that left 'open'.
	found := false
	for _, s := range stmts {
		if strings.Contains(s, "corr_current") {
			found = true
			if !strings.Contains(s, "DELETE WHERE state != 'open'") {
				t.Errorf("corr_current TTL must only expire non-open rows: %s", s)
			}
		}
	}
	if !found {
		t.Error("production profile must bound corr_current closed rows")
	}
}
