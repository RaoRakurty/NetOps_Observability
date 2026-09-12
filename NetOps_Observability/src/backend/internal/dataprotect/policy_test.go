// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

// policy_test.go — #150: the snapshot-policy control plane.
//
// Two halves, matching the surface's two risks:
//  1. the SM plumbing — the view must parse the real policy/explain shapes and
//     the update must perform the seq_no/primary_term dance (SM rejects a
//     token-less PUT — the apply-ism.sh bug class) and ride _start/_stop for
//     the enabled flip;
//  2. the stored INTENT — the api half of the 2026-09-03 bootstrap defect,
//     where a policy an operator deliberately stopped was silently re-enabled
//     on the next `docker compose up`.
//
// The §3a gate is injected and asserted by the integrator's route tests.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSnapshotPolicyViewParsesPolicyAndExplain(t *testing.T) {
	h := newHarness(t, newOSStub())
	v := h.svc.PolicyView(t.Context())

	if !v.Enabled {
		t.Error("enabled not parsed")
	}
	if v.ScheduleCron != "30 1 * * *" {
		t.Errorf("cron: %q", v.ScheduleCron)
	}
	if v.RetentionMaxCount != 14 {
		t.Errorf("retention: %d", v.RetentionMaxCount)
	}
	if v.RetentionMaxAgeDays != 0 {
		t.Errorf("no max_age in the policy must read as 0 (no age limit), got %d", v.RetentionMaxAgeDays)
	}
	if v.NextRun == "" {
		t.Error("next_run missing (explain trigger not parsed)")
	}
	if v.LastRun == nil || v.LastRun.Status != "SUCCESS" {
		t.Fatalf("last_run: %+v", v.LastRun)
	}
	if v.LastRun.DurationSeconds != 179 { // (1786066432336-1786066252803)/1000
		t.Errorf("duration: %d", v.LastRun.DurationSeconds)
	}
	if v.Detail != "" {
		t.Errorf("healthy read must carry no Detail, got %q", v.Detail)
	}
	// The repository registration is read INDEPENDENTLY of the policy: a
	// healthy policy over a dead repository is the 2026-08-27 state.
	if !v.Repository.Registered || v.Repository.Verified != nil || v.Repository.VerifiedDetail == "" {
		t.Errorf("repository not exposed honestly: %+v", v.Repository)
	}
}

func TestSnapshotPolicyViewParsesMaxAge(t *testing.T) {
	for expr, want := range map[string]int{"30d": 30, "336h": 14, "weird": 0} {
		stub := newOSStub()
		cond := stub.policy["deletion"].(map[string]any)["condition"].(map[string]any)
		cond["max_age"] = expr
		h := newHarness(t, stub)
		if v := h.svc.PolicyView(t.Context()); v.RetentionMaxAgeDays != want {
			t.Errorf("max_age %q: got %d, want %d", expr, v.RetentionMaxAgeDays, want)
		}
	}
}

func TestSnapshotPolicyViewIsHonestWhenUnreadable(t *testing.T) {
	stub := newOSStub()
	stub.failPolicyGET = true
	h := newHarness(t, stub)

	v := h.svc.PolicyView(t.Context())
	if v.Detail == "" {
		t.Fatal("unreadable policy must set Detail — a blank panel reads as healthy")
	}
	if v.ManagedBy != "unknown" || v.ManagedByDetail == "" {
		t.Errorf("an unreadable policy has an unknown writer, said out loud: %q / %q", v.ManagedBy, v.ManagedByDetail)
	}
}

func TestSMApplyUpdateDoesTheSeqNoDanceAndStartStop(t *testing.T) {
	h := newHarness(t, newOSStub())

	cron := "0 2 * * *"
	keep := 21
	age := 30
	off := false
	if err := h.svc.smApplyUpdate(t.Context(), snapshotPolicyUpdate{
		ScheduleCron: &cron, RetentionMaxCount: &keep, RetentionMaxAgeDays: &age, Enabled: &off,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	q, body := h.stub.lastPolicyPut()
	if !strings.Contains(q, "if_seq_no=1573863") || !strings.Contains(q, "if_primary_term=19") {
		t.Errorf("PUT missing concurrency token: %q", q)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("PUT body: %v", err)
	}
	if got := digMap(doc, "creation", "schedule", "cron", "expression"); got != "0 2 * * *" {
		t.Errorf("cron not applied: %v", got)
	}
	if got := digMap(doc, "deletion", "condition", "max_count"); got != float64(21) {
		t.Errorf("retention not applied: %v", got)
	}
	if got := digMap(doc, "deletion", "condition", "max_age"); got != "30d" {
		t.Errorf("max_age not applied as days: %v", got)
	}
	// Server-side bookkeeping fields must be stripped before the PUT — SM
	// rejects them on write.
	for _, k := range []string{"schema_version", "last_updated_time"} {
		if _, present := doc[k]; present {
			t.Errorf("PUT body still carries %s", k)
		}
	}
	start, stop := h.stub.startStop()
	if stop != 1 {
		t.Errorf("enabled=false must ride _stop exactly once, got %d", stop)
	}
	if start != 0 {
		t.Errorf("_start must not fire on a disable")
	}
}

func TestSMApplyUpdateMaxAgeZeroClearsTheCondition(t *testing.T) {
	stub := newOSStub()
	cond := stub.policy["deletion"].(map[string]any)["condition"].(map[string]any)
	cond["max_age"] = "30d"
	h := newHarness(t, stub)

	zero := 0
	if err := h.svc.smApplyUpdate(t.Context(), snapshotPolicyUpdate{RetentionMaxAgeDays: &zero}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	_, body := h.stub.lastPolicyPut()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("PUT body: %v", err)
	}
	if got := digMap(doc, "deletion", "condition", "max_age"); got != nil {
		t.Errorf("max_age=0 must remove the condition, PUT body still carries %v", got)
	}
	// The count condition must survive the round trip — 0 clears ONLY the age.
	if got := digMap(doc, "deletion", "condition", "max_count"); got != float64(14) {
		t.Errorf("max_count lost in the round trip: %v", got)
	}
}

// TestSnapshotPolicyPutValidation — garbage cron and out-of-range retention are
// 400s, and an EMPTY update is refused rather than silently acknowledged.
func TestSnapshotPolicyPutValidation(t *testing.T) {
	h := newHarness(t, newOSStub())
	for _, bad := range []map[string]any{
		{"schedule_cron": "not-a-cron"},
		{"retention_max_count": 0},
		{"retention_max_count": 400},
		{"retention_max_age_days": -1},
		{"retention_max_age_days": 4000},
		{},
	} {
		if st, b := h.do(t, "PUT", "/api/system/backup/snapshots", bad); st != 400 {
			t.Errorf("bad update %v must 400, got %d (%s)", bad, st, b)
		}
	}
	// A valid partial update round-trips.
	if st, b := h.do(t, "PUT", "/api/system/backup/snapshots", map[string]any{"retention_max_count": 21}); st != 200 {
		t.Fatalf("valid PUT: %d %s", st, b)
	}
}

// ── the intent store (the 2026-09-03 bootstrap defect) ──────────────────────

func TestSnapshotScheduleIntentIsStoredAndExposed(t *testing.T) {
	h := newHarness(t, newOSStub())

	// Fresh install: no deliberate stop on record.
	if enabled, reason, at, by := h.svc.SnapshotScheduleIntent(); !enabled || reason != "" || !at.IsZero() || by != "" {
		t.Fatalf("fresh intent: %v %q %v %q", enabled, reason, at, by)
	}

	// Disable through the GUI.
	st, b := h.do(t, "PUT", "/api/system/backup/snapshots",
		map[string]any{"enabled": false, "reason": "restore drill in progress"})
	if st != 200 {
		t.Fatalf("disable: %d %s", st, b)
	}
	enabled, reason, at, by := h.svc.SnapshotScheduleIntent()
	if enabled {
		t.Fatal("the stored intent must be DISABLED — this is exactly what the bootstrap silently overrode")
	}
	if reason != "restore drill in progress" || at.IsZero() || by == "" {
		t.Errorf("intent: %q %v %q", reason, at, by)
	}

	// It is exposed on the existing GET, additively.
	st, b = h.do(t, "GET", "/api/system/backup/snapshots", nil)
	if st != 200 {
		t.Fatalf("policy GET: %d %s", st, b)
	}
	var view SnapshotPolicyView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.DisabledReason != "restore drill in progress" || view.DisabledAt == "" || view.DisabledBy == "" {
		t.Errorf("disabled_* not exposed: %+v", view)
	}
	if view.ManagedBy != "gui" {
		t.Errorf("managed_by: %q", view.ManagedBy)
	}
	// The existing shape is untouched.
	if view.ScheduleCron != "30 1 * * *" || view.RetentionMaxCount != 14 {
		t.Errorf("the existing policy shape regressed: %+v", view)
	}

	// A backup-config PUT must NOT clear the intent (§3a.2: never from the body).
	st, b = h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "rsync://nas/backups", "schedule_enabled": false,
		"snapshot_schedule_disabled_at": time.Time{}, "snapshot_schedule_disabled_by": "attacker",
		"snapshot_schedule_disabled_reason": "forged",
	})
	if st != 200 {
		t.Fatalf("backup config PUT: %d %s", st, b)
	}
	enabled, reason, _, by = h.svc.SnapshotScheduleIntent()
	if enabled || reason != "restore drill in progress" || by == "attacker" {
		t.Errorf("a backup-config PUT rewrote the snapshot intent: %v %q %q", enabled, reason, by)
	}

	// Re-enabling clears the stop record.
	if st, b = h.do(t, "PUT", "/api/system/backup/snapshots", map[string]any{"enabled": true}); st != 200 {
		t.Fatalf("enable: %d %s", st, b)
	}
	if enabled, _, _, _ = h.svc.SnapshotScheduleIntent(); !enabled {
		t.Error("re-enabling must clear the deliberate-stop record")
	}

	// Reason bounds.
	if st, _ = h.do(t, "PUT", "/api/system/backup/snapshots",
		map[string]any{"enabled": false, "reason": strings.Repeat("x", 201)}); st != 400 {
		t.Errorf("over-long reason must 400, got %d", st)
	}
}

// TestSnapshotPolicyManagedBy — the closed vocabulary, resolved from evidence.
// The value that matters operationally is "external": it is what an operator
// sees when a redeploy's bootstrap overwrote a policy they set by hand.
func TestSnapshotPolicyManagedBy(t *testing.T) {
	base := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name                  string
		lastUpdated, ourWrite time.Time
		want                  string
		wantDetail            string
	}{
		{"no last_updated_time", time.Time{}, base, "unknown", "cannot be determined"},
		{"never written by this api", base, time.Time{}, "policy-file", "apply-ism.sh"},
		{"our write is the newest", base, base.Add(time.Second), "gui", "stored GUI intent"},
		{"within the skew tolerance", base.Add(30 * time.Second), base, "gui", "stored GUI intent"},
		{"someone wrote after us", base.Add(time.Hour), base, "external", "AFTER this api's last write"},
	}
	for _, tc := range cases {
		got, detail := snapshotPolicyManagedBy(tc.lastUpdated, tc.ourWrite)
		if got != tc.want {
			t.Errorf("%s: managed_by = %q, want %q", tc.name, got, tc.want)
		}
		if !strings.Contains(detail, tc.wantDetail) {
			t.Errorf("%s: detail %q does not explain the verdict (want %q)", tc.name, detail, tc.wantDetail)
		}
	}
}

func TestSnapshotPolicyManagedByOverTheRoute(t *testing.T) {
	h := newHarness(t, newOSStub())

	read := func() SnapshotPolicyView {
		t.Helper()
		st, b := h.do(t, "GET", "/api/system/backup/snapshots", nil)
		if st != 200 {
			t.Fatalf("policy GET: %d %s", st, b)
		}
		var v SnapshotPolicyView
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return v
	}

	// Before this api has ever written: the bootstrap is the shipped writer,
	// and the detail admits a hand edit reads the same.
	before := read()
	if before.ManagedBy != "policy-file" {
		t.Errorf("managed_by before any GUI write = %q, want policy-file", before.ManagedBy)
	}
	if before.ManagedByDetail == "" {
		t.Error("managed_by must always ship its detail")
	}

	// After a GUI PUT: ours is the newest write.
	if st, b := h.do(t, "PUT", "/api/system/backup/snapshots", map[string]any{"retention_max_count": 21}); st != 200 {
		t.Fatalf("policy PUT: %d %s", st, b)
	}
	if after := read(); after.ManagedBy != "gui" {
		t.Errorf("managed_by after a GUI write = %q, want gui", after.ManagedBy)
	}
}
