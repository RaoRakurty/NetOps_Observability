// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

// coverage_test.go — the per-engine coverage table.
//
// The value of this surface is entirely in its HONESTY, so that is what is
// tested. The invariants below are written as explicit, per-field checks over
// the whole payload (no reflection): every row must say WHY it reports what it
// reports, and every null must ship with a sibling detail explaining the null.
// A row that quietly reports "covered" with an empty reason, or a null RPO with
// no rpo_detail, is exactly the shape of the 2026-08-27 incident — every
// surface said "fine" while every restore point was unrestorable.
//
// No org-isolation test, deliberately: this route returns the PLATFORM's backup
// posture, not tenant data (CLAUDE.md §3a rule 3). The only isolation question
// that applies — that a tenant admin cannot read it at all — is the injected
// gate's, and the integrator asserts it over the real mux.

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBackupCoverageHonestyInvariants is the table-driven guard over the WHOLE
// payload. It runs twice — once with no host backup report (the shipped state)
// and once with a successful one — because the two states exercise different
// branches of every bundle-derived row.
func TestBackupCoverageHonestyInvariants(t *testing.T) {
	for _, withReport := range []bool{false, true} {
		name := "no-backup-report"
		if withReport {
			name = "successful-backup-report"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, newOSStub())
			if withReport {
				writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-03T02:31:00Z","size_bytes":91234,"duration_seconds":61,"failures":0,"artifact":"correlix-2026-09-03.tar.zst"}`)
			}

			st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
			if st != 200 {
				t.Fatalf("coverage: %d %s", st, b)
			}
			var view BackupCoverageView
			if err := json.Unmarshal(b, &view); err != nil {
				t.Fatalf("decode: %v (%s)", err, b)
			}

			// Exactly the seven engines the contract names, in a stable order.
			wantIDs := []string{
				"opensearch", "system_bundle", "postgres", "clickhouse",
				"victoriametrics", "secrets_tls", "device_configs",
			}
			if len(view.Engines) != len(wantIDs) {
				t.Fatalf("got %d engine rows, want %d", len(view.Engines), len(wantIDs))
			}
			for i, want := range wantIDs {
				if view.Engines[i].ID != want {
					t.Errorf("engine[%d] = %q, want %q", i, view.Engines[i].ID, want)
				}
			}

			validVerdict := map[string]bool{
				CoverageYes: true, CoverageNo: true, CoverageNotApplicable: true, CoverageUnknown: true,
			}
			validTarget := map[string]bool{
				TargetNone: true, TargetLocal: true, TargetRemote: true, TargetOffsite: true,
			}

			for _, row := range view.Engines {
				t.Run(row.ID, func(t *testing.T) {
					if row.Name == "" {
						t.Error("no human name")
					}
					if !validVerdict[row.Covered] {
						t.Errorf("covered = %q, outside the closed vocabulary", row.Covered)
					}
					// THE headline invariant: a reason on EVERY verdict,
					// including "yes". An operator must be able to read why.
					if strings.TrimSpace(row.CoveredReason) == "" {
						t.Errorf("covered=%q with NO covered_reason — an unexplained verdict is the thing this page exists to stop", row.Covered)
					}
					if !validTarget[row.Target.Kind] {
						t.Errorf("target.kind = %q, outside the closed vocabulary", row.Target.Kind)
					}

					// Every nullable field ships with a sibling detail.
					if row.Target.Immutable == nil && strings.TrimSpace(row.Target.ImmutableDetail) == "" {
						t.Error("immutable is null with no immutable_detail")
					}
					if row.Target.Encrypted == nil && strings.TrimSpace(row.Target.EncryptedDetail) == "" {
						t.Error("encrypted is null with no encrypted_detail")
					}
					if row.SizeBytes == nil && strings.TrimSpace(row.SizeDetail) == "" {
						t.Error("size_bytes is null with no size_detail")
					}
					if row.RPOHours == nil && strings.TrimSpace(row.RPODetail) == "" {
						t.Error("rpo_hours is null with no rpo_detail")
					}
					if row.Retention != nil && strings.TrimSpace(row.Retention.Detail) == "" {
						t.Error("retention with no detail")
					}
					if row.Schedule != nil && strings.TrimSpace(row.Schedule.Detail) == "" {
						t.Error("schedule with no detail")
					}
					// The three nullable STRUCTS carry their own sibling
					// detail: populated exactly when the pointer is nil, empty
					// exactly when it is set. A bare null would fall back to
					// the row-level detail, which is a different sentence.
					if (row.Schedule == nil) != (strings.TrimSpace(row.ScheduleDetail) != "") {
						t.Errorf("schedule=%v but schedule_detail=%q — the sibling must be set iff the pointer is nil",
							row.Schedule != nil, row.ScheduleDetail)
					}
					if (row.LastAttempt == nil) != (strings.TrimSpace(row.LastAttemptDetail) != "") {
						t.Errorf("last_attempt=%v but last_attempt_detail=%q — the sibling must be set iff the pointer is nil",
							row.LastAttempt != nil, row.LastAttemptDetail)
					}
					if (row.Retention == nil) != (strings.TrimSpace(row.RetentionDetail) != "") {
						t.Errorf("retention=%v but retention_detail=%q — the sibling must be set iff the pointer is nil",
							row.Retention != nil, row.RetentionDetail)
					}
					// A null last_verified must still be explained somewhere:
					// the contract has no dedicated sibling for it.
					if row.LastVerified == nil &&
						strings.TrimSpace(row.Detail) == "" && strings.TrimSpace(row.CoveredReason) == "" {
						t.Error("a null last_verified with no explanation anywhere on the row")
					}
					// The TARGET recovery point is never invented: nil demands
					// a reason, and a value demands a stated derivation.
					if strings.TrimSpace(row.RPOTargetDetail) == "" {
						t.Error("rpo_target_detail is empty — a target (or its absence) must always be explained")
					}
					if row.RPOTargetHours != nil && *row.RPOTargetHours <= 0 {
						t.Errorf("rpo_target_hours = %v — a non-positive target is not a target", *row.RPOTargetHours)
					}
					if row.LastAttempt != nil && strings.TrimSpace(row.LastAttempt.Result) == "" {
						t.Error("last_attempt with no result")
					}
					if row.LastVerified != nil && strings.TrimSpace(row.LastVerified.Result) == "" {
						t.Error("last_verified with no result")
					}
					// No row may claim a restorability proof it does not have.
					if row.LastVerified != nil && strings.TrimSpace(row.LastVerified.At) == "" {
						t.Error("last_verified with no timestamp — an undated proof is not a proof")
					}
				})
			}

			// The external list is present and every entry says it is not
			// governed here; the view says the list is incomplete.
			if len(view.External) == 0 {
				t.Error("external mechanisms must be listed — a host job the GUI does not govern is the defect this page closes")
			}
			for _, ext := range view.External {
				if ext.Name == "" || ext.Source == "" || ext.Detail == "" {
					t.Errorf("incomplete external mechanism: %+v", ext)
				}
				if !strings.Contains(ext.Detail, "external to the product") {
					t.Errorf("external mechanism must say it is not governed here: %q", ext.Detail)
				}
			}
			if !strings.Contains(view.Detail, "not a complete inventory") &&
				!strings.Contains(view.Detail, "not a\ncomplete inventory") {
				t.Errorf("the view must state that the list is incomplete: %q", view.Detail)
			}
			if view.GeneratedAt.IsZero() {
				t.Error("generated_at is zero")
			}
		})
	}
}

// TestBackupCoverageSpecificClaims pins the wording that carries operational
// meaning. These are not cosmetics: each sentence is the one an operator reads
// before deciding whether they have a backup.
func TestBackupCoverageSpecificClaims(t *testing.T) {
	h := newHarness(t, newOSStub())

	st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
	if st != 200 {
		t.Fatalf("coverage: %d %s", st, b)
	}
	var view BackupCoverageView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rows := map[string]EngineCoverage{}
	for _, r := range view.Engines {
		rows[r.ID] = r
	}

	// OpenSearch: live, and honest about the failure domain.
	osRow := rows["opensearch"]
	if osRow.Covered != CoverageYes {
		t.Errorf("opensearch covered = %q, want yes with a live SUCCESS snapshot", osRow.Covered)
	}
	if osRow.Target.Immutable == nil || *osRow.Target.Immutable {
		t.Error("an fs repository on the same host is NOT immutable")
	}
	if !strings.Contains(osRow.Target.ImmutableDetail, "2026-08-27") {
		t.Errorf("immutable_detail must name the incident it came from: %q", osRow.Target.ImmutableDetail)
	}
	if osRow.Target.Encrypted == nil || *osRow.Target.Encrypted {
		t.Error("compress=true is not encryption")
	}
	if osRow.LastSuccessAt == "" || osRow.RPOHours == nil {
		t.Errorf("a live SUCCESS snapshot must yield last_success_at + rpo_hours: %+v", osRow)
	}
	if osRow.Schedule == nil || !osRow.Schedule.GovernedByGUI {
		t.Error("the SM policy IS governed by this GUI")
	}
	if osRow.Retention == nil || osRow.Retention.MaxCount == nil || *osRow.Retention.MaxCount != 14 {
		t.Errorf("retention not read from the policy: %+v", osRow.Retention)
	}
	// Never probed → no proof, and the row says so.
	if osRow.LastVerified != nil {
		t.Error("no probe has run, so there must be no verification claim")
	}
	if !strings.Contains(osRow.Detail, "never probed") {
		t.Errorf("the unproven state must be stated: %q", osRow.Detail)
	}

	// system_bundle with no report: the loudest possible answer.
	bundle := rows["system_bundle"]
	if bundle.Covered != CoverageNo || !strings.Contains(bundle.CoveredReason, "no backup report has ever been written") {
		t.Errorf("system_bundle: %q / %q", bundle.Covered, bundle.CoveredReason)
	}
	if !strings.Contains(bundle.CoveredReason, h.dir) {
		t.Errorf("the absent report must be named by PATH so an operator knows what to look for: %q", bundle.CoveredReason)
	}
	if bundle.Target.Kind != TargetNone || !strings.Contains(bundle.Target.Detail, "NOT disaster recovery") {
		t.Errorf("an empty remote must read as on-host-only and not DR: %+v", bundle.Target)
	}

	// postgres / clickhouse: the exact operational claims.
	pg := rows["postgres"]
	if !strings.Contains(pg.CoveredReason, "pg_dumpall runs only INSIDE the system bundle") {
		t.Errorf("postgres reason: %q", pg.CoveredReason)
	}
	ch := rows["clickhouse"]
	if !strings.Contains(ch.CoveredReason, "cold TIERING, not a backup") {
		t.Errorf("clickhouse must call ch-cold-export.sh tiering, not backup: %q", ch.CoveredReason)
	}
	if !strings.Contains(ch.Detail, "host cron") {
		t.Errorf("clickhouse must say the api cannot see the host cron: %q", ch.Detail)
	}

	// victoriametrics / secrets_tls.
	//
	// CHANGED BY S4 (2026-09-04). Both rows used to assert "no mechanism at
	// all": a nil schedule and TargetNone, because nothing in the platform
	// copied either. scripts/backup.sh now snapshots VictoriaMetrics through
	// its own /snapshot/create and ships the sealed custody material as a
	// separately encrypted member, so BOTH now inherit the bundle's schedule
	// and the bundle's destination. What has NOT changed, and is what these
	// assertions now pin, is the honesty: with no backup report on this host
	// neither row may read as covered, and each must say why in words an
	// operator can act on.
	vm := rows["victoriametrics"]
	if vm.Covered != CoverageNo {
		t.Errorf("victoriametrics with no bundle report must be covered=no, got %q", vm.Covered)
	}
	if vm.Schedule == nil || !vm.Schedule.GovernedByGUI {
		t.Errorf("victoriametrics now inherits the bundle's GUI-governed schedule: %+v", vm.Schedule)
	}
	if !strings.Contains(vm.CoveredReason, "indistinguishable from no backup") {
		t.Errorf("victoriametrics reason must name the unreported-run state: %q", vm.CoveredReason)
	}
	if !strings.Contains(vm.Detail, "TORN") {
		t.Errorf("victoriametrics must explain why a live-tree rsync is not the mechanism: %q", vm.Detail)
	}
	sec := rows["secrets_tls"]
	if sec.Covered != CoverageNo {
		t.Errorf("secrets_tls with no bundle report must be covered=no, got %q", sec.Covered)
	}
	if sec.Schedule == nil {
		t.Errorf("secrets_tls now inherits the bundle's schedule: %+v", sec.Schedule)
	}
	if !strings.Contains(sec.CoveredReason, "unrecoverable even from a good data backup") {
		t.Errorf("secrets_tls reason: %q", sec.CoveredReason)
	}
	// The encryption answer on the custody row is this row's OWN and is a
	// measured yes: the envelope is ciphertext before it is written, whatever
	// the destination does.
	if sec.Target.Encrypted == nil || !*sec.Target.Encrypted {
		t.Errorf("the custody envelope is encrypted before it is written: %+v", sec.Target)
	}
	if !strings.Contains(sec.Target.EncryptedDetail, "openssl enc -aes-256-cbc -pbkdf2") {
		t.Errorf("the encryption claim must name the mechanism: %q", sec.Target.EncryptedDetail)
	}

	// device_configs with the module OFF (the harness does not wire it).
	dc := rows["device_configs"]
	if dc.Covered != CoverageNotApplicable {
		t.Errorf("device_configs with the module off: %q", dc.Covered)
	}
	if !strings.Contains(dc.CoveredReason, "FEATURE_CONFIG_BACKUP") {
		t.Errorf("the reason must name the switch that turns the module on: %q", dc.CoveredReason)
	}
	if dc.LastAttempt != nil {
		t.Error("the manager records no last-run timestamp, so last_attempt must be null — never invented")
	}
	if !strings.Contains(dc.RPODetail, "does not record a last-run timestamp") {
		t.Errorf("the missing timestamp must be explained: %q", dc.RPODetail)
	}

	// The intent store is reachable from the same service (sanity: the coverage
	// build reads it without panicking on a fresh install).
	if enabled, _, _, _ := h.svc.SnapshotScheduleIntent(); !enabled {
		t.Error("a fresh install must report the snapshot schedule as not deliberately stopped")
	}
}

// TestBackupCoverageWithTheConfigModuleOn — the injected facts drive the row,
// including the env NAMES the reasons quote.
func TestBackupCoverageWithTheConfigModuleOn(t *testing.T) {
	h := newHarness(t, newOSStub(), func(d *Deps) {
		d.DeviceConfigs = stubDeviceConfigs{on: true, facts: DeviceConfigFacts{
			Interval: 6 * time.Hour, KeepVersions: 30,
			FeatureFlagEnv: "FEATURE_CONFIG_BACKUP", IntervalEnv: "CONFIG_BACKUP_INTERVAL",
			KeepVersionsEnv: "CONFIG_BACKUP_KEEP_VERSIONS",
			Versions:        7, Failed: 1, Pruned: 2, HasCounters: true,
		}}
	})
	view := h.svc.BuildCoverage(t.Context())
	var dc EngineCoverage
	for _, r := range view.Engines {
		if r.ID == "device_configs" {
			dc = r
		}
	}
	if dc.Covered != CoverageYes {
		t.Fatalf("with the module on the row must read covered: %q", dc.Covered)
	}
	if dc.RPOTargetHours == nil || *dc.RPOTargetHours != 6 {
		t.Errorf("the target comes from the module's capture interval: %v", dc.RPOTargetHours)
	}
	if !strings.Contains(dc.RPOTargetDetail, "CONFIG_BACKUP_INTERVAL") {
		t.Errorf("the target must name the env it derives from: %q", dc.RPOTargetDetail)
	}
	if dc.Retention == nil || dc.Retention.MaxCount == nil || *dc.Retention.MaxCount != 30 {
		t.Errorf("retention depth not taken from the module: %+v", dc.Retention)
	}
	if !strings.Contains(dc.Detail, "7 new versions") || !strings.Contains(dc.Detail, "1 failed captures") {
		t.Errorf("the counters must be reported: %q", dc.Detail)
	}
}

// TestBackupCoverageRedactsTheRemoteDestination — §8: no credential may reach a
// response body. A destination URL is the single most likely place for one.
func TestBackupCoverageRedactsTheRemoteDestination(t *testing.T) {
	h := newHarness(t, newOSStub())

	if st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "rsync://backupuser:sup3rs3cret@nas.example.net/vol/correlix?token=abcdef123456",
	}); st != 200 {
		t.Fatalf("set remote: %d %s", st, b)
	}
	st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
	if st != 200 {
		t.Fatalf("coverage: %d %s", st, b)
	}
	body := string(b)
	for _, secret := range []string{"sup3rs3cret", "abcdef123456", "token="} {
		if strings.Contains(body, secret) {
			t.Fatalf("the coverage payload leaked %q", secret)
		}
	}
	var view BackupCoverageView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, row := range view.Engines {
		if row.Target.Kind != TargetRemote {
			continue
		}
		if !strings.Contains(row.Target.Location, "nas.example.net") {
			t.Errorf("the host must survive redaction so an operator can still identify the destination: %q", row.Target.Location)
		}
		if !strings.Contains(row.Target.Location, "redacted@") {
			t.Errorf("the userinfo must be visibly redacted, not silently dropped: %q", row.Target.Location)
		}
		// A remote we cannot inspect must report null, not a guessed "no".
		//
		// The ONE exception is secrets_tls, and it is an exception because the
		// claim is about a different thing: the custody envelope is encrypted
		// by scripts/backup.sh BEFORE it is written into the bundle, so it is
		// ciphertext in transit and at rest no matter what the destination
		// provides. That is measured, not guessed — but immutability at the
		// destination still is not, and must stay a measured "no" with its
		// reason rather than a null.
		if row.ID == "secrets_tls" {
			if row.Target.Encrypted == nil || !*row.Target.Encrypted {
				t.Errorf("the custody envelope is encrypted before it is pushed: %+v", row.Target)
			}
			// Immutability is still a property of the DESTINATION, which the api
			// cannot inspect from inside its container — so it stays null with
			// its reason on this row exactly like every other remote row.
			if row.Target.Immutable != nil {
				t.Errorf("immutability at the destination is not measurable from here: %+v", row.Target)
			}
			continue
		}
		if row.Target.Immutable != nil || row.Target.Encrypted != nil {
			t.Errorf("a remote's immutability/encryption is not measurable from here — it must be null: %+v", row.Target)
		}
	}
}

func TestRedactBackupRemote(t *testing.T) {
	cases := map[string]string{
		"":                                    "",
		"/mnt/nas/correlix":                   "/mnt/nas/correlix",
		"rsync://nas/vol":                     "rsync://nas/vol",
		"s3://bucket/path?X-Amz-Signature=ab": "s3://bucket/path (query string redacted)",
		"rsync://u:p@nas/vol":                 "rsync://redacted@nas/vol",
	}
	for in, want := range cases {
		if got := redactBackupRemote(in); got != want {
			t.Errorf("redactBackupRemote(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(redactBackupRemote(in), ":p@") {
			t.Errorf("password survived redaction of %q", in)
		}
	}
}

// TestBackupCoverageReflectsAFailingBundle — a failed bundle must NOT read as
// covered, and Postgres/ClickHouse must reflect it rather than reporting their
// own independent (nonexistent) state.
func TestBackupCoverageReflectsAFailingBundle(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"failed","ended":"2026-09-03T02:31:00Z","size_bytes":0,"duration_seconds":12,"failures":3}`)

	st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
	if st != 200 {
		t.Fatalf("coverage: %d %s", st, b)
	}
	var view BackupCoverageView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, row := range view.Engines {
		switch row.ID {
		case "system_bundle":
			if row.Covered != CoverageNo || row.LastSuccessAt != "" {
				t.Errorf("a failed bundle must not read as covered: %q / %q", row.Covered, row.LastSuccessAt)
			}
			if row.LastAttempt == nil || row.LastAttempt.Result != "failed" {
				t.Errorf("the failed attempt must be reported: %+v", row.LastAttempt)
			}
		case "postgres", "clickhouse":
			if !strings.Contains(row.CoveredReason, "failed") {
				t.Errorf("%s must reflect the bundle's failure: %q", row.ID, row.CoveredReason)
			}
			if row.RPOHours != nil {
				t.Errorf("%s must not claim an RPO off a failed bundle", row.ID)
			}
		}
	}
}

func writeBackupReport(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(dir+"/backup-report.json", []byte(body), 0o600); err != nil {
		t.Fatalf("write backup report: %v", err)
	}
}

// TestCronCadenceHours — the RPO TARGET derivation. The rule under test is
// "never invent a target": every shape this platform actually writes yields a
// number, and everything else must yield ok=false so the caller publishes null
// with a reason. A wrong target is worse than none — it would make an RPO
// breach render as compliant.
func TestCronCadenceHours(t *testing.T) {
	derivable := map[string]float64{
		"30 1 * * *":  24,      // the shipped netops-daily creation cron
		"30 2 * * *":  24,      // the shipped bundle cron
		"0 3 * * 0":   24 * 7,  // weekly
		"15 4 1 * *":  24 * 30, // monthly (nominal 30d)
		"*/0 * * * *": 1,       // minute field ignored when the hour is *
		"0 * * * *":   1,       // hourly
		"0 */6 * * *": 6,       // every six hours
	}
	for expr, want := range derivable {
		got, ok := cronCadenceHours(expr)
		if expr == "*/0 * * * *" {
			// A step in the MINUTE field is not a shape this platform writes;
			// it must not be silently read as hourly.
			if ok {
				t.Errorf("cronCadenceHours(%q) claimed %v — a minute-field step is not derivable", expr, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("cronCadenceHours(%q) = %v,%v; want %v,true", expr, got, ok, want)
		}
	}
	for _, expr := range []string{
		"", "not a cron", "30 1 * *", "30 1 * * * *",
		"30 1,13 * * *", // twice daily — a list we will not pretend to read
		"30 1-5 * * *",  // a range
		"30 1 * 6 *",    // a specific month
		"30 */30 * * *", // an out-of-range hour step
		"30 1 15 * 3",   // day-of-month AND weekday together
	} {
		if got, ok := cronCadenceHours(expr); ok {
			t.Errorf("cronCadenceHours(%q) = %v,true — an underivable cadence must return false so the "+
				"caller publishes a null target with a reason", expr, got)
		}
	}
}

// TestCoverageRPOTargetsComeFromRealSchedules pins WHERE each target comes
// from: a real schedule, or nothing.
func TestCoverageRPOTargetsComeFromRealSchedules(t *testing.T) {
	h := newHarness(t, newOSStub())
	// Give the bundle a real, enabled schedule so its target is derivable.
	if st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "rsync://nas/backups", "schedule_enabled": true, "schedule_cron": "30 2 * * *",
	}); st != 200 {
		t.Fatalf("set schedule: %d %s", st, b)
	}
	st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
	if st != 200 {
		t.Fatalf("coverage: %d %s", st, b)
	}
	var view BackupCoverageView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rows := map[string]EngineCoverage{}
	for _, r := range view.Engines {
		rows[r.ID] = r
	}
	// The SM policy's daily cron → a 24h target, with the cron quoted.
	if got := rows["opensearch"].RPOTargetHours; got == nil || *got != 24 {
		t.Errorf("opensearch rpo_target_hours = %v, want 24 from the 30 1 * * * creation cron", got)
	}
	if !strings.Contains(rows["opensearch"].RPOTargetDetail, "30 1 * * *") {
		t.Errorf("the target must name the cron it came from: %q", rows["opensearch"].RPOTargetDetail)
	}
	// The bundle's own cron.
	if got := rows["system_bundle"].RPOTargetHours; got == nil || *got != 24 {
		t.Errorf("system_bundle rpo_target_hours = %v, want 24", got)
	}
	// Engines with no schedule of their own must publish NO target.
	for _, id := range []string{"postgres", "clickhouse", "victoriametrics", "secrets_tls"} {
		row := rows[id]
		if row.RPOTargetHours != nil {
			t.Errorf("%s published a target (%v) despite having no schedule of its own", id, *row.RPOTargetHours)
		}
		if !strings.Contains(row.RPOTargetDetail, "no ") {
			t.Errorf("%s rpo_target_detail must say why there is no target: %q", id, row.RPOTargetDetail)
		}
	}
}

// TestCoverageReportsBundleRetentionInForce — the bundle row must report the
// retention that is ACTUALLY enforced, in the three states it can be in.
//
// Before retain_count existed on the config the row reported no count at all,
// while backup.sh was pruning to one all along — so an operator had to go to
// the host to read a number this GUI had set. The row states the POLICY and
// says, in words, that it is not a count of artifacts on disk: the api cannot
// see them, and a policy presented as an observation is the fabrication this
// surface refuses everywhere else.
func TestCoverageReportsBundleRetentionInForce(t *testing.T) {
	bundleRow := func(t *testing.T, h *harness) EngineCoverage {
		t.Helper()
		st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
		if st != 200 {
			t.Fatalf("coverage: %d %s", st, b)
		}
		var view BackupCoverageView
		if err := json.Unmarshal(b, &view); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, r := range view.Engines {
			if r.ID == "system_bundle" {
				return r
			}
		}
		t.Fatal("no system_bundle row in the coverage table")
		return EngineCoverage{}
	}

	// 1 · nothing stored: the applier's fallback is in force, and is named as a
	// default rather than published as a count somebody chose.
	h := newHarness(t, newOSStub())
	row := bundleRow(t, h)
	if row.Retention == nil {
		t.Fatal("the bundle row must always carry a retention object")
	}
	if row.Retention.MaxCount != nil {
		t.Errorf("an unset retention must publish no count, got %d", *row.Retention.MaxCount)
	}
	if !strings.Contains(row.Retention.Detail, strconv.Itoa(BackupRetainApplierDefault)) ||
		!strings.Contains(row.Retention.Detail, "default") {
		t.Errorf("the detail must name the applier fallback AS a default: %q", row.Retention.Detail)
	}

	// 2 · a chosen count: published, with the "policy, not a file count" caveat.
	if st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "/mnt/nas/x", "retain_count": 30,
	}); st != 200 {
		t.Fatalf("set retention: %d %s", st, b)
	}
	row = bundleRow(t, h)
	if row.Retention.MaxCount == nil || *row.Retention.MaxCount != 30 {
		t.Fatalf("the chosen retention was not published: %v", row.Retention.MaxCount)
	}
	if !strings.Contains(row.Retention.Detail, "policy in force") {
		t.Errorf("the detail must say this is a policy, not a count of artifacts: %q", row.Retention.Detail)
	}
	if row.Retention.MaxAgeDays != nil {
		t.Errorf("the bundle has no age-based retention; publishing one would be invented: %v", *row.Retention.MaxAgeDays)
	}

	// 3 · a deliberate 0: pruning OFF. Publishing max_count 0 would read as
	// "keep nothing" — the exact opposite of what the host does.
	if st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "/mnt/nas/x", "retain_count": 0,
	}); st != 200 {
		t.Fatalf("disable pruning: %d %s", st, b)
	}
	row = bundleRow(t, h)
	if row.Retention.MaxCount != nil {
		t.Errorf("retain_count 0 must not be published as a max_count of 0: %d", *row.Retention.MaxCount)
	}
	if !strings.Contains(row.Retention.Detail, "Pruning is off") {
		t.Errorf("the detail must say pruning is off and what that costs: %q", row.Retention.Detail)
	}
}
