package dataprotect

// drill_test.go — the BUNDLE restore drill's contribution to the coverage
// table, and the per-component verdicts the bundle report now carries.
//
// WHAT THESE TESTS ARE FOR. Two claims became possible on 2026-09-04 that were
// impossible before, and both are the kind of claim that is worth nothing
// unless it is exactly true:
//
//   1. "this store's copy inside the last bundle succeeded" — previously every
//      store inherited the WHOLE run's status, so a night on which only the
//      VictoriaMetrics snapshot failed reported a green Postgres dump;
//   2. "this store's copy has been RESTORED and checked" — previously nothing
//      had ever restored a bundle, and four coverage rows said so in words.
//
// The failure mode to guard against in both directions is generosity: an
// absent component map must not read as "everything passed", and an absent or
// skipped drill leg must not read as "verified". Every test below is written
// so that removing the guard makes it red.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func writeDrillReport(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(dir+"/backup-drill.report.json", []byte(body), 0o600); err != nil {
		t.Fatalf("write drill report: %v", err)
	}
}

func coverageRows(t *testing.T, h *harness) map[string]EngineCoverage {
	t.Helper()
	st, b := h.do(t, "GET", "/api/system/backup/coverage", nil)
	if st != 200 {
		t.Fatalf("coverage: %d %s", st, b)
	}
	var view BackupCoverageView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
	rows := map[string]EngineCoverage{}
	for _, e := range view.Engines {
		rows[e.ID] = e
	}
	return rows
}

// TestCoverageUsesPerComponentVerdicts is the whole point of the components
// map: a run that succeeded OVERALL while one store's component failed must
// report that store as uncovered. Before this existed the row would have read
// "covered" off the run's status.
func TestCoverageUsesPerComponentVerdicts(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":91234,
	  "duration_seconds":61,"failures":0,"artifact":"correlix-2026-09-04.tar.zst",
	  "components":{"postgres":"pass","clickhouse":"fail","victoriametrics":"pass","sealed_material":"skip"}}`)
	rows := coverageRows(t, h)

	// Postgres passed -> it has a dateable recovery point.
	if rows["postgres"].RPOHours == nil {
		t.Errorf("postgres component passed, so its RPO must be measurable: %+v", rows["postgres"])
	}
	if !strings.Contains(rows["postgres"].CoveredReason, "PASSED") {
		t.Errorf("postgres reason must state the component's own verdict: %q", rows["postgres"].CoveredReason)
	}
	// ClickHouse FAILED inside a successful run -> no recovery point, and the
	// row must not borrow the run's success.
	ch := rows["clickhouse"]
	if ch.RPOHours != nil {
		t.Errorf("clickhouse component failed, so there is no dateable good copy: %v", *ch.RPOHours)
	}
	if ch.LastSuccessAt != "" {
		t.Errorf("a failed component must not record a last success: %q", ch.LastSuccessAt)
	}
	if !strings.Contains(ch.CoveredReason, "FAILED") {
		t.Errorf("clickhouse reason must state the component's own verdict: %q", ch.CoveredReason)
	}
	if ch.LastAttempt == nil || ch.LastAttempt.Result != "failed" {
		t.Errorf("the attempt row must show the COMPONENT's outcome, not the run's: %+v", ch.LastAttempt)
	}
	// VictoriaMetrics passed -> covered, with a real recovery point.
	vm := rows["victoriametrics"]
	if vm.Covered != CoverageYes || vm.RPOHours == nil {
		t.Errorf("victoriametrics component passed: covered=%q rpo=%v", vm.Covered, vm.RPOHours)
	}
	// Sealed material SKIPPED -> explicitly not covered, and the reason must
	// name the consequence rather than shrugging.
	sec := rows["secrets_tls"]
	if sec.Covered != CoverageNo {
		t.Errorf("a skipped custody component is not covered: %q", sec.Covered)
	}
	if !strings.Contains(sec.CoveredReason, "EXCLUDED") || !strings.Contains(sec.CoveredReason, "unrecoverable") {
		t.Errorf("the skip reason must name the consequence: %q", sec.CoveredReason)
	}
}

// TestCoverageComponentMapAbsentIsUnknownNotPass pins the generosity guard: a
// report written before per-component verdicts existed must NOT be read as "all
// components passed".
func TestCoverageComponentMapAbsentIsUnknownNotPass(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":1,"duration_seconds":1,"failures":0}`)
	rows := coverageRows(t, h)
	for _, id := range []string{"postgres", "clickhouse", "victoriametrics", "secrets_tls"} {
		row := rows[id]
		if !strings.Contains(row.CoveredReason, "UNKNOWN") {
			t.Errorf("%s must report the component as unknown, not assume a pass: %q", id, row.CoveredReason)
		}
		if row.RPOHours != nil {
			t.Errorf("%s must not publish a recovery point off an unknown component: %v", id, *row.RPOHours)
		}
	}
	if rows["secrets_tls"].Covered != CoverageUnknown {
		t.Errorf("an unknown custody component is covered=unknown, got %q", rows["secrets_tls"].Covered)
	}
}

// TestCoverageSealedFailClosedIsReportedAsFailure — the fail-closed path.
// backup.sh refuses to write custody material in the clear, so an unset
// BACKUP_SEALED_PASSPHRASE produces a component FAILURE, and this row has to
// name the fix instead of leaving an operator staring at "no".
func TestCoverageSealedFailClosedIsReportedAsFailure(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"failed","ended":"2026-09-04T02:31:00Z","size_bytes":1,"duration_seconds":1,
	  "failures":1,"components":{"sealed_material":"fail"}}`)
	sec := coverageRows(t, h)["secrets_tls"]
	if sec.Covered != CoverageNo {
		t.Errorf("a failed custody component is not covered: %q", sec.Covered)
	}
	for _, want := range []string{"BACKUP_SEALED_PASSPHRASE", "BACKUP_SEALED_MATERIAL=0", "never write custody material in the clear"} {
		if !strings.Contains(sec.CoveredReason, want) {
			t.Errorf("the fail-closed reason must name %q: %q", want, sec.CoveredReason)
		}
	}
}

// TestCoverageClickHousePartialIsNotCovered — the per-table size ceiling. An
// export that skipped the store's largest tables holds their SCHEMA and none of
// their rows, and must never round up to covered.
func TestCoverageClickHousePartialIsNotCovered(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":1,
	  "duration_seconds":1,"failures":0,"components":{"clickhouse":"partial"}}`)
	ch := coverageRows(t, h)["clickhouse"]
	if ch.Covered == CoverageYes {
		t.Errorf("a partial export is not a covered store: %q", ch.Covered)
	}
	if ch.RPOHours != nil {
		t.Errorf("a partial export gives no whole-store recovery point: %v", *ch.RPOHours)
	}
	for _, want := range []string{"PARTIAL", "SCHEMA ONLY", "BACKUP_CH_MAX_TABLE_MB", "ch-cold-export.sh"} {
		if !strings.Contains(ch.CoveredReason, want) {
			t.Errorf("the partial reason must name %q: %q", want, ch.CoveredReason)
		}
	}
	if ch.LastAttempt == nil || ch.LastAttempt.Result != "partial" {
		t.Errorf("the attempt row must render the component's own word: %+v", ch.LastAttempt)
	}
}

// TestCoverageDrillVerdicts — last_verified comes from the drill, per leg, and
// never from a run report. All four states are pinned because three of them are
// "not proven" and only one is a proof.
func TestCoverageDrillVerdicts(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":1,"duration_seconds":1,
	  "failures":0,"components":{"postgres":"pass","clickhouse":"pass","victoriametrics":"pass","sealed_material":"pass"}}`)

	// No drill at all: every leg is unproven, and each row says where the proof
	// would have come from.
	rows := coverageRows(t, h)
	for _, id := range []string{"postgres", "clickhouse", "victoriametrics", "secrets_tls", "system_bundle"} {
		if rows[id].LastVerified != nil {
			t.Errorf("%s: a bundle report is not a restore proof: %+v", id, rows[id].LastVerified)
		}
		if !strings.Contains(rows[id].Detail, "backup-drill.sh") {
			t.Errorf("%s must name the mechanism that would produce a proof: %q", id, rows[id].Detail)
		}
	}

	// A drill with one pass, one fail, one skip and one absent leg.
	writeDrillReport(t, h.dir, `{"drill_id":"backup-drill_20260904_030000_1","bundle":"correlix-2026-09-04.tar.zst",
	  "started":"2026-09-04T03:00:00Z","ended":"2026-09-04T03:07:00Z","result":"fail",
	  "assertions_passed":9,"assertions_failed":2,
	  "legs":{"postgres":{"result":"pass","detail":"restored 41 tables / 9182 rows","duration_seconds":38},
	          "clickhouse":{"result":"fail","detail":"3 of 16 dumps failed to load"},
	          "victoriametrics":{"result":"skip","detail":"the bundle carries no snapshot"}}}`)
	rows = coverageRows(t, h)

	pg := rows["postgres"].LastVerified
	if pg == nil || pg.Result != DrillPass || pg.At != "2026-09-04T03:07:00Z" {
		t.Fatalf("postgres last_verified: %+v", pg)
	}
	for _, want := range []string{"restored 41 tables", "restore took 38s", "backup-drill_20260904_030000_1"} {
		if !strings.Contains(pg.Detail, want) {
			t.Errorf("the proof detail must carry %q: %q", want, pg.Detail)
		}
	}
	if ch := rows["clickhouse"].LastVerified; ch == nil || ch.Result != DrillFail {
		t.Errorf("a FAILED leg is still a verdict and must be published as one: %+v", ch)
	}
	// A SKIPPED leg proves nothing — the pointer must stay nil, with the reason.
	if vm := rows["victoriametrics"].LastVerified; vm != nil {
		t.Errorf("a skipped leg is not a proof: %+v", vm)
	}
	if !strings.Contains(rows["victoriametrics"].Detail, "SKIPPED") {
		t.Errorf("the skip must be explained: %q", rows["victoriametrics"].Detail)
	}
	// An ABSENT leg is a fourth state and must not silently borrow the run's
	// overall result.
	if sec := rows["secrets_tls"].LastVerified; sec != nil {
		t.Errorf("a leg the drill never ran is not a proof: %+v", sec)
	}
	if !strings.Contains(rows["secrets_tls"].Detail, "did not include a sealed_material leg") {
		t.Errorf("an absent leg must be named: %q", rows["secrets_tls"].Detail)
	}
	// The bundle row takes the drill's OVERALL verdict.
	if b := rows["system_bundle"].LastVerified; b == nil || b.Result != DrillFail ||
		!strings.Contains(b.Detail, "correlix-2026-09-04.tar.zst") {
		t.Errorf("system_bundle last_verified: %+v", b)
	}
}

// TestCoverageRemoteTransferSentence — the three off-host states the page must
// keep apart. "proven" is reserved for a checksum re-verified at the far end.
func TestCoverageRemoteTransferSentence(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   string
		deny   string
	}{
		{
			name:   "pushed-but-unverified",
			report: `"remote":{"configured":true,"pushed":true}`,
			want:   "reported as done, not as proven",
			deny:   "PROVEN",
		},
		{
			name:   "push-failed",
			report: `"remote":{"configured":true,"pushed":false}`,
			want:   "on this host only",
			deny:   "PROVEN",
		},
		{
			name:   "verified",
			report: `"remote":{"configured":true,"pushed":true,"verified_at":"2026-09-04T02:40:00Z"}`,
			want:   "External transfer PROVEN 2026-09-04T02:40:00Z",
			deny:   "not as proven",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, newOSStub())
			writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":1,
			  "duration_seconds":1,"failures":0,`+tc.report+`}`)
			d := coverageRows(t, h)["system_bundle"].Detail
			if !strings.Contains(d, tc.want) {
				t.Errorf("detail must contain %q: %q", tc.want, d)
			}
			if tc.deny != "" && strings.Contains(d, tc.deny) {
				t.Errorf("detail must NOT contain %q: %q", tc.deny, d)
			}
		})
	}
}

// TestCoverageNarrowedBundleIsDeclared — a bundle taken with operator excludes
// is a smaller promise, and presenting it as a full one is the F-59 defect in
// miniature.
func TestCoverageNarrowedBundleIsDeclared(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":1,
	  "duration_seconds":1,"failures":0,"data_excludes":"/kafka /opensearch-snapshots"}`)
	d := coverageRows(t, h)["system_bundle"].Detail
	if !strings.Contains(d, "NARROWED BUNDLE") || !strings.Contains(d, "/opensearch-snapshots") {
		t.Errorf("a narrowed bundle must be declared, with what was dropped: %q", d)
	}
}

// TestCoverageRPOObjectivesAreDeclaredAndSeparate — the objective is POLICY and
// lives in its own field. The schedule-derived target must stay null wherever no
// schedule exists, which is the invariant
// TestCoverageRPOTargetsComeFromRealSchedules already guards; this pins that
// adding objectives did not quietly relax it.
func TestCoverageRPOObjectivesAreDeclaredAndSeparate(t *testing.T) {
	h := newHarness(t, newOSStub())
	rows := coverageRows(t, h)
	for id, want := range map[string]float64{
		"opensearch": 24, "system_bundle": 24, "postgres": 24,
		"clickhouse": 24, "victoriametrics": 24, "device_configs": 24, "secrets_tls": 0,
	} {
		row := rows[id]
		if row.RPOObjectiveHours == nil {
			t.Errorf("%s publishes no declared objective: %q", id, row.RPOObjectiveDetail)
			continue
		}
		if *row.RPOObjectiveHours != want {
			t.Errorf("%s objective = %v, want %v", id, *row.RPOObjectiveHours, want)
		}
		if strings.TrimSpace(row.RPOObjectiveDetail) == "" {
			t.Errorf("%s: an objective without its provenance is a number someone typed", id)
		}
		if !strings.Contains(row.RPOObjectiveDetail, "policy statement") {
			t.Errorf("%s: the objective must say it is policy, not measurement: %q", id, row.RPOObjectiveDetail)
		}
	}
	// The custody objective is 0 and must say WHY 0 is meetable, or an operator
	// reads it as permanently missed.
	if !strings.Contains(rows["secrets_tls"].RPOObjectiveDetail, "CHANGE-driven") {
		t.Errorf("the 0h objective must explain itself: %q", rows["secrets_tls"].RPOObjectiveDetail)
	}
	// Separation: with no schedule in force, the DERIVED target stays null.
	for _, id := range []string{"postgres", "clickhouse", "victoriametrics", "secrets_tls"} {
		if rows[id].RPOTargetHours != nil {
			t.Errorf("%s: a declared objective must never leak into the schedule-derived target", id)
		}
	}
}

// TestCoverageSealedCustodyRPOIsZeroWhenCaptured — the change-driven recovery
// point. A captured envelope means the newest bundle holds the material as it
// stands, which is a real 0, published with the caveat that makes it honest.
func TestCoverageSealedCustodyRPOIsZeroWhenCaptured(t *testing.T) {
	h := newHarness(t, newOSStub())
	writeBackupReport(t, h.dir, `{"status":"success","ended":"2026-09-04T02:31:00Z","size_bytes":1,
	  "duration_seconds":1,"failures":0,"components":{"sealed_material":"pass"}}`)
	sec := coverageRows(t, h)["secrets_tls"]
	if sec.Covered != CoverageYes {
		t.Fatalf("a captured envelope is covered: %q — %s", sec.Covered, sec.CoveredReason)
	}
	if sec.RPOHours == nil || *sec.RPOHours != 0 {
		t.Fatalf("a captured change-driven envelope has a 0h recovery point: %v", sec.RPOHours)
	}
	if !strings.Contains(sec.RPODetail, "rotated without a bundle run") {
		t.Errorf("the 0 must ship with the condition under which it stops being 0: %q", sec.RPODetail)
	}
}

// TestDrillMetricsPublishNeverAsZero — the gauge contract the alert rules are
// written against. "never drilled" must render as timestamp 0 (which both rules
// deliberately do NOT fire on), and a real verdict must render its own time.
func TestDrillMetricsPublishNeverAsZero(t *testing.T) {
	h := newHarness(t, newOSStub())

	h.svc.refreshDrillMetrics()
	if known, _, at := h.svc.Metrics().DrillSnapshot(); known || !at.IsZero() {
		t.Fatalf("with no report the drill gauges must read never: known=%v at=%v", known, at)
	}
	var buf strings.Builder
	h.svc.Metrics().Write(&buf)
	for _, want := range []string{
		"netops_backup_drill_pass 0",
		"netops_backup_drill_last_timestamp_seconds 0",
		`netops_backup_drill_leg{leg="sealed_material"} -1`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics must contain %q:\n%s", want, buf.String())
		}
	}

	writeDrillReport(t, h.dir, `{"drill_id":"d1","bundle":"b","started":"2026-09-04T03:00:00Z",
	  "ended":"2026-09-04T03:07:00Z","result":"pass","assertions_passed":11,"assertions_failed":0,
	  "legs":{"postgres":{"result":"pass"},"sealed_material":{"result":"pass"},"clickhouse":{"result":"fail"}}}`)
	h.svc.refreshDrillMetrics()
	known, pass, at := h.svc.Metrics().DrillSnapshot()
	if !known || !pass || at.IsZero() {
		t.Fatalf("drill gauges after a passing report: known=%v pass=%v at=%v", known, pass, at)
	}
	buf.Reset()
	h.svc.Metrics().Write(&buf)
	for _, want := range []string{
		"netops_backup_drill_pass 1",
		`netops_backup_drill_leg{leg="postgres"} 1`,
		`netops_backup_drill_leg{leg="clickhouse"} 0`,
		`netops_backup_drill_leg{leg="victoriametrics"} -1`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics must contain %q:\n%s", want, buf.String())
		}
	}

	// A report we cannot DATE is not a current proof: the gauges fall back to
	// never rather than publishing an undateable green.
	writeDrillReport(t, h.dir, `{"drill_id":"d2","ended":"not-a-time","result":"pass"}`)
	h.svc.refreshDrillMetrics()
	if known, _, _ := h.svc.Metrics().DrillSnapshot(); known {
		t.Errorf("an undateable drill report must not publish a verdict")
	}
}
