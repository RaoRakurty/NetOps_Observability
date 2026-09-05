package dataprotect

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// coverage.go — GET /api/system/backup/coverage: the enterprise per-engine
// backup table.
//
// THE QUESTION THIS PAGE ANSWERS, and the one nothing in the product could
// answer before: for EVERY store that holds state on this host, is there a copy,
// when was it last taken, when was it last PROVEN restorable, where does it
// live, and what protects it there?
//
// The answers here are deliberately unflattering. Five of the seven rows report
// covered="no", and each says why in words an operator can act on. That is the
// point: the 2026-08-27 incident was survivable operationally and unsurvivable
// informationally — every surface said "fine". A coverage table that rounds
// "we do not measure this" up to "covered" would recreate exactly that.
//
// HONESTY RULES enforced by system_backup_coverage_test.go:
//   - CoveredReason is non-empty on EVERY row, including covered="yes";
//   - every nil pointer (Immutable, Encrypted, SizeBytes, RPOHours, Retention,
//     Schedule, LastAttempt, LastVerified) ships with a non-empty sibling
//     detail saying why it is nil;
//   - the External list is explicitly incomplete, and says so.
//
// ISOLATION: platform-GLOBAL (§3a rule 3) — the injected platform-admin gate,
// category "platform". No tenant data crosses this route, so there is
// deliberately no org-isolation test.

// BuildCoverage assembles the whole table. Pure-ish: it reads OpenSearch, the
// intent store, the backup report and the config-backup facts, and otherwise
// computes.
func (s *Service) BuildCoverage(ctx context.Context) BackupCoverageView {
	cfg := s.config()
	bundle := s.readBackupReport()
	view := BackupCoverageView{
		GeneratedAt: s.now().UTC(),
		Engines: []EngineCoverage{
			s.coverageOpenSearch(ctx),
			s.coverageSystemBundle(cfg, bundle),
			s.coveragePostgres(cfg, bundle),
			s.coverageClickHouse(cfg, bundle),
			coverageVictoriaMetrics(),
			coverageSecretsTLS(),
			s.coverageDeviceConfigs(),
		},
		External: externalMechanisms(),
		Detail: "This table covers the mechanisms the PRODUCT knows about. It is not a " +
			"complete inventory of everything that copies data on this host: the api runs in a " +
			"container and cannot read the host crontab, systemd timers or any operator-installed " +
			"job. Treat the External list as a known subset, never as proof that nothing else runs.",
	}
	// The nullable STRUCT fields get their sibling explanation here, in one
	// place, so a row can never ship a bare null that the GUI has to interpret.
	// Rows that have a specific reason set it themselves; this fills the rest
	// with the honest generic one and CLEARS the sibling wherever the pointer
	// is present (an explanation next to a value would read as a caveat on it).
	for i := range view.Engines {
		normalizeCoverageNulls(&view.Engines[i])
	}
	return view
}

// normalizeCoverageNulls enforces the per-field honesty rule for the three
// nullable structs (§ the contract's "a value we do not measure is a nil
// pointer, and it always ships with a sibling detail saying WHY").
func normalizeCoverageNulls(row *EngineCoverage) {
	switch {
	case row.Schedule != nil:
		row.ScheduleDetail = ""
	case row.ScheduleDetail == "":
		row.ScheduleDetail = "no schedule is published for this engine because no scheduled mechanism exists in the product"
	}
	switch {
	case row.LastAttempt != nil:
		row.LastAttemptDetail = ""
	case row.LastAttemptDetail == "":
		row.LastAttemptDetail = "no attempt has been recorded — either nothing has ever run a copy for this engine, " +
			"or no report of one is readable from inside the api container"
	}
	switch {
	case row.Retention != nil:
		row.RetentionDetail = ""
	case row.RetentionDetail == "":
		row.RetentionDetail = "no retention policy is published for this engine because no copies are kept"
	}
	if row.RPOTargetHours == nil && row.RPOTargetDetail == "" {
		row.RPOTargetDetail = "no schedule is in force for this engine, so no recovery-point target is defined"
	}
}

// ── OpenSearch ──────────────────────────────────────────────────────────────

func (s *Service) coverageOpenSearch(ctx context.Context) EngineCoverage {
	no := false
	row := EngineCoverage{
		ID:   "opensearch",
		Name: "OpenSearch (search tier: logs, traps, flows, findings, audit)",
		Target: CoverageTarget{
			Kind:     TargetLocal,
			Location: "data/opensearch-snapshots (bind mount on this host)",
			// Pointers, not omissions: on a filesystem repository the honest
			// answer to both is a measured NO, not "unknown".
			Immutable: &no,
			ImmutableDetail: "a filesystem repository on the same host; nothing prevents deletion — " +
				"this is exactly the 2026-08-27 failure, where the repository's blob tree was removed " +
				"out from under a still-registered repository and every restore point became unrestorable",
			Encrypted:       &no,
			EncryptedDetail: "fs repository, compress=true is not encryption",
			Detail:          "same failure domain as the data it protects: a host loss loses both",
		},
		SizeBytes:  nil,
		SizeDetail: "not measured here — sizing every snapshot costs one _status call each against the repository; GET /api/system/backup/snapshots/list?sizes=1 measures on demand",
	}

	repo := s.RepositoryView(ctx)
	policy := s.PolicyView(ctx)
	docs, docErr := s.fetchSnapshots(ctx)

	// Schedule — from the SM policy, which this GUI governs.
	row.Schedule = &CoverageSchedule{
		Enabled:       policy.Enabled,
		Cron:          policy.ScheduleCron,
		Timezone:      "UTC",
		GovernedByGUI: true,
		Detail:        "the netops-daily Snapshot Management policy; editable from this page (GET/PUT /api/system/backup/snapshots)",
	}
	if policy.Detail != "" {
		row.Schedule.Detail = "policy partially unreadable: " + policy.Detail
	}

	// Retention — count and age straight off the policy.
	retention := &CoverageRetention{
		Detail: "OpenSearch Snapshot Management deletion conditions on the netops-daily policy",
	}
	if policy.RetentionMaxCount > 0 {
		n := policy.RetentionMaxCount
		retention.MaxCount = &n
	} else {
		retention.Detail += "; no max_count configured"
	}
	if policy.RetentionMaxAgeDays > 0 {
		d := policy.RetentionMaxAgeDays
		retention.MaxAgeDays = &d
	} else {
		retention.Detail += "; no max_age configured (count-only retention)"
	}
	row.Retention = retention

	// Last attempt / last success / RPO — from the repository itself.
	switch {
	case docErr != nil:
		row.Covered = CoverageUnknown
		row.CoveredReason = "the snapshot repository could not be read, so coverage cannot be asserted either way: " + docErr.Error()
		row.RPODetail = "no readable restore point to date"
		row.LastAttemptDetail = "the repository is unreadable, so the newest snapshot attempt cannot be dated: " + docErr.Error()
	case !repo.Registered:
		row.Covered = CoverageNo
		row.CoveredReason = "snapshot repository " + s.repo() + " is NOT registered — the search tier has no backup at all"
		row.RPODetail = "no repository, therefore no recovery point"
		row.LastAttemptDetail = "there is no registered repository, so no snapshot has ever been attempted into one"
	case len(docs) == 0:
		row.Covered = CoverageNo
		row.CoveredReason = "the repository is registered but holds NO snapshots — a registered repository is not a backup"
		row.RPODetail = "no restore point exists"
		row.LastAttemptDetail = "the repository holds no snapshots, so there is no attempt to report"
	default:
		newest := docs[0]
		row.LastAttempt = &CoverageRun{
			At:     time.UnixMilli(newest.StartTimeMs).UTC().Format(time.RFC3339),
			Result: strings.ToLower(newest.State),
			Detail: "newest snapshot " + newest.Snapshot + " over " + strconv.Itoa(len(newest.Indices)) + " indices",
		}
		if success, ok := newestSuccessSnapshot(docs); ok {
			at := time.UnixMilli(success.EndTimeMs).UTC()
			row.LastSuccessAt = at.Format(time.RFC3339)
			hours := s.now().Sub(at).Hours()
			row.RPOHours = &hours
			row.RPODetail = "age of the newest SUCCESS snapshot (" + success.Snapshot + ")"
			row.Covered = CoverageYes
			row.CoveredReason = "the repository is registered and holds a SUCCESS snapshot taken " +
				strconv.Itoa(int(hours)) + "h ago under " +
				enabledWord(policy.Enabled) + " schedule — but see target.immutable: this copy lives on the same host"
			if !policy.Enabled {
				row.Covered = CoverageNo
				row.CoveredReason = "restore points exist, but the schedule is DISABLED — the newest copy is " +
					strconv.Itoa(int(hours)) + "h old and nothing will take another"
			}
		} else {
			row.Covered = CoverageNo
			row.CoveredReason = "the repository holds snapshots but NONE of them is in state SUCCESS — a PARTIAL or FAILED snapshot is not a restore point"
			row.RPODetail = "no SUCCESS snapshot exists"
		}
	}

	// The TARGET recovery point, derived from the schedule that is actually in
	// force. Never a number someone typed: an off schedule has no target.
	if policy.Enabled {
		if hours, ok := cronCadenceHours(policy.ScheduleCron); ok {
			row.RPOTargetHours = &hours
			row.RPOTargetDetail = "derived from the netops-daily creation cron " + strconv.Quote(policy.ScheduleCron)
		} else {
			row.RPOTargetDetail = "the schedule is enabled but its cadence is not derivable from the cron expression " +
				strconv.Quote(policy.ScheduleCron) + " — the target is left null rather than guessed"
		}
	} else {
		row.RPOTargetDetail = "the snapshot schedule is disabled, so no recovery-point target is in force"
	}

	// Last VERIFIED — the probe verdict, which is a different question from
	// "did a snapshot succeed".
	row.LastVerified = nil
	verdicts := s.verdicts.all()
	if len(docs) > 0 {
		if success, ok := newestSuccessSnapshot(docs); ok {
			if v, seen := verdicts[success.Snapshot]; seen {
				result := "fail"
				if v.Verified {
					result = "pass"
				}
				row.LastVerified = &CoverageRun{
					At: v.At.UTC().Format(time.RFC3339), Result: result, Detail: v.Detail,
				}
			}
		}
	}
	if row.LastVerified == nil {
		row.Detail = SnapshotNeverProbedDetail + " — the newest SUCCESS snapshot has no recorded probe verdict; " +
			"POST /api/system/backup/snapshots/verify runs one now"
		if !s.deps.ProbeEnabled {
			row.Detail += " (the nightly probe worker is DISABLED via SNAPSHOT_PROBE_ENABLED)"
		}
	}
	return row
}

// enabledWord carries its own article so the sentence it lands in reads.
func enabledWord(b bool) string {
	if b {
		return "an enabled"
	}
	return "a disabled"
}

// ── the Correlix system bundle (scripts/backup.sh) ──────────────────────────

func (s *Service) coverageSystemBundle(cfg Config, run *FullBackupRun) EngineCoverage {
	row := EngineCoverage{
		ID:   "system_bundle",
		Name: "Correlix system bundle (scripts/backup.sh: Postgres dump, ClickHouse export, api state, vault metadata)",
		Schedule: &CoverageSchedule{
			Enabled:       cfg.ScheduleEnabled,
			Cron:          cfg.ScheduleCron,
			Timezone:      "host local time (the crontab's, not UTC)",
			GovernedByGUI: true,
			Detail: "stored intent in data/api/system_backup.json; the HOST applier (the stack watchdog) " +
				"writes the actual root crontab entry — the api runs in a container and cannot write it itself, " +
				"so an enabled toggle here is an intent, not a proof that cron is running it",
		},
		Target: bundleTarget(cfg),
		Retention: &CoverageRetention{
			Detail: "artifact retention is the HOST applier's (scripts/backup.sh keeps a bounded number of " +
				"archives under the backup directory); the api cannot read the host filesystem outside its own " +
				"mounts, so neither a count nor an age is reported here rather than guessed",
		},
	}
	if cfg.ScheduleEnabled {
		if hours, ok := cronCadenceHours(cfg.ScheduleCron); ok {
			row.RPOTargetHours = &hours
			row.RPOTargetDetail = "derived from the stored bundle schedule " + strconv.Quote(cfg.ScheduleCron)
		} else {
			row.RPOTargetDetail = "the bundle schedule is enabled but its cadence is not derivable from " +
				strconv.Quote(cfg.ScheduleCron) + " — the target is left null rather than guessed"
		}
	} else {
		row.RPOTargetDetail = "the bundle schedule is disabled, so no recovery-point target is in force"
	}
	s.applyBundleRun(&row, run)
	return row
}

// cronCadenceHours derives the interval a 5-field cron implies, for the small
// set of shapes this platform actually writes. It is deliberately NOT a cron
// parser: anything it cannot read with certainty returns ok=false so the caller
// publishes a null target with a reason, which is the honest answer. A wrong
// target is worse than none — it would make an RPO breach look compliant.
func cronCadenceHours(expr string) (float64, bool) {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return 0, false
	}
	minute, hour, dom, mon, dow := f[0], f[1], f[2], f[3], f[4]
	numeric := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	// Only fixed day-of-month/month are handled; a list or range there means a
	// cadence we will not pretend to know.
	if mon != "*" || (dom != "*" && !numeric(dom)) {
		return 0, false
	}
	switch {
	case numeric(minute) && numeric(hour) && dom == "*" && dow == "*":
		return 24, true // daily
	case numeric(minute) && numeric(hour) && dom == "*" && numeric(dow):
		return 24 * 7, true // weekly, one fixed weekday
	case numeric(minute) && numeric(hour) && numeric(dom) && dow == "*":
		return 24 * 30, true // monthly (nominal 30d — stated as a month in the detail)
	case numeric(minute) && hour == "*" && dom == "*" && dow == "*":
		return 1, true // hourly
	case numeric(minute) && strings.HasPrefix(hour, "*/") && dom == "*" && dow == "*":
		n, err := strconv.Atoi(strings.TrimPrefix(hour, "*/"))
		if err != nil || n <= 0 || n > 23 {
			return 0, false
		}
		return float64(n), true
	}
	return 0, false
}

// bundleTarget describes where the bundle is pushed, with the destination
// REDACTED of anything that could carry a credential.
func bundleTarget(cfg Config) CoverageTarget {
	no := false
	if strings.TrimSpace(cfg.RemoteURL) == "" {
		return CoverageTarget{
			Kind:            TargetNone,
			Immutable:       &no,
			ImmutableDetail: "there is no off-host copy to protect",
			Encrypted:       &no,
			EncryptedDetail: "there is no off-host copy to encrypt",
			Detail: "no off-host destination is configured — the bundle would land on the same host as the data, " +
				"which is NOT disaster recovery: one host loss loses the data and the backup together",
		}
	}
	return CoverageTarget{
		Kind:            TargetRemote,
		Location:        redactBackupRemote(cfg.RemoteURL),
		Immutable:       nil,
		ImmutableDetail: "not measured — the api cannot inspect the remote's object-lock or WORM policy from inside the container",
		Encrypted:       nil,
		EncryptedDetail: "not measured — encryption at the destination is the remote's property, not something the push command reports",
		Detail:          "pushed by the host applier using the configured transport",
	}
}

// redactBackupRemote strips ANYTHING a destination URL could carry a secret in:
// userinfo (user:password@) and the query string (presigned tokens, SAS
// signatures, access keys). §8: no credential may reach a response body, a log
// or an audit detail.
func redactBackupRemote(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "/") {
		return raw // an absolute host path carries no credential
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Unparseable: reveal only the scheme, never the rest.
		if i := strings.Index(raw, "://"); i > 0 {
			return raw[:i] + "://(destination withheld — unparseable URL, not echoed in case it carries a credential)"
		}
		return "(destination withheld — unparseable)"
	}
	redacted := *u
	if u.User != nil {
		// A bare word, not "(redacted)": url.User percent-escapes anything
		// outside the userinfo charset, and "%28redacted%29" reads like data.
		redacted.User = url.User("redacted")
	}
	redacted.RawQuery = ""
	redacted.Fragment = ""
	out := redacted.String()
	if u.RawQuery != "" {
		out += " (query string redacted)"
	}
	return out
}

// applyBundleRun folds the host report into a row. An ABSENT report is the
// loudest state: it means nothing has ever reported a backup on this host.
func (s *Service) applyBundleRun(row *EngineCoverage, run *FullBackupRun) {
	row.SizeDetail = "no backup report has been written, so no artifact size is known"
	row.RPODetail = "no reported bundle run to date"
	if run == nil {
		row.Covered = CoverageNo
		row.LastAttemptDetail = "no backup report exists at " + s.deps.BackupReportPath +
			", so no bundle run — successful or failed — has ever been reported to the api"
		row.CoveredReason = "no backup report has ever been written on this host (" +
			s.deps.BackupReportPath + " is absent) — nothing has reported taking a system bundle, " +
			"and an unreported backup is indistinguishable from no backup"
		return
	}
	result := strings.ToLower(strings.TrimSpace(run.Status))
	row.LastAttempt = &CoverageRun{At: run.Ended, Result: result, Detail: bundleRunDetail(run)}
	if run.SizeBytes > 0 {
		n := run.SizeBytes
		row.SizeBytes = &n
		row.SizeDetail = "size of the last reported bundle artifact"
	}
	if result == "success" || result == "ok" {
		row.LastSuccessAt = run.Ended
		row.Covered = CoverageYes
		row.CoveredReason = "the host bundle reported success at " + run.Ended
		if at, err := time.Parse(time.RFC3339, run.Ended); err == nil {
			hours := s.now().Sub(at).Hours()
			row.RPOHours = &hours
			row.RPODetail = "age of the last reported SUCCESSFUL bundle"
		} else {
			row.RPODetail = "the report's end time (" + run.Ended + ") is not RFC3339, so its age cannot be computed"
		}
	} else {
		row.Covered = CoverageNo
		row.CoveredReason = "the last reported bundle run did not succeed (status " + run.Status +
			", " + strconv.Itoa(run.Failures) + " failures) — the newest artifact, if any, predates it"
		row.RPODetail = "the last run failed, so there is no dateable good copy"
	}
	// The bundle has never been restore-tested by this product.
	row.LastVerified = nil
	if row.Detail == "" {
		row.Detail = "no restorability proof exists for the bundle: scripts/restore-drill.sh is the only " +
			"mechanism that would produce one and this page does not run it"
	}
}

func bundleRunDetail(run *FullBackupRun) string {
	d := "duration " + strconv.Itoa(run.DurationSeconds) + "s, " + strconv.Itoa(run.Failures) + " component failures"
	if run.Artifact != "" {
		d += ", artifact " + run.Artifact
	}
	return d
}

// readBackupReport reads the host bundle's report (Deps.BackupReportPath, named
// in the reasons so an operator knows exactly which file was absent). Absent =
// nil, and nil is rendered as "never", never as blank.
func (s *Service) readBackupReport() *FullBackupRun {
	b, err := readReportFile(s.deps.BackupReportPath)
	if err != nil {
		return nil
	}
	var rep FullBackupRun
	if json.Unmarshal(b, &rep) != nil || rep.Status == "" {
		return nil
	}
	return &rep
}

// ── Postgres ────────────────────────────────────────────────────────────────

func (s *Service) coveragePostgres(cfg Config, run *FullBackupRun) EngineCoverage {
	row := EngineCoverage{
		ID:      "postgres",
		Name:    "PostgreSQL (control plane: tenants, users, policies, incidents, config-version metadata)",
		Covered: CoverageNo,
		CoveredReason: "pg_dumpall runs only INSIDE the system bundle (scripts/backup.sh); there is no " +
			"independent Postgres backup job. Covered only when the bundle is scheduled and succeeding.",
		Target:     bundleTarget(cfg),
		SizeBytes:  nil,
		SizeDetail: "not measured — the dump's size is not reported separately from the bundle artifact",
		Retention: &CoverageRetention{
			Detail: "no independent retention: the dump lives and dies with the bundle artifact, whose retention is the host applier's",
		},
		RPODetail: "no independent Postgres copy exists; the bundle's RPO is the only one that applies",
		RPOTargetDetail: "no Postgres-specific schedule exists, so no Postgres-specific target is defined — " +
			"the only cadence that applies is the system bundle's, on its own row",
	}
	row.Schedule = &CoverageSchedule{
		Enabled:       cfg.ScheduleEnabled,
		Cron:          cfg.ScheduleCron,
		Timezone:      "host local time",
		GovernedByGUI: true,
		Detail:        "inherited from the system bundle's schedule — there is nothing separate to enable",
	}
	// Reflect the bundle's actual state: a failing bundle means a failing
	// Postgres dump, and saying so is the whole reason this row exists.
	if run == nil {
		row.CoveredReason += " No backup report exists on this host, so no dump has been reported at all."
		row.LastAttemptDetail = "no backup report exists at " + s.deps.BackupReportPath +
			"; this row has no independent job of its own to report on"
		return row
	}
	result := strings.ToLower(strings.TrimSpace(run.Status))
	row.LastAttempt = &CoverageRun{At: run.Ended, Result: result, Detail: "reported by the system bundle, not by an independent job"}
	if result == "success" || result == "ok" {
		row.LastSuccessAt = run.Ended
		row.CoveredReason += " The bundle last reported success at " + run.Ended +
			", so a dump of that vintage exists inside that artifact."
		if at, err := time.Parse(time.RFC3339, run.Ended); err == nil {
			hours := s.now().Sub(at).Hours()
			row.RPOHours = &hours
			row.RPODetail = "age of the bundle that contains the newest dump"
		}
	} else {
		row.CoveredReason += " The bundle's last run reported " + run.Status + ", so the newest dump is older than that run."
	}
	row.LastVerified = nil
	row.Detail = "no restorability proof: nothing in this product has restored a pg_dumpall from a bundle and compared it to the live database"
	return row
}

// ── ClickHouse ──────────────────────────────────────────────────────────────

func (s *Service) coverageClickHouse(cfg Config, run *FullBackupRun) EngineCoverage {
	row := EngineCoverage{
		ID:      "clickhouse",
		Name:    "ClickHouse (OLAP tier: flows, path graph, correlation facts)",
		Covered: CoverageNo,
		CoveredReason: "ClickHouse is exported only INSIDE the system bundle (scripts/backup.sh), which writes the " +
			"schema plus per-table data; there is no independent ClickHouse backup job. " +
			"scripts/ch-cold-export.sh is cold TIERING, not a backup — it moves aged partitions out of the hot " +
			"tier and deleting the cold copy loses that data outright. Covered only when the bundle is scheduled and succeeding.",
		Target:     bundleTarget(cfg),
		SizeBytes:  nil,
		SizeDetail: "not measured — the export's size is not reported separately from the bundle artifact",
		Retention: &CoverageRetention{
			Detail: "no independent retention: the export lives and dies with the bundle artifact",
		},
		RPODetail: "no independent ClickHouse copy exists; the bundle's RPO is the only one that applies",
		RPOTargetDetail: "no ClickHouse-specific schedule exists, so no ClickHouse-specific target is defined — " +
			"the only cadence that applies is the system bundle's, on its own row",
		Detail: "whether a host cron runs scripts/ch-cold-export.sh is NOT something the api can see from inside " +
			"the container — the page lists host cron separately under `external`, and that list is itself incomplete",
	}
	row.Schedule = &CoverageSchedule{
		Enabled:       cfg.ScheduleEnabled,
		Cron:          cfg.ScheduleCron,
		Timezone:      "host local time",
		GovernedByGUI: false,
		Detail: "the DATA export is inherited from the system bundle's schedule (governed by this GUI), but cold " +
			"tiering is a host cron this GUI does not govern and cannot enumerate",
	}
	if run == nil {
		row.CoveredReason += " No backup report exists on this host, so no export has been reported at all."
		row.LastAttemptDetail = "no backup report exists at " + s.deps.BackupReportPath +
			"; this row has no independent job of its own to report on"
		return row
	}
	result := strings.ToLower(strings.TrimSpace(run.Status))
	row.LastAttempt = &CoverageRun{At: run.Ended, Result: result, Detail: "reported by the system bundle, not by an independent job"}
	if result == "success" || result == "ok" {
		row.LastSuccessAt = run.Ended
		row.CoveredReason += " The bundle last reported success at " + run.Ended + "."
		if at, err := time.Parse(time.RFC3339, run.Ended); err == nil {
			hours := s.now().Sub(at).Hours()
			row.RPOHours = &hours
			row.RPODetail = "age of the bundle that contains the newest export"
		}
	} else {
		row.CoveredReason += " The bundle's last run reported " + run.Status + "."
	}
	row.LastVerified = nil
	return row
}

// ── VictoriaMetrics ─────────────────────────────────────────────────────────

func coverageVictoriaMetrics() EngineCoverage {
	no := false
	return EngineCoverage{
		ID:      "victoriametrics",
		Name:    "VictoriaMetrics (time-series tier: every metric, including the ones this page's alerts fire on)",
		Covered: CoverageNo,
		CoveredReason: "no VictoriaMetrics snapshot caller exists in this platform; the only protection is in-place " +
			"retention (-retentionPeriod). A lost data/victoria is unrecoverable.",
		Schedule:          nil,
		ScheduleDetail:    "no VictoriaMetrics snapshot mechanism exists in this platform, so there is no schedule to show",
		LastAttempt:       nil,
		LastAttemptDetail: "nothing has ever attempted a VictoriaMetrics snapshot, so there is no attempt to report",
		LastVerified:      nil,
		SizeBytes:         nil,
		SizeDetail:        "not measured — no copy exists to size",
		Retention: &CoverageRetention{
			Detail: "in-place retention only (-retentionPeriod on the vmsingle container). Retention is not backup: " +
				"it bounds how long data survives, not whether it survives losing the disk.",
		},
		Target: CoverageTarget{
			Kind:            TargetNone,
			Immutable:       &no,
			ImmutableDetail: "there is no copy to protect",
			Encrypted:       &no,
			EncryptedDetail: "there is no copy to encrypt",
			Detail:          "VictoriaMetrics exposes /snapshot/create; nothing in this platform calls it",
		},
		RPOHours:        nil,
		RPODetail:       "there is no copy, so there is no recovery point at all",
		RPOTargetHours:  nil,
		RPOTargetDetail: "no schedule exists, so no recovery-point target is defined",
		Detail: "schedule is null because no mechanism exists to schedule — showing a disabled toggle would " +
			"imply one could be turned on here, and nothing on this page can create a VictoriaMetrics snapshot; " +
			"last_attempt and last_verified are null for the same reason",
	}
}

// ── sealed secrets / TLS material ───────────────────────────────────────────

func coverageSecretsTLS() EngineCoverage {
	no := false
	return EngineCoverage{
		ID:      "secrets_tls",
		Name:    "Sealed key material (data/swtpm, data/tls, wrapped secret keys)",
		Covered: CoverageNo,
		CoveredReason: "sealed key material (data/swtpm, data/tls, wrapped secret keys) is in no scheduled copy; " +
			"losing it makes vault contents unrecoverable even from a good data backup.",
		Schedule:          nil,
		ScheduleDetail:    "no mechanism copies this material, so there is no schedule to show — a disabled toggle here would imply one could be turned on",
		LastAttempt:       nil,
		LastAttemptDetail: "nothing has ever attempted a copy of this material, so there is no attempt to report",
		LastVerified:      nil,
		SizeBytes:         nil,
		SizeDetail:        "not measured — no copy exists to size",
		Retention: &CoverageRetention{
			Detail: "no copies are made, so there is nothing to retain",
		},
		Target: CoverageTarget{
			Kind:            TargetNone,
			Immutable:       &no,
			ImmutableDetail: "there is no copy to protect",
			Encrypted:       &no,
			EncryptedDetail: "there is no copy to encrypt; the material is sealed AT REST but never copied anywhere",
			Detail:          "custody material deliberately never leaves the host automatically — copying it is an owner decision, not a default",
		},
		RPOHours:        nil,
		RPODetail:       "there is no copy, so there is no recovery point at all",
		RPOTargetHours:  nil,
		RPOTargetDetail: "no schedule exists, so no recovery-point target is defined",
		Detail: "this is the row that turns a survivable data loss into an unsurvivable one: a restored data " +
			"backup whose KEK is gone decrypts nothing. schedule, last_attempt and last_verified are null " +
			"because no mechanism copies this material at all — there is nothing to schedule, attempt or verify",
	}
}

// ── device configuration versions (the in-product config-backup module) ─────

// coverageDeviceConfigs renders the config-backup module's row from the
// INJECTED facts (Deps.DeviceConfigs). This package deliberately does not
// import the module: it needs the module's cadence, depth and counters, not its
// types, and importing it would be a cross-domain dependency (§13) for four
// numbers and three env NAMES.
func (s *Service) coverageDeviceConfigs() EngineCoverage {
	row := EngineCoverage{
		ID:   "device_configs",
		Name: "Device configuration versions (in-product config backup)",
		Target: CoverageTarget{
			Kind:            TargetLocal,
			Location:        "data/api/config-backups (sealed blobs on this host)",
			Immutable:       coverageBool(false),
			ImmutableDetail: "content-addressed but deletable: retention prunes old versions and nothing prevents removal of the directory",
			Encrypted:       coverageBool(true),
			EncryptedDetail: "each version is sealed under the platform sealing mechanism before it is written",
			Detail:          "on-host only — these versions are themselves protected ONLY by the system bundle",
		},
		LastAttempt:  nil,
		LastVerified: nil,
		RPOHours:     nil,
		RPODetail:    "the manager does not record a last-run timestamp, so the age of the newest capture cannot be reported here",
	}
	var (
		facts DeviceConfigFacts
		on    bool
	)
	if s.deps.DeviceConfigs != nil {
		facts, on = s.deps.DeviceConfigs.Facts()
	}
	if !on {
		row.Covered = CoverageNotApplicable
		row.CoveredReason = "the config-backup module is OFF (" + deviceConfigEnv(facts.FeatureFlagEnv, "FEATURE_CONFIG_BACKUP") +
			" is not true), so no device configuration is captured at all"
		row.Schedule = &CoverageSchedule{
			Enabled:       false,
			GovernedByGUI: false,
			Detail:        "the module is disabled by feature flag; enabling it is an env change on the api container, not a GUI toggle",
		}
		row.Retention = &CoverageRetention{
			Detail: "no versions are stored while the module is off",
		}
		row.RPOTargetDetail = "the config-backup module is off, so no capture cadence — and therefore no target — is in force"
		row.SizeDetail = "not measured — the module is off"
		row.Detail = "with the module off, a device's running configuration exists only on the device"
		return row
	}
	interval := facts.Interval
	intervalEnv := deviceConfigEnv(facts.IntervalEnv, "CONFIG_BACKUP_INTERVAL")
	row.Covered = CoverageYes
	row.CoveredReason = "the config-backup module is enabled and captures every eligible device on a " +
		interval.String() + " jittered cadence, keeping " + strconv.Itoa(facts.KeepVersions) +
		" versions per device under data/api/config-backups — but those versions are themselves on this host " +
		"and are protected only by the system bundle"
	row.Schedule = &CoverageSchedule{
		Enabled:       true,
		Cron:          "every " + interval.String() + " (jittered; not a cron expression)",
		Timezone:      "UTC",
		GovernedByGUI: false,
		Detail: "cadence comes from " + intervalEnv + " on the api container, not from this page; " +
			"the module jitters every interval so replicas never capture in lockstep",
	}
	targetHours := interval.Hours()
	row.RPOTargetHours = &targetHours
	row.RPOTargetDetail = "derived from the module's capture interval (" + intervalEnv + " = " +
		interval.String() + "); captures are jittered around it, so a single capture can land slightly late"
	keep := facts.KeepVersions
	row.Retention = &CoverageRetention{
		MaxCount:   &keep,
		MaxAgeDays: nil,
		Detail: "per-device version depth from " + deviceConfigEnv(facts.KeepVersionsEnv, "CONFIG_BACKUP_KEEP_VERSIONS") +
			"; there is no age-based retention — depth is the only bound",
	}
	// The manager exposes counters but no last-run timestamp: report the
	// counters and say plainly that the timestamp does not exist rather than
	// inventing one from "now".
	row.SizeDetail = "not measured as a total — the module reports sealed BYTES WRITTEN as a counter, which is not the same as the size on disk after retention pruning"
	if facts.HasCounters {
		row.Detail = "counters since this api process started: " +
			strconv.Itoa(int(facts.Versions)) + " new versions, " +
			strconv.Itoa(int(facts.Failed)) + " failed captures, " +
			strconv.Itoa(int(facts.Pruned)) + " pruned. " +
			"The manager does not record a last-run timestamp, so last_attempt is null rather than guessed."
	} else {
		row.Detail = "the manager exposes no counters in this build; last_attempt is null rather than guessed"
	}
	return row
}

// deviceConfigEnv falls back to the shipped env NAME when the integrator did
// not supply one. The name is operator-facing prose, so a blank there would
// produce a sentence with a hole in it — the opposite of an actionable reason.
func deviceConfigEnv(name, fallback string) string {
	if strings.TrimSpace(name) == "" {
		return fallback
	}
	return name
}

// ── external, host-side mechanisms ──────────────────────────────────────────

// externalMechanisms lists the host-side jobs the PRODUCT knows exist. The api
// runs in a container: it cannot read /etc/crontab, the root crontab or systemd
// timers, so this list is HARD-CODED from what the product itself installs and
// is explicitly incomplete (BackupCoverageView.Detail says so). Showing the
// known subset beats showing nothing, because a GUI toggle that reads "off"
// while a host job still runs is precisely the defect this page closes.
func externalMechanisms() []ExternalMechanism {
	const notGoverned = "external to the product — this page does not govern it"
	return []ExternalMechanism{
		{
			Name:     "stack watchdog backup applier (scripts/stack-watchdog.sh)",
			Source:   "host crontab",
			Schedule: "every 1 minute",
			Detail: notGoverned + "; it reads data/api/system_backup.json and installs/removes the root crontab " +
				"entry for scripts/backup.sh, which is how the schedule stored on this page reaches cron at all",
		},
		{
			Name:     "weekly docker hygiene (scripts/docker-hygiene.sh)",
			Source:   "host crontab",
			Schedule: "weekly",
			Detail:   notGoverned + "; prunes images/volumes on this host — it does not copy data, but it can remove things",
		},
		{
			Name:     "host hygiene sweep (scripts/host-hygiene.sh)",
			Source:   "host crontab",
			Schedule: "weekly",
			Detail:   notGoverned + "; reclaims host disk space, including under data/ — it can delete what a backup would have needed",
		},
	}
}

// coverageBool is a local helper so a literal true/false can be a pointer field
// without a named variable at every call site. (Named for this surface: the
// test tree already has a boolPtr.)
func coverageBool(b bool) *bool { return &b }
