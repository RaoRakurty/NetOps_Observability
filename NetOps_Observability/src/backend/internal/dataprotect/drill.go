package dataprotect

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// drill.go — the RESTORE DRILL's side of the honesty rule.
//
// WHY THIS FILE EXISTS. Every other file in this package answers "is there a
// copy, and how old is it". None of them could answer the only question that
// matters at recovery time: has anyone ever put one back? The coverage table
// said so out loud on four rows — "no restorability proof: nothing in this
// product has restored a pg_dumpall from a bundle and compared it to the live
// database" — and that sentence was true.
//
// scripts/backup-drill.sh makes it false. It takes a REAL bundle artifact,
// restores the Postgres and ClickHouse dumps into throwaway databases and
// compares row counts, imports the VictoriaMetrics snapshot into a scratch
// vmsingle and queries a series back out, decrypts the sealed custody envelope
// and verifies it against its own sha256 manifest, then deletes every
// temporary. It writes the verdict as JSON, per leg. This file reads that file.
//
// THE RULES IT KEEPS, which are the same ones the rest of the surface keeps:
//   - a leg that did not run is NOT a leg that passed. An absent report, an
//     absent leg and a skipped leg are three different answers and none of them
//     is "verified";
//   - the verdict carries its own age. The drill proves the bundle it was RUN
//     against, so a leg's proof is only as current as the drill that produced
//     it, and LastVerified.At is what lets the GUI and the alert rule say that;
//   - nothing here fabricates a pass on the strength of an exit code. The
//     script asserts CONTENT (row counts, a queried sample, a checksum
//     manifest) and this file reports what it asserted.

// Drill leg keys. Closed vocabulary, matched to scripts/backup-drill.sh.
const (
	DrillLegPostgres        = "postgres"
	DrillLegClickHouse      = "clickhouse"
	DrillLegVictoriaMetrics = "victoriametrics"
	DrillLegSealedMaterial  = "sealed_material"
)

// Drill leg results. "skip" is first-class: a leg the operator restricted out
// of the run has proven nothing, and must never read as a pass.
const (
	DrillPass = "pass"
	DrillFail = "fail"
	DrillSkip = "skip"
)

// BackupDrillLeg is one store's verdict inside a drill run.
type BackupDrillLeg struct {
	Result string `json:"result"` // pass | fail | skip
	// Detail is the assertion in words — "restored 3 of 3 tables, 1284 rows
	// matched the live count". It is operator-facing prose and is echoed into
	// the coverage row, so a blank one is a defect, not a style choice.
	Detail          string `json:"detail,omitempty"`
	DurationSeconds int    `json:"duration_seconds,omitempty"`
}

// BackupDrillReport mirrors scripts/backup-drill.sh's report JSON verbatim.
type BackupDrillReport struct {
	DrillID          string                    `json:"drill_id"`
	Bundle           string                    `json:"bundle,omitempty"`
	Started          string                    `json:"started"`
	Ended            string                    `json:"ended"`
	Result           string                    `json:"result"` // pass | fail
	AssertionsPassed int                       `json:"assertions_passed"`
	AssertionsFailed int                       `json:"assertions_failed"`
	Legs             map[string]BackupDrillLeg `json:"legs,omitempty"`
}

// readBackupDrillReport reads the drill report at Deps.BackupDrillReportPath.
// Absent, unparseable or resultless = nil, and nil is rendered as "no drill has
// ever been recorded" — never as a blank an operator reads as fine.
func (s *Service) readBackupDrillReport() *BackupDrillReport {
	b, err := readReportFile(s.deps.BackupDrillReportPath)
	if err != nil {
		return nil
	}
	var rep BackupDrillReport
	if json.Unmarshal(b, &rep) != nil || strings.TrimSpace(rep.Result) == "" {
		return nil
	}
	return &rep
}

// drillLeg yields one leg's verdict, or ok=false when the report is absent or
// carries no such leg. The caller must render ok=false as "not proven", which
// is the whole discipline: unproven is not a synonym for fine.
func (r *BackupDrillReport) drillLeg(key string) (BackupDrillLeg, bool) {
	if r == nil || len(r.Legs) == 0 {
		return BackupDrillLeg{}, false
	}
	leg, ok := r.Legs[key]
	if !ok {
		return BackupDrillLeg{}, false
	}
	leg.Result = strings.ToLower(strings.TrimSpace(leg.Result))
	return leg, true
}

// applyDrillVerdict fills a coverage row's LastVerified from the drill report.
//
// It sets LastVerified ONLY for a leg that actually ran (pass or fail). A
// missing report, a missing leg or a skipped leg leaves the pointer nil and
// writes the reason into row.Detail, because a null with no explanation is the
// exact shape this surface exists to remove.
func (s *Service) applyDrillVerdict(row *EngineCoverage, rep *BackupDrillReport, leg string) {
	var reason string
	if rep == nil {
		reason = "no restore drill has ever been recorded at " + s.deps.BackupDrillReportPath +
			" — scripts/backup-drill.sh is the mechanism that would produce one, and nothing has run it on this host"
	} else {
		l, ok := rep.drillLeg(leg)
		switch {
		case !ok:
			reason = "the last restore drill (" + rep.DrillID + ", " + rep.Ended + ") did not include a " + leg +
				" leg, so this engine's restorability is still unproven"
		case l.Result == DrillSkip:
			reason = "the " + leg + " leg was SKIPPED in the last restore drill (" + rep.Ended + ")" +
				detailSuffix(l.Detail) + " — a skipped leg proves nothing"
		case l.Result == DrillPass || l.Result == DrillFail:
			row.LastVerified = &CoverageRun{
				At:     rep.Ended,
				Result: l.Result,
				Detail: drillLegDetail(rep, l),
			}
			return
		default:
			reason = "the last restore drill reported an unrecognised result " + strconv.Quote(l.Result) +
				" for the " + leg + " leg, which is not a proof of anything"
		}
	}
	row.LastVerified = nil
	if row.Detail == "" {
		row.Detail = reason
	} else {
		row.Detail += " " + reason
	}
}

// drillLegDetail composes the sentence the GUI shows next to a verdict: what
// was asserted, how long the restore took (the RTO half), and which drill it
// came from so the operator can find its log.
func drillLegDetail(rep *BackupDrillReport, l BackupDrillLeg) string {
	d := l.Detail
	if strings.TrimSpace(d) == "" {
		d = "the drill recorded a verdict but no detail — treat the proof as thin"
	}
	if l.DurationSeconds > 0 {
		d += " (restore took " + strconv.Itoa(l.DurationSeconds) + "s)"
	}
	if rep != nil && rep.DrillID != "" {
		d += " [drill " + rep.DrillID + "]"
	}
	return d
}

// detailSuffix appends a script-supplied detail without producing a dangling
// separator when there is none.
func detailSuffix(d string) string {
	if strings.TrimSpace(d) == "" {
		return ""
	}
	return ": " + d
}

// drillEndedAt parses the report's end time. ok=false covers both "no report"
// and "a report whose timestamp is not RFC3339", which are equally unusable as
// an age and equally must not be rounded to now().
func (r *BackupDrillReport) drillEndedAt() (time.Time, bool) {
	if r == nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(r.Ended))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// refreshDrillMetrics republishes the drill gauges from the report on disk. It
// is called on every probe tick — BEFORE the tick's OpenSearch call, so a
// cluster outage cannot also freeze the drill signal — and is cheap: one read
// of a few hundred bytes from the api's own /data mount.
//
// An unreadable report publishes known=false, which renders as a ZERO
// timestamp. That is the state BackupRestoreDrillMissed alerts on, and it is
// the right default: a platform that has never proved a bundle restores is in
// the same operational position as one whose last proof expired.
func (s *Service) refreshDrillMetrics() {
	rep := s.readBackupDrillReport()
	if rep == nil {
		s.metrics.setDrill(false, false, time.Time{}, nil)
		return
	}
	at, ok := rep.drillEndedAt()
	if !ok {
		// A report we cannot date is a report we cannot age, and an undateable
		// proof is not a current one.
		s.deps.Log.Warn("backup.drill", "restore-drill report has an unparseable end time — the drill gauges stay at never",
			map[string]any{"path": s.deps.BackupDrillReportPath, "ended": rep.Ended})
		s.metrics.setDrill(false, false, time.Time{}, nil)
		return
	}
	legs := make(map[string]string, len(rep.Legs))
	for k, v := range rep.Legs {
		legs[k] = strings.ToLower(strings.TrimSpace(v.Result))
	}
	s.metrics.setDrill(true, strings.EqualFold(strings.TrimSpace(rep.Result), DrillPass), at, legs)
}
