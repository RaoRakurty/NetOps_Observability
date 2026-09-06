// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// policy.go — #150: the OpenSearch snapshot-policy control plane.
//
// The GUI's snapshot controls are a THIN TRUTHFUL VIEW over the netops-daily
// Snapshot Management policy (owner decision: mirror the OS SM vocabulary —
// enabled / schedule cron / retention.max_count — never invent a parallel
// one). Reads combine the policy document with the SM explain API (last run,
// next trigger); writes go straight to the policy with the seq_no/primary_term
// concurrency dance apply-ism.sh proved necessary, and enable/disable rides
// the plugin's own _start/_stop. Policy CRUD only: snapshot create/restore/
// delete live in ops.go behind their own type-to-confirm guards.

// SnapshotRun is one SM execution outcome (creation or deletion leg).
type SnapshotRun struct {
	Status          string `json:"status"`
	Time            string `json:"time,omitempty"` // end time, RFC3339
	DurationSeconds int    `json:"duration_seconds,omitempty"`
}

// SnapshotPolicyView is what the GUI renders. Detail carries the honest
// explanation whenever any part could not be read — never a blank panel.
type SnapshotPolicyView struct {
	Enabled           bool   `json:"enabled"`
	ScheduleCron      string `json:"schedule_cron"`
	RetentionMaxCount int    `json:"retention_max_count"`
	// RetentionMaxAgeDays mirrors deletion.condition.max_age ("<N>d"); 0 = no
	// age limit configured (count-only retention).
	RetentionMaxAgeDays int          `json:"retention_max_age_days"`
	LastRun             *SnapshotRun `json:"last_run,omitempty"`
	NextRun             string       `json:"next_run,omitempty"` // RFC3339
	Detail              string       `json:"detail,omitempty"`

	// ── additive, 2026-09-03 (the existing shape above is unchanged) ────────

	// Repository is the repository itself, not its contents: a registered
	// repository whose blob tree is gone still answers with a policy, a
	// schedule and a list of restore points (the 2026-08-27 incident), so the
	// registration fact is carried separately and never inferred from the
	// policy. Verified is always nil here — verification WRITES to the
	// repository and a read must not.
	Repository SnapshotRepositoryView `json:"repository"`

	// DisabledReason/At/By are the stored OPERATOR INTENT behind an off
	// schedule. Empty when the schedule was never deliberately stopped.
	DisabledReason string `json:"disabled_reason,omitempty"`
	DisabledAt     string `json:"disabled_at,omitempty"` // RFC3339 UTC
	DisabledBy     string `json:"disabled_by,omitempty"`
	// ManagedBy names WHO last WROTE the live policy, from a CLOSED vocabulary:
	//
	//   "gui"         — this api's own PUT is the newest write (its recorded
	//                   write time matches the policy's last_updated_time).
	//   "policy-file" — this api has never written the policy, so the
	//                   opensearch-init bootstrap (apply-ism.sh) is the writer
	//                   this platform ships. See ManagedByDetail: the SM
	//                   document records no author, so a hand edit on a
	//                   never-GUI-managed policy also reads policy-file.
	//   "external"    — the policy was updated AFTER this api's last write.
	//                   That is a redeploy's bootstrap or a person; the
	//                   document does not say which, and ManagedByDetail says
	//                   so rather than picking one.
	//   "unknown"     — the policy or its last_updated_time is unreadable.
	//
	// A guess dressed as a fact is what this whole surface exists to stop, so
	// the ambiguity lives in the detail rather than in a confident label.
	ManagedBy       string `json:"managed_by"`
	ManagedByDetail string `json:"managed_by_detail"`
}

// snapshotPolicyUpdate is the PUT body — all fields optional (partial update,
// the same convention the OS SM policy API itself uses).
type snapshotPolicyUpdate struct {
	Enabled           *bool   `json:"enabled,omitempty"`
	ScheduleCron      *string `json:"schedule_cron,omitempty"`
	RetentionMaxCount *int    `json:"retention_max_count,omitempty"`
	// 0 clears the age condition (count-only retention); 1..3650 sets "<N>d".
	RetentionMaxAgeDays *int `json:"retention_max_age_days,omitempty"`
	// Reason is the operator's stated reason for an enable/disable. Recorded
	// with the intent so a stopped schedule can never look like an accident.
	// Optional, bounded, control chars refused; ignored unless Enabled is set.
	Reason *string `json:"reason,omitempty"`
}

const smPolicyPath = "/_plugins/_sm/policies/netops-daily"

// smPolicyTimeout is the fixed deadline for a policy read/write. Right for a
// policy call and deliberately NOT reused by the long snapshot operations,
// which pass their own (§9).
const smPolicyTimeout = 10 * time.Second

// smPolicyDoc is the subset of the SM policy document we read AND write back.
// Raw preserves the full policy body so an update round-trips fields this
// struct does not model (notification config, deletion schedule, time limits).
type smPolicyDoc struct {
	SeqNo       int64
	PrimaryTerm int64
	Raw         map[string]any
}

func (s *Service) smGetPolicy(ctx context.Context) (*smPolicyDoc, error) {
	var body struct {
		SeqNo       int64          `json:"_seq_no"`
		PrimaryTerm int64          `json:"_primary_term"`
		Policy      map[string]any `json:"sm_policy"`
	}
	if err := s.osDo(ctx, http.MethodGet, smPolicyPath, nil, &body, smPolicyTimeout); err != nil {
		return nil, err
	}
	return &smPolicyDoc{SeqNo: body.SeqNo, PrimaryTerm: body.PrimaryTerm, Raw: body.Policy}, nil
}

// digMap walks nested map[string]any keys, returning nil when any hop is absent.
func digMap(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

// PolicyView renders the snapshot-policy control plane.
func (s *Service) PolicyView(ctx context.Context) SnapshotPolicyView {
	v := SnapshotPolicyView{ManagedBy: "unknown",
		ManagedByDetail: "the snapshot policy could not be read, so its last writer is unknown"}
	// The repository registration is read INDEPENDENTLY of the policy, and both
	// are rendered: a healthy policy over a dead repository is precisely the
	// 2026-08-27 state, and a view that showed only one of them could not tell
	// the difference.
	v.Repository = s.RepositoryView(ctx)
	// The stored operator intent, whatever the cluster currently says. When the
	// two disagree — cluster enabled, intent disabled — the operator can SEE
	// that the bootstrap re-enabled a policy they stopped.
	if enabled, reason, at, by := s.SnapshotScheduleIntent(); !enabled {
		v.DisabledReason = reason
		v.DisabledBy = by
		if !at.IsZero() {
			v.DisabledAt = at.UTC().Format(time.RFC3339)
		}
	}
	doc, err := s.smGetPolicy(ctx)
	if err != nil {
		v.Detail = "snapshot policy unreadable: " + err.Error()
		return v
	}
	if b, ok := doc.Raw["enabled"].(bool); ok {
		v.Enabled = b
	}
	if cron, ok := digMap(doc.Raw, "creation", "schedule", "cron", "expression").(string); ok {
		v.ScheduleCron = cron
	}
	v.ManagedBy, v.ManagedByDetail = snapshotPolicyManagedBy(
		policyLastUpdated(doc.Raw), s.config().SnapshotPolicyWrittenAt)
	if mc, ok := digMap(doc.Raw, "deletion", "condition", "max_count").(float64); ok {
		v.RetentionMaxCount = int(mc)
	}
	if ma, ok := digMap(doc.Raw, "deletion", "condition", "max_age").(string); ok {
		v.RetentionMaxAgeDays = maxAgeDays(ma)
	}

	// Explain: last execution + next trigger for the creation leg.
	var expl struct {
		Policies []struct {
			Name     string `json:"name"`
			Creation struct {
				Trigger struct {
					Time int64 `json:"time"`
				} `json:"trigger"`
				LatestExecution *struct {
					Status    string `json:"status"`
					StartTime int64  `json:"start_time"`
					EndTime   int64  `json:"end_time"`
				} `json:"latest_execution"`
			} `json:"creation"`
		} `json:"policies"`
	}
	if err := s.osDo(ctx, http.MethodGet, smPolicyPath+"/_explain", nil, &expl, smPolicyTimeout); err == nil && len(expl.Policies) > 0 {
		c := expl.Policies[0].Creation
		if c.Trigger.Time > 0 {
			v.NextRun = time.UnixMilli(c.Trigger.Time).UTC().Format(time.RFC3339)
		}
		if le := c.LatestExecution; le != nil {
			run := &SnapshotRun{Status: le.Status}
			if le.EndTime > 0 {
				run.Time = time.UnixMilli(le.EndTime).UTC().Format(time.RFC3339)
				if le.StartTime > 0 {
					run.DurationSeconds = int((le.EndTime - le.StartTime) / 1000)
				}
			}
			v.LastRun = run
		}
	} else if err != nil && v.Detail == "" {
		v.Detail = "policy readable; explain unavailable: " + err.Error()
	}
	return v
}

var errBadSnapshotUpdate = jsonError("schedule_cron must be a 5-field cron expression, retention_max_count must be 1..365 and retention_max_age_days must be 0..3650 (0 = no age limit)")

// maxAgeDays parses the SM duration this surface writes ("<N>d") plus the hour
// spelling ("<N>h") an operator may have set by hand. Anything else reads as 0
// (no age limit) — the write side only ever emits days.
func maxAgeDays(s string) int {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		if v, err := strconv.Atoi(n); err == nil {
			return v
		}
	}
	if n, ok := strings.CutSuffix(s, "h"); ok {
		if v, err := strconv.Atoi(n); err == nil {
			return v / 24
		}
	}
	return 0
}

// validCron5 is a shape check (5 whitespace-separated fields), not a parser —
// OpenSearch validates semantics on write and its error is surfaced verbatim.
func validCron5(expr string) bool {
	return len(strings.Fields(expr)) == 5
}

func (s *Service) smApplyUpdate(ctx context.Context, upd snapshotPolicyUpdate) error {
	// Cron / retention changes mutate the policy document in place and PUT it
	// back with the concurrency token (SM rejects a token-less PUT).
	if upd.ScheduleCron != nil || upd.RetentionMaxCount != nil || upd.RetentionMaxAgeDays != nil {
		doc, err := s.smGetPolicy(ctx)
		if err != nil {
			return err
		}
		if upd.ScheduleCron != nil {
			if cron, ok := digMap(doc.Raw, "creation", "schedule", "cron").(map[string]any); ok {
				cron["expression"] = *upd.ScheduleCron
			} else {
				return jsonError("policy document has no creation.schedule.cron to update")
			}
		}
		if upd.RetentionMaxCount != nil {
			if cond, ok := digMap(doc.Raw, "deletion", "condition").(map[string]any); ok {
				cond["max_count"] = *upd.RetentionMaxCount
			} else {
				return jsonError("policy document has no deletion.condition to update")
			}
		}
		if upd.RetentionMaxAgeDays != nil {
			cond, ok := digMap(doc.Raw, "deletion", "condition").(map[string]any)
			if !ok {
				return jsonError("policy document has no deletion.condition to update")
			}
			if *upd.RetentionMaxAgeDays == 0 {
				delete(cond, "max_age") // count-only retention
			} else {
				cond["max_age"] = strconv.Itoa(*upd.RetentionMaxAgeDays) + "d"
			}
		}
		// The GET echoes server-side bookkeeping fields the PUT rejects.
		for _, k := range []string{"schema_version", "last_updated_time", "enabled_time", "policy_id"} {
			delete(doc.Raw, k)
		}
		body, err := json.Marshal(doc.Raw)
		if err != nil {
			return err
		}
		path := smPolicyPath + "?if_seq_no=" + strconv.FormatInt(doc.SeqNo, 10) + "&if_primary_term=" + strconv.FormatInt(doc.PrimaryTerm, 10)
		if err := s.osDo(ctx, http.MethodPut, path, body, nil, smPolicyTimeout); err != nil {
			return err
		}
	}
	// Enable/disable rides the plugin's own endpoints — simpler and immune to
	// the document round-trip dropping a field.
	if upd.Enabled != nil {
		verb := "/_stop"
		if *upd.Enabled {
			verb = "/_start"
		}
		if err := s.osDo(ctx, http.MethodPost, smPolicyPath+verb, nil, nil, smPolicyTimeout); err != nil {
			return err
		}
	}
	return nil
}

// ── the snapshot-schedule INTENT (the 2026-09-03 bootstrap defect) ──────────

// SnapshotScheduleIntent is the ONE source of truth for "did a human
// deliberately stop the nightly snapshot?". It is exported on purpose: the
// opensearch-init bootstrap fix and its tests read it rather than each guessing
// a default, which is how the two halves got out of step in the first place.
//
// enabled=true with a zero `at` and empty `by` means NO deliberate stop is on
// record — the shipped state, and the state a fresh install reports. When a
// schedule is re-enabled the stop record is cleared: who re-enabled it lives in
// the audit trail, which is where an attribution question belongs.
func (s *Service) SnapshotScheduleIntent() (enabled bool, reason string, at time.Time, by string) {
	cfg := s.config()
	if cfg.SnapshotScheduleDisabledAt.IsZero() {
		return true, "", time.Time{}, ""
	}
	return false, cfg.SnapshotScheduleDisabledReason, cfg.SnapshotScheduleDisabledAt, cfg.SnapshotScheduleDisabledBy
}

// recordSnapshotScheduleIntent stores (or clears) the deliberate-stop record.
func (s *Service) recordSnapshotScheduleIntent(enabled bool, actor string, reason *string) error {
	cfg := s.config()
	if enabled {
		cfg.SnapshotScheduleDisabledAt = time.Time{}
		cfg.SnapshotScheduleDisabledBy = ""
		cfg.SnapshotScheduleDisabledReason = ""
	} else {
		cfg.SnapshotScheduleDisabledAt = s.now().UTC()
		cfg.SnapshotScheduleDisabledBy = actor
		cfg.SnapshotScheduleDisabledReason = "stopped from the Data Protection page"
		if reason != nil {
			if r := strings.TrimSpace(*reason); r != "" {
				cfg.SnapshotScheduleDisabledReason = r
			}
		}
	}
	return s.putConfig(cfg)
}

// policyLastUpdated reads the SM document's own last_updated_time (epoch ms).
func policyLastUpdated(raw map[string]any) time.Time {
	ms, ok := raw["last_updated_time"].(float64)
	if !ok || ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// snapshotPolicyManagedByTolerance absorbs the gap between the api committing a
// PUT and OpenSearch stamping last_updated_time (plus any clock skew between
// the two containers). Wider than the real gap on purpose: mislabelling our own
// write as "external" would cry wolf on every GUI edit.
const snapshotPolicyManagedByTolerance = 2 * time.Minute

// snapshotPolicyManagedBy resolves the closed managed_by vocabulary from the
// only two facts available: when OpenSearch says the policy was last updated,
// and when this api last recorded writing it.
func snapshotPolicyManagedBy(lastUpdated, ourWrite time.Time) (string, string) {
	switch {
	case lastUpdated.IsZero():
		return "unknown", "the policy document carries no last_updated_time, so its last writer cannot be determined"
	case ourWrite.IsZero():
		return "policy-file", "this api has never written the policy. The opensearch-init bootstrap " +
			"(deployment/docker/opensearch/apply-ism.sh) is the only other writer this platform ships, but the SM " +
			"document records no author — a hand edit would also read policy-file. Last updated " +
			lastUpdated.Format(time.RFC3339) + "."
	case !lastUpdated.After(ourWrite.Add(snapshotPolicyManagedByTolerance)):
		return "gui", "this api wrote the policy at " + ourWrite.Format(time.RFC3339) +
			" and OpenSearch has not recorded a newer write, so the stored GUI intent and the live policy agree"
	default:
		return "external", "the policy was updated at " + lastUpdated.Format(time.RFC3339) +
			", AFTER this api's last write at " + ourWrite.Format(time.RFC3339) +
			". That is either a redeploy's opensearch-init bootstrap or a hand edit — the SM document does not say " +
			"which. If the schedule is on and the stored intent says it was deliberately stopped, this is the " +
			"bootstrap overriding an operator decision."
	}
}

// recordSnapshotPolicyWrite stamps the intent store with this api's write.
func (s *Service) recordSnapshotPolicyWrite() error {
	cfg := s.config()
	cfg.SnapshotPolicyWrittenAt = s.now().UTC()
	return s.putConfig(cfg)
}
