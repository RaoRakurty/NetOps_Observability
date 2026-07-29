package main

// verify_service.go — Active Verification service layer (RCA spec item 8):
// per-tenant opt-in config (default OFF), the bounded run store, target
// resolution from a case's affected devices, run orchestration, audit, and the
// evidence emit to the netops.verification bus lane.
//
// §3a: the config and run stores are keyed by tenant IN the store; no unscoped
// listing exists. SSH secrets are vault-sealed at rest (same custody envelope
// as the SNMP credential store) and write-only through the API.

import (
	"context"
	"errors"
	"fmt"
	"netops/backend/internal/chschema"
	"netops/backend/internal/verify"
	"strings"
	"time"

	"netops/backend/collectors"
)

const verifyTopic = "netops.verification"

// verifyCooldown is the auto-trigger dedupe window: at most one verification
// run per case per window.
func verifyCooldown() time.Duration {
	return secEnvDuration("VERIFY_COOLDOWN_SEC", 900, 60, 86400)
}

// ---- store aliases ----------------------------------------------------------
// The config + run stores moved to internal/verify/service_store.go (Phase-2
// W1.4). Aliases keep the handlers/trigger/tests source-compatible; the env
// reads (paths, feature flag) stay here.
type (
	verifyTenantConfig  = verify.TenantConfig
	verifyConfigStore   = verify.ConfigStore
	verifySettingsPatch = verify.SettingsPatch
	verifyRunRecord     = verify.RunRecord
	verifyRunStore      = verify.RunStore
)

func verifyConfigPath() string {
	if p := strings.TrimSpace(envOr("VERIFY_CONFIG_PATH", "")); p != "" {
		return p
	}
	return "/data/verify_config.json"
}

// ---- feature gates ----------------------------------------------------------

func (s *server) verifyFeatureOn() bool { return envBool("FEATURE_ACTIVE_VERIFICATION") }

func (s *server) verifyEnabledFor(tenant string) bool {
	return s.verifyFeatureOn() && s.verifyCfg.Get(tenant).Enabled
}

// ---- case lookup + target resolution ---------------------------------------

type verifyCaseRow struct {
	TenantID string
	State    string
	Verdict  string
	Devices  []string
	// Module-trigger context (verify_modules.go): seam owner badge, winning
	// hypothesis id and incident window start.
	Owner       string
	TopHyp      string
	WindowStart time.Time
}

// caseContext projects the row into the module-trigger/parser context.
func (r verifyCaseRow) caseContext() verify.CaseContext {
	return verify.CaseContext{
		Owner:         r.Owner,
		TopHypothesis: r.TopHyp,
		VerdictTier:   r.Verdict,
		WindowStart:   r.WindowStart,
	}
}

// verifyCaseLookup fetches the case from the corr_current hot projection under
// the caller's scope. A case outside the scope simply does not exist (404 —
// never reveal another tenant's id).
func (s *server) verifyCaseLookup(ctx context.Context, scope, caseID string) (verifyCaseRow, bool) {
	if !isUUIDToken(caseID) {
		return verifyCaseRow{}, false
	}
	sql := fmt.Sprintf(`SELECT tenant_id, toString(state) AS state,
       toString(verdict_tier) AS verdict, affected,
       toString(owner) AS owner, top_hypothesis,
       %s AS window_start
  FROM netops.corr_current FINAL
 WHERE correlation_id = toUUID('%s')
 LIMIT 1
FORMAT JSONEachRow`, chschema.ISO("window_start"), caseID)
	rows, err := s.chRowsScope(ctx, scope, sql, "verify_case_lookup")
	if err != nil {
		// The projection did not answer. That is NOT "this case does not exist":
		// the caller still gets a not-found (never invent a case), but the reason
		// is recorded so a ClickHouse outage cannot masquerade as a 404 storm.
		logWarn("verify", "case lookup failed — reporting not-found for a case whose existence is UNKNOWN",
			map[string]any{"case": caseID, "err": err.Error()})
		return verifyCaseRow{}, false
	}
	if len(rows) == 0 {
		return verifyCaseRow{}, false // answered: no such case in this scope
	}
	row := rows[0]
	return verifyCaseRow{
		TenantID:    asStr(row["tenant_id"]),
		State:       asStr(row["state"]),
		Verdict:     asStr(row["verdict"]),
		Devices:     affectedDevices(row["affected"]),
		Owner:       asStr(row["owner"]),
		TopHyp:      asStr(row["top_hypothesis"]),
		WindowStart: parseCHTime(row["window_start"]),
	}, true
}

// resolveVerifyTargets maps the case's implicated device names/ids to
// discovered devices VISIBLE TO THE CASE'S TENANT, with whatever management
// channels are configured. Devices the tenant cannot see never become targets.
func (s *server) resolveVerifyTargets(tenant string, names []string) []verify.Target {
	if len(names) == 0 || s.discovery == nil {
		return nil
	}
	want := map[string]bool{}
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			want[strings.ToLower(n)] = true
		}
	}
	sshCred := s.verifyCfg.SSHCredFor(tenant)
	var out []verify.Target
	for _, dev := range s.discovery.Devices() {
		if !want[strings.ToLower(dev.ID)] && !want[strings.ToLower(dev.Name)] {
			continue
		}
		if !canSeeDevice(dev, tenant, false) || strings.TrimSpace(dev.Address) == "" {
			continue
		}
		t := verify.Target{Device: dev, SSH: sshCred}
		if s.snmpCreds != nil && dev.CredentialRef != "" {
			ref := dev.CredentialRef
			if s.credOverrides != nil {
				if ov, ok := s.credOverrides.Get(dev.ID); ok {
					ref = ov.ProfileID
				}
			}
			if c, ok := s.snmpCreds.Resolve(ref); ok {
				tgt := collectors.Target{ID: dev.ID, Address: dev.Address}
				applyCredToTarget(&tgt, c)
				t.SNMP = &tgt
			}
		}
		out = append(out, t)
		if len(out) >= verify.MaxDevices() {
			break
		}
	}
	return out
}

// ---- run orchestration ------------------------------------------------------

var errVerifyRunning = errors.New("a verification run is already in progress for this case")
var errVerifyNoTargets = errors.New("no verifiable devices resolved from the case's affected set")

// startVerificationRun validates, records and launches one bounded run for the
// case. Async: returns the RUNNING record immediately; the engine's run budget
// bounds the background work. Every run is audited with who/what/why.
func (s *server) startVerificationRun(tenant, caseID, trigger, actor, why string, devices []string, cc verify.CaseContext) (verifyRunRecord, error) {
	if !s.verifyEnabledFor(tenant) {
		return verifyRunRecord{}, verify.ErrDisabled
	}
	if last, ok := s.verifyRuns.Latest(tenant, caseID); ok && last.Status == "running" &&
		time.Since(last.StartedAt) < verify.RunBudget()+time.Minute {
		return verifyRunRecord{}, errVerifyRunning
	}
	targets := s.resolveVerifyTargets(tenant, devices)
	if len(targets) == 0 {
		return verifyRunRecord{}, errVerifyNoTargets
	}
	// The battery this case earns: core checks + seam/fault-fired modules.
	battery := verify.ActiveBattery(cc)
	devIDs := make([]string, 0, len(targets))
	cmds := map[string]any{}
	for _, t := range targets {
		devIDs = append(devIDs, t.Device.ID)
		if t.SSH != nil {
			for _, spec := range verify.GroupSpecsIn(battery, "ssh") {
				if cmd, ok := verify.CommandFor(t.Device.Vendor, spec.ID); ok {
					cmds[t.Device.ID+"/"+spec.ID] = cmd
				}
			}
		}
	}
	rec := verifyRunRecord{
		RunID:         randID(),
		TenantID:      tenant,
		CorrelationID: caseID,
		Trigger:       trigger,
		Actor:         actor,
		StartedAt:     time.Now().UTC(),
		Status:        "running",
		Devices:       devIDs,
		Modules:       verify.ModulesFor(cc),
	}
	s.verifyRuns.Put(rec)
	s.auditVerifyRun(rec, "start", why, cmds)

	run := rec // own copy — the caller returns the RUNNING record
	// Panic-guarded: this drives SSH sessions and parses device output, and it
	// runs detached from the request, so a panic here would kill the API rather
	// than fail one verification run.
	safeGo("verify-run", func() {
		// Bounded by the engine's own run budget; independent of the request.
		engine := verify.NewEngineForCase(s.newVerifyDialers(), cc)
		results := engine.Run(context.Background(), targets)
		run.Results = results
		run.FinishedAt = time.Now().UTC()
		run.Status = "completed"
		s.verifyRuns.Put(run)
		s.emitVerificationResults(run)
		s.auditVerifyRun(run, "complete", why, nil)
		logInfo("verify", "verification run completed", map[string]any{
			"tenant": tenant, "correlation_id": caseID, "run_id": run.RunID,
			"trigger": trigger, "devices": len(targets), "results": len(results),
		})
	})
	return rec, nil
}

// auditVerifyRun records who/what/why for every run start and completion.
// Detail carries the exact allowlisted commands scheduled — and never any
// credential material.
func (s *server) auditVerifyRun(rec verifyRunRecord, phase, why string, cmds map[string]any) {
	if s.audit == nil {
		return
	}
	detail := map[string]any{
		"action":         "active_verification_" + phase,
		"run_id":         rec.RunID,
		"correlation_id": rec.CorrelationID,
		"trigger":        rec.Trigger,
		"why":            why,
		"devices":        rec.Devices,
		"modules":        rec.Modules,
	}
	if len(cmds) > 0 {
		detail["commands"] = cmds
	}
	if phase == "complete" {
		counts := map[string]int{}
		for _, r := range rec.Results {
			counts[r.Status]++
		}
		detail["result_counts"] = counts
	}
	s.audit.Record(AuditEvent{
		Actor: rec.Actor, Tenant: rec.TenantID, Cross: false,
		Method: "VERIFY_RUN", Path: "/api/correlations/" + rec.CorrelationID + "/verify",
		Status: 200, Decision: "allow", Detail: detail,
	})
}

// emitVerificationResults publishes every non-skipped check result to the
// netops.verification lane (best-effort — the run store is the UI's source of
// truth; the topic is the correlation feed).
func (s *server) emitVerificationResults(rec verifyRunRecord) {
	recs := make([]proxyRecord, 0, len(rec.Results))
	for _, r := range rec.Results {
		if r.Status == verify.StatusSkipped {
			continue // a skipped check is an operational fact, not evidence
		}
		recs = append(recs, proxyRecord{Key: rec.TenantID, Value: map[string]any{
			"tenant_id":          rec.TenantID,
			"run_id":             rec.RunID,
			"correlation_id":     rec.CorrelationID,
			"trigger":            rec.Trigger,
			"check":              r.Check,
			"method":             r.Method,
			"device_id":          r.DeviceID,
			"device_name":        r.DeviceName,
			"target":             r.Target,
			"status":             r.Status,
			"observed":           r.Observed,
			"command":            r.Command,
			"ts":                 r.Ts.Format(time.RFC3339Nano),
			"duration_ms":        r.DurationMS,
			"corroborates_kinds": r.CorroboratesKinds,
			"refutes_kinds":      r.RefutesKinds,
		}})
	}
	if len(recs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := produceJSON(ctx, verifyTopic, recs); err != nil {
		logWarn("verify", "verification evidence emit failed", map[string]any{
			"tenant": rec.TenantID, "run_id": rec.RunID, "err": err.Error(),
		})
	}
}
