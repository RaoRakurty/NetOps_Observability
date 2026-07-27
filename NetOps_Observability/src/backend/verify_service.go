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
	"encoding/json"
	"errors"
	"fmt"
	"netops/backend/internal/chschema"
	"netops/backend/internal/vault"
	"netops/backend/internal/verify"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
)

const verifyTopic = "netops.verification"

// verifyCooldown is the auto-trigger dedupe window: at most one verification
// run per case per window.
func verifyCooldown() time.Duration {
	return secEnvDuration("VERIFY_COOLDOWN_SEC", 900, 60, 86400)
}

// ---- per-tenant config (opt-in flag + read-only SSH credential) -------------

const (
	// Vault FIELD IDENTIFIERS (envelope AAD labels), not credential values.
	verifyFieldPassword   = "verify_ssh_password"   // #nosec G101 -- field id, not a credential
	verifyFieldKey        = "verify_ssh_key"        // #nosec G101 -- field id, not a credential
	verifyFieldPassphrase = "verify_ssh_passphrase" // #nosec G101 -- field id, not a credential
)

type verifyTenantConfig struct {
	TenantID string `json:"tenant_id"`
	Enabled  bool   `json:"enabled,omitempty"`
	SSHUser  string `json:"ssh_user,omitempty"`
	// Secret material — vault-sealed at rest, write-only via the API, never in
	// audit detail or logs.
	SSHPassword   string `json:"ssh_password,omitempty"`
	SSHKey        string `json:"ssh_key,omitempty"`
	SSHPassphrase string `json:"ssh_passphrase,omitempty"`
	SSHPort       int    `json:"ssh_port,omitempty"`
}

// verifyConfigStore is a file-backed per-tenant map (tenant_display pattern)
// plus the secret-custody vault for the SSH fields.
type verifyConfigStore struct {
	mu    sync.RWMutex
	cfgs  map[string]verifyTenantConfig
	path  string
	vault *vault.Vault
	// loadErr is set when the stored config could NOT be read (I/O error or
	// corrupt bytes) — which is a different fact from "no tenant has opted in
	// yet". §10: without it an unreadable file made verification read "off" for
	// EVERY tenant while suspected cases piled up, and the next single-tenant
	// PUT flushed a map containing only that tenant over the survivors.
	loadErr error
}

func newVerifyConfigStore(path string, v *vault.Vault) *verifyConfigStore {
	s := &verifyConfigStore{cfgs: map[string]verifyTenantConfig{}, path: path, vault: v}
	if err := s.load(); err != nil {
		s.loadErr = err
		logError("verify", "verification config unreadable — every tenant will read as OPTED OUT and writes are refused until it is repaired", errf(err))
	}
	return s
}

func verifyConfigPath() string {
	if p := strings.TrimSpace(envOr("VERIFY_CONFIG_PATH", "")); p != "" {
		return p
	}
	return "/data/verify_config.json"
}

// load reads the stored per-tenant config. THREE states, never two
// (cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — genuinely no opt-in yet) / loaded.
func (s *verifyConfigStore) load() error {
	b, err := kvLoad(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no tenant has configured verification yet
	}
	if err != nil {
		return fmt.Errorf("read verification config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = nothing stored yet
	}
	var m map[string]verifyTenantConfig
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode verification config: %w", err)
	}
	for id, c := range m {
		c.TenantID = id
		m[id] = c
	}
	s.cfgs = m
	return nil
}

// unavailable reports the load failure, if any. Callers use it to say "unknown"
// instead of reporting the empty map as an operator's deliberate "off".
func (s *verifyConfigStore) unavailable() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *verifyConfigStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	// The in-memory map is NOT the stored state when the read failed: flushing it
	// would delete every other tenant's opt-in and SSH credential. Fail closed.
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite verification config: its stored contents were never read: %w", s.loadErr)
	}
	b, err := json.MarshalIndent(s.cfgs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode verification config: %w", err)
	}
	if err := kvSave(s.path, b); err != nil {
		logError("verify", "persist verification config failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist verification config: %w", err)
	}
	return nil
}

func (s *verifyConfigStore) seal(tenant, field, v string) (string, error) {
	if s.vault == nil || v == "" {
		return v, nil
	}
	return s.vault.Encrypt(tenant, field, v)
}

func (s *verifyConfigStore) open(tenant, field, v string) string {
	if s.vault == nil || v == "" {
		return v
	}
	out, err := s.vault.Decrypt(tenant, field, v)
	if err != nil {
		logWarn("verify", "unseal verification secret failed", map[string]any{"tenant": tenant, "field": field})
		return ""
	}
	return out
}

// get returns the tenant's raw (still-sealed) record. Nil-safe.
func (s *verifyConfigStore) get(tenant string) verifyTenantConfig {
	if s == nil {
		return verifyTenantConfig{TenantID: tenant}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	return c
}

// enabledTenants lists tenants that opted in — the auto-trigger's work list.
func (s *verifyConfigStore) enabledTenants() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, c := range s.cfgs {
		if c.Enabled && id != "" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// verifySettingsPatch is the PUT body. Secret fields are write-only: empty
// keeps the stored value; ClearSSH wipes the credential entirely.
type verifySettingsPatch struct {
	Enabled       *bool   `json:"enabled,omitempty"`
	SSHUser       *string `json:"ssh_user,omitempty"`
	SSHPassword   string  `json:"ssh_password,omitempty"`
	SSHKey        string  `json:"ssh_private_key,omitempty"`
	SSHPassphrase string  `json:"ssh_passphrase,omitempty"`
	SSHPort       *int    `json:"ssh_port,omitempty"`
	ClearSSH      bool    `json:"clear_ssh,omitempty"`
}

// set applies a patch for the PRINCIPAL's tenant (callers pass the
// principalTenant result — body tenant is ignored by construction).
func (s *verifyConfigStore) set(tenant string, p verifySettingsPatch) (verifyTenantConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	if p.Enabled != nil {
		c.Enabled = *p.Enabled
	}
	if p.ClearSSH {
		c.SSHUser, c.SSHPassword, c.SSHKey, c.SSHPassphrase, c.SSHPort = "", "", "", "", 0
	}
	if p.SSHUser != nil {
		c.SSHUser = strings.TrimSpace(*p.SSHUser)
	}
	if p.SSHPort != nil {
		if *p.SSHPort < 0 || *p.SSHPort > 65535 {
			return c, errors.New("ssh_port out of range")
		}
		c.SSHPort = *p.SSHPort
	}
	var err error
	if p.SSHPassword != "" {
		if c.SSHPassword, err = s.seal(tenant, verifyFieldPassword, p.SSHPassword); err != nil {
			return c, err
		}
	}
	if p.SSHKey != "" {
		if c.SSHKey, err = s.seal(tenant, verifyFieldKey, p.SSHKey); err != nil {
			return c, err
		}
	}
	if p.SSHPassphrase != "" {
		if c.SSHPassphrase, err = s.seal(tenant, verifyFieldPassphrase, p.SSHPassphrase); err != nil {
			return c, err
		}
	}
	prev, had := s.cfgs[tenant]
	s.cfgs[tenant] = c
	if err := s.saveLocked(); err != nil {
		if had {
			s.cfgs[tenant] = prev
		} else {
			delete(s.cfgs, tenant)
		}
		return prev, err
	}
	return c, nil
}

// sshCredFor unseals the tenant's verification SSH credential; nil when the
// tenant has not configured one (ssh checks are then skipped honestly).
func (s *verifyConfigStore) sshCredFor(tenant string) *verify.SSHCred {
	c := s.get(tenant)
	if c.SSHUser == "" {
		return nil
	}
	cred := &verify.SSHCred{
		User:       c.SSHUser,
		Password:   s.open(tenant, verifyFieldPassword, c.SSHPassword),
		PrivateKey: s.open(tenant, verifyFieldKey, c.SSHKey),
		Passphrase: s.open(tenant, verifyFieldPassphrase, c.SSHPassphrase),
		Port:       c.SSHPort,
	}
	if cred.Password == "" && cred.PrivateKey == "" {
		return nil
	}
	return cred
}

// publicView is the API/UI projection — never any secret material.
func (s *verifyConfigStore) publicView(tenant string) map[string]any {
	c := s.get(tenant)
	out := map[string]any{
		"tenant_id":      tenant,
		"enabled":        c.Enabled,
		"feature":        envBool("FEATURE_ACTIVE_VERIFICATION"),
		"ssh_configured": c.SSHUser != "" && (c.SSHPassword != "" || c.SSHKey != ""),
		"ssh_user":       c.SSHUser,
		"ssh_port":       c.SSHPort,
	}
	// An unreadable store must never render as a deliberate "off": the operator
	// sees UNKNOWN plus the reason, and the settings surface stays read-only.
	if s.unavailable() != nil {
		out["config_unavailable"] = true
		out["config_error"] = "stored verification config could not be read — settings shown are not the stored state"
	}
	return out
}

// ---- run store (bounded; latest run per case) -------------------------------

type verifyRunRecord struct {
	RunID         string               `json:"run_id"`
	TenantID      string               `json:"tenant_id"`
	CorrelationID string               `json:"correlation_id"`
	Trigger       string               `json:"trigger"` // manual | auto
	Actor         string               `json:"actor"`
	StartedAt     time.Time            `json:"started_at"`
	FinishedAt    time.Time            `json:"finished_at,omitempty"`
	Status        string               `json:"status"` // running | completed
	Devices       []string             `json:"devices"`
	Modules       []string             `json:"modules,omitempty"` // seam/fault-fired troubleshooting modules
	Results       []verify.CheckResult `json:"results,omitempty"`
}

const verifyRunsPerTenantCap = 200

// verifyRunStore keeps the LATEST run per (tenant, case) — bounded by
// construction, tenant-keyed in the store (§3a), persisted best-effort.
type verifyRunStore struct {
	mu   sync.RWMutex
	runs map[string]map[string]verifyRunRecord // tenant → correlation_id → latest
	path string
}

func newVerifyRunStore(path string) *verifyRunStore {
	s := &verifyRunStore{runs: map[string]map[string]verifyRunRecord{}, path: path}
	if b, err := kvLoad(path); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &s.runs)
	}
	return s
}

func (s *verifyRunStore) latest(tenant, caseID string) (verifyRunRecord, bool) {
	if s == nil {
		return verifyRunRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[tenant][caseID]
	return r, ok
}

func (s *verifyRunStore) put(rec verifyRunRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byCase := s.runs[rec.TenantID]
	if byCase == nil {
		byCase = map[string]verifyRunRecord{}
		s.runs[rec.TenantID] = byCase
	}
	byCase[rec.CorrelationID] = rec
	// Bounded: evict the oldest cases past the cap.
	if len(byCase) > verifyRunsPerTenantCap {
		type kv struct {
			id string
			at time.Time
		}
		all := make([]kv, 0, len(byCase))
		for id, r := range byCase {
			all = append(all, kv{id, r.StartedAt})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
		for _, e := range all[:len(byCase)-verifyRunsPerTenantCap] {
			delete(byCase, e.id)
		}
	}
	if s.path != "" {
		if b, err := json.Marshal(s.runs); err == nil {
			if err := kvSave(s.path, b); err != nil {
				logWarn("verify", "persist verification runs failed", map[string]any{"err": err.Error()})
			}
		}
	}
}

// ---- feature gates ----------------------------------------------------------

func (s *server) verifyFeatureOn() bool { return envBool("FEATURE_ACTIVE_VERIFICATION") }

func (s *server) verifyEnabledFor(tenant string) bool {
	return s.verifyFeatureOn() && s.verifyCfg.get(tenant).Enabled
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
	sshCred := s.verifyCfg.sshCredFor(tenant)
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
	if last, ok := s.verifyRuns.latest(tenant, caseID); ok && last.Status == "running" &&
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
	s.verifyRuns.put(rec)
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
		s.verifyRuns.put(run)
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
