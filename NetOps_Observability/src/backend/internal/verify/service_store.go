package verify

// service_store.go — the Active Verification service-layer stores (RCA spec
// item 8), extracted from package main (Phase-2 W1.4): the per-tenant opt-in
// config with vault-sealed SSH custody, and the bounded latest-run-per-case
// store. §3a: both are keyed by tenant IN the store; no unscoped listing
// exists. Env reads (paths, the feature flag) stay with the caller.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
)

// ---- per-tenant config (opt-in flag + read-only SSH credential) -------------

const (
	// Vault FIELD IDENTIFIERS (envelope AAD labels), not credential values.
	verifyFieldPassword   = "verify_ssh_password"   // #nosec G101 -- field id, not a credential
	verifyFieldKey        = "verify_ssh_key"        // #nosec G101 -- field id, not a credential
	verifyFieldPassphrase = "verify_ssh_passphrase" // #nosec G101 -- field id, not a credential
)

type TenantConfig struct {
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

// ConfigStore is a file-backed per-tenant map (tenant_display pattern)
// plus the secret-custody vault for the SSH fields.
type ConfigStore struct {
	mu    sync.RWMutex
	cfgs  map[string]TenantConfig
	path  string
	vault *vault.Vault
	// loadErr is set when the stored config could NOT be read (I/O error or
	// corrupt bytes) — which is a different fact from "no tenant has opted in
	// yet". §10: without it an unreadable file made verification read "off" for
	// EVERY tenant while suspected cases piled up, and the next single-tenant
	// PUT flushed a map containing only that tenant over the survivors.
	loadErr error
}

func NewConfigStore(path string, v *vault.Vault) *ConfigStore {
	s := &ConfigStore{cfgs: map[string]TenantConfig{}, path: path, vault: v}
	if err := s.load(); err != nil {
		s.loadErr = err
		applog.Error("verify", "verification config unreadable — every tenant will read as OPTED OUT and writes are refused until it is repaired", map[string]any{"error": err.Error()})
	}
	return s
}

// load reads the stored per-tenant config. THREE states, never two
// (cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — genuinely no opt-in yet) / loaded.
func (s *ConfigStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no tenant has configured verification yet
	}
	if err != nil {
		return fmt.Errorf("read verification config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = nothing stored yet
	}
	var m map[string]TenantConfig
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
func (s *ConfigStore) Unavailable() error {
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
func (s *ConfigStore) saveLocked() error {
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
	if err := platformdb.Save(s.path, b); err != nil {
		applog.Error("verify", "persist verification config failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist verification config: %w", err)
	}
	return nil
}

func (s *ConfigStore) seal(tenant, field, v string) (string, error) {
	if s.vault == nil || v == "" {
		return v, nil
	}
	return s.vault.Encrypt(tenant, field, v)
}

func (s *ConfigStore) open(tenant, field, v string) string {
	if s.vault == nil || v == "" {
		return v
	}
	out, err := s.vault.Decrypt(tenant, field, v)
	if err != nil {
		applog.Warn("verify", "unseal verification secret failed", map[string]any{"tenant": tenant, "field": field})
		return ""
	}
	return out
}

// get returns the tenant's raw (still-sealed) record. Nil-safe.
func (s *ConfigStore) Get(tenant string) TenantConfig {
	if s == nil {
		return TenantConfig{TenantID: tenant}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfgs[tenant]
	c.TenantID = tenant
	return c
}

// enabledTenants lists tenants that opted in — the auto-trigger's work list.
func (s *ConfigStore) EnabledTenants() []string {
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

// SettingsPatch is the PUT body. Secret fields are write-only: empty
// keeps the stored value; ClearSSH wipes the credential entirely.
type SettingsPatch struct {
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
func (s *ConfigStore) Set(tenant string, p SettingsPatch) (TenantConfig, error) {
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
func (s *ConfigStore) SSHCredFor(tenant string) *SSHCred {
	c := s.Get(tenant)
	if c.SSHUser == "" {
		return nil
	}
	cred := &SSHCred{
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
func (s *ConfigStore) PublicView(tenant string, featureOn bool) map[string]any {
	c := s.Get(tenant)
	out := map[string]any{
		"tenant_id":      tenant,
		"enabled":        c.Enabled,
		"feature":        featureOn,
		"ssh_configured": c.SSHUser != "" && (c.SSHPassword != "" || c.SSHKey != ""),
		"ssh_user":       c.SSHUser,
		"ssh_port":       c.SSHPort,
	}
	// An unreadable store must never render as a deliberate "off": the operator
	// sees UNKNOWN plus the reason, and the settings surface stays read-only.
	if s.Unavailable() != nil {
		out["config_unavailable"] = true
		out["config_error"] = "stored verification config could not be read — settings shown are not the stored state"
	}
	return out
}

// ---- run store (bounded; latest run per case) -------------------------------

type RunRecord struct {
	RunID         string        `json:"run_id"`
	TenantID      string        `json:"tenant_id"`
	CorrelationID string        `json:"correlation_id"`
	Trigger       string        `json:"trigger"` // manual | auto
	Actor         string        `json:"actor"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at,omitempty"`
	Status        string        `json:"status"` // running | completed
	Devices       []string      `json:"devices"`
	Modules       []string      `json:"modules,omitempty"` // seam/fault-fired troubleshooting modules
	Results       []CheckResult `json:"results,omitempty"`
}

const verifyRunsPerTenantCap = 200

// RunStore keeps the LATEST run per (tenant, case) — bounded by
// construction, tenant-keyed in the store (§3a), persisted best-effort.
type RunStore struct {
	mu   sync.RWMutex
	runs map[string]map[string]RunRecord // tenant → correlation_id → latest
	path string
}

func NewRunStore(path string) *RunStore {
	s := &RunStore{runs: map[string]map[string]RunRecord{}, path: path}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &s.runs)
	}
	return s
}

func (s *RunStore) Latest(tenant, caseID string) (RunRecord, bool) {
	if s == nil {
		return RunRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.runs[tenant][caseID]
	return r, ok
}

func (s *RunStore) Put(rec RunRecord) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byCase := s.runs[rec.TenantID]
	if byCase == nil {
		byCase = map[string]RunRecord{}
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
			if err := platformdb.Save(s.path, b); err != nil {
				applog.Warn("verify", "persist verification runs failed", map[string]any{"err": err.Error()})
			}
		}
	}
}
