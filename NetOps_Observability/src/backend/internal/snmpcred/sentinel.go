package snmpcred

// sentinel.go — self-healing SNMP credential resolution (extracted P2 RA.14).
// See the entrypoint's cred_sentinel.go history: the sentinel verifies each
// device's ACTIVE credential every cycle and, on failure, probes the OTHER
// stored profiles for the device's tenant (credential *selection*, never
// *guessing*), stickily adopting the first that answers; the bound profile
// recovering clears the override — intent wins when it works. Zero-trust
// bounds: same-tenant candidates only (default-closed §3a), bounded probes,
// per-device cooldown, every adoption/clear logged. Env intervals stay with
// the entrypoint (ctor params); the probe is injectable for tests.

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/applog"
	"netops/backend/models"
)

// SetProbeForTest swaps the SNMP probe (tests inject a scripted prober).
func (cs *Sentinel) SetProbeForTest(p func(ctx context.Context, t collectors.Target) error) {
	cs.probe = p
}

// Override is one learned, sticky credential binding.
type Override struct {
	DeviceID  string    `json:"device_id"`
	ProfileID string    `json:"profile_id"` // the profile that actually answers
	BoundRef  string    `json:"bound_ref"`  // what the inventory binds (for audit + intent-restore)
	Since     time.Time `json:"since"`
}

// OverrideStore persists learned overrides across restarts (file-backed,
// same pattern as the other /data stores).
type OverrideStore struct {
	mu   sync.RWMutex
	path string
	m    map[string]Override // device id -> override
}

func NewOverrideStore(path string) (*OverrideStore, error) {
	s := &OverrideStore{path: path, m: map[string]Override{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var list []Override
	if err := json.Unmarshal(raw, &list); err != nil {
		// A corrupt overrides file must never block boot — overrides are a
		// recoverable cache of learned state, not source-of-truth config.
		applog.Warn("credsentinel", "overrides file unreadable — starting empty", map[string]any{"path": path, "err": err.Error()})
		return s, nil
	}
	for _, o := range list {
		if o.DeviceID != "" && o.ProfileID != "" {
			s.m[o.DeviceID] = o
		}
	}
	return s, nil
}

func (s *OverrideStore) Get(deviceID string) (Override, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.m[deviceID]
	return o, ok
}

// Set stores an override, returning a persist failure so the caller can refuse
// to report success for a suppression that did not stick (F-78 class).
func (s *OverrideStore) Set(o Override) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[o.DeviceID] = o
	return s.flushLocked()
}

// Clear removes an override, returning a persist failure for the same reason.
func (s *OverrideStore) Clear(deviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[deviceID]; !ok {
		return nil
	}
	delete(s.m, deviceID)
	return s.flushLocked()
}

// All returns a stable snapshot (devices API join + tests).
func (s *OverrideStore) All() []Override {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Override, 0, len(s.m))
	for _, o := range s.m {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// flushLocked persists the overrides, returning any failure. These are
// SECURITY overrides — an operator suppressing a credential alarm must not be
// told it stuck when it did not (F-78 class).
func (s *OverrideStore) flushLocked() error {
	list := make([]Override, 0, len(s.m))
	for _, o := range s.m {
		list = append(list, o)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].DeviceID < list[j].DeviceID })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		applog.Warn("credsentinel", "marshal overrides failed", map[string]any{"err": err.Error()})
		return err
	}
	if err := os.WriteFile(s.path, raw, 0o600); err != nil {
		applog.Warn("credsentinel", "persist overrides failed", map[string]any{"err": err.Error()})
		return err
	}
	return nil
}

// ApplyCredToTarget threads a resolved credential profile into a poll target —
// the ONE place the profile→target mapping lives (used by the pool's target
// builder and the sentinel's probes, so they can never drift apart).
func ApplyCredToTarget(tgt *collectors.Target, c Credential) {
	if strings.EqualFold(c.Version, "v3") {
		tgt.SNMPVersion = 3
		tgt.V3User = c.SecurityName
		tgt.V3Level = c.SecurityLevel
		tgt.V3AuthProto = c.AuthProtocol
		tgt.V3AuthKey = c.AuthKey
		tgt.V3PrivProto = c.PrivProtocol
		tgt.V3PrivKey = c.PrivKey
		tgt.V3Context = c.Context
		return
	}
	tgt.SNMPVersion = 0
	tgt.Community = c.Community
	tgt.V3User, tgt.V3Level, tgt.V3AuthProto, tgt.V3AuthKey = "", "", "", ""
	tgt.V3PrivProto, tgt.V3PrivKey, tgt.V3Context = "", "", ""
}

// Sentinel periodically verifies and, when needed, re-resolves each SNMP
// device's working credential from the stored profiles.
type Sentinel struct {
	overrides *OverrideStore
	creds     *Store
	devices   func() []models.Device
	// probe is injectable for tests; production uses collectors.ProbeSNMP.
	probe    func(ctx context.Context, t collectors.Target) error
	interval time.Duration
	cooldown time.Duration

	mu        sync.Mutex
	nextSweep map[string]time.Time // device id -> earliest next full profile sweep
}

func NewSentinel(overrides *OverrideStore, creds *Store, devices func() []models.Device, interval, cooldown time.Duration) *Sentinel {
	return &Sentinel{
		overrides: overrides,
		creds:     creds,
		devices:   devices,
		probe:     collectors.ProbeSNMP,
		interval:  interval,
		cooldown:  cooldown,
		nextSweep: map[string]time.Time{},
	}
}

func (cs *Sentinel) Run(ctx context.Context) {
	t := time.NewTicker(cs.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cs.sweep(ctx)
		}
	}
}

// sweep runs one verification pass over the inventory.
func (cs *Sentinel) sweep(ctx context.Context) {
	for _, dev := range cs.devices() {
		if ctx.Err() != nil {
			return
		}
		proto := strings.ToLower(dev.PreferredProtocol)
		if dev.Address == "" || (proto != "" && proto != "snmp") {
			continue
		}
		// Devices WITHOUT a bound profile (fresh discovery) are covered too —
		// that's the "new device tomorrow" case: the sentinel binds them to
		// whichever stored profile actually answers.
		cs.CheckDevice(ctx, dev)
	}
}

// CheckDevice verifies one device's active credential and re-resolves on failure.
func (cs *Sentinel) CheckDevice(ctx context.Context, dev models.Device) {
	bound, boundOK := cs.creds.Resolve(dev.CredentialRef)
	ov, hasOv := cs.overrides.Get(dev.ID)

	// Which credential is ACTIVE right now (what the poller is using)?
	active, activeOK := bound, boundOK
	if hasOv {
		if c, ok := cs.creds.Resolve(ov.ProfileID); ok {
			active, activeOK = c, true
		} else {
			// The learned profile was deleted — drop the stale override.
			if err := cs.overrides.Clear(dev.ID); err != nil {
				applog.Warn("credsentinel", "clear override failed", map[string]any{"device": dev.ID, "err": err.Error()})
			}
			hasOv = false
			active, activeOK = bound, boundOK
		}
	}

	// No bound profile and no override (fresh discovery): if the poller's
	// default community (SNMP_COMMUNITY/"public") answers, leave it alone —
	// only bind a profile when the default fails.
	if !activeOK {
		tgt := collectors.Target{ID: dev.ID, Address: dev.Address}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defaultOK := cs.probe(pctx, tgt) == nil
		cancel()
		if defaultOK {
			return
		}
	}

	if activeOK && cs.probeWith(ctx, dev, active) == nil {
		// Active credential works. If we're on an override, check whether the
		// BOUND profile recovered — intent wins when it works again.
		if hasOv && boundOK && bound.ID != active.ID && cs.probeWith(ctx, dev, bound) == nil {
			if err := cs.overrides.Clear(dev.ID); err != nil {
				applog.Warn("credsentinel", "clear override failed", map[string]any{"device": dev.ID, "err": err.Error()})
			}
			applog.Info("credsentinel", "bound credential recovered — override cleared", map[string]any{
				"device": dev.ID, "bound": dev.CredentialRef, "was_override": ov.ProfileID,
			})
		}
		return
	}

	// Active credential is failing. Rate-limit full sweeps per device.
	cs.mu.Lock()
	next := cs.nextSweep[dev.ID]
	now := time.Now()
	if now.Before(next) {
		cs.mu.Unlock()
		return
	}
	cs.nextSweep[dev.ID] = now.Add(cs.cooldown)
	cs.mu.Unlock()

	// Probe the stored profiles for this device's tenant, bound profile first
	// (fastest path back to intent), then the rest in stable order.
	for _, cand := range cs.candidates(dev, bound, boundOK) {
		if ctx.Err() != nil {
			return
		}
		if cs.probeWith(ctx, dev, cand) != nil {
			continue
		}
		if boundOK && cand.ID == bound.ID {
			// The bound profile itself answers (the earlier failure was the
			// override's) — restoring intent means clearing, not overriding.
			if err := cs.overrides.Clear(dev.ID); err != nil {
				applog.Warn("credsentinel", "clear override failed", map[string]any{"device": dev.ID, "err": err.Error()})
			}
			applog.Info("credsentinel", "bound credential works — override cleared", map[string]any{"device": dev.ID, "bound": dev.CredentialRef})
			return
		}
		if err := cs.overrides.Set(Override{DeviceID: dev.ID, ProfileID: cand.ID, BoundRef: dev.CredentialRef, Since: now.UTC()}); err != nil {
			applog.Warn("credsentinel", "set override failed", map[string]any{"device": dev.ID, "err": err.Error()})
		}
		applog.Info("credsentinel", "credential override adopted — bound profile does not answer", map[string]any{
			"device": dev.ID, "bound": dev.CredentialRef, "adopted": cand.ID, "version": cand.Version,
		})
		return
	}
	// Nothing answers — genuinely unreachable/misconfigured device-side. The
	// poller keeps reporting it down; we just avoided a silent wrong binding.
}

// candidates returns the profiles worth probing for this device: same-tenant
// only (default-closed §3a), bound profile first, then stable id order.
func (cs *Sentinel) candidates(dev models.Device, bound Credential, boundOK bool) []Credential {
	all := cs.creds.ResolveAll()
	out := make([]Credential, 0, len(all))
	if boundOK {
		out = append(out, bound)
	}
	for _, c := range all {
		if boundOK && c.ID == bound.ID {
			continue
		}
		if c.TenantID != dev.TenantID {
			continue
		}
		out = append(out, c)
	}
	return out
}

// probeWith runs one bounded credentialed probe of the device.
func (cs *Sentinel) probeWith(ctx context.Context, dev models.Device, c Credential) error {
	tgt := collectors.Target{ID: dev.ID, Address: dev.Address}
	ApplyCredToTarget(&tgt, c)
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return cs.probe(pctx, tgt)
}
