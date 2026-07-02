package main

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// cred_sentinel.go — self-healing SNMP credential resolution.
//
// Problem this solves permanently: a device's bound credential profile
// (devices.yaml credential_ref / discovery) can stop matching the device —
// labs get redeployed, SNMPv3 users vanish on platforms that don't persist
// them (IOS-XE), operators rotate credentials device-side first. Today that
// fails DARK: the poller times out forever and the device silently loses its
// whole metric plane (the "DMZ-FW has no interfaces" class).
//
// The sentinel makes credential binding self-healing and VENDOR-AGNOSTIC:
//   - Every cycle it verifies each SNMP device still answers its ACTIVE
//     credential (bound profile, or a previously learned override).
//   - When the active credential fails, it probes the OTHER stored profiles
//     for that device's tenant (admin-configured profiles ONLY — this is
//     credential *selection*, never credential *guessing*) and stickily
//     adopts the first one that answers. The override is persisted, audited,
//     and surfaced on the devices API (`credential_active`).
//   - When the BOUND profile answers again (device brought back in line with
//     intent), the override is cleared — intent always wins when it works.
//
// Zero-trust bounds: candidates are limited to the same tenant as the device
// (default-closed), probes are the same sysUpTime GET the poller already
// sends, sweeps are rate-limited per device (cooldown) so a dead device never
// turns into a periodic credential spray, and every adoption/clear is logged.

// credOverride is one learned, sticky credential binding.
type credOverride struct {
	DeviceID  string    `json:"device_id"`
	ProfileID string    `json:"profile_id"` // the profile that actually answers
	BoundRef  string    `json:"bound_ref"`  // what the inventory binds (for audit + intent-restore)
	Since     time.Time `json:"since"`
}

// credOverrideStore persists learned overrides across restarts (file-backed,
// same pattern as the other /data stores).
type credOverrideStore struct {
	mu   sync.RWMutex
	path string
	m    map[string]credOverride // device id -> override
}

func newCredOverrideStore(path string) (*credOverrideStore, error) {
	s := &credOverrideStore{path: path, m: map[string]credOverride{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var list []credOverride
	if err := json.Unmarshal(raw, &list); err != nil {
		// A corrupt overrides file must never block boot — overrides are a
		// recoverable cache of learned state, not source-of-truth config.
		logWarn("credsentinel", "overrides file unreadable — starting empty", map[string]any{"path": path, "err": err.Error()})
		return s, nil
	}
	for _, o := range list {
		if o.DeviceID != "" && o.ProfileID != "" {
			s.m[o.DeviceID] = o
		}
	}
	return s, nil
}

func (s *credOverrideStore) Get(deviceID string) (credOverride, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.m[deviceID]
	return o, ok
}

func (s *credOverrideStore) Set(o credOverride) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[o.DeviceID] = o
	s.flushLocked()
}

func (s *credOverrideStore) Clear(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[deviceID]; !ok {
		return
	}
	delete(s.m, deviceID)
	s.flushLocked()
}

// All returns a stable snapshot (devices API join + tests).
func (s *credOverrideStore) All() []credOverride {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]credOverride, 0, len(s.m))
	for _, o := range s.m {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

func (s *credOverrideStore) flushLocked() {
	list := make([]credOverride, 0, len(s.m))
	for _, o := range s.m {
		list = append(list, o)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].DeviceID < list[j].DeviceID })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(s.path, raw, 0o600); err != nil {
		logWarn("credsentinel", "persist overrides failed", map[string]any{"err": err.Error()})
	}
}

// applyCredToTarget threads a resolved credential profile into a poll target —
// the ONE place the profile→target mapping lives (used by the pool's target
// builder and the sentinel's probes, so they can never drift apart).
func applyCredToTarget(tgt *collectors.Target, c SNMPCredential) {
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

// credSentinel periodically verifies and, when needed, re-resolves each SNMP
// device's working credential from the stored profiles.
type credSentinel struct {
	overrides *credOverrideStore
	creds     *snmpCredStore
	devices   func() []models.Device
	// probe is injectable for tests; production uses collectors.ProbeSNMP.
	probe    func(ctx context.Context, t collectors.Target) error
	interval time.Duration
	cooldown time.Duration

	mu        sync.Mutex
	nextSweep map[string]time.Time // device id -> earliest next full profile sweep
}

func newCredSentinel(overrides *credOverrideStore, creds *snmpCredStore, devices func() []models.Device) *credSentinel {
	return &credSentinel{
		overrides: overrides,
		creds:     creds,
		devices:   devices,
		probe:     collectors.ProbeSNMP,
		interval:  envDuration("CRED_SENTINEL_INTERVAL", 2*time.Minute),
		cooldown:  envDuration("CRED_SENTINEL_COOLDOWN", 10*time.Minute),
		nextSweep: map[string]time.Time{},
	}
}

func (cs *credSentinel) run(ctx context.Context) {
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
func (cs *credSentinel) sweep(ctx context.Context) {
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
		cs.checkDevice(ctx, dev)
	}
}

// checkDevice verifies one device's active credential and re-resolves on failure.
func (cs *credSentinel) checkDevice(ctx context.Context, dev models.Device) {
	bound, boundOK := cs.creds.Resolve(dev.CredentialRef)
	ov, hasOv := cs.overrides.Get(dev.ID)

	// Which credential is ACTIVE right now (what the poller is using)?
	active, activeOK := bound, boundOK
	if hasOv {
		if c, ok := cs.creds.Resolve(ov.ProfileID); ok {
			active, activeOK = c, true
		} else {
			// The learned profile was deleted — drop the stale override.
			cs.overrides.Clear(dev.ID)
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
			cs.overrides.Clear(dev.ID)
			logInfo("credsentinel", "bound credential recovered — override cleared", map[string]any{
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
			cs.overrides.Clear(dev.ID)
			logInfo("credsentinel", "bound credential works — override cleared", map[string]any{"device": dev.ID, "bound": dev.CredentialRef})
			return
		}
		cs.overrides.Set(credOverride{DeviceID: dev.ID, ProfileID: cand.ID, BoundRef: dev.CredentialRef, Since: now.UTC()})
		logInfo("credsentinel", "credential override adopted — bound profile does not answer", map[string]any{
			"device": dev.ID, "bound": dev.CredentialRef, "adopted": cand.ID, "version": cand.Version,
		})
		return
	}
	// Nothing answers — genuinely unreachable/misconfigured device-side. The
	// poller keeps reporting it down; we just avoided a silent wrong binding.
}

// candidates returns the profiles worth probing for this device: same-tenant
// only (default-closed §3a), bound profile first, then stable id order.
func (cs *credSentinel) candidates(dev models.Device, bound SNMPCredential, boundOK bool) []SNMPCredential {
	all := cs.creds.ResolveAll()
	out := make([]SNMPCredential, 0, len(all))
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
func (cs *credSentinel) probeWith(ctx context.Context, dev models.Device, c SNMPCredential) error {
	tgt := collectors.Target{ID: dev.ID, Address: dev.Address}
	applyCredToTarget(&tgt, c)
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return cs.probe(pctx, tgt)
}

// withCredActive annotates devices with the sentinel's learned binding, so the
// Devices UI/API can show when polling runs on a different profile than bound.
func (s *server) withCredActive(devs []models.Device) []models.Device {
	if s.credOverrides == nil {
		return devs
	}
	for i := range devs {
		if ov, ok := s.credOverrides.Get(devs[i].ID); ok {
			devs[i].CredentialActive = ov.ProfileID
		}
	}
	return devs
}
