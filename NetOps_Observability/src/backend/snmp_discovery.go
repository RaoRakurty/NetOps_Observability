// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/snmpcred"
	"netops/backend/internal/vault"
	"os"
	"sort"
	"strings"
	"sync"

	"netops/backend/models"
)

// snmp_discovery.go — real SNMP subnet discovery (replaces the historical
// no-op SNMPSource stub) plus its runtime configuration.
//
// Zero-trust posture: pointing the platform's prober at a network is a
// platform-infrastructure decision, so the config API is platform-owner
// gated (like the external-SoT connector), every range is validated
// server-side (IPv4 unicast, private-only unless explicitly acknowledged,
// hard host cap), and the scan engine is bounded (worker cap, per-host
// timeout, cooldown between sweeps). Env vars (ENABLE_SNMP_DISCOVERY /
// SNMP_CIDR_RANGES) remain only as the bootstrap default when nothing has been
// configured from the console.
//
// CREDENTIALS (owner decision 2026-10-04): SNMP credentials live in ONE place —
// the SNMP credential profiles (/api/snmp/credentials). Discovery has no
// community of its own: the sweep tries the platform-owned profiles in name
// order per host and binds each device it finds to the profile that answered.
// A community stored by an older build is migrated ONCE into a profile
// ("Migrated discovery community", sealed by the profile store like every
// other profile secret) — see migrateLegacyCommunity.

type discoveryScanConfig struct {
	Enabled bool     `json:"enabled"`
	Ranges  []string `json:"ranges"`
	// AllowNonPrivate acknowledges scanning ranges outside RFC 1918. Enterprises
	// routinely squat on unrouted public space internally; requiring an explicit
	// flag keeps the default posture closed (you must SAY you own that space)
	// while not locking those networks out. Loopback / link-local / multicast /
	// reserved space is refused regardless.
	AllowNonPrivate bool `json:"allow_non_private"`
	// IntervalSec is the periodic sweep cadence; 0 → default 300s.
	IntervalSec int `json:"interval_sec"`
}

// storedDiscoveryConfig is the at-rest shape. LegacyCommunity is the sealed
// probe community an older build saved; it is read ONLY so the one-time
// migration can move it into an SNMP profile, and is written back only while
// that migration has not yet succeeded (so a failed migration never loses it).
type storedDiscoveryConfig struct {
	discoveryScanConfig
	LegacyCommunity string `json:"community,omitempty"`
}

// migratedCommunityProfileName is the name a migrated discovery community gets
// as an SNMP profile; a comma-separated legacy list yields "… 2", "… 3", ….
const migratedCommunityProfileName = "Migrated discovery community"

type discoveryConfigStore struct {
	mu    sync.RWMutex
	cfg   *discoveryScanConfig
	path  string
	vault *vault.Vault
	// loadErr is set when the SAVED config could not be read or unsealed. That is
	// not "no config saved": falling through to the env bootstrap would sweep a
	// range the operator never chose (the shipped default is 10.0.0.0/8), and a
	// legacy community that cannot be unsealed must not be "migrated" as
	// ciphertext into a profile (§10).
	loadErr error
	// legacyCommunity is the unsealed pre-2026-10-04 discovery community still
	// awaiting migration into an SNMP profile ("" once migrated or never set).
	// Never logged, never returned by the API, never used to probe.
	legacyCommunity string
}

func newDiscoveryConfigStore(path string, v *vault.Vault) *discoveryConfigStore {
	s := &discoveryConfigStore{path: path, vault: v}
	if err := s.load(); err != nil {
		s.loadErr = err
		logError("discovery", "saved SNMP discovery config unreadable — discovery is DISABLED (the env bootstrap is deliberately not substituted)", errf(err))
	}
	return s
}

// load reads the saved scan config. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer / it answered with
// nothing (no operator config yet — the env bootstrap applies) / loaded.
func (s *discoveryConfigStore) load() error {
	b, err := platformdb.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = no console config yet; effective() uses env
	}
	if err != nil {
		return fmt.Errorf("read discovery config: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = nothing saved yet
	}
	var c storedDiscoveryConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode discovery config: %w", err)
	}
	if c.LegacyCommunity != "" {
		plain, derr := openFn(s.vault)("", fieldDiscoveryComm, c.LegacyCommunity)
		if derr != nil {
			// NEVER carry the sealed bytes forward: migrating ciphertext into a
			// profile would authenticate against nothing and look like an empty
			// network.
			return fmt.Errorf("unseal discovery community: %w", derr)
		}
		s.legacyCommunity = plain
	}
	cfg := c.discoveryScanConfig
	s.cfg = &cfg
	return nil
}

// persistLocked writes cfg, carrying the (re-sealed) legacy community along
// while it still awaits migration. Caller holds s.mu.
func (s *discoveryConfigStore) persistLocked(cfg discoveryScanConfig) error {
	out := storedDiscoveryConfig{discoveryScanConfig: cfg}
	if s.legacyCommunity != "" {
		sealed, err := sealFn(s.vault)("", fieldDiscoveryComm, s.legacyCommunity)
		if err != nil {
			return err
		}
		out.LegacyCommunity = sealed
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// migrateLegacyCommunity moves a discovery community saved by an older build
// into platform-owned SNMP profiles, ONCE: each comma-separated community
// becomes a v2c profile ("Migrated discovery community", "… 2", …) sealed by
// the profile store, then the discovery config is re-saved without it. It is
// idempotent — a profile that already holds the same community is reused, so
// a crash between the two writes (or a second run) never duplicates one. A
// failure leaves the legacy community on disk for the next boot to retry. The
// log line names the profiles, never the secret.
func (s *discoveryConfigStore) migrateLegacyCommunity(creds *snmpcred.Store) error {
	if s == nil || creds == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil || s.legacyCommunity == "" {
		return nil
	}
	var names []string
	for _, comm := range strings.Split(s.legacyCommunity, ",") {
		if comm = strings.TrimSpace(comm); comm == "" {
			continue
		}
		name, err := migrateOneCommunity(creds, comm)
		if err != nil {
			return fmt.Errorf("migrate discovery community: %w", err)
		}
		names = append(names, name)
	}
	cfg := discoveryScanConfig{}
	if s.cfg != nil {
		cfg = *s.cfg
	}
	prev := s.legacyCommunity
	s.legacyCommunity = ""
	if err := s.persistLocked(cfg); err != nil {
		s.legacyCommunity = prev // still on disk; retried next boot (idempotent)
		return fmt.Errorf("re-save discovery config without its community: %w", err)
	}
	logInfo("discovery", "discovery community migrated to SNMP profile", map[string]any{
		"profiles": names, "count": len(names),
	})
	return nil
}

// migrateOneCommunity finds (or creates) the platform-owned v2c profile holding
// comm under the migrated-profile name series and returns its name.
func migrateOneCommunity(creds *snmpcred.Store, comm string) (string, error) {
	const maxSlots = 64
	for i := 1; i <= maxSlots; i++ {
		name := migratedCommunityProfileName
		if i > 1 {
			name = fmt.Sprintf("%s %d", migratedCommunityProfileName, i)
		}
		existing, ok := creds.ResolveFor(name, "")
		if ok {
			if snmpcred.PlatformOwned(existing.TenantID) && !strings.EqualFold(existing.Version, "v3") && existing.Community == comm {
				return name, nil // already migrated (idempotent re-run)
			}
			continue // the name holds something else — never overwrite it
		}
		if _, err := creds.Upsert(snmpcred.Credential{Name: name, Version: "v2c", Community: comm}); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("no free %q profile name", migratedCommunityProfileName)
}

// unavailable reports the load failure, if any — "we do not know what was
// configured", which is not the same as "nothing is configured".
func (s *discoveryConfigStore) unavailable() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// effective resolves the live scan config: a console-saved config wins;
// otherwise the env bootstrap (ENABLE_SNMP_DISCOVERY + SNMP_CIDR_RANGES)
// applies. Env ranges are NOT pre-validated here — the scanner validates at
// sweep time and surfaces the refusal in the source stats, so a fresh install
// with the wide default range shows "narrow the range" instead of scanning it.
func (s *discoveryConfigStore) effective() discoveryScanConfig {
	s.mu.RLock()
	c, loadErr := s.cfg, s.loadErr
	s.mu.RUnlock()
	if loadErr != nil {
		// Fail closed: we do not know what the operator saved, so we scan
		// nothing rather than scanning the env default at a real network.
		return discoveryScanConfig{}
	}
	if c != nil {
		return *c
	}
	var ranges []string
	for _, r := range strings.Split(os.Getenv("SNMP_CIDR_RANGES"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			ranges = append(ranges, r)
		}
	}
	return discoveryScanConfig{
		Enabled: os.Getenv("ENABLE_SNMP_DISCOVERY") == "true" && len(ranges) > 0,
		Ranges:  ranges,
	}
}

func (s *discoveryConfigStore) set(in discoveryScanConfig) (discoveryScanConfig, error) {
	clean, _, err := discovery.ValidateScanRanges(in.Ranges, in.AllowNonPrivate)
	if err != nil {
		return discoveryScanConfig{}, err
	}
	in.Ranges = clean
	if in.Enabled && len(clean) == 0 {
		return discoveryScanConfig{}, errors.New("at least one CIDR range is required to enable discovery")
	}
	if in.IntervalSec < 0 {
		in.IntervalSec = 0
	}
	if in.IntervalSec != 0 && in.IntervalSec < 60 {
		in.IntervalSec = 60 // floor: never sweep more often than once a minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.persistLocked(in); err != nil {
		return discoveryScanConfig{}, err
	}
	stored := in
	s.cfg = &stored
	// A successful save IS the repair: the stored bytes are now known-good, so
	// the degraded (fail-closed) mode ends here rather than at the next restart.
	s.loadErr = nil
	return stored, nil
}

// publicDiscoveryConfig is the redacted GET shape.
type publicDiscoveryConfig struct {
	Enabled         bool     `json:"enabled"`
	Ranges          []string `json:"ranges"`
	AllowNonPrivate bool     `json:"allow_non_private"`
	IntervalSec     int      `json:"interval_sec"`
}

func (c discoveryScanConfig) public() publicDiscoveryConfig {
	if c.Ranges == nil {
		c.Ranges = []string{}
	}
	return publicDiscoveryConfig{Enabled: c.Enabled, Ranges: c.Ranges, AllowNonPrivate: c.AllowNonPrivate, IntervalSec: c.IntervalSec}
}

// =============================================================================
// SNMPSource — the real subnet scanner, registered with the aggregator.
// =============================================================================

// discoveryProbe is the per-host probe seam (injectable for tests).
// The scanner moved to internal/discovery/snmp_source.go (Phase-2 W3.9).
// The sealed store stays; scanSettings adapts it onto the scanner's slice.
type SNMPSource = discovery.SNMPSource

func newSNMPSourceFromStore(store *discoveryConfigStore, creds func() *snmpcred.Store, known func() []models.Device) *SNMPSource {
	return discovery.NewSNMPSource(func() discovery.ScanSettings {
		c := store.effective()
		return discovery.ScanSettings{
			Enabled: c.Enabled, Ranges: c.Ranges,
			Credentials: scanCredentials(creds()), AllowNonPrivate: c.AllowNonPrivate,
		}
	}, known)
}

// scanCredentials maps the sweep-eligible profiles (platform-owned, name order —
// snmpcred.Store.ScanCandidates) onto probe templates via the same
// ApplyCredToTarget the pollers use, so a profile discovery proves is exactly
// what polling will speak.
func scanCredentials(creds *snmpcred.Store) []discovery.ScanCredential {
	cands := creds.ScanCandidates()
	out := make([]discovery.ScanCredential, 0, len(cands))
	for _, c := range cands {
		var tgt collectors.Target
		snmpcred.ApplyCredToTarget(&tgt, c)
		out = append(out, discovery.ScanCredential{ProfileID: c.ID, Target: tgt})
	}
	return out
}

// scanProfileSummary counts the profiles the sweep will try, for the console.
func scanProfileSummary(creds *snmpcred.Store) map[string]int {
	out := map[string]int{"total": 0, "v2c": 0, "v3": 0}
	for _, c := range creds.ScanCandidates() {
		out["total"]++
		if strings.EqualFold(c.Version, "v3") {
			out["v3"]++
		} else {
			out["v2c"]++
		}
	}
	return out
}

// discoveredDevice is one row of the sweep's results in the console.
type discoveredDevice struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Address       string `json:"address"`
	Vendor        string `json:"vendor,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
}

// maxDiscoveredListed bounds the results list in one GET (§9: bounded).
const maxDiscoveredListed = 500

// discoveredBySweep lists the inventory devices the subnet sweep reported, in
// address order. Scan-found devices are platform-owned and the endpoint is
// requireCrossTenant, so nothing here crosses a tenant boundary.
func (s *server) discoveredBySweep() []discoveredDevice {
	out := []discoveredDevice{}
	if s.discovery == nil {
		return out
	}
	for _, d := range s.discovery.Devices() {
		if d.Source != "snmp" {
			continue
		}
		out = append(out, discoveredDevice{ID: d.ID, Name: d.Name, Address: d.Address, Vendor: d.Vendor, CredentialRef: d.CredentialRef})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	if len(out) > maxDiscoveredListed {
		out = out[:maxDiscoveredListed]
	}
	return out
}

// discoveryConfigInput is the PUT body. Community is decoded ONLY to refuse it:
// discovery no longer has a credential of its own, and silently dropping a
// secret the caller believes it saved would be a quiet lie (§10).
type discoveryConfigInput struct {
	discoveryScanConfig
	Community string `json:"community,omitempty"`
}

var errDiscoveryCommunityRemoved = errors.New("subnet discovery no longer has its own community — add it as an SNMP profile under Administration → Data sources → SNMP Profiles; the sweep tries those profiles")

func (s *server) handleDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		body := map[string]any{
			"config": s.discoveryCfg.effective().public(),
			"limits": map[string]int{"max_hosts": discovery.MaxScanHosts, "max_ranges": discovery.MaxScanRanges},
			"stats":  s.discovery.Health()["snmp"],
			// What the sweep will authenticate with — the platform-owned SNMP
			// profiles, tried in name order (counts only; no secret, no tenant data).
			"scan_profiles": scanProfileSummary(s.snmpCreds),
			"found":         s.discoveredBySweep(),
		}
		// A config that could not be READ must not render as an operator who
		// disabled discovery — the console says so, and PUT is the repair path.
		if s.discoveryCfg.unavailable() != nil {
			body["config_unavailable"] = true
			body["config_error"] = "the saved discovery config could not be read or decrypted — discovery is disabled until it is re-saved"
		}
		writeJSON(w, http.StatusOK, body)
	case http.MethodPut:
		var in discoveryConfigInput
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(in.Community) != "" {
			writeError(w, http.StatusBadRequest, errDiscoveryCommunityRemoved)
			return
		}
		out, err := s.discoveryCfg.set(in.discoveryScanConfig)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.discovery.RefreshNow() // apply immediately (cooldown still bounds the sweep rate)
		writeJSON(w, http.StatusOK, map[string]any{"config": out.public()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
