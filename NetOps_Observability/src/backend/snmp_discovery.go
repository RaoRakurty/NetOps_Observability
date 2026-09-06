// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
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
// hard host cap), the scan engine is
// bounded (worker cap, per-host timeout, cooldown between sweeps), and the
// probe community is a secret: encrypted at rest via the vault.Vault, never echoed
// back to a client. Env vars (ENABLE_SNMP_DISCOVERY / SNMP_CIDR_RANGES /
// SNMP_COMMUNITY) remain only as the bootstrap default when nothing has been
// configured from the console.

type discoveryScanConfig struct {
	Enabled bool     `json:"enabled"`
	Ranges  []string `json:"ranges"`
	// Community is the SNMP v2c probe credential — a comma-separated priority
	// list (real fleets use per-vendor communities, e.g. "arista-public,
	// cisco-public"); each host is tried in order until one answers. Write-only
	// through the API (GETs report only whether one is set); sealed at rest via
	// the vault.Vault. Empty falls back to SNMP_COMMUNITY, then "public".
	Community string `json:"community,omitempty"`
	// AllowNonPrivate acknowledges scanning ranges outside RFC 1918. Enterprises
	// routinely squat on unrouted public space internally; requiring an explicit
	// flag keeps the default posture closed (you must SAY you own that space)
	// while not locking those networks out. Loopback / link-local / multicast /
	// reserved space is refused regardless.
	AllowNonPrivate bool `json:"allow_non_private"`
	// IntervalSec is the periodic sweep cadence; 0 → default 300s.
	IntervalSec int `json:"interval_sec"`
}

// validateDiscoveryRanges enforces the scan-target policy: IPv4 CIDRs only,
// RFC1918 private space by default (non-private unicast needs the explicit
// allowNonPrivate acknowledgment; loopback/link-local/multicast/reserved is
// refused regardless), bounded count and expansion size. It returns the
// normalized ranges and the total host count.
func mapDiscovery(c discoveryScanConfig, f secretXform) (discoveryScanConfig, error) {
	var e error
	c.Community, e = f("", fieldDiscoveryComm, c.Community)
	return c, e
}

type discoveryConfigStore struct {
	mu    sync.RWMutex
	cfg   *discoveryScanConfig
	path  string
	vault *vault.Vault
	// loadErr is set when the SAVED config could not be read or unsealed. That is
	// not "no config saved": falling through to the env bootstrap would sweep a
	// range and community the operator never chose (the shipped default is
	// 10.0.0.0/8), and a failed unseal used to leave the CIPHERTEXT in place as
	// the SNMP community — every probe then failed auth while the sweep reported
	// a clean "no devices found" (§10).
	loadErr error
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
	var c discoveryScanConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("decode discovery config: %w", err)
	}
	out, derr := mapDiscovery(c, openFn(s.vault))
	if derr != nil {
		// NEVER keep the sealed bytes as the community: a sweep with a ciphertext
		// community authenticates against nothing and looks like an empty network.
		return fmt.Errorf("unseal discovery community: %w", derr)
	}
	s.cfg = &out
	return nil
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
		Enabled:   os.Getenv("ENABLE_SNMP_DISCOVERY") == "true" && len(ranges) > 0,
		Ranges:    ranges,
		Community: os.Getenv("SNMP_COMMUNITY"),
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
	// Blank community on save preserves the stored secret (GET never echoes it).
	if in.Community == "" && s.cfg != nil {
		in.Community = s.cfg.Community
	}
	sealed, err := mapDiscovery(in, sealFn(s.vault))
	if err != nil {
		return discoveryScanConfig{}, err
	}
	b, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return discoveryScanConfig{}, err
	}
	if err := platformdb.Save(s.path, b); err != nil {
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
	CommunitySet    bool     `json:"community_set"`
	AllowNonPrivate bool     `json:"allow_non_private"`
	IntervalSec     int      `json:"interval_sec"`
}

func (c discoveryScanConfig) public() publicDiscoveryConfig {
	if c.Ranges == nil {
		c.Ranges = []string{}
	}
	return publicDiscoveryConfig{Enabled: c.Enabled, Ranges: c.Ranges, CommunitySet: c.Community != "", AllowNonPrivate: c.AllowNonPrivate, IntervalSec: c.IntervalSec}
}

// =============================================================================
// SNMPSource — the real subnet scanner, registered with the aggregator.
// =============================================================================

// discoveryProbe is the per-host probe seam (injectable for tests).
// The scanner moved to internal/discovery/snmp_source.go (Phase-2 W3.9).
// The sealed store stays; scanSettings adapts it onto the scanner's slice.
type SNMPSource = discovery.SNMPSource

func newSNMPSourceFromStore(store *discoveryConfigStore, known func() []models.Device) *SNMPSource {
	return discovery.NewSNMPSource(func() discovery.ScanSettings {
		c := store.effective()
		community := c.Community
		if community == "" {
			community = envOr("SNMP_COMMUNITY", "public")
		}
		return discovery.ScanSettings{
			Enabled: c.Enabled, Ranges: c.Ranges,
			Community: community, AllowNonPrivate: c.AllowNonPrivate,
		}
	}, known)
}

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
		}
		// A config that could not be READ must not render as an operator who
		// disabled discovery — the console says so, and PUT is the repair path.
		if s.discoveryCfg.unavailable() != nil {
			body["config_unavailable"] = true
			body["config_error"] = "the saved discovery config could not be read or decrypted — discovery is disabled until it is re-saved"
		}
		writeJSON(w, http.StatusOK, body)
	case http.MethodPut:
		var in discoveryScanConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		out, err := s.discoveryCfg.set(in)
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
