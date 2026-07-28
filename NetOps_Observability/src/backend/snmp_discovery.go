package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"netops/backend/internal/discovery"
	"netops/backend/internal/vault"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
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

const (
	// discoveryMaxHosts caps the TOTAL number of addresses a scan may expand
	// to across all ranges. This is the guardrail that makes the shipped
	// 10.0.0.0/8 env default safe: an oversized range is refused with a clear
	// error instead of sweeping sixteen million hosts.
	discoveryMaxHosts = 4096
	// discoveryMaxRanges bounds the config list itself.
	discoveryMaxRanges = 32
	// discoveryWorkers bounds concurrent UDP probes (§9: all queues bounded).
	discoveryWorkers = 32
	// discoveryProbeTimeout is the per-host probe budget.
	discoveryProbeTimeout = 2 * time.Second
	// discoveryCooldown is the minimum gap between real sweeps, so the
	// tenant-triggerable /api/discovery/refresh cannot be abused to hammer
	// the network with back-to-back scans.
	discoveryCooldown = 60 * time.Second
)

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
func validateDiscoveryRanges(ranges []string, allowNonPrivate bool) ([]string, int, error) {
	clean := make([]string, 0, len(ranges))
	total := 0
	for _, raw := range ranges {
		r := strings.TrimSpace(raw)
		if r == "" {
			continue
		}
		ip, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			return nil, 0, fmt.Errorf("%q is not valid CIDR notation (e.g. 10.20.0.0/24)", r)
		}
		v4 := ip.To4()
		if v4 == nil {
			return nil, 0, fmt.Errorf("%q: only IPv4 ranges are supported", r)
		}
		if v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsMulticast() || v4.IsUnspecified() || v4[0] >= 224 {
			return nil, 0, fmt.Errorf("%q is not a scannable unicast range", r)
		}
		if !v4.IsPrivate() && !allowNonPrivate {
			return nil, 0, fmt.Errorf("%q is not private (RFC 1918) address space — enable \"allow non-private ranges\" only if your network uses that space internally", r)
		}
		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return nil, 0, fmt.Errorf("%q: only IPv4 ranges are supported", r)
		}
		total += 1 << (bits - ones)
		if total > discoveryMaxHosts {
			return nil, 0, fmt.Errorf("ranges expand to more than %d addresses — narrow them to your management subnets (a /20 is the widest single range)", discoveryMaxHosts)
		}
		clean = append(clean, ipnet.String())
	}
	if len(clean) > discoveryMaxRanges {
		return nil, 0, fmt.Errorf("at most %d ranges are allowed", discoveryMaxRanges)
	}
	return clean, total, nil
}

// expandCIDR lists the probeable addresses of an already-validated IPv4 CIDR,
// skipping the network and broadcast addresses of ranges wider than /31.
func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	v4 := ip.Mask(ipnet.Mask).To4()
	if v4 == nil {
		return nil
	}
	ones, _ := ipnet.Mask.Size()
	count := 1 << (32 - ones)
	out := make([]string, 0, count)
	base := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	for i := 0; i < count; i++ {
		if ones < 31 && (i == 0 || i == count-1) {
			continue // network / broadcast
		}
		a := base + uint32(i)
		out = append(out, net.IPv4(byte(a>>24), byte(a>>16), byte(a>>8), byte(a)).String())
	}
	return out
}

// mapDiscovery transforms the probe community (platform DEK), mirroring
// mapNetbox/mapCopilot in secrets_config.go.
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
	b, err := kvLoad(s.path)
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
	clean, _, err := validateDiscoveryRanges(in.Ranges, in.AllowNonPrivate)
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
	if err := kvSave(s.path, b); err != nil {
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
type discoveryProbe func(ctx context.Context, addr, community string) (sysName, vendor, sysDescr string, ok bool)

type SNMPSource struct {
	cfg   func() discoveryScanConfig // live getter — console changes apply without restart
	known func() []models.Device     // current inventory, to skip already-known addresses
	probe discoveryProbe

	mu        sync.Mutex
	lastSweep time.Time
	found     map[string]models.Device // sticky across sweeps; devices don't vanish on a missed probe
}

func NewSNMPSource(cfg func() discoveryScanConfig, known func() []models.Device) *SNMPSource {
	return &SNMPSource{cfg: cfg, known: known, probe: collectors.ProbeIdentity, found: map[string]models.Device{}}
}

func (s *SNMPSource) Name() string            { return "snmp" }
func (s *SNMPSource) Interval() time.Duration { return 5 * time.Minute }

func (s *SNMPSource) Poll(ctx context.Context) ([]models.Device, error) {
	cfg := s.cfg()
	if !cfg.Enabled || len(cfg.Ranges) == 0 {
		return nil, nil
	}
	ranges, _, err := validateDiscoveryRanges(cfg.Ranges, cfg.AllowNonPrivate)
	if err != nil {
		// Surfaces in source stats / the console instead of failing silently
		// (§10: no silent failures) — and refuses oversized env defaults.
		return s.snapshot(), fmt.Errorf("discovery ranges refused: %w", err)
	}

	s.mu.Lock()
	if since := time.Since(s.lastSweep); since < discoveryCooldown {
		snap := s.snapshotLocked()
		s.mu.Unlock()
		return snap, nil // refresh-triggered re-poll inside the cooldown: serve cache
	}
	s.lastSweep = time.Now()
	s.mu.Unlock()

	// The community field is a comma-separated priority list (per-vendor
	// communities are the norm on mixed fleets); each host is tried in order
	// until one answers.
	raw := cfg.Community
	if raw == "" {
		raw = envOr("SNMP_COMMUNITY", "public")
	}
	var communities []string
	for _, c := range strings.Split(raw, ",") {
		if c = strings.TrimSpace(c); c != "" {
			communities = append(communities, c)
		}
	}

	// Addresses already in inventory (any source) are not re-probed: discovery
	// only hunts for NEW devices, so it cannot duplicate manual/SoT entries.
	knownAddr := map[string]bool{}
	if s.known != nil {
		for _, d := range s.known() {
			if d.Address != "" {
				knownAddr[d.Address] = true
			}
		}
	}

	var todo []string
	for _, r := range ranges {
		for _, addr := range expandCIDR(r) {
			if !knownAddr[addr] {
				todo = append(todo, addr)
			}
		}
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var fmu sync.Mutex
	for i := 0; i < discoveryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				var sysName, vendor, descr string
				var ok bool
				for _, community := range communities {
					pctx, cancel := context.WithTimeout(ctx, discoveryProbeTimeout)
					sysName, vendor, descr, ok = s.probe(pctx, addr, community)
					cancel()
					if ok || ctx.Err() != nil {
						break
					}
				}
				if !ok {
					continue
				}
				name := strings.TrimSpace(sysName)
				if name == "" {
					name = addr
				}
				dev := models.Device{
					ID:      discoveryDeviceID(sysName, addr),
					Name:    name,
					Address: addr,
					Vendor:  vendor,
					OS:      discovery.TruncateDescr(descr),
					Source:  "snmp",
					// TenantID deliberately empty: discovered infrastructure is
					// platform-scoped until an operator assigns it (untagged =
					// platform-only under the strict tenancy model).
					LastSeen: time.Now().UTC(),
				}
				fmu.Lock()
				s.found[dev.Address] = dev
				fmu.Unlock()
			}
		}()
	}
	for _, addr := range todo {
		select {
		case <-ctx.Done():
			// Stop feeding; workers drain and exit.
			close(jobs)
			wg.Wait()
			return s.snapshot(), ctx.Err()
		case jobs <- addr:
		}
	}
	close(jobs)
	wg.Wait()
	return s.snapshot(), nil
}

func (s *SNMPSource) snapshot() []models.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *SNMPSource) snapshotLocked() []models.Device {
	out := make([]models.Device, 0, len(s.found))
	for _, d := range s.found {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// discoveryDeviceID derives a stable inventory id from sysName (lowercased,
// unsafe runes collapsed) falling back to the address.
func discoveryDeviceID(sysName, addr string) string {
	id := strings.ToLower(strings.TrimSpace(sysName))
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if out := strings.Trim(b.String(), "-."); out != "" {
		return out
	}
	return addr
}

// handleDiscoveryConfig serves GET/PUT /api/discovery/config (platform-owner
// only, §3a: directing the platform's prober at a network is platform-global
// plumbing — a tenant admin must never reach it). Mutations are recorded by
// the audit middleware.
func (s *server) handleDiscoveryConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		body := map[string]any{
			"config": s.discoveryCfg.effective().public(),
			"limits": map[string]int{"max_hosts": discoveryMaxHosts, "max_ranges": discoveryMaxRanges},
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
