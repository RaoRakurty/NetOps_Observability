// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// snmp_source.go — the real SNMP subnet scanner (Phase-2 W3.9, extracted from
// package main's snmp_discovery.go): range validation with the private-CIDR
// guardrail and the 4096-host expansion cap, the bounded worker-pool sweep
// with cooldown and ordered SNMP-profile fallback, and the stable device-id
// derivation. The sealed config STORE, its env bootstrap and the handler stay
// in main — the source reads live settings through the injected getter.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/owner"
	"netops/backend/models"
)

// ScanSettings is the slice of the operator config the scanner needs; the
// caller adapts its (sealed, env-seeded) stores onto it.
//
// Enabled is the master switch; each ScanScope is one discovery CHANNEL. The
// caller passes only the scopes that are turned on.
type ScanSettings struct {
	Enabled bool
	Scopes  []ScanScope
}

// PlatformScopeID is the id of the platform's own scope (tenant ""), the
// operator config at /api/discovery/config.
const PlatformScopeID = "platform"

// ScanScope is one discovery channel: a set of ranges probed with a set of
// credentials ON BEHALF OF ONE OWNER (tenant-owned scopes, 2026-11-10).
//
// THE SCOPE IS THE CHANNEL. A device found through a scope belongs to the
// scope's tenant, because the platform owner pointed that probe at that
// network for that customer — never because of anything the device answered
// (sysName, address, serial). TenantID "" is the platform scope: today's
// operator config, unchanged, and its devices keep today's ids.
type ScanScope struct {
	// ID is opaque and server-generated; PlatformScopeID for the platform.
	ID string
	// TenantID owns every device this scope finds. "" (or the global tenant)
	// is the platform.
	TenantID string
	Ranges   []string
	// AllowNonPrivate acknowledges ranges outside RFC 1918 for this scope.
	AllowNonPrivate bool
	// Credentials are the stored SNMP profiles the sweep tries, IN ORDER, per
	// host until one answers (owner decision 2026-10-04: SNMP credentials live
	// in ONE place — the SNMP profiles; discovery has no community of its own).
	// The caller decides which profiles are eligible — the platform scope gets
	// platform-owned profiles only, a tenant scope that tenant's own profiles
	// only (owner decision D2) — and their order. Empty means the scope cannot
	// authenticate to anything: it is refused loudly rather than guessing
	// "public".
	Credentials []ScanCredential
}

// scopeTenant is the normalized owner of a scope: trimmed, lower-cased, and
// the platform realm in either spelling ("" or the global tenant) is "".
func scopeTenant(t string) string {
	t = normFoundTenant(t)
	if owner.IsPlatform(t) {
		return ""
	}
	return t
}

// ScopeStatus is what the last sweep made of one scope, for the console and
// the scope API. Counts are the scope's own partition, inside its ranges.
type ScopeStatus struct {
	ScopeID   string    `json:"scope_id"`
	TenantID  string    `json:"tenant_id"`
	LastSweep time.Time `json:"last_sweep"`
	LastError string    `json:"last_error,omitempty"`
	Answering int       `json:"answering"`
	Stale     int       `json:"stale"`
}

// ScanCredential is one stored SNMP profile, pre-applied to a probe target
// template (v1/v2c community or v3 USM fields — the same mapping the pollers
// use). ProfileID is what a device found with it is bound to (credential_ref).
type ScanCredential struct {
	ProfileID string
	Target    collectors.Target
}

// ErrNoScanCredentials is the refusal the sweep reports when no SNMP profile is
// eligible — surfaced in the source stats so the console says what to do.
var ErrNoScanCredentials = errors.New("no SNMP profiles to try — add the credentials your devices use under Administration → Discovery → SNMP Profiles")

const (
	// MaxScanHosts caps the TOTAL number of addresses a scan may expand
	// to across all ranges. This is the guardrail that makes the shipped
	// 10.0.0.0/8 env default safe: an oversized range is refused with a clear
	// error instead of sweeping sixteen million hosts.
	//
	// It is ONE budget for the appliance, shared by every scope: one sweep
	// probes at most this many addresses, so a sweep's duration and the scan
	// memory bound (maxFound) are what they were before tenant scopes. Scopes
	// are charged in order — the platform scope first — and a scope that would
	// overflow the budget is refused for that sweep with a clear error while
	// the scopes before it still run.
	MaxScanHosts = 4096
	// MaxScanRanges bounds the config list itself.
	MaxScanRanges = 32
	// scanWorkers bounds concurrent UDP probes (§9: all queues bounded).
	scanWorkers = 32
	// probeTimeout is the per-host probe budget.
	probeTimeout = 2 * time.Second
	// ScanCooldown is the minimum gap between real sweeps, so the
	// tenant-triggerable /api/discovery/refresh cannot be abused to hammer
	// the network with back-to-back scans.
	ScanCooldown = 60 * time.Second
)

func ValidateScanRanges(ranges []string, allowNonPrivate bool) ([]string, int, error) {
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
		if total > MaxScanHosts {
			return nil, 0, fmt.Errorf("ranges expand to more than %d addresses — narrow them to your management subnets (a /20 is the widest single range)", MaxScanHosts)
		}
		clean = append(clean, ipnet.String())
	}
	if len(clean) > MaxScanRanges {
		return nil, 0, fmt.Errorf("at most %d ranges are allowed", MaxScanRanges)
	}
	return clean, total, nil
}

// expandCIDR lists the probeable addresses of an already-validated IPv4 CIDR,
// skipping the network and broadcast addresses of ranges wider than /31.
// ExpandCIDRForTest exposes the expansion for the white-box range tests.
func ExpandCIDRForTest(cidr string) []string { return expandCIDR(cidr) }

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

// Probe identifies one host with one credential (t carries the address and the
// SNMP fields). Production is collectors.ProbeIdentityTarget.
type Probe func(ctx context.Context, t collectors.Target) (sysName, vendor, sysDescr string, ok bool)

// SCAN MEMORY AND AGEING (tracker 366).
//
// `found` is the scanner's memory of every device it has found, keyed by
// FoundKey{tenant, source, address} — the same identity the FoundStore rows
// carry (0063's primary key). One address can therefore be remembered once per
// OWNER: the platform scope's record and a tenant scope's record of the same
// box are two devices with two ids (tenant scopes, 2026-11-10), never one
// record that the freshest owner wins. It is restored from a FoundStore before
// the first poll (Restore),
// so a device that is down at boot is still inventory — with its id, its
// tenant attribution and its topology node — instead of vanishing until it
// answers again.
//
// Each COMPLETED sweep re-probes the source's own in-range found addresses
// (the bound CredentialRef first) as well as hunting unknown ones. Re-probing
// a known address updates its LIVENESS only (last answered, misses) — never its
// id or name, which history, alerts and the tenant map are keyed on.
//
// Only a completed sweep is evidence. A disabled, refused, cooled-down or
// cancelled poll counts nothing (an unread observation must not age anything —
// the tracker 290/307 rule). A device that misses staleAfterMisses consecutive
// completed sweeps is marked STALE; it is never deleted for misses alone. A
// stale device is pruned only once it has been stale for pruneAfterStale AND
// the sweep that would prune it had at least one answer — an all-silent sweep
// is a site outage or a broken credential, not evidence that devices left.
const (
	staleAfterMisses = 3
	pruneAfterStale  = 7 * 24 * time.Hour
	// answeredPersistEvery bounds the write rate of a healthy fleet: a device
	// that keeps answering rewrites its last_answered at most this often.
	answeredPersistEvery = time.Hour
	// maxFound bounds the scanner's memory (§9): twice the widest sweep, so a
	// re-ranged network keeps its previous devices while the new ranges fill.
	maxFound = 2 * MaxScanHosts
)

// foundEntry is one remembered device plus the liveness the ageing reads.
type foundEntry struct {
	dev          models.Device // identity: set when first found (or restored), never rewritten by a re-probe
	firstFound   time.Time
	lastAnswered time.Time
	staleSince   time.Time // zero = not stale
	misses       int       // consecutive completed sweeps without an answer (not persisted)
	data         json.RawMessage
	// savedAnswered is the last_answered value the store holds, so a healthy
	// device is rewritten only hourly.
	savedAnswered time.Time
}

type SNMPSource struct {
	cfg   func() ScanSettings    // live getter — console changes apply without restart
	known func() []models.Device // current inventory, to skip already-known addresses
	probe Probe
	now   func() time.Time

	mu        sync.Mutex
	lastSweep time.Time
	found     map[FoundKey]*foundEntry // the scan memory — see the header above
	// reported is the set of partitions (owners) the last poll had a turned-on
	// scope for; nil = every partition (the restore at Start). A partition with
	// no scope left is not reported, so the aggregator drops its devices — the
	// pre-scope "discovery disabled" behaviour, per owner. Its memory is kept.
	reported map[string]bool
	// scopes is the last poll's view of each turned-on scope, by scope id.
	scopes map[string]*scopeState

	// Persistence. store == nil keeps the pre-366 in-memory behaviour (tests,
	// a backend without per-record capability). THREE states, never two:
	// no store / store read OK (restored) / store unreadable (loadErr) — an
	// unreadable store refuses every write, because the scanner cannot tell
	// what it would overwrite or prune.
	store    FoundStore
	loadErr  error
	restored bool
	// dirty is key → generation of the change; a write clears an entry
	// only if no newer change arrived meanwhile. prunes are deletes not yet
	// written. Both are kept across a failed write and retried by the next poll.
	dirty   map[FoundKey]uint64
	gen     uint64
	prunes  map[FoundKey]bool
	flushMu sync.Mutex // one write at a time

	// §10 counters (guarded by mu).
	writeErrors uint64
	capDropped  uint64
}

func NewSNMPSource(cfg func() ScanSettings, known func() []models.Device) *SNMPSource {
	return &SNMPSource{
		cfg: cfg, known: known, probe: collectors.ProbeIdentityTarget,
		now:   func() time.Time { return time.Now().UTC() },
		found: map[FoundKey]*foundEntry{}, dirty: map[FoundKey]uint64{}, prunes: map[FoundKey]bool{},
		scopes: map[string]*scopeState{},
	}
}

// scopeState is one scope as the last poll saw it.
type scopeState struct {
	tenant    string
	ranges    []*net.IPNet // validated; empty when the scope was refused
	lastSweep time.Time
	lastErr   string
}

// foundKey is the memory key of addr in tenant's partition.
func (s *SNMPSource) foundKey(tenant, addr string) FoundKey {
	return FoundKey{TenantID: scopeTenant(tenant), Source: s.Name(), Address: addr}
}

// SetProbeForTest injects a fake prober — tests only.
func (s *SNMPSource) SetProbeForTest(p Probe) { s.probe = p }

// SetClockForTest injects the clock the cooldown and the ageing read — tests only.
func (s *SNMPSource) SetClockForTest(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *SNMPSource) Name() string            { return "snmp" }
func (s *SNMPSource) Interval() time.Duration { return 5 * time.Minute }

// Restore loads the scan memory from st and attaches st as the write target.
// Call once, before the aggregator's Start. A read failure is returned AND
// remembered: the source then refuses every write and does not report itself
// restored, so the aggregator stays "not ready" for it until a completed sweep
// (Ready in discovery.go) — and the enrichment exports keep their previous
// files rather than publishing a memory that may be missing devices.
func (s *SNMPSource) Restore(ctx context.Context, st FoundStore) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store = st
	if st == nil {
		return nil
	}
	recs, err := st.Load(ctx, "", true) // the scanner is platform-wide: the boot read is the one cross-tenant call
	if err != nil {
		s.loadErr = fmt.Errorf("discovered-device store unreadable — scan memory not restored and writes refused: %w", err)
		s.restored = false
		log.Printf("discovery snmp: %v", s.loadErr)
		return s.loadErr
	}
	mine := recs[:0:0]
	for _, r := range recs {
		if r.Source == s.Name() {
			mine = append(mine, r)
		}
	}
	// Most recently answered first, so the bound keeps the freshest evidence.
	sort.Slice(mine, func(i, j int) bool {
		if !mine[i].LastAnswered.Equal(mine[j].LastAnswered) {
			return mine[i].LastAnswered.After(mine[j].LastAnswered)
		}
		if mine[i].Address != mine[j].Address {
			return mine[i].Address < mine[j].Address
		}
		return normFoundTenant(mine[i].TenantID) < normFoundTenant(mine[j].TenantID)
	})
	dropped := 0
	for _, r := range mine {
		// Keyed by the record's own identity: an address stored under two
		// owners is two devices, and both are restored (tenant scopes — before
		// them this collapsed to the freshest record and the other owner's
		// device vanished at every restart).
		k := r.Key()
		if _, have := s.found[k]; have {
			continue
		}
		if len(s.found) >= maxFound {
			dropped++
			continue
		}
		s.found[k] = &foundEntry{
			dev: models.Device{
				ID: r.DeviceID, Name: r.Name, Address: r.Address, Vendor: r.Vendor, OS: r.OS,
				Source: s.Name(), CredentialRef: r.CredentialRef, TenantID: k.TenantID, LastSeen: r.LastAnswered,
			},
			firstFound: r.FirstFound, lastAnswered: r.LastAnswered, staleSince: r.StaleSince,
			data: r.Data, savedAnswered: r.LastAnswered,
		}
	}
	if dropped > 0 {
		s.capDropped += uint64(dropped)
		log.Printf("discovery snmp: %d stored devices exceed the scan memory bound of %d and were not restored (least recently answered dropped)", dropped, maxFound)
	}
	s.restored = true
	return nil
}

// Restored reports the restored scan memory and whether the restore
// succeeded. The aggregator ingests it at Start (Restorer).
func (s *SNMPSource) Restored() ([]models.Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.restored {
		return nil, false
	}
	return s.snapshotLocked(), true
}

// WriteMetrics exposes the scan memory's health to the /metrics scrape (§10).
// Nil-safe.
//
// The per-scope families carry the scope id — opaque and server-generated —
// never a tenant id, so a scrape names no customer.
func (s *SNMPSource) WriteMetrics(w io.Writer) {
	if s == nil {
		return
	}
	s.mu.Lock()
	var answering, stale int
	for _, e := range s.found {
		if e.staleSince.IsZero() {
			answering++
		} else {
			stale++
		}
	}
	writeErrors, capDropped := s.writeErrors, s.capDropped
	state := 0
	switch {
	case s.store == nil:
		state = -1
	case s.loadErr == nil:
		state = 1
	}
	statuses := s.scopeStatusesLocked()
	s.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_discovery_found_store_errors_total Failed writes of the SNMP scan memory (retried by the next poll).\n# TYPE netops_discovery_found_store_errors_total counter\nnetops_discovery_found_store_errors_total{source=\"snmp\"} %d\n", writeErrors)
	fmt.Fprintf(w, "# HELP netops_discovery_found_store_loaded Scan memory state: 1 restored, 0 store unreadable (writes refused), -1 no store.\n# TYPE netops_discovery_found_store_loaded gauge\nnetops_discovery_found_store_loaded{source=\"snmp\"} %d\n", state)
	fmt.Fprintf(w, "# HELP netops_discovery_found_devices Devices in the SNMP scan memory, by liveness.\n# TYPE netops_discovery_found_devices gauge\nnetops_discovery_found_devices{source=\"snmp\",state=\"answering\"} %d\nnetops_discovery_found_devices{source=\"snmp\",state=\"stale\"} %d\n", answering, stale)
	fmt.Fprintf(w, "# HELP netops_discovery_found_dropped_total Devices not remembered because the scan memory bound was reached.\n# TYPE netops_discovery_found_dropped_total counter\nnetops_discovery_found_dropped_total{source=\"snmp\"} %d\n", capDropped)
	if len(statuses) == 0 {
		return
	}
	fmt.Fprint(w, "# HELP netops_discovery_scope_found_devices Devices one discovery scope has found inside its ranges, by liveness (scope = scope id).\n# TYPE netops_discovery_scope_found_devices gauge\n")
	for _, st := range statuses {
		id := promLabelValue(st.ScopeID)
		fmt.Fprintf(w, "netops_discovery_scope_found_devices{source=\"snmp\",scope=\"%s\",state=\"answering\"} %d\n", id, st.Answering)
		fmt.Fprintf(w, "netops_discovery_scope_found_devices{source=\"snmp\",scope=\"%s\",state=\"stale\"} %d\n", id, st.Stale)
	}
	fmt.Fprint(w, "# HELP netops_discovery_scope_refused 1 when a discovery scope was refused by its last poll (bad ranges, no credential, over the sweep budget), else 0.\n# TYPE netops_discovery_scope_refused gauge\n")
	for _, st := range statuses {
		refused := 0
		if st.LastError != "" {
			refused = 1
		}
		fmt.Fprintf(w, "netops_discovery_scope_refused{source=\"snmp\",scope=\"%s\"} %d\n", promLabelValue(st.ScopeID), refused)
	}
}

// promLabelValue escapes a Prometheus label value (backslash, quote, newline).
func promLabelValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// ScopeStatuses reports each turned-on scope as the last poll saw it, platform
// scope first. Nil-safe.
func (s *SNMPSource) ScopeStatuses() []ScopeStatus {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopeStatusesLocked()
}

// scopeStatusesLocked counts each scope's own partition inside its ranges.
// Caller holds mu.
func (s *SNMPSource) scopeStatusesLocked() []ScopeStatus {
	out := make([]ScopeStatus, 0, len(s.scopes))
	for id, st := range s.scopes {
		ss := ScopeStatus{ScopeID: id, TenantID: st.tenant, LastSweep: st.lastSweep, LastError: st.lastErr}
		for k, e := range s.found {
			if k.TenantID != st.tenant || !inNets(st.ranges, k.Address) {
				continue
			}
			if e.staleSince.IsZero() {
				ss.Answering++
			} else {
				ss.Stale++
			}
		}
		out = append(out, ss)
	}
	sort.Slice(out, func(i, j int) bool {
		return scopeLess(out[i].TenantID, out[i].ScopeID, out[j].TenantID, out[j].ScopeID)
	})
	return out
}

// scopeLess orders scopes: the platform scope first, then by tenant, then id.
func scopeLess(ti, ii, tj, ij string) bool {
	if (ti == "") != (tj == "") {
		return ti == ""
	}
	if ti != tj {
		return ti < tj
	}
	return ii < ij
}

func inNets(nets []*net.IPNet, addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// probeAnswer is one host's answer in a sweep.
type probeAnswer struct {
	sysName, vendor, descr, profileID string
}

// scopeRun is one turned-on scope prepared for a sweep.
type scopeRun struct {
	scope  ScanScope // TenantID normalized (scopeTenant)
	ranges []string  // validated CIDRs; nil when refused
	err    error     // why the scope cannot run this sweep; nil = it runs
}

// prepareScopes normalizes, orders and validates the turned-on scopes. Each
// scope is refused on its own (bad ranges, no credential, over the shared
// sweep budget) and the others still run. Pure.
func prepareScopes(cfg ScanSettings) []scopeRun {
	if !cfg.Enabled {
		return nil
	}
	scopes := make([]ScanScope, 0, len(cfg.Scopes))
	seen := map[string]bool{}
	for _, sc := range cfg.Scopes {
		sc.TenantID = scopeTenant(sc.TenantID)
		sc.ID = strings.TrimSpace(sc.ID)
		if sc.ID == "" && sc.TenantID == "" {
			sc.ID = PlatformScopeID
		}
		if sc.ID == "" || seen[sc.ID] {
			log.Printf("discovery snmp: a scope with an empty or repeated id was ignored")
			continue
		}
		hasRange := false
		for _, r := range sc.Ranges {
			if strings.TrimSpace(r) != "" {
				hasRange = true
				break
			}
		}
		if !hasRange {
			continue // no range = not turned on
		}
		seen[sc.ID] = true
		scopes = append(scopes, sc)
	}
	sort.SliceStable(scopes, func(i, j int) bool {
		return scopeLess(scopes[i].TenantID, scopes[i].ID, scopes[j].TenantID, scopes[j].ID)
	})
	runs := make([]scopeRun, 0, len(scopes))
	budget := 0
	for _, sc := range scopes {
		run := scopeRun{scope: sc}
		ranges, hosts, err := ValidateScanRanges(sc.Ranges, sc.AllowNonPrivate)
		switch {
		case err != nil:
			// Surfaces in the scope status / source stats instead of failing
			// silently (§10) — and refuses oversized env defaults.
			run.err = fmt.Errorf("discovery ranges refused: %w", err)
		case len(sc.Credentials) == 0 && sc.TenantID == "":
			// §10: never a silent "no devices found" when the truth is "nothing
			// to authenticate with" — and never a guessed default community.
			run.err = fmt.Errorf("discovery sweep refused: %w", ErrNoScanCredentials)
		case len(sc.Credentials) == 0:
			run.err = fmt.Errorf("discovery sweep refused: %w (a customer's scan tries only that customer's own SNMP profiles)", ErrNoScanCredentials)
		case budget+hosts > MaxScanHosts:
			run.err = fmt.Errorf("discovery ranges refused: the scans together would probe more than %d addresses per sweep (one budget for the appliance, the platform scan charged first) — narrow this scan's ranges", MaxScanHosts)
		default:
			budget += hosts
			run.ranges = ranges
		}
		if run.err != nil && sc.TenantID != "" {
			run.err = fmt.Errorf("scope %s: %w", sc.ID, run.err)
		}
		runs = append(runs, run)
	}
	return runs
}

// syncScopesLocked records the turned-on scopes this poll found. Caller holds mu.
func (s *SNMPSource) syncScopesLocked(runs []scopeRun) {
	next := make(map[string]*scopeState, len(runs))
	for _, r := range runs {
		st := &scopeState{tenant: r.scope.TenantID}
		if prev, ok := s.scopes[r.scope.ID]; ok && prev.tenant == st.tenant {
			st.lastSweep = prev.lastSweep
		}
		if r.err != nil {
			st.lastErr = r.err.Error()
		}
		for _, c := range r.ranges {
			if _, n, err := net.ParseCIDR(c); err == nil {
				st.ranges = append(st.ranges, n)
			}
		}
		next[r.scope.ID] = st
	}
	s.scopes = next
}

func (s *SNMPSource) Poll(ctx context.Context) ([]models.Device, error) {
	runs := prepareScopes(s.cfg())
	reported := make(map[string]bool, len(runs))
	var refused []error
	for _, r := range runs {
		reported[r.scope.TenantID] = true
		if r.err != nil {
			refused = append(refused, r.err)
		}
	}
	s.mu.Lock()
	s.reported = reported
	s.syncScopesLocked(runs)
	if len(runs) == 0 {
		// Nothing turned on: no device is reported (the aggregator drops them
		// from the inventory, the pre-366 behaviour) and NOTHING is aged — the
		// stored memory is left exactly as it is.
		s.mu.Unlock()
		s.flush(ctx)
		return nil, nil
	}
	if len(refused) == len(runs) {
		// Every scope refused: an error the source stats carry, and the memory
		// served as it is (a refusal is not evidence that anything left).
		snap := s.snapshotLocked()
		s.mu.Unlock()
		s.flush(ctx)
		return snap, errors.Join(refused...)
	}
	now := s.now()
	if since := now.Sub(s.lastSweep); since < ScanCooldown {
		snap := s.snapshotLocked()
		s.mu.Unlock()
		s.flush(ctx)
		return snap, nil // refresh-triggered re-poll inside the cooldown: serve cache
	}
	s.lastSweep = now
	// The source's own memory, by key, with the profile each is bound to.
	ownCred := make(map[FoundKey]string, len(s.found))
	for k, e := range s.found {
		ownCred[k] = e.dev.CredentialRef
	}
	s.mu.Unlock()

	// Addresses already in inventory from ANOTHER source are not probed:
	// discovery only hunts for NEW devices, so it cannot duplicate manual/SoT
	// entries. The source's own found addresses ARE re-probed — that is the
	// liveness the ageing reads (the inventory contains them too, which is why
	// they are taken from ownCred first).
	//
	// "Already in inventory" is asked PER OWNER. The platform scope keeps the
	// rule it always had — any device, of any owner, makes an address known, so
	// it never adds a platform copy of a box a customer already has. A tenant
	// scope sees only ITS OWN tenant's devices as known: the platform's copy of
	// an edge, or another customer's device at the same RFC 1918 address, is
	// not this customer's device, and treating it as known would leave the
	// customer's own scan unable to ever find the box.
	knownAll := map[string]bool{}
	knownBy := map[string]map[string]bool{}
	if s.known != nil {
		for _, d := range s.known() {
			if d.Address == "" {
				continue
			}
			knownAll[d.Address] = true
			t := normFoundTenant(d.TenantID)
			if knownBy[t] == nil {
				knownBy[t] = map[string]bool{}
			}
			knownBy[t][d.Address] = true
		}
	}

	type job struct {
		key   FoundKey
		creds []ScanCredential
	}
	var todo []job
	queued := map[FoundKey]bool{}
	inRange := map[FoundKey]bool{}
	for _, r := range runs {
		if r.err != nil {
			continue
		}
		known := knownAll
		if r.scope.TenantID != "" {
			known = knownBy[r.scope.TenantID]
		}
		for _, cidr := range r.ranges {
			for _, addr := range expandCIDR(cidr) {
				k := s.foundKey(r.scope.TenantID, addr)
				inRange[k] = true
				if queued[k] {
					continue // two scopes of one owner cover it: the first scope probes
				}
				if _, own := ownCred[k]; own || !known[addr] {
					queued[k] = true
					todo = append(todo, job{key: k, creds: r.scope.Credentials})
				}
			}
		}
	}

	// Each host is tried with its scope's profiles in the caller's order until
	// one answers; the device is then BOUND to that profile, so polling uses
	// exactly the credential discovery proved works.
	jobs := make(chan job)
	answers := map[FoundKey]probeAnswer{}
	var wg sync.WaitGroup
	var amu sync.Mutex
	for i := 0; i < scanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				var sysName, vendor, descr, profileID string
				var ok bool
				for _, cred := range credOrder(j.creds, ownCred[j.key]) {
					tgt := cred.Target
					tgt.Address = j.key.Address
					pctx, cancel := context.WithTimeout(ctx, probeTimeout)
					sysName, vendor, descr, ok = s.probe(pctx, tgt)
					cancel()
					if ok {
						profileID = cred.ProfileID
						break
					}
					if ctx.Err() != nil {
						break
					}
				}
				if !ok {
					continue
				}
				amu.Lock()
				answers[j.key] = probeAnswer{sysName: sysName, vendor: vendor, descr: descr, profileID: profileID}
				amu.Unlock()
			}
		}()
	}
	cancelled := false
feed:
	for _, j := range todo {
		select {
		case <-ctx.Done():
			cancelled = true
			break feed // stop feeding; workers drain and exit
		case jobs <- j:
		}
	}
	close(jobs)
	wg.Wait()
	if !cancelled && ctx.Err() != nil {
		cancelled = true // cancelled after the last address was handed out: probes were cut short
	}

	s.mu.Lock()
	s.applyAnswersLocked(answers, now)
	if !cancelled {
		s.ageLocked(answers, inRange, now)
		for _, r := range runs {
			if st, ok := s.scopes[r.scope.ID]; ok && r.err == nil {
				st.lastSweep = now
			}
		}
	}
	snap := s.snapshotLocked()
	s.mu.Unlock()
	if cancelled {
		// A cancelled sweep is not evidence: what answered is remembered (it
		// answered), nothing is aged, and the write waits for the next poll —
		// this context can no longer carry it.
		return snap, ctx.Err()
	}
	s.flush(ctx)
	return snap, nil
}

// credOrder is the profile order for one host: the profile the device is
// already bound to first (it is the one that worked), then the rest in the
// caller's order.
func credOrder(creds []ScanCredential, bound string) []ScanCredential {
	if bound == "" {
		return creds
	}
	out := make([]ScanCredential, 0, len(creds))
	for _, c := range creds {
		if c.ProfileID == bound {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return creds // the bound profile is no longer eligible: plain order
	}
	for _, c := range creds {
		if c.ProfileID != bound {
			out = append(out, c)
		}
	}
	return out
}

// markDirtyLocked records a change to persist. Caller holds mu.
func (s *SNMPSource) markDirtyLocked(k FoundKey) {
	s.gen++
	s.dirty[k] = s.gen
}

// sortedKeys orders memory keys by (tenant, address) — deterministic admission
// when the bound is reached, and deterministic writes.
func sortedKeys[V any](m map[FoundKey]V) []FoundKey {
	keys := make([]FoundKey, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return foundKeyLess(keys[i], keys[j]) })
	return keys
}

func foundKeyLess(a, b FoundKey) bool {
	if a.TenantID != b.TenantID {
		return a.TenantID < b.TenantID
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	return a.Source < b.Source
}

// applyAnswersLocked folds a sweep's answers into the memory: a new key
// becomes a device OWNED BY THE KEY'S TENANT (the scope that found it); a
// known one updates its liveness only. Caller holds mu.
func (s *SNMPSource) applyAnswersLocked(answers map[FoundKey]probeAnswer, now time.Time) {
	capHit := 0
	for _, k := range sortedKeys(answers) {
		ans := answers[k]
		if e, ok := s.found[k]; ok {
			// LIVENESS ONLY: the id and name stay what they were when the
			// device was first found — they are what history keys on.
			e.lastAnswered, e.misses = now, 0
			e.dev.LastSeen = now
			if !e.staleSince.IsZero() {
				e.staleSince = time.Time{}
				s.markDirtyLocked(k)
			} else if now.Sub(e.savedAnswered) >= answeredPersistEvery {
				s.markDirtyLocked(k)
			}
			continue
		}
		if len(s.found) >= maxFound {
			capHit++
			continue
		}
		name := strings.TrimSpace(ans.sysName)
		if name == "" {
			name = k.Address
		}
		s.found[k] = &foundEntry{
			dev: models.Device{
				// The platform scope's ids are exactly what they always were;
				// a tenant scope's ids are salted with the tenant, so its copy
				// of a box can never take the platform's (or another tenant's)
				// cache key — see ScanDeviceIDFor.
				ID:      ScanDeviceIDFor(k.TenantID, ans.sysName, k.Address),
				Name:    name,
				Address: k.Address,
				Vendor:  ans.vendor,
				OS:      TruncateDescr(ans.descr),
				Source:  "snmp",
				// Bound to the profile that answered (owner decision b).
				CredentialRef: ans.profileID,
				// The owner is the CHANNEL's: the scope's tenant, set by the
				// platform owner when the scope was created — "" for the
				// platform scope (untagged = platform-only under the strict
				// tenancy model). Never derived from what the device answered.
				TenantID: k.TenantID,
				LastSeen: now,
			},
			firstFound: now, lastAnswered: now,
		}
		// A device pruned earlier and found again is a new arrival, not a delete.
		delete(s.prunes, k)
		s.markDirtyLocked(k)
	}
	if capHit > 0 {
		s.capDropped += uint64(capHit)
		log.Printf("discovery snmp: scan memory is at its bound of %d devices; %d newly answering devices were not added", maxFound, capHit)
	}
}

// ageLocked applies one COMPLETED sweep's evidence: in-range devices that did
// not answer accrue a miss and turn stale at staleAfterMisses; stale devices
// past pruneAfterStale are pruned — but only when the sweep had at least one
// answer IN THAT DEVICE'S PARTITION (one customer's all-silent scan is that
// customer's outage, whatever the other scopes heard). Out-of-range devices
// were not measured and accrue nothing. Caller holds mu.
func (s *SNMPSource) ageLocked(answers map[FoundKey]probeAnswer, inRange map[FoundKey]bool, now time.Time) {
	answeredIn := map[string]int{}
	for k := range answers {
		answeredIn[k.TenantID]++
	}
	for k, e := range s.found {
		if _, ok := answers[k]; ok || !inRange[k] {
			continue
		}
		e.misses++
		if e.misses >= staleAfterMisses && e.staleSince.IsZero() {
			e.staleSince = now
			s.markDirtyLocked(k)
		}
	}
	for k, e := range s.found {
		if e.staleSince.IsZero() || now.Sub(e.staleSince) < pruneAfterStale {
			continue
		}
		if answeredIn[k.TenantID] == 0 {
			continue // an all-silent partition prunes nothing
		}
		delete(s.found, k)
		delete(s.dirty, k)
		s.prunes[k] = true
	}
}

// recordLocked is the persisted form of one entry. Caller holds mu.
func (s *SNMPSource) recordLocked(k FoundKey, e *foundEntry) FoundRecord {
	return FoundRecord{
		TenantID: k.TenantID, Source: s.Name(), Address: k.Address,
		DeviceID: e.dev.ID, Name: e.dev.Name, Vendor: e.dev.Vendor, OS: e.dev.OS, CredentialRef: e.dev.CredentialRef,
		FirstFound: e.firstFound, LastAnswered: e.lastAnswered, StaleSince: e.staleSince, Data: e.data,
	}
}

// flush writes the changed records — synchronously, from the poll that made
// them, so no goroutine of its own exists. A failure never fails the poll: the
// changes stay pending, the error is logged and counted, and the next poll
// retries. An unreadable store refuses every write (see Restore).
func (s *SNMPSource) flush(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	if s.store == nil || s.loadErr != nil || (len(s.dirty) == 0 && len(s.prunes) == 0) {
		s.mu.Unlock()
		return
	}
	st := s.store
	gens := make(map[FoundKey]uint64, len(s.dirty))
	ups := make([]FoundRecord, 0, len(s.dirty))
	for _, k := range sortedKeys(s.dirty) {
		e, ok := s.found[k]
		if !ok {
			delete(s.dirty, k) // gone from memory: its prune (if any) carries it
			continue
		}
		gens[k] = s.dirty[k]
		ups = append(ups, s.recordLocked(k, e))
	}
	prunes := sortedKeys(s.prunes)
	s.mu.Unlock()

	err := st.Apply(ctx, ups, prunes)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.writeErrors++
		log.Printf("discovery snmp: scan memory write failed (%d changes, %d removals pending, retried next poll): %v", len(ups), len(prunes), err)
		return
	}
	for _, r := range ups {
		k := s.foundKey(r.TenantID, r.Address)
		if s.dirty[k] == gens[k] {
			delete(s.dirty, k)
		}
		if e, ok := s.found[k]; ok {
			e.savedAnswered = r.LastAnswered
		}
	}
	for _, k := range prunes {
		delete(s.prunes, k)
	}
}

func (s *SNMPSource) snapshotLocked() []models.Device {
	// Every device keeps the COLLISION-SAFE hashed scan id it was created with
	// (ScanDeviceID(name, addr)). An earlier revision (M1) re-keyed a uniquely-
	// named device back to the address-less legacy id to spare the F-69 delete
	// tombstones a migration — but that rewrite (a) collided with a static-file
	// device that already used the bare name as its id (the aggregator, keyed by
	// d.ID with the static source registered first, then SKIPPED the SNMP record
	// as a lower-precedence duplicate, dropping its vendor/OS/address), and
	// (b) still missed tombstones written during the hashed-id window. The
	// migration problem is solved WITHOUT sacrificing address-hash uniqueness by
	// making suppression order-independent in the aggregator: pollOnce checks
	// BOTH the legacy address-less id and the hashed id, so a delete sticks in
	// either id era. So here we simply hand back the hashed ids untouched.
	//
	// Only partitions with a turned-on scope are reported (s.reported; nil =
	// all, the restore at Start).
	out := make([]models.Device, 0, len(s.found))
	for k, e := range s.found {
		if s.reported != nil && !s.reported[k.TenantID] {
			continue
		}
		d := e.dev
		d.DiscoveryStale = !e.staleSince.IsZero()
		if !e.lastAnswered.IsZero() {
			d.LastSeen = e.lastAnswered
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

// sanitizeScanName lowercases sysName and collapses unsafe runes to '-'.
func sanitizeScanName(sysName string) string {
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
	return strings.Trim(b.String(), "-.")
}

// ScanDeviceID derives a stable inventory id from sysName (lowercased,
// unsafe runes collapsed) falling back to the address. It is the PLATFORM
// scope's id; a tenant scope uses ScanDeviceIDFor.
func ScanDeviceID(sysName, addr string) string {
	name := sanitizeScanName(sysName)
	addr = strings.TrimSpace(addr)
	// Disambiguate by ADDRESS. sysName alone is not unique: a factory default
	// ("Switch") repeats across a fleet, and distinct names can sanitize to the
	// same string ("core#1" and "core@1" both fold to "core-1"). With a name-only
	// id, two such devices collided on one cache key and one silently overwrote
	// the other — vanishing from inventory, never polled or alerted, no error.
	// A short address hash makes the scan id unique per device while staying
	// stable across re-scans (same device, same address, same id). dedupeDevices
	// still merges records that are GENUINELY the same device via identity tokens
	// (ip/serial/name), so this only prevents the silent collision, it does not
	// fragment a real device across sources.
	if name != "" && addr != "" {
		return name + "-" + shortAddrHash(addr)
	}
	if name != "" {
		return name
	}
	return addr
}

// ScanDeviceIDFor is the scan id of a device found by tenant's scope.
//
// The platform scope ("" or the global tenant) gets ScanDeviceID unchanged, so
// no existing device changes id. A tenant scope's id has the same shape, but
// the hash covers the tenant AND the address: the same box found by the
// platform scope and by a customer's scope (the transition state of moving a
// customer's devices onto its own channel), or by two customers on one RFC 1918
// address, gets a different id per owner. The aggregator's cache is keyed by
// id, so a shared id would let one owner's record REPLACE the other's.
//
// It is stable per (tenant, device) and does not depend on whether another
// owner's row exists — unlike the collision-only suffix of tenantSafeIDLocked,
// which would change the id the moment the platform row is retired.
func ScanDeviceIDFor(tenant, sysName, addr string) string {
	t := scopeTenant(tenant)
	if t == "" {
		return ScanDeviceID(sysName, addr)
	}
	addr = strings.TrimSpace(addr)
	// NUL separator: no tenant id or address contains one, so (tenant, addr)
	// pairs cannot be forged into each other's hash input.
	salt := shortAddrHash(t + "\x00" + addr)
	if name := sanitizeScanName(sysName); name != "" {
		return name + "-" + salt
	}
	if addr != "" {
		return addr + "-" + salt
	}
	return ""
}

// shortAddrHash is a stable, compact, collision-resistant tag for an address —
// 8 hex chars of its SHA-256, enough to disambiguate a fleet without bloating
// the id or leaking the full address into an API path segment.
func shortAddrHash(addr string) string {
	sum := sha256.Sum256([]byte(addr))
	return hex.EncodeToString(sum[:])[:8]
}

func (s *SNMPSource) snapshot() []models.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}
