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
	"netops/backend/models"
)

// ScanSettings is the slice of the operator config the scanner needs; the
// caller adapts its (sealed, env-seeded) store onto it.
type ScanSettings struct {
	Enabled bool
	Ranges  []string
	// Credentials are the stored SNMP profiles the sweep tries, IN ORDER, per
	// host until one answers (owner decision 2026-10-04: SNMP credentials live
	// in ONE place — the SNMP profiles; discovery has no community of its own).
	// The caller decides which profiles are eligible (platform-owned only) and
	// their order. Empty means the sweep cannot authenticate to anything: it
	// refuses loudly rather than guessing "public".
	Credentials     []ScanCredential
	AllowNonPrivate bool
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
// address. It is restored from a FoundStore before the first poll (Restore),
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
	found     map[string]*foundEntry // the scan memory — see the header above

	// Persistence. store == nil keeps the pre-366 in-memory behaviour (tests,
	// a backend without per-record capability). THREE states, never two:
	// no store / store read OK (restored) / store unreadable (loadErr) — an
	// unreadable store refuses every write, because the scanner cannot tell
	// what it would overwrite or prune.
	store    FoundStore
	loadErr  error
	restored bool
	// dirty is address → generation of the change; a write clears an entry
	// only if no newer change arrived meanwhile. prunes are deletes not yet
	// written. Both are kept across a failed write and retried by the next poll.
	dirty   map[string]uint64
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
		found: map[string]*foundEntry{}, dirty: map[string]uint64{}, prunes: map[FoundKey]bool{},
	}
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
	// Most recently answered first, so the bound (and an address claimed by
	// two tenants' records) keeps the freshest evidence.
	sort.Slice(mine, func(i, j int) bool {
		if !mine[i].LastAnswered.Equal(mine[j].LastAnswered) {
			return mine[i].LastAnswered.After(mine[j].LastAnswered)
		}
		return mine[i].Address < mine[j].Address
	})
	dropped := 0
	for _, r := range mine {
		if _, have := s.found[r.Address]; have {
			if r.TenantID != s.found[r.Address].dev.TenantID {
				log.Printf("discovery snmp: address %s is stored under more than one tenant; keeping the most recently answered record", r.Address)
			}
			continue
		}
		if len(s.found) >= maxFound {
			dropped++
			continue
		}
		s.found[r.Address] = &foundEntry{
			dev: models.Device{
				ID: r.DeviceID, Name: r.Name, Address: r.Address, Vendor: r.Vendor, OS: r.OS,
				Source: s.Name(), CredentialRef: r.CredentialRef, TenantID: r.TenantID, LastSeen: r.LastAnswered,
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
	s.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_discovery_found_store_errors_total Failed writes of the SNMP scan memory (retried by the next poll).\n# TYPE netops_discovery_found_store_errors_total counter\nnetops_discovery_found_store_errors_total{source=\"snmp\"} %d\n", writeErrors)
	fmt.Fprintf(w, "# HELP netops_discovery_found_store_loaded Scan memory state: 1 restored, 0 store unreadable (writes refused), -1 no store.\n# TYPE netops_discovery_found_store_loaded gauge\nnetops_discovery_found_store_loaded{source=\"snmp\"} %d\n", state)
	fmt.Fprintf(w, "# HELP netops_discovery_found_devices Devices in the SNMP scan memory, by liveness.\n# TYPE netops_discovery_found_devices gauge\nnetops_discovery_found_devices{source=\"snmp\",state=\"answering\"} %d\nnetops_discovery_found_devices{source=\"snmp\",state=\"stale\"} %d\n", answering, stale)
	fmt.Fprintf(w, "# HELP netops_discovery_found_dropped_total Devices not remembered because the scan memory bound was reached.\n# TYPE netops_discovery_found_dropped_total counter\nnetops_discovery_found_dropped_total{source=\"snmp\"} %d\n", capDropped)
}

// probeAnswer is one host's answer in a sweep.
type probeAnswer struct {
	sysName, vendor, descr, profileID string
}

func (s *SNMPSource) Poll(ctx context.Context) ([]models.Device, error) {
	cfg := s.cfg()
	if !cfg.Enabled || len(cfg.Ranges) == 0 {
		// Disabled: no device is reported (the aggregator drops them from the
		// inventory, the pre-366 behaviour) and NOTHING is aged — the stored
		// memory is left exactly as it is.
		s.flush(ctx)
		return nil, nil
	}
	ranges, _, err := ValidateScanRanges(cfg.Ranges, cfg.AllowNonPrivate)
	if err != nil {
		// Surfaces in source stats / the console instead of failing silently
		// (§10: no silent failures) — and refuses oversized env defaults.
		s.flush(ctx)
		return s.snapshot(), fmt.Errorf("discovery ranges refused: %w", err)
	}
	if len(cfg.Credentials) == 0 {
		// §10: never a silent "no devices found" when the truth is "nothing to
		// authenticate with" — and never a guessed default community.
		s.flush(ctx)
		return s.snapshot(), fmt.Errorf("discovery sweep refused: %w", ErrNoScanCredentials)
	}

	s.mu.Lock()
	now := s.now()
	if since := now.Sub(s.lastSweep); since < ScanCooldown {
		snap := s.snapshotLocked()
		s.mu.Unlock()
		s.flush(ctx)
		return snap, nil // refresh-triggered re-poll inside the cooldown: serve cache
	}
	s.lastSweep = now
	// The source's own memory, by address, with the profile each is bound to.
	ownCred := make(map[string]string, len(s.found))
	for addr, e := range s.found {
		ownCred[addr] = e.dev.CredentialRef
	}
	s.mu.Unlock()

	// Each host is tried with the stored profiles in the caller's order until
	// one answers; the device is then BOUND to that profile, so polling uses
	// exactly the credential discovery proved works.
	creds := cfg.Credentials

	// Addresses already in inventory from ANOTHER source are not probed:
	// discovery only hunts for NEW devices, so it cannot duplicate manual/SoT
	// entries. The source's own found addresses ARE re-probed — that is the
	// liveness the ageing reads (the inventory contains them too, which is why
	// they are taken from ownCred first).
	knownAddr := map[string]bool{}
	if s.known != nil {
		for _, d := range s.known() {
			if d.Address != "" {
				knownAddr[d.Address] = true
			}
		}
	}

	var todo []string
	inRange := map[string]bool{}
	for _, r := range ranges {
		for _, addr := range expandCIDR(r) {
			inRange[addr] = true
			if _, own := ownCred[addr]; own || !knownAddr[addr] {
				todo = append(todo, addr)
			}
		}
	}

	jobs := make(chan string)
	answers := map[string]probeAnswer{}
	var wg sync.WaitGroup
	var amu sync.Mutex
	for i := 0; i < scanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				var sysName, vendor, descr, profileID string
				var ok bool
				for _, cred := range credOrder(creds, ownCred[addr]) {
					tgt := cred.Target
					tgt.Address = addr
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
				answers[addr] = probeAnswer{sysName: sysName, vendor: vendor, descr: descr, profileID: profileID}
				amu.Unlock()
			}
		}()
	}
	cancelled := false
feed:
	for _, addr := range todo {
		select {
		case <-ctx.Done():
			cancelled = true
			break feed // stop feeding; workers drain and exit
		case jobs <- addr:
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
func (s *SNMPSource) markDirtyLocked(addr string) {
	s.gen++
	s.dirty[addr] = s.gen
}

// applyAnswersLocked folds a sweep's answers into the memory: a new address
// becomes a device; a known one updates its liveness only. Caller holds mu.
func (s *SNMPSource) applyAnswersLocked(answers map[string]probeAnswer, now time.Time) {
	addrs := make([]string, 0, len(answers))
	for a := range answers {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs) // deterministic admission when the bound is reached
	capHit := 0
	for _, addr := range addrs {
		ans := answers[addr]
		if e, ok := s.found[addr]; ok {
			// LIVENESS ONLY: the id and name stay what they were when the
			// device was first found — they are what history keys on.
			e.lastAnswered, e.misses = now, 0
			e.dev.LastSeen = now
			if !e.staleSince.IsZero() {
				e.staleSince = time.Time{}
				s.markDirtyLocked(addr)
			} else if now.Sub(e.savedAnswered) >= answeredPersistEvery {
				s.markDirtyLocked(addr)
			}
			continue
		}
		if len(s.found) >= maxFound {
			capHit++
			continue
		}
		name := strings.TrimSpace(ans.sysName)
		if name == "" {
			name = addr
		}
		s.found[addr] = &foundEntry{
			dev: models.Device{
				ID:      ScanDeviceID(ans.sysName, addr),
				Name:    name,
				Address: addr,
				Vendor:  ans.vendor,
				OS:      TruncateDescr(ans.descr),
				Source:  "snmp",
				// Bound to the profile that answered (owner decision b).
				CredentialRef: ans.profileID,
				// TenantID deliberately empty: discovered infrastructure is
				// platform-scoped until an operator assigns it (untagged =
				// platform-only under the strict tenancy model).
				LastSeen: now,
			},
			firstFound: now, lastAnswered: now,
		}
		// A device pruned earlier and found again is a new arrival, not a delete.
		delete(s.prunes, FoundKey{TenantID: "", Source: s.Name(), Address: addr})
		s.markDirtyLocked(addr)
	}
	if capHit > 0 {
		s.capDropped += uint64(capHit)
		log.Printf("discovery snmp: scan memory is at its bound of %d devices; %d newly answering devices were not added", maxFound, capHit)
	}
}

// ageLocked applies one COMPLETED sweep's evidence: in-range devices that did
// not answer accrue a miss and turn stale at staleAfterMisses; stale devices
// past pruneAfterStale are pruned — but only when the sweep had at least one
// answer. Out-of-range devices were not measured and accrue nothing. Caller
// holds mu.
func (s *SNMPSource) ageLocked(answers map[string]probeAnswer, inRange map[string]bool, now time.Time) {
	for addr, e := range s.found {
		if _, ok := answers[addr]; ok || !inRange[addr] {
			continue
		}
		e.misses++
		if e.misses >= staleAfterMisses && e.staleSince.IsZero() {
			e.staleSince = now
			s.markDirtyLocked(addr)
		}
	}
	if len(answers) == 0 {
		return // an all-silent sweep prunes nothing
	}
	for addr, e := range s.found {
		if e.staleSince.IsZero() || now.Sub(e.staleSince) < pruneAfterStale {
			continue
		}
		delete(s.found, addr)
		delete(s.dirty, addr)
		s.prunes[FoundKey{TenantID: normFoundTenant(e.dev.TenantID), Source: s.Name(), Address: addr}] = true
	}
}

// recordLocked is the persisted form of one entry. Caller holds mu.
func (s *SNMPSource) recordLocked(e *foundEntry) FoundRecord {
	return FoundRecord{
		TenantID: normFoundTenant(e.dev.TenantID), Source: s.Name(), Address: e.dev.Address,
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
	gens := make(map[string]uint64, len(s.dirty))
	ups := make([]FoundRecord, 0, len(s.dirty))
	for addr, g := range s.dirty {
		e, ok := s.found[addr]
		if !ok {
			delete(s.dirty, addr) // gone from memory: its prune (if any) carries it
			continue
		}
		gens[addr] = g
		ups = append(ups, s.recordLocked(e))
	}
	sort.Slice(ups, func(i, j int) bool { return ups[i].Address < ups[j].Address })
	prunes := make([]FoundKey, 0, len(s.prunes))
	for k := range s.prunes {
		prunes = append(prunes, k)
	}
	sort.Slice(prunes, func(i, j int) bool { return prunes[i].Address < prunes[j].Address })
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
		if s.dirty[r.Address] == gens[r.Address] {
			delete(s.dirty, r.Address)
		}
		if e, ok := s.found[r.Address]; ok {
			e.savedAnswered = r.LastAnswered
		}
	}
	for _, k := range prunes {
		delete(s.prunes, k)
	}
}

func (s *SNMPSource) snapshot() []models.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
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
	out := make([]models.Device, 0, len(s.found))
	for _, e := range s.found {
		d := e.dev
		d.DiscoveryStale = !e.staleSince.IsZero()
		if !e.lastAnswered.IsZero() {
			d.LastSeen = e.lastAnswered
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// ScanDeviceID derives a stable inventory id from sysName (lowercased,
// unsafe runes collapsed) falling back to the address.
func ScanDeviceID(sysName, addr string) string {
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
	name := strings.Trim(b.String(), "-.")
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

// shortAddrHash is a stable, compact, collision-resistant tag for an address —
// 8 hex chars of its SHA-256, enough to disambiguate a fleet without bloating
// the id or leaking the full address into an API path segment.
func shortAddrHash(addr string) string {
	sum := sha256.Sum256([]byte(addr))
	return hex.EncodeToString(sum[:])[:8]
}
