// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// snmp_source.go — the real SNMP subnet scanner (Phase-2 W3.9, extracted from
// package main's snmp_discovery.go): range validation with the private-CIDR
// guardrail and the 4096-host expansion cap, the bounded worker-pool sweep
// with cooldown and multi-community fallback, and the stable device-id
// derivation. The sealed config STORE, its env bootstrap and the handler stay
// in main — the source reads live settings through the injected getter.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	// Community is a comma-separated priority list (per-vendor communities are
	// the norm on mixed fleets); the caller resolves its env default.
	Community       string
	AllowNonPrivate bool
}

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

// mapDiscovery transforms the probe community (platform DEK), mirroring
// mapNetbox/mapCopilot in secrets_config.go.
type Probe func(ctx context.Context, addr, community string) (sysName, vendor, sysDescr string, ok bool)

type SNMPSource struct {
	cfg   func() ScanSettings    // live getter — console changes apply without restart
	known func() []models.Device // current inventory, to skip already-known addresses
	probe Probe

	mu        sync.Mutex
	lastSweep time.Time
	found     map[string]models.Device // sticky across sweeps; devices don't vanish on a missed probe
}

func NewSNMPSource(cfg func() ScanSettings, known func() []models.Device) *SNMPSource {
	return &SNMPSource{cfg: cfg, known: known, probe: collectors.ProbeIdentity, found: map[string]models.Device{}}
}

// SetProbeForTest injects a fake prober — tests only.
func (s *SNMPSource) SetProbeForTest(p Probe) { s.probe = p }

func (s *SNMPSource) Name() string            { return "snmp" }
func (s *SNMPSource) Interval() time.Duration { return 5 * time.Minute }

func (s *SNMPSource) Poll(ctx context.Context) ([]models.Device, error) {
	cfg := s.cfg()
	if !cfg.Enabled || len(cfg.Ranges) == 0 {
		return nil, nil
	}
	ranges, _, err := ValidateScanRanges(cfg.Ranges, cfg.AllowNonPrivate)
	if err != nil {
		// Surfaces in source stats / the console instead of failing silently
		// (§10: no silent failures) — and refuses oversized env defaults.
		return s.snapshot(), fmt.Errorf("discovery ranges refused: %w", err)
	}

	s.mu.Lock()
	if since := time.Since(s.lastSweep); since < ScanCooldown {
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
		raw = "public" // the SNMP protocol default; the caller's env may override
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
	for i := 0; i < scanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				var sysName, vendor, descr string
				var ok bool
				for _, community := range communities {
					pctx, cancel := context.WithTimeout(ctx, probeTimeout)
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
					ID:      ScanDeviceID(sysName, addr),
					Name:    name,
					Address: addr,
					Vendor:  vendor,
					OS:      TruncateDescr(descr),
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
	for _, d := range s.found {
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
