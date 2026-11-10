// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// store.go — the NMS rows the api holds between controller polls.
//
// The NMS runtime hands one integration's resolved interface rows to Ingest
// once per poll cycle. A device's rows from that poll REPLACE its previous rows
// (the controller lists a device's whole interface table per request), and the
// newer of two polls wins when two integrations of one owner report one device.
// Snapshot projects the rows onto the CURRENT inventory every minute and is
// what the api publishes.

// Resolution outcomes of one controller interface record, a closed set (the
// metrics' outcome label). "bridged" is a row that reached the bridge.
const (
	OutcomeBridged          = "bridged"
	OutcomeDeviceUnresolved = "device_unresolved"
	OutcomeDeviceAmbiguous  = "device_ambiguous"
	OutcomeInternalVPN      = SkipInternalVPN
	OutcomeUnidentifying    = SkipAddress
	OutcomeTruncated        = "truncated"
	OutcomeStale            = "stale"
)

// Record is one controller interface handed to Ingest, with the device it
// resolved to.
type Record struct {
	// DeviceID is the inventory id the controller key resolved to; "" when it
	// did not resolve.
	DeviceID string
	// Resolve is the resolver's outcome: "matched", or why not ("no_match",
	// "ambiguous", "conflict", "no_index").
	Resolve string
	// At is the controller's own time for the reading, or the poll time.
	At  time.Time
	Row Row
}

// ingestCounts is the last poll's per-outcome record counts of one integration.
type ingestCounts map[string]int

// Store holds the NMS rows. Safe for concurrent use.
type Store struct {
	mu sync.Mutex
	st State
	// last holds each integration's last poll counts, keyed by
	// tenant + "\x00" + integration. Bounded by the enabled integrations.
	last map[string]ingestCounts
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{st: NewState(), last: map[string]ingestCounts{}}
}

// Load seeds the store from a persisted state (a restart). Rows already in
// memory are newer and win. The state is sanitized first.
func (s *Store) Load(st State, now time.Time) {
	st.Sanitize(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, d := range st.Devices {
		if _, ok := s.st.Devices[id]; !ok && len(s.st.Devices) < MaxDevices {
			s.st.Devices[id] = d
		}
	}
}

// Ingest folds one integration's poll into the store. tenant is the
// integration's owner, stamped by the runtime from the integration record
// (never from the controller's payload). An unresolved record contributes
// nothing but its count.
func (s *Store) Ingest(tenant, integration, system string, recs []Record, now time.Time) {
	counts := ingestCounts{}
	nowMs := now.UnixMilli()
	type pending struct {
		at   int64
		rows []Row
	}
	byDev := map[string]*pending{}
	for _, rec := range recs {
		row, ok, dropped := Normalize(rec.Row)
		if !ok {
			if InternalVPN(rec.Row.VRF) || InternalLoopback(rec.Row.IfName) {
				counts[OutcomeInternalVPN]++
			}
			continue
		}
		if rec.DeviceID == "" {
			switch rec.Resolve {
			case "ambiguous", "conflict":
				counts[OutcomeDeviceAmbiguous]++
			default:
				counts[OutcomeDeviceUnresolved]++
			}
			continue
		}
		if dropped > 0 {
			counts[OutcomeUnidentifying] += dropped
		}
		p := byDev[rec.DeviceID]
		if p == nil {
			p = &pending{}
			byDev[rec.DeviceID] = p
		}
		at := rec.At.UnixMilli()
		if rec.At.IsZero() || at <= 0 || at > nowMs {
			at = nowMs // no reading time, or one from the future: the poll's own time
		}
		if at > p.at {
			p.at = at
		}
		if len(p.rows) >= MaxRowsPerDevice {
			counts[OutcomeTruncated]++
			continue
		}
		p.rows = append(p.rows, row)
	}
	own := normOwner(tenant)
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(byDev))
	for id := range byDev {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := byDev[id]
		rows := mergeDuplicateRows(p.rows)
		prev := s.st.Devices[id]
		if prev != nil && prev.At > p.at && SameOwner(prev.Tenant, own) {
			continue // a newer poll (another integration of this owner) already stands
		}
		if prev == nil && len(s.st.Devices) >= MaxDevices {
			counts[OutcomeTruncated] += len(rows)
			continue
		}
		s.st.Devices[id] = &DeviceRows{Tenant: own, Integration: integration, System: system, At: p.at, Rows: rows}
	}
	s.last[own+"\x00"+integration] = counts
}

// mergeDuplicateRows folds rows of one interface (vEdge lists an interface
// once per address family) into one, in a stable order.
func mergeDuplicateRows(rows []Row) []Row {
	type k struct{ name, vrf string }
	idx := map[k]int{}
	var out []Row
	for _, r := range rows {
		key := k{strings.ToLower(r.IfName), r.VRF}
		i, ok := idx[key]
		if !ok {
			idx[key] = len(out)
			out = append(out, r)
			continue
		}
		m := &out[i]
		if m.IfIndex == "" {
			m.IfIndex = r.IfIndex
		}
		if m.Alias == "" {
			m.Alias = r.Alias
		}
		seen := map[string]bool{}
		for _, a := range m.Addrs {
			seen[a] = true
		}
		for _, a := range r.Addrs {
			if !seen[a] && len(m.Addrs) < MaxAddrsPerRow {
				seen[a] = true
				m.Addrs = append(m.Addrs, a)
			}
		}
		sort.Strings(m.Addrs)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].IfName != out[b].IfName {
			return out[a].IfName < out[b].IfName
		}
		return out[a].VRF < out[b].VRF
	})
	return out
}

// Forget drops an integration's poll counts (it was disabled or deleted). Its
// rows age out on their own.
func (s *Store) Forget(tenant, integration string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.last, normOwner(tenant)+"\x00"+integration)
}

// Snapshot (below) projects the rows onto the current inventory and returns
// the state to publish, pruning in place what may not stand: a device no
// longer in inventory, a device whose owner is not the owner the rows were
// resolved under (discarded, never relabelled), and rows past MaxAge.
//
// SnapshotStats is what one Snapshot pruned or left out.
type SnapshotStats struct {
	Stale     int // devices pruned for age
	Truncated int // rows left out by MaxTotalRows
}

// Snapshot projects the rows onto the current inventory (device id → owner).
func (s *Store) Snapshot(owners map[string]string, now time.Time) (State, SnapshotStats) {
	var stats SnapshotStats
	nowMs := now.UnixMilli()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := NewState()
	total := 0
	ids := make([]string, 0, len(s.st.Devices))
	for id := range s.st.Devices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := s.st.Devices[id]
		devOwner, inInventory := owners[id]
		switch {
		case !inInventory, !SameOwner(devOwner, d.Tenant):
			delete(s.st.Devices, id)
			continue
		case nowMs-d.At >= MaxAge.Milliseconds():
			delete(s.st.Devices, id)
			stats.Stale++
			continue
		}
		if total+len(d.Rows) > MaxTotalRows {
			stats.Truncated += len(d.Rows)
			continue
		}
		total += len(d.Rows)
		cp := *d
		cp.Rows = append([]Row(nil), d.Rows...)
		out.Devices[id] = &cp
	}
	return out, stats
}

// IngestCounts sums the last poll's per-outcome counts over every integration.
func (s *Store) IngestCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, c := range s.last {
		for k, v := range c {
			out[k] += v
		}
	}
	return out
}
