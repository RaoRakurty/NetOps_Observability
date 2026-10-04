// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// monitoring.go — WHICH devices Correlix collects from, and the one place that
// decides it.
//
// THE RULE (owner decision 2026-10-03; internal/devmon holds the policy): every
// inventory device with an address is monitored, up to the licence ceiling.
// Past the ceiling the FIRST N devices by first-seen time are collected from;
// the rest stay in the inventory, marked over the licence limit. There is no
// per-device switch and no operator decision to persist.
//
// The registry owns the FIRST-SEEN LEDGER because it owns the device: a device
// is first seen when a record for it first enters the cache, under the same
// lock as every other mutation of that row. The ledger is persisted
// (FirstSeenStore) so the order survives a restart — without it, whichever
// source happened to poll first after a reboot would take the licence slots.
//
// Every consumer (the collector pool, the licence usage counter, the API) reads
// the state the registry stamps on Devices()/Get(); nothing re-derives it.
//
// LOCKING. Everything here runs under a.mu. The FirstSeenStore is a LEAF — it
// persists and never calls back into the aggregator — and so is the injected
// limit function, so the lock order is always a.mu → store, with no cycle.

import (
	"log"
	"sort"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/rbac"
	"netops/backend/models"
)

// FirstSeenRecord is one ledger entry: when the platform first saw the record
// stored under DeviceID. TenantID is the OWNING tenant, stamped from the device
// record (server-side state), never from a request.
type FirstSeenRecord struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	DeviceID  string    `json:"device_id"`
	FirstSeen time.Time `json:"first_seen"`
}

// FirstSeenStore persists the first-seen ledger. OPTIONAL: with no store the
// ledger lives only in memory (tests, unwired builds), and the order is the
// order of this process's first sightings.
//
// The ledger is registry-internal state, never served to a caller: it is read
// once at boot (the same platform-wide seed DeviceStore.Devices performs) and
// written as a whole. Implementations MUST be safe for concurrent use and MUST
// NOT call back into the aggregator.
type FirstSeenStore interface {
	// FirstSeenRecords returns the whole ledger. Called once, at wiring time.
	FirstSeenRecords() []FirstSeenRecord
	// SaveFirstSeen replaces the stored ledger with recs.
	SaveFirstSeen(recs []FirstSeenRecord) error
}

// SetFirstSeenStore attaches persistence and seeds the ledger from it. Called
// once at startup, before Start(), like SetStore.
func (a *DiscoveryAggregator) SetFirstSeenStore(st FirstSeenStore) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.firstSeenStore = st
	if st == nil {
		return
	}
	for _, rec := range st.FirstSeenRecords() {
		if rec.DeviceID == "" || rec.FirstSeen.IsZero() {
			continue
		}
		// The stored time wins over any sighting this process already made
		// (SetStore may have run first): the ledger is the older memory.
		if cur, ok := a.firstSeen[rec.DeviceID]; !ok || rec.FirstSeen.Before(cur) {
			a.firstSeen[rec.DeviceID] = rec.FirstSeen.UTC()
		}
	}
}

// SetMonitorLimit injects the MONITORED-DEVICE ceiling: how many devices may be
// collected from right now (devmon.NoLimit for no ceiling). It is asked on
// every evaluation, so a licence that grows starts collection on the next
// devices in line at once.
//
// nil (the default, and what every test gets) means no ceiling, so this package
// keeps knowing nothing about licensing.
func (a *DiscoveryAggregator) SetMonitorLimit(limit func() int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.monitorLimit = limit
}

// limitLocked is the ceiling in force. Caller holds a.mu.
func (a *DiscoveryAggregator) limitLocked() int {
	if a.monitorLimit == nil {
		return devmon.NoLimit
	}
	return a.monitorLimit()
}

// noteSeenLocked records the first sighting of a cache id and reports whether
// the ledger changed. Caller holds a.mu.
func (a *DiscoveryAggregator) noteSeenLocked(id string, now time.Time) bool {
	if _, ok := a.firstSeen[id]; ok {
		return false
	}
	a.firstSeen[id] = now.UTC()
	return true
}

// forgetSeenLocked drops a cache id from the ledger — the device left the
// inventory, so if it ever returns it is a new arrival and joins the back of
// the line. Caller holds a.mu.
func (a *DiscoveryAggregator) forgetSeenLocked(id string) bool {
	if _, ok := a.firstSeen[id]; !ok {
		return false
	}
	delete(a.firstSeen, id)
	return true
}

// persistSeenLocked writes the ledger. A failure is logged and NOT fatal: the
// in-memory order is still correct for this process, and the next change
// retries the whole write. Caller holds a.mu.
func (a *DiscoveryAggregator) persistSeenLocked() {
	if a.firstSeenStore == nil {
		return
	}
	recs := make([]FirstSeenRecord, 0, len(a.firstSeen))
	for id, at := range a.firstSeen {
		recs = append(recs, FirstSeenRecord{TenantID: deviceTenantKey(a.cache[id]), DeviceID: id, FirstSeen: at})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].DeviceID < recs[j].DeviceID })
	if err := a.firstSeenStore.SaveFirstSeen(recs); err != nil {
		log.Printf("discovery: first-seen ledger not persisted (%d entries): %v — the licence order is correct until a restart; the next inventory change retries", len(recs), err)
	}
}

// monitorViewLocked evaluates monitoring for the whole registry in one pass.
//
// It works on the DEDUPED projection, because the deduped record is the device:
// two rows that share an identity token (a NetBox entry and the SNMP scan that
// found the same box) are one physical device and take one licence slot. The
// group's first-seen time is the EARLIEST of its members — the platform knew
// the device from the first moment any source reported it.
//
// It returns the deduped devices, their verdicts keyed by canonical id, and the
// raw-id → canonical-id map. Caller holds a.mu.
func (a *DiscoveryAggregator) monitorViewLocked() ([]models.Device, map[string]devmon.Verdict, map[string]string) {
	devices, owners := dedupeWithOwners(a.cache)
	first := make(map[string]time.Time, len(devices))
	for rawID, ownerID := range owners {
		at, ok := a.firstSeen[rawID]
		if !ok {
			// Every insertion path notes a sighting; a gap is a bug, so rank
			// the record by when it was last seen rather than at the front.
			at = a.cache[rawID].LastSeen
		}
		if cur, has := first[ownerID]; !has || at.Before(cur) {
			first[ownerID] = at
		}
	}
	cands := make([]devmon.Candidate, 0, len(devices))
	for _, d := range devices {
		cands = append(cands, devmon.Candidate{Device: d, FirstSeen: first[d.ID]})
	}
	return devices, devmon.Assign(cands, a.limitLocked()), owners
}

// stampMonitoring fills the monitoring fields on a copy of d from its verdict.
func stampMonitoring(d models.Device, v devmon.Verdict) models.Device {
	d.Monitored = v.Monitored
	d.MonitorState = v.State
	d.MonitorReason = v.Reason
	d.MonitorLimit = v.Limit
	if v.Monitored {
		d.MonitorMethods = devmon.Methods(d)
	} else {
		d.MonitorMethods = nil
	}
	return d
}

// clearMonitoring strips the server-stamped monitoring fields — they are never
// request input and never persisted with the device.
func clearMonitoring(d models.Device) models.Device {
	d.Monitored, d.MonitorState, d.MonitorReason, d.MonitorLimit, d.MonitorMethods = false, "", "", 0, nil
	return d
}

// monitoredCountLocked is the authoritative usage number: how many DISTINCT
// devices Correlix is collecting from right now. Caller holds a.mu.
func (a *DiscoveryAggregator) monitoredCountLocked() (monitored, overLimit int) {
	_, state, _ := a.monitorViewLocked()
	for _, v := range state {
		switch v.State {
		case devmon.StateMonitored:
			monitored++
		case devmon.StateOverLimit:
			overLimit++
		}
	}
	return monitored, overLimit
}

// MonitoredCount is the platform-wide count of monitored devices — the number
// the licence ceiling is measured against.
func (a *DiscoveryAggregator) MonitoredCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n, _ := a.monitoredCountLocked()
	return n
}

// AddressableCount is the platform-wide number of DISTINCT addressable
// devices — monitored plus over the limit. It is the licence's usage number
// (owner decision 2026-10-03: monitored means "in the inventory and
// addressable"); MonitoredCount is how many of them are actually collected.
func (a *DiscoveryAggregator) AddressableCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n, over := a.monitoredCountLocked()
	return n + over
}

// logOverLimitLocked logs when the number of over-limit devices changes, so a
// device that stops being collected from is never a silent event (§10).
// Caller holds a.mu (write).
func (a *DiscoveryAggregator) logOverLimitLocked() {
	_, over := a.monitoredCountLocked()
	if over == a.lastOverLimit {
		return
	}
	if over > 0 {
		log.Printf("discovery: %d device(s) are over the licence limit of %d and are not collected from — they stay in the inventory and are listed on the Devices and Licence pages", over, a.limitLocked())
	} else {
		log.Printf("discovery: no devices are over the licence limit; every addressable device is collected from")
	}
	a.lastOverLimit = over
}

// WithheldMonitoring is one device Correlix does NOT collect from because it is
// past the licence ceiling in first-seen order.
type WithheldMonitoring struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id,omitempty"`
	Name     string `json:"name,omitempty"`
	Reason   string `json:"reason"`
}

// MonitoringWithheldFor lists the over-limit devices FOR ONE PRINCIPAL. These
// devices are in the inventory, nothing about them was deleted or hidden, and
// the operator is told exactly which ones are not being collected from and why.
//
// The scope is a required argument and there is deliberately no unscoped
// sibling: the rows carry another tenant's device ids and names, so a caller
// that wants the platform-wide view has to TYPE cross=true (CLAUDE.md §3a rules
// 1 and 3). The decision funnels through rbac.Authorize so this read can never
// drift from the one policy. Order is the licence order (first-seen).
func (a *DiscoveryAggregator) MonitoringWithheldFor(tenant string, cross bool) []WithheldMonitoring {
	a.mu.RLock()
	defer a.mu.RUnlock()
	devices, state, _ := a.monitorViewLocked()
	p := rbac.Principal{Tenant: tenant, Cross: cross}
	out := make([]WithheldMonitoring, 0)
	for _, d := range devices {
		v := state[d.ID]
		if v.State != devmon.StateOverLimit {
			continue
		}
		w := WithheldMonitoring{DeviceID: d.ID, TenantID: deviceTenantKey(d), Name: d.Name, Reason: v.Reason}
		if !rbac.Authorize(p, rbac.ActionView, rbac.Resource{Type: rbac.ResDevice, Tenant: w.TenantID}).Allow {
			continue
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// MonitoringWithheldCount is the PLATFORM-WIDE number of over-limit devices,
// without the copy. It carries no tenant's identities: it feeds the licence
// page (itself platform-global) and the /metrics gauge. Anything that renders
// WHICH devices must go through MonitoringWithheldFor.
func (a *DiscoveryAggregator) MonitoringWithheldCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, over := a.monitoredCountLocked()
	return over
}

// OverCeiling is one monitored device beyond a SOFT licensed allowance: still
// collected from, recorded for true-up.
type OverCeiling struct {
	DeviceID  string    `json:"device_id"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Name      string    `json:"name,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
}

// MonitoredOverCeiling lists the monitored devices beyond `limit` in the
// licence's own order: the devices first seen AFTER the first `limit`, newest
// first. Under a soft ceiling (paid tiers) every one of them is still being
// collected from; the list exists for true-up.
//
// A limit of entitlement-unlimited (-1) or a non-positive limit returns
// nothing: there is no "beyond" an unlimited allowance, and a zero limit is a
// pathological licence whose overage is the whole fleet.
func (a *DiscoveryAggregator) MonitoredOverCeiling(limit int) []OverCeiling {
	if limit <= 0 {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	devices, state, owners := a.monitorViewLocked()
	first := make(map[string]time.Time, len(devices))
	for rawID, ownerID := range owners {
		at, ok := a.firstSeen[rawID]
		if !ok {
			continue
		}
		if cur, has := first[ownerID]; !has || at.Before(cur) {
			first[ownerID] = at
		}
	}
	rows := make([]OverCeiling, 0, len(devices))
	for _, d := range devices {
		if !state[d.ID].Monitored {
			continue
		}
		rows = append(rows, OverCeiling{DeviceID: d.ID, TenantID: deviceTenantKey(d), Name: d.Name, FirstSeen: first[d.ID]})
	}
	if len(rows) <= limit {
		return nil
	}
	// Licence order (oldest first, ties by id), then take the tail newest-first.
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].FirstSeen.Equal(rows[j].FirstSeen) {
			return rows[i].FirstSeen.Before(rows[j].FirstSeen)
		}
		return rows[i].DeviceID < rows[j].DeviceID
	})
	tail := append([]OverCeiling(nil), rows[limit:]...)
	for i, j := 0, len(tail)-1; i < j; i, j = i+1, j-1 {
		tail[i], tail[j] = tail[j], tail[i]
	}
	return tail
}
