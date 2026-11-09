// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/applog"
)

// if_rows_retention.go — each device's LAST-KNOWN interface rows.
//
// The SNMP metrics collector publishes two maps: interface IP → ifName
// (ifAddrKey) and ifIndex → ifName (ifIndexKey). They used to be rebuilt on
// every poll from the devices that answered THAT poll, so a device that stopped
// answering lost all its rows one minute later. That is the worst moment to
// forget: a device that has stopped answering polls is the one most likely to
// be failing, and it may still send traps from an interface address. The
// correlation engine recovers such a trap through
// EntityResolver.device_for_ip; with the rows gone it refuses the trap as
// identity_unattributable and stage [1] loses the evidence.
//
// The rules, in the order they bind:
//
//  1. A walk that completed replaces that map's rows in full, so a removed
//     address disappears at once.
//  2. Anything short of that — no answer, a walk that failed, a name table we
//     could not read — keeps the last rows. It says nothing about the device.
//  3. Rows are published only for devices in this cycle's target set, and a
//     change of the device's tenant discards them. See ifRowEntry.Tenant.
//  4. Rows age out at ifRowMaxAge after the last completed walk.
//  5. An address another device of the SAME tenant GAINED after this device's
//     last walk has moved: fresh wins and the retained row goes. An address both
//     devices claimed at the same time is shared (a NAT-collapsed or re-used
//     address): both rows stay, and the resolver's rule — a conflicting address
//     resolves to nobody — keeps answering. See evictMovedAddrs.
//
// The published keys keep their format and their 1800 s TTL: they carry no age or
// tenant to retain on, and a dead collector must still let them self-expire. The
// retained rows live in their own key (ifRowStateKey), written every cycle.

const (
	// ifRowMaxAge bounds how long a device's rows outlive its last completed walk.
	// Seven days is discovery's pruneAfterStale (internal/discovery/snmp_source.go):
	// a scan device that stays silent leaves the inventory about then, so its
	// addresses stop being attributable at about the time it stops existing, and a
	// static or NetBox device — which is never pruned for silence — gets the same
	// bound. It is long enough to cover a failure over a weekend or a change freeze,
	// and short enough that a re-used address cannot stay attributed to a dead box
	// for long. A constant, like pruneAfterStale.
	ifRowMaxAge = 7 * 24 * time.Hour

	// ifRowAbsentGrace is how long the STATE keeps a device missing from the target
	// set. Its rows stop being PUBLISHED immediately; this only decides whether they
	// come back if the device does. It exists because the first poll after a restart
	// runs before the static and NetBox sources have finished their own first poll
	// (discovery.Start restores only the SNMP scan memory synchronously), so
	// "absent" at boot does not mean "removed". A tenant change during the absence
	// still discards the rows.
	ifRowAbsentGrace = 15 * time.Minute

	// ifRowStateKey holds the retained rows. It is not the published map: see above.
	ifRowStateKey = "netops:topology:ifrows_retained"
	// ifRowStateVersion is the state schema. A payload of any other version is
	// treated as absent, never reinterpreted.
	ifRowStateVersion = 1
	// ifRowStateTTLSec outlives ifRowMaxAge by a day, so an api outage of any length
	// inside the bound reads its rows back; past that they would have expired anyway.
	ifRowStateTTLSec = int((ifRowMaxAge + 24*time.Hour) / time.Second)
	// ifRowPublishTTLSec is the published maps' self-expiry if the collector dies.
	ifRowPublishTTLSec = 1800
	// ifRowLogDevices caps the device ids in one log line.
	ifRowLogDevices = 20
)

// errIfRowStateCorrupt marks a state payload that will not decode. It is not
// retryable: a later read returns the same bytes.
var errIfRowStateCorrupt = errors.New("retained interface rows are corrupt")

// ifRowStore persists the retained rows across a restart.
type ifRowStore interface {
	// Load returns the stored state; absent or unconfigured is an empty state and
	// nil. A failed read is an error: it says nothing about what is stored.
	Load(ctx context.Context) (ifRowState, error)
	// Save stores the state. A failed write is reported by the store and made good
	// on the next cycle, which writes the whole state again.
	Save(ctx context.Context, st ifRowState) error
}

// ifRowSet is one map's rows for one device.
type ifRowSet struct {
	Rows map[string]string `json:"rows,omitempty"`
	// At is the unix-ms stamp the age bound runs from: the last completed walk, or
	// the first partial read of a set that has none.
	At int64 `json:"at,omitempty"`
}

// ifRowEntry is one device's retained rows.
type ifRowEntry struct {
	// Tenant is the owner the rows were read under, normalised like deviceTenant. The
	// published maps carry no tenant — the exporter stamps a row with the device's
	// CURRENT tenant — so a row that outlived a tenant change would be handed to the
	// new owner. Rows from before the change are discarded, never relabelled.
	Tenant string   `json:"tenant"`
	Addr   ifRowSet `json:"addr"`
	// AddrFirst is when this device first claimed each address (unix ms), which is
	// what separates a moved address from a shared one.
	AddrFirst map[string]int64 `json:"addr_first,omitempty"`
	Index     ifRowSet         `json:"index"`
	// AbsentSince is when the device left the target set (unix ms); 0 = present.
	AbsentSince int64 `json:"absent_since,omitempty"`
}

// ifRowState is the retained rows of every device. It is owned by the collector's
// Run goroutine: pollOnce is never concurrent with itself. Bounded by the target
// set (absent devices leave after ifRowAbsentGrace), by ifRowMaxAge, and per device
// by snmpWalkMaxRows.
type ifRowState struct {
	Version int                    `json:"version"`
	Devices map[string]*ifRowEntry `json:"devices"`
}

// ifRowInput is what one target's poll said about its interface rows.
type ifRowInput struct {
	id, tenant    string
	addr          map[string]string
	addrComplete  bool
	index         map[string]string
	indexComplete bool
}

// ifRowCycle is the outcome of one cycle.
type ifRowCycle struct {
	addr, index map[string]map[string]string // what to publish

	retained  []string      // devices served at least one map from retained rows
	oldestAge time.Duration // age of the oldest row served from retention

	expired, absent, tenantChanged, moved int
}

func newIfRowState() ifRowState {
	return ifRowState{Version: ifRowStateVersion, Devices: map[string]*ifRowEntry{}}
}

func normIfRowTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// update applies one poll to a set and reports whether its rows aged out.
func (s *ifRowSet) update(nowMs int64, fresh map[string]string, complete bool, maxAgeMs int64) (expired bool) {
	if complete {
		s.Rows, s.At = cloneRows(fresh), nowMs
		return false
	}
	if len(s.Rows) > 0 && nowMs-s.At >= maxAgeMs {
		s.Rows, s.At, expired = nil, 0, true
	}
	if len(fresh) == 0 {
		return expired
	}
	// A partial read adds what it saw; it cannot say the rest are gone.
	if s.Rows == nil {
		s.Rows = make(map[string]string, len(fresh))
	}
	for k, v := range fresh {
		s.Rows[k] = v
	}
	if s.At == 0 {
		s.At = nowMs
	}
	return expired
}

func cloneRows(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// noteAddrClaims keeps AddrFirst in step with the address rows: an address keeps its
// stamp while claimed, a new one is stamped now, one no longer claimed loses it.
func (e *ifRowEntry) noteAddrClaims(nowMs int64) {
	next := make(map[string]int64, len(e.Addr.Rows))
	for ip := range e.Addr.Rows {
		if at, ok := e.AddrFirst[ip]; ok {
			next[ip] = at
		} else {
			next[ip] = nowMs
		}
	}
	e.AddrFirst = next
}

func (e *ifRowEntry) empty() bool { return len(e.Addr.Rows) == 0 && len(e.Index.Rows) == 0 }

// apply folds one cycle into the state and returns what to publish. Pure: no IO, and
// time comes in as an argument. inputs holds exactly the current target set.
func (st *ifRowState) apply(now time.Time, inputs []ifRowInput, maxAge, absentGrace time.Duration) ifRowCycle {
	nowMs := now.UnixMilli()
	maxAgeMs := maxAge.Milliseconds()
	cy := ifRowCycle{addr: map[string]map[string]string{}, index: map[string]map[string]string{}}

	inTargets := make(map[string]*ifRowInput, len(inputs))
	for i := range inputs {
		in := &inputs[i]
		if in.id == "" {
			continue
		}
		inTargets[in.id] = in
		tenant := normIfRowTenant(in.tenant)
		e := st.Devices[in.id]
		if e != nil && e.Tenant != tenant {
			delete(st.Devices, in.id)
			e = nil
			cy.tenantChanged++
		}
		if e == nil {
			e = &ifRowEntry{Tenant: tenant}
			st.Devices[in.id] = e
		}
		e.AbsentSince = 0
		addrExpired := e.Addr.update(nowMs, in.addr, in.addrComplete, maxAgeMs)
		indexExpired := e.Index.update(nowMs, in.index, in.indexComplete, maxAgeMs)
		if addrExpired || indexExpired {
			cy.expired++
		}
		e.noteAddrClaims(nowMs)
	}

	cy.moved = st.evictMovedAddrs(inTargets)

	for id, e := range st.Devices {
		if _, ok := inTargets[id]; ok {
			continue
		}
		// Not published; kept briefly in case "absent" was only a boot-time gap.
		if e.AbsentSince == 0 {
			e.AbsentSince = nowMs
		}
		if nowMs-e.AbsentSince >= absentGrace.Milliseconds() {
			delete(st.Devices, id)
			cy.absent++
		}
	}

	for id, in := range inTargets {
		e := st.Devices[id]
		if e == nil {
			continue
		}
		if e.empty() {
			delete(st.Devices, id)
			continue
		}
		served := false
		if len(e.Addr.Rows) > 0 {
			cy.addr[id] = cloneRows(e.Addr.Rows)
			if !in.addrComplete {
				served = true
				cy.noteAge(nowMs, e.Addr.At)
			}
		}
		if len(e.Index.Rows) > 0 {
			cy.index[id] = cloneRows(e.Index.Rows)
			if !in.indexComplete {
				served = true
				cy.noteAge(nowMs, e.Index.At)
			}
		}
		if served {
			cy.retained = append(cy.retained, id)
		}
	}
	sort.Strings(cy.retained)
	return cy
}

func (cy *ifRowCycle) noteAge(nowMs, at int64) {
	if age := time.Duration(nowMs-at) * time.Millisecond; age > cy.oldestAge {
		cy.oldestAge = age
	}
}

// evictMovedAddrs removes a retained address another device has since gained, and
// returns how many it removed.
//
// A claim only ever competes inside one tenant. Two tenants re-using 10.0.0.1 is
// ordinary, says nothing about a move, and one tenant's poll must never edit another
// tenant's rows (§3a). Those rows stand, and the all-tenant ingest resolver finds the
// address ambiguous — it never picks one.
//
// Inside a tenant the test is the time of the claim. If the other device claimed the
// address after this device's last walk, this device could not have contradicted it:
// the address moved. If it claimed it at or before that walk, both held it at once:
// the address is shared. Removing this device's row then would resolve the address to
// the other device, which is exactly the wrong-device guess the resolver refuses.
func (st *ifRowState) evictMovedAddrs(inTargets map[string]*ifRowInput) int {
	type claimKey struct{ tenant, ip string }
	claims := map[claimKey][]string{}
	for id, in := range inTargets {
		e := st.Devices[id]
		if e == nil {
			continue
		}
		for ip := range in.addr {
			k := claimKey{e.Tenant, ip}
			claims[k] = append(claims[k], id)
		}
	}
	moved := 0
	for id, e := range st.Devices {
		in, ok := inTargets[id]
		if !ok || in.addrComplete {
			continue
		}
		for ip := range e.Addr.Rows {
			if _, readNow := in.addr[ip]; readNow {
				continue // this device read it too: both are fresh, so both stand
			}
			for _, other := range claims[claimKey{e.Tenant, ip}] {
				if st.Devices[other].AddrFirst[ip] > e.Addr.At {
					delete(e.Addr.Rows, ip)
					delete(e.AddrFirst, ip)
					moved++
					break
				}
			}
		}
	}
	return moved
}

// sanitize drops what a loaded state must not be believed about (§3: never trust
// cached data without validation). A stamp from the future would defeat the age bound
// for as long as it stays in the future; a row with no stamp could not be aged at all.
func (st *ifRowState) sanitize(now time.Time) {
	nowMs := now.UnixMilli()
	valid := func(s *ifRowSet) {
		if s.At <= 0 || s.At > nowMs {
			s.Rows, s.At = nil, 0
		}
	}
	for id, e := range st.Devices {
		if id == "" || e == nil {
			delete(st.Devices, id)
			continue
		}
		e.Tenant = normIfRowTenant(e.Tenant)
		valid(&e.Addr)
		valid(&e.Index)
		e.noteAddrClaims(nowMs)
		if e.empty() {
			delete(st.Devices, id)
		}
	}
}

// valkeyIfRowStore is the production ifRowStore.
type valkeyIfRowStore struct{}

// Load implements ifRowStore.
func (valkeyIfRowStore) Load(ctx context.Context) (ifRowState, error) {
	st := newIfRowState()
	c, err := redisDial(ctx)
	if errors.Is(err, ErrNotConfigured) {
		return st, nil // no channel on this deployment: retention is in-memory only
	}
	if err != nil {
		return st, err
	}
	defer c.Close()
	raw, err := redisCmd(c, "GET", ifRowStateKey)
	if err != nil {
		return st, fmt.Errorf("%s was not read: %w", ifRowStateKey, err)
	}
	if raw == "" {
		return st, nil
	}
	var got ifRowState
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		return st, fmt.Errorf("%w: %s: %w", errIfRowStateCorrupt, ifRowStateKey, err)
	}
	if got.Version != ifRowStateVersion || got.Devices == nil {
		return st, fmt.Errorf("%w: %s has version %d, want %d", errIfRowStateCorrupt, ifRowStateKey, got.Version, ifRowStateVersion)
	}
	return got, nil
}

// Save implements ifRowStore.
func (valkeyIfRowStore) Save(ctx context.Context, st ifRowState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", ifRowStateKey, err)
	}
	// redisPublish counts and reports a failed write.
	redisPublish(ctx, "interface-rows-retained", ifRowStateKey, string(b), ifRowStateTTLSec)
	return nil
}

// loadIfRows reads the stored rows once. A failed read is retried on the next cycle,
// and until it succeeds the state is not saved: writing now would overwrite the rows
// this collector has not yet managed to read.
func (c *metricsCollector) loadIfRows(ctx context.Context, now time.Time) {
	if c.ifRowsLoaded {
		return
	}
	got, err := c.ifRowStore.Load(ctx)
	switch {
	case errors.Is(err, errIfRowStateCorrupt):
		// A later read returns the same bytes. Start again, and overwrite them.
		applog.Error("snmpmetrics", "retained interface rows are unusable and are discarded — devices not answering polls lose their interface addresses until they answer again",
			map[string]any{"key": ifRowStateKey, "error": err.Error()})
	case err != nil:
		applog.Warn("snmpmetrics", "retained interface rows could not be read — retrying next cycle, and not saving until then",
			map[string]any{"key": ifRowStateKey, "error": err.Error()})
		return
	default:
		got.sanitize(now)
		for id, e := range got.Devices {
			// A device already in memory answered during a failed-read window: newer.
			if _, ok := c.ifRows.Devices[id]; !ok {
				c.ifRows.Devices[id] = e
			}
		}
	}
	c.ifRowsLoaded = true
}

// publishIfRows folds this cycle's polls into the retained rows, publishes the maps,
// saves the state, and returns the cycle's outcome. results[i] belongs to targets[i]:
// a device that did not answer has no id in its outcome.
func (c *metricsCollector) publishIfRows(ctx context.Context, now time.Time, targets []Target, results []deviceOutcome) ifRowCycle {
	c.loadIfRows(ctx, now)
	inputs := make([]ifRowInput, len(targets))
	for i, tg := range targets {
		r := results[i]
		inputs[i] = ifRowInput{
			id: tg.ID, tenant: tg.TenantID,
			addr: r.ifaddr, addrComplete: r.ifaddrComplete,
			index: r.ifindex, indexComplete: r.ifindexComplete,
		}
	}
	cy := c.ifRows.apply(now, inputs, ifRowMaxAge, ifRowAbsentGrace)

	// An empty map is published too once the state is known: it is how the last
	// device leaving the inventory stops being served. Before that, an empty map
	// would only overwrite rows nobody has read back yet.
	if len(cy.addr) > 0 || c.ifRowsLoaded {
		if b, err := json.Marshal(cy.addr); err == nil {
			// Read by the topology API to enrich BGP-LS links.
			redisPublish(ctx, "interface-addrs", ifAddrKey, string(b), ifRowPublishTTLSec)
		}
	}
	// ifIndex → ifName per device, for the C7.1 EntityResolver (flow exporter
	// in/out ifIndex → device:ifName).
	if len(cy.index) > 0 || c.ifRowsLoaded {
		if b, err := json.Marshal(cy.index); err == nil {
			redisPublish(ctx, "interface-index", ifIndexKey, string(b), ifRowPublishTTLSec)
		}
	}
	if c.ifRowsLoaded {
		if err := c.ifRowStore.Save(ctx, c.ifRows); err != nil {
			applog.Error("snmpmetrics", "retained interface rows could not be saved — they will not survive a restart",
				map[string]any{"key": ifRowStateKey, "error": err.Error()})
		}
	}
	c.logIfRowChanges(cy)
	return cy
}

// logIfRowChanges reports a CHANGE in what retention is doing: the set of devices
// served from retained rows, or rows dropped this cycle. The steady state is in the
// metrics (ifRowMetricLines); a line per minute per outage would only be noise.
func (c *metricsCollector) logIfRowChanges(cy ifRowCycle) {
	joined := strings.Join(cy.retained, ",")
	changed := joined != c.ifRowsLastRetained
	c.ifRowsLastRetained = joined
	if !changed && cy.expired == 0 && cy.absent == 0 && cy.tenantChanged == 0 && cy.moved == 0 {
		return
	}
	shown := cy.retained
	if len(shown) > ifRowLogDevices {
		shown = shown[:ifRowLogDevices]
	}
	applog.Info("snmpmetrics", "last-known interface rows changed",
		map[string]any{
			"retained_devices":      len(cy.retained),
			"oldest_age_seconds":    int64(cy.oldestAge / time.Second),
			"devices":               shown,
			"dropped_expired":       cy.expired,
			"dropped_absent":        cy.absent,
			"dropped_tenant_change": cy.tenantChanged,
			"moved_addresses":       cy.moved,
			"max_age_seconds":       int64(ifRowMaxAge / time.Second),
		})
}

// ifRowMetricLines states how many devices are served from retained rows and how old
// the oldest row is. Both read 0 when every device answered a complete walk.
func ifRowMetricLines(cy ifRowCycle, nowMs int64) []string {
	return []string{
		fmt.Sprintf(`collector_if_rows_retained_devices{collector="snmpmetrics"} %d %d`, len(cy.retained), nowMs),
		fmt.Sprintf(`collector_if_rows_retained_oldest_age_seconds{collector="snmpmetrics"} %d %d`, int64(cy.oldestAge/time.Second), nowMs),
	}
}
