// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// os_version.go — running the OS-VERSION SOURCE LADDER from the enrichment
// tick, and writing what it learns onto the inventory row.
//
// WHY HERE. The version is a property of the DEVICE ROW, and the enrichment
// loop is already the place that reaches out to devices and folds what they say
// back into the cache (enrichVendors does exactly this for the vendor and the OS
// label). Putting the ladder anywhere else would mean a second scheduler, a
// second copy of the cache-write discipline and a NEW HTTP route to trigger it;
// none of those are needed, and the version now simply appears on the device
// JSON the API already serves, with its provenance beside it.
//
// WHAT IT WILL NOT DO. It never probes a device whose row could not accept the
// answer anyway (osprobe.Plan decides that, derived from the overwrite rule), it
// never writes to a device, and it never re-probes a device faster than the
// cool-downs below — a fleet of devices that cannot answer must not turn the
// enrichment tick into a permanent SSH storm.

import (
	"context"
	"io"
	"log"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/deviceident"
	"netops/backend/internal/osprobe"
	"netops/backend/models"
)

const (
	// osProbeRetryInterval is how long a device that LEARNED NOTHING is left
	// alone before the ladder tries it again. The enrichment tick runs every two
	// minutes; a device with no reachable version source would otherwise be
	// dialled 720 times a day to be told the same thing.
	osProbeRetryInterval = 30 * time.Minute
	// osProbeRefreshInterval is how often a device that HAS a probed version is
	// re-read by the same source, so an upgrade shows up without an operator
	// doing anything. Software versions change on the scale of maintenance
	// windows, not minutes.
	osProbeRefreshInterval = 6 * time.Hour
	// osProbeMaxPerTick bounds how many devices one tick will probe (§9). The
	// rungs are sequential and each is bounded by its own timeout, so this is
	// what keeps the worst case (a large fleet, every device timing out) from
	// running past the next tick.
	osProbeMaxPerTick = 25
)

// SetOSVersionLadder injects the OS-version ladder. A nil ladder (every test,
// and any build that wired no transport) leaves the enrichment tick doing
// exactly what it did before — the feature is additive, never a precondition.
func (a *DiscoveryAggregator) SetOSVersionLadder(l *osprobe.Ladder) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.osLadder = l
}

// WriteOSVersionMetrics exposes the ladder's counter to the /metrics scrape
// (§10). Nil-safe.
func (a *DiscoveryAggregator) WriteOSVersionMetrics(w io.Writer) {
	a.mu.RLock()
	l := a.osLadder
	a.mu.RUnlock()
	l.WriteMetrics(w)
}

// osVersionLoop is the ladder's own tick. It shares the vendor loop's two-minute
// cadence — that is the enrichment rhythm this package already has — but not its
// gate: it runs whether or not SNMP vendor detection is enabled, and does
// nothing at all until a ladder is injected.
func (a *DiscoveryAggregator) osVersionLoop(ctx context.Context) {
	a.enrichOSVersions(ctx)
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.enrichOSVersions(ctx)
		}
	}
}

// osProbeCandidate is one device's snapshot, taken under the read lock so the
// probes themselves never hold it.
type osProbeCandidate struct {
	target  osprobe.Target
	current osprobe.Current
}

// enrichOSVersions runs one pass of the ladder over the devices that need a
// version and are due a probe.
func (a *DiscoveryAggregator) enrichOSVersions(ctx context.Context) {
	a.mu.RLock()
	ladder := a.osLadder
	pending := a.osProbeCandidatesLocked(time.Now().UTC())
	a.mu.RUnlock()
	if ladder == nil || len(pending) == 0 {
		return
	}
	for _, c := range pending {
		if ctx.Err() != nil {
			return
		}
		reading, ok := ladder.Probe(ctx, c.target, c.current)
		a.mu.Lock()
		a.osProbeAt[c.target.DeviceID] = time.Now().UTC()
		if ok {
			a.applyProbeReadingLocked(c.target.DeviceID, c.current, reading)
		}
		a.mu.Unlock()
	}
}

// osProbeCandidatesLocked picks the devices to probe this tick, in a stable
// order so a fleet larger than the per-tick bound is walked fairly rather than
// the same map-order prefix being probed forever. Caller holds a.mu (read).
func (a *DiscoveryAggregator) osProbeCandidatesLocked(now time.Time) []osProbeCandidate {
	ids := make([]string, 0, len(a.cache))
	for id := range a.cache {
		ids = append(ids, id)
	}
	// Least-recently-probed first, id as the tiebreak: a device never probed
	// (zero time) sorts ahead of every device that has been.
	sort.Slice(ids, func(i, j int) bool {
		ai, aj := a.osProbeAt[ids[i]], a.osProbeAt[ids[j]]
		if !ai.Equal(aj) {
			return ai.Before(aj)
		}
		return ids[i] < ids[j]
	})
	out := make([]osProbeCandidate, 0, osProbeMaxPerTick)
	for _, id := range ids {
		if len(out) >= osProbeMaxPerTick {
			break
		}
		d := a.cache[id]
		if d.Address == "" || d.Vendor == "" {
			// No address is nothing to dial; no vendor is nothing to resolve a
			// profile with, and enrichVendors owns that half of the problem.
			continue
		}
		cur := osprobe.Current{
			Version:      d.OSVersion,
			Source:       osprobe.Method(d.OSVersionSource),
			At:           d.OSVersionAt,
			Serial:       d.SerialNumber,
			SerialSource: osprobe.Method(d.SerialSource),
			SerialAt:     d.SerialAt,
		}
		if len(osprobe.Plan(cur))+len(osprobe.PlanIdentity(cur)) == 0 {
			// Operator values on BOTH halves; nothing the ladder learns could
			// replace either, so the device is not dialled at all.
			continue
		}
		cool := osProbeRetryInterval
		if cur.Version != "" || cur.Serial != "" {
			// SOMETHING has been learned off this device, so the fast retry has
			// done its job and the slow refresh takes over — for both halves.
			// A platform that answers with a version and will never answer with
			// a serial must not be re-dialled every half hour forever; that is
			// the SSH storm this cool-down exists to prevent.
			cool = osProbeRefreshInterval
		}
		if last, ok := a.osProbeAt[id]; ok && now.Sub(last) < cool {
			continue
		}
		out = append(out, osProbeCandidate{
			target: osprobe.Target{
				DeviceID: d.ID, Name: d.Name, Address: d.Address,
				Vendor: d.Vendor, OSText: osProbeText(d), TenantID: d.TenantID,
			},
			current: cur,
		})
	}
	return out
}

// osProbeText is the label the vendor profile is resolved from. The OS column
// is the authored one ("SR Linux"); a row whose OS is empty falls back to the
// version leaf, which on a row written by an importer may be the whole
// description line.
func osProbeText(d models.Device) string {
	if d.OS != "" {
		return d.OS
	}
	return d.OSVersion
}

// applyProbeReadingLocked writes an accepted reading onto the cached row and,
// for an OPERATOR-OWNED row, persists it — ONE cache write and at most ONE
// store write for both halves of the reading.
//
// Caller holds a.mu.
// RecordIdentity folds a hardware identity learned OUTSIDE the probe ladder onto
// a device row — today, from a TAC escalation's own read-only collection.
//
// It exists because the collection has already fetched exactly the output the
// probe would fetch. A TAC escalation runs `show version` and `show inventory`
// against the device on its way to opening a case; re-dialling the box a minute
// later to ask the same question would be a second session on a router that is,
// by definition, having a bad day. So the capture's answer is folded in here,
// through the SAME apply rules the ladder uses (applyIdentity) — same overwrite
// order, same model rule, same provenance stamp — rather than through a second,
// subtly different path.
//
// The METHOD is the caller's to name, so provenance stays honest: a serial the
// escalation read says so, and is not dressed up as a probe result.
func (a *DiscoveryAggregator) RecordIdentity(id string, ident deviceident.Identity, method osprobe.Method, at time.Time) {
	if strings.TrimSpace(id) == "" || ident.Empty() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.cache[id]
	if !ok {
		return // the device left the inventory while the collection was running
	}
	cur := osprobe.Current{Serial: d.SerialNumber, SerialSource: osprobe.Method(d.SerialSource)}
	a.applyProbeReadingLocked(id, cur, osprobe.Reading{
		Identity: ident, IdentityMethod: method, IdentityAt: at,
	})
}

func (a *DiscoveryAggregator) applyProbeReadingLocked(id string, cur osprobe.Current, r osprobe.Reading) {
	d, ok := a.cache[id]
	if !ok {
		return // the device left the inventory while the probe was in flight
	}
	changed := false
	if r.Version != "" {
		changed = applyOSVersion(&d, id, r) || changed
	}
	if !r.Identity.Empty() {
		changed = applyIdentity(&d, id, cur, r) || changed
	}
	if !changed {
		return
	}
	a.cache[id] = d
	if a.store == nil || d.Source != "manual" {
		return
	}
	// Monitoring is server state, recomputed on every read and never persisted
	// with the device (see upsertLocked). Stripping it here keeps this write on
	// the same rule rather than letting a probe be the one path that persists a
	// stale copy of it.
	persist := d
	persist.Monitored, persist.MonitorReason, persist.MonitorMethods = false, "", nil
	if err := a.store.Put(persist); err != nil {
		// The cache keeps what was learned either way; the next boot re-probes.
		log.Printf("discovery: device %s probe reading not persisted: %v", id, err)
	}
}

// applyOSVersion folds the VERSION half of a reading onto a row. It reports
// whether anything about the row changed.
func applyOSVersion(d *models.Device, id string, r osprobe.Reading) bool {
	if d.OSVersion == r.Version && d.OSVersionSource == string(r.Method) {
		if d.OSVersionAt.Equal(r.At) {
			return false
		}
		d.OSVersionAt = r.At
		return true
	}
	log.Printf("discovery: device %s os_version learned via %s: %q (was %q via %q)",
		id, r.Method, r.Version, d.OSVersion, d.OSVersionSource)
	d.OSVersion, d.OSVersionSource, d.OSVersionAt = r.Version, string(r.Method), r.At
	return true
}

// applyIdentity folds the HARDWARE IDENTITY half of a reading onto a row.
//
// THE MODEL RULE, stated here because this is the only place it is applied. The
// serial's own overwrite rule lives in osprobe (AcceptIdentity) and has already
// been applied by the ladder; the model has no such rule because it is not an
// identity and it has other legitimate writers — a NetBox device_type, an SNMP
// inference, an operator. So a probe may:
//
//   - FILL an empty model, always: a blank column is nobody's answer; and
//   - REFRESH a model it already owns, meaning the row's serial provenance is
//     this same method — that is the chassis-swap path, where the model must
//     move with the serial or the row would describe two different boxes;
//
// and it may NOT displace a model that came from somewhere else. Reporting the
// disagreement is left to whoever compares the two claims; silently picking a
// winner here would destroy the evidence that they differ.
func applyIdentity(d *models.Device, id string, cur osprobe.Current, r osprobe.Reading) bool {
	changed := false
	if r.Identity.Serial != "" {
		if d.SerialNumber == r.Identity.Serial && d.SerialSource == string(r.IdentityMethod) {
			if !d.SerialAt.Equal(r.IdentityAt) {
				d.SerialAt = r.IdentityAt
				changed = true
			}
		} else {
			log.Printf("discovery: device %s serial_number learned via %s from %q: %q (was %q via %q)",
				id, r.IdentityMethod, r.Identity.SerialCommand, r.Identity.Serial,
				d.SerialNumber, d.SerialSource)
			d.SerialNumber = r.Identity.Serial
			d.SerialSource = string(r.IdentityMethod)
			d.SerialAt = r.IdentityAt
			changed = true
		}
	}
	if m := r.Identity.Model; m != "" && d.Model != m {
		ownsRow := cur.SerialSource == r.IdentityMethod && cur.Serial != ""
		if d.Model == "" || ownsRow {
			log.Printf("discovery: device %s model learned via %s from %q: %q (was %q)",
				id, r.IdentityMethod, r.Identity.ModelCommand, m, d.Model)
			d.Model = m
			changed = true
		}
	}
	return changed
}
