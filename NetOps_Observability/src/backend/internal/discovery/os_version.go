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
	"time"

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
			a.applyOSVersionLocked(c.target.DeviceID, reading)
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
			Version: d.OSVersion,
			Source:  osprobe.Method(d.OSVersionSource),
			At:      d.OSVersionAt,
		}
		if len(osprobe.Plan(cur)) == 0 {
			continue // an operator's value; nothing the ladder learns could replace it
		}
		cool := osProbeRetryInterval
		if cur.Version != "" {
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

// applyOSVersionLocked writes an accepted reading onto the cached row and, for
// an OPERATOR-OWNED row, persists it.
//
// Tenancy: the row is looked up by id in the aggregator's own cache and only
// its version fields are touched, so the device's TenantID travels with it
// untouched — there is no list of "all devices" here and no path by which one
// tenant's probe can reach another tenant's row (§3a). Persistence is limited to
// manual rows on purpose: a source-reported device's source is its authority,
// and persisting a shadow of one would resurrect what pollOnce legitimately
// prunes (see the store field's own doc).
//
// Caller holds a.mu.
func (a *DiscoveryAggregator) applyOSVersionLocked(id string, r osprobe.Reading) {
	d, ok := a.cache[id]
	if !ok {
		return // the device left the inventory while the probe was in flight
	}
	if d.OSVersion == r.Version && d.OSVersionSource == string(r.Method) {
		d.OSVersionAt = r.At
		a.cache[id] = d
		return
	}
	log.Printf("discovery: device %s os_version learned via %s: %q (was %q via %q)",
		id, r.Method, r.Version, d.OSVersion, d.OSVersionSource)
	d.OSVersion, d.OSVersionSource, d.OSVersionAt = r.Version, string(r.Method), r.At
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
		// The cache keeps the learned version either way; the next boot re-probes.
		log.Printf("discovery: device %s os_version learned but not persisted: %v", id, err)
	}
}
