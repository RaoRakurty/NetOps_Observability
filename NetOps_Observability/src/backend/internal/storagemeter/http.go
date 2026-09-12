// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package storagemeter

import (
	"encoding/json"
	"net/http"
	"time"
)

// RouteMeasured is the one HTTP route this package owns. Exported so the
// integrator registers the SAME string the OpenAPI entry and the isolation
// ledger name — three copies of a path is three chances to disagree.
const RouteMeasured = "/api/system/storage/measured"

// Report is the wire contract of GET /api/system/storage/measured.
//
// FROZEN SHAPE. The frontend renders `bytes_on_disk == null` as
// "not measured — <detail>" and never as a zero; changing the nil-means-unknown
// contract is a breaking change to the honesty guarantee, not a refactor.
type Report struct {
	// Scope is ScopePlatform for a cross-tenant caller, else the caller's tenant.
	Scope string `json:"scope"`
	// CrossTenant says whether this report spans every tenant.
	CrossTenant bool `json:"cross_tenant"`
	// GeneratedAt is when the probes ran for THIS request.
	GeneratedAt time.Time `json:"generated_at"`
	// Readings is every store × scope, measured or explicitly not.
	Readings []Reading `json:"readings"`
	// TotalMeasuredBytes sums ONLY the readings that carry a number. It is
	// therefore a lower bound whenever UnmeasuredStores is non-empty, which is
	// what MeasurementNote says in words.
	TotalMeasuredBytes int64 `json:"total_measured_bytes"`
	// UnmeasuredStores names the stores contributing nothing to the total.
	UnmeasuredStores []string `json:"unmeasured_stores"`
	// MeasurementNote is the sentence that keeps the total honest. Always set.
	MeasurementNote string `json:"measurement_note"`
}

// noteComplete and noteIncomplete are the two forms of the standing caveat.
const (
	noteComplete = "Every number here was MEASURED: read back from the store that owns the bytes, " +
		"by the query named in each reading's `source`, at the reading's `sampled_at`. " +
		"No figure on this surface is derived from a rate multiplied by an assumed bytes-per-row — " +
		"the derived model lives in scripts/resource_planner.py and docs/design/resource-sizing-design.md " +
		"and is labelled an ESTIMATE there."
	noteIncomplete = "PARTIAL. `total_measured_bytes` is a LOWER BOUND: it sums only the stores that " +
		"could be measured, and the stores in `unmeasured_stores` contribute nothing to it. " +
		"Each of those carries the reason in its `detail`. Do not treat the total as the " +
		"installation's footprint while that list is non-empty, and do not substitute a " +
		"derived estimate for a missing store without relabelling it as one."
)

// HandleMeasured serves GET /api/system/storage/measured.
//
// ISOLATION (§3a): the scope comes from the TOKEN and nothing else. This handler
// reads no tenant selector from the query string or the body — a platform
// principal sees every tenant because its own claims say cross-tenant, and a
// scoped principal cannot widen itself by asking. The stores are probed with the
// caller's scope already baked into the OpenSearch index pattern and the
// ClickHouse WHERE clause, and the readings are filtered again on the way out.
func (m *Meter) HandleMeasured(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if m == nil || m.deps.Gate == nil {
		http.Error(w, "storage measurement is not wired on this installation", http.StatusServiceUnavailable)
		return
	}
	p, ok := m.deps.Gate(w, r)
	if !ok {
		return // the gate already wrote the refusal
	}
	if !p.CrossTenant && p.Tenant == "" {
		// A principal with no tenant and no cross grant reads NOTHING. Default
		// closed: an empty scope must never fall through to the platform view.
		writeJSON(w, http.StatusOK, Report{
			Scope: "", GeneratedAt: m.deps.now(), Readings: []Reading{},
			UnmeasuredStores: storeNames(Stores),
			MeasurementNote: "This principal is bound to no tenant and holds no cross-tenant grant, " +
				"so there is no scope whose bytes it may read. Nothing was measured.",
		})
		return
	}
	readings := m.Probe(r.Context(), p)
	rep := Report{
		Scope:       scopeOf(p),
		CrossTenant: p.CrossTenant,
		GeneratedAt: m.deps.now(),
		Readings:    readings,
	}
	unmeasured := map[Store]bool{}
	measuredStore := map[Store]bool{}
	for _, rd := range readings {
		if rd.Measured() {
			rep.TotalMeasuredBytes += *rd.BytesOnDisk
			measuredStore[rd.Store] = true
		} else {
			unmeasured[rd.Store] = true
		}
	}
	for _, s := range Stores {
		if unmeasured[s] && !measuredStore[s] {
			rep.UnmeasuredStores = append(rep.UnmeasuredStores, string(s))
		}
	}
	if rep.Readings == nil {
		rep.Readings = []Reading{}
	}
	rep.MeasurementNote = noteComplete
	if len(rep.UnmeasuredStores) > 0 {
		rep.MeasurementNote = noteIncomplete
	}
	writeJSON(w, http.StatusOK, rep)
}

func storeNames(ss []Store) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, string(s))
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line and headers are already committed, so a write failure has
	// no recoverable action left beyond the client's own transport error.
	// best-effort: response body write, nothing actionable after WriteHeader
	_ = json.NewEncoder(w).Encode(v)
}
