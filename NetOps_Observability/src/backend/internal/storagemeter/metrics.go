// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package storagemeter

import (
	"fmt"
	"io"
	"time"
)

// Metrics renders the storage-measurement series for /metrics.
//
// THREE RULES, all learned the hard way elsewhere in this codebase:
//
//  1. The scrape formats a CACHE. It never probes a store — a Prometheus
//     scrape that runs `system.parts` is a scrape that times out under load and
//     takes the dashboard with it.
//  2. A store that was NOT measured emits netops_storage_measured{store}=0 and
//     emits NO bytes series for it. A zero-byte gauge and an unmeasured store
//     must not look the same, which is exactly the presentation bug tracker 204
//     was filed about.
//  3. Every store in the fixed vocabulary emits its `measured` gauge on EVERY
//     scrape, including as a zero, so a vanished series means a scrape failure
//     rather than a state change.
//
// THE TENANT LABEL AND §3a. These series carry a `tenant` label and are written
// from a PLATFORM-scoped sample, so /metrics does name every tenant's bytes.
// That is the same posture the endpoint already had — nginx gates `/metrics`
// behind the platform-owner auth_request precisely because "it exposes internal
// hostnames/cardinality that can reveal tenants/devices", and the DEM collector
// already labels a series by tenant. It does NOT widen what a TENANT can read:
// a tenant querying VictoriaMetrics goes through /api/metrics/query, whose
// scope is injected as `{device=~"…"}` / `{hostname=~"…"}` / `{source=~"…"}`,
// and these series carry none of those labels, so a scoped caller matches
// nothing. A tenant's own bytes come from GET /api/system/storage/measured,
// which is gated and scoped per §3a. Do not add a `device` label here without
// re-deriving that argument.
type Metrics struct{ m *Meter }

// Metrics returns the /metrics writer for this meter. nil-safe.
func (m *Meter) Metrics() *Metrics { return &Metrics{m: m} }

// Write renders the exposition text. nil-safe on both the writer and the meter.
func (x *Metrics) Write(w io.Writer) {
	if x == nil {
		return
	}
	var readings []Reading
	var sampled time.Time
	var passes int64
	if x.m != nil {
		readings, sampled, passes = x.m.Snapshot()
	}

	fmt.Fprintf(w, "# HELP netops_storage_bytes_measured Bytes on disk MEASURED from the store itself. Absent for a store whose size could not be measured — see netops_storage_measured.\n")
	fmt.Fprintf(w, "# TYPE netops_storage_bytes_measured gauge\n")
	for _, r := range readings {
		if !r.Measured() {
			continue
		}
		fmt.Fprintf(w, "netops_storage_bytes_measured{store=%q,tenant=%q} %d\n",
			string(r.Store), r.Scope, *r.BytesOnDisk)
	}

	// Per-store measured/not-measured, over the FIXED vocabulary so every store
	// is present on every scrape.
	ok := map[Store]bool{}
	for _, r := range readings {
		if r.Measured() {
			ok[r.Store] = true
		}
	}
	fmt.Fprintf(w, "# HELP netops_storage_measured Whether the last sampling pass MEASURED this store's bytes on disk (1) or could not (0).\n")
	fmt.Fprintf(w, "# TYPE netops_storage_measured gauge\n")
	for _, s := range Stores {
		v := 0
		if ok[s] {
			v = 1
		}
		fmt.Fprintf(w, "netops_storage_measured{store=%q} %d\n", string(s), v)
	}

	// Staleness. A measurement nobody has refreshed is a measurement of the
	// past, and an operator sizing retention off a week-old number is the same
	// failure class as a derived number labelled as measured. The sentinel is
	// -1, NOT 0: "never sampled" and "sampled this instant" are opposite states
	// and a zero would render them identically.
	age := float64(-1)
	if !sampled.IsZero() {
		age = x.m.deps.now().Sub(sampled).Seconds()
		if age < 0 {
			age = 0
		}
	}
	fmt.Fprintf(w, "# HELP netops_storage_measurement_age_seconds Age of the cached storage measurement. -1 means NEVER SAMPLED, which is not the same as fresh.\n")
	fmt.Fprintf(w, "# TYPE netops_storage_measurement_age_seconds gauge\n")
	fmt.Fprintf(w, "netops_storage_measurement_age_seconds %.0f\n", age)
	fmt.Fprintf(w, "# HELP netops_storage_measurement_passes_total Completed storage-measurement sampling passes since start.\n")
	fmt.Fprintf(w, "# TYPE netops_storage_measurement_passes_total counter\n")
	fmt.Fprintf(w, "netops_storage_measurement_passes_total %d\n", passes)
}
