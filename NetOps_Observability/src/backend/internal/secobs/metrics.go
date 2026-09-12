// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secobs

import (
	"fmt"
	"io"
	"time"
)

// Metrics emits the SEC-020.1 families. It follows the repo idiom: a writer
// method called from the api's /metrics handler (nil-guarded there), no
// client library, HELP/TYPE before samples.
//
// All inputs are fixed at construction: the inventory is immutable after boot
// and the validator report describes the booted configuration (env does not
// change under a running process). Nothing here reads live state, so the
// writer is lock-free and cannot block a scrape.
type Metrics struct {
	inv *Inventory
	// finding counts from the boot security-posture validator (SEC-002).
	fatal, warn, info int
	now               func() time.Time
}

// NewMetrics builds the writer. now is injectable for tests; pass nil for
// time.Now.
func NewMetrics(inv *Inventory, fatal, warn, info int, now func() time.Time) *Metrics {
	if now == nil {
		now = time.Now
	}
	return &Metrics{inv: inv, fatal: fatal, warn: warn, info: info, now: now}
}

// Write emits the families. Label values are edge ids and tier names from the
// checked-in inventory and the fixed severity enum — never operator input,
// tokens, or credential material (the redaction test pins this).
func (m *Metrics) Write(w io.Writer) {
	fmt.Fprintf(w, "# HELP netops_sec_posture_findings Boot security-posture validator finding counts for the running configuration.\n")
	fmt.Fprintf(w, "# TYPE netops_sec_posture_findings gauge\n")
	fmt.Fprintf(w, "netops_sec_posture_findings{severity=%q} %d\n", "fatal", m.fatal)
	fmt.Fprintf(w, "netops_sec_posture_findings{severity=%q} %d\n", "warn", m.warn)
	fmt.Fprintf(w, "netops_sec_posture_findings{severity=%q} %d\n", "info", m.info)

	if m.inv == nil {
		// Inventory failed to load at boot: emit nothing rather than zeros —
		// an absent series is a visible failure (the boot log carries the
		// error), a zero is a lie.
		return
	}

	fmt.Fprintf(w, "# HELP netops_sec_declared_edges Transport-inventory edges by declared security_profile transport tier.\n")
	fmt.Fprintf(w, "# TYPE netops_sec_declared_edges gauge\n")
	for _, tc := range m.inv.DeclaredTierCensus() {
		fmt.Fprintf(w, "netops_sec_declared_edges{tier=%q} %d\n", tc.Tier, tc.Count)
	}

	exc := m.inv.Exceptions()
	if len(exc) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP netops_sec_exception_age_seconds Age of each declared plaintext exception since its last review (accepted date in the transport inventory).\n")
	fmt.Fprintf(w, "# TYPE netops_sec_exception_age_seconds gauge\n")
	now := m.now()
	for _, e := range exc {
		at, err := e.Exception.AcceptedTime()
		if err != nil {
			// LoadInventory validated this; reaching here means the edge was
			// mutated post-load, which nothing does. Skip loudly-typed rather
			// than emit a wrong age.
			continue
		}
		fmt.Fprintf(w, "netops_sec_exception_age_seconds{edge=%q} %.0f\n", e.ID, now.Sub(at).Seconds())
	}
}
