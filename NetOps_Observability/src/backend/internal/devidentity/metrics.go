// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devidentity

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// netops_tenant_registry_controller_rows{tier,outcome} is a GAUGE over the last
// registry export: how many controller-derived claims were written, and how many
// were withheld because a direct device stands, because the identity is shared,
// or because it is malformed. No tenant or device label — platform plumbing.
//
// netops_tenant_registry_held_total{reason} counts export ticks that left the
// previous registry file as it stands: an inventory source not complete yet
// (snmp, controller) or the interface map unread while platform controller
// devices exist.

// Hold reasons.
const (
	HoldSNMPNotReady       = "snmp_not_ready"
	HoldControllerNotReady = "controller_not_ready"
	HoldInterfacesUnread   = "interfaces_unread"
)

func metricPairs() []StatKey {
	var pairs []StatKey
	for _, t := range []string{TierID, TierPlatform} {
		for _, o := range []string{OutcomeWritten, OutcomeDirectStands, OutcomeShared, OutcomeInvalid} {
			pairs = append(pairs, StatKey{t, o})
		}
	}
	return pairs
}

// Metrics is the exposition state. Safe for concurrent use; a nil *Metrics is a
// no-op so a partially wired server never panics.
type Metrics struct {
	mu   sync.Mutex
	rows map[StatKey]int

	heldSNMP       atomic.Uint64
	heldController atomic.Uint64
	heldInterfaces atomic.Uint64
}

// NewMetrics returns zeroed metrics.
func NewMetrics() *Metrics { return &Metrics{rows: map[StatKey]int{}} }

// Set replaces the gauge with one export's stats.
func (m *Metrics) Set(stats map[StatKey]int) {
	if m == nil {
		return
	}
	next := make(map[StatKey]int, len(stats))
	for k, v := range stats {
		next[k] = v
	}
	m.mu.Lock()
	m.rows = next
	m.mu.Unlock()
}

// Held counts one export tick that kept the previous file, by reason.
func (m *Metrics) Held(reason string) {
	if m == nil {
		return
	}
	switch reason {
	case HoldSNMPNotReady:
		m.heldSNMP.Add(1)
	case HoldControllerNotReady:
		m.heldController.Add(1)
	case HoldInterfacesUnread:
		m.heldInterfaces.Add(1)
	}
}

// Rows returns one gauge value (tests).
func (m *Metrics) Rows(tier, outcome string) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[StatKey{tier, outcome}]
}

// WriteMetrics renders the series (Prometheus exposition).
func (m *Metrics) WriteMetrics(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	rows := make(map[StatKey]int, len(m.rows))
	for k, v := range m.rows {
		rows[k] = v
	}
	m.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_tenant_registry_controller_rows Controller-derived device-registry claims of the last export, by tier and outcome (tracker 371).\n")
	fmt.Fprintf(w, "# TYPE netops_tenant_registry_controller_rows gauge\n")
	for _, p := range metricPairs() {
		fmt.Fprintf(w, "netops_tenant_registry_controller_rows{tier=%q,outcome=%q} %d\n", p.Tier, p.Outcome, rows[p])
	}
	fmt.Fprintf(w, "# HELP netops_tenant_registry_held_total Registry export ticks that left the previous file as it stands, by reason.\n")
	fmt.Fprintf(w, "# TYPE netops_tenant_registry_held_total counter\n")
	fmt.Fprintf(w, "netops_tenant_registry_held_total{reason=%q} %d\n", HoldSNMPNotReady, m.heldSNMP.Load())
	fmt.Fprintf(w, "netops_tenant_registry_held_total{reason=%q} %d\n", HoldControllerNotReady, m.heldController.Load())
	fmt.Fprintf(w, "netops_tenant_registry_held_total{reason=%q} %d\n", HoldInterfacesUnread, m.heldInterfaces.Load())
}
