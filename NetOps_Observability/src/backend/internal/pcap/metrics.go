package pcap

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// metrics.go — the module's Prometheus surface (§10). Deliberately UNLABELLED by
// tenant: the questions these answer — "is capture working, how much are we
// storing, is anything running right now" — need no tenant breakdown, and an
// unlabelled series cannot leak a tenant roster (§3a) or blow up cardinality
// with the fleet.

// Capture outcomes — the CLOSED `outcome` label vocabulary.
const (
	// OutcomeStored is a capture that completed and is sealed at rest.
	OutcomeStored = "stored"
	// OutcomeFailed is a capture that could not be taken, fetched or stored.
	OutcomeFailed = "failed"
	// OutcomeRefused is a request refused by a guardrail before the device was
	// touched (a bound breach, an unsupported filter, an unknown platform).
	OutcomeRefused = "refused"
	// OutcomeInFlight is a request refused because one was already running for
	// the device (the 409 condition).
	OutcomeInFlight = "in_flight"
)

// outcomes is the closed vocabulary, in a stable render order.
var outcomes = []string{OutcomeStored, OutcomeFailed, OutcomeRefused, OutcomeInFlight}

// Metrics counts capture runs, sealed bytes, downloads and the live gauge.
type Metrics struct {
	mu          sync.Mutex
	runs        map[string]int64
	bytesSealed int64
	downloads   int64
	pruned      int64
	active      int64
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics { return &Metrics{runs: map[string]int64{}} }

// RecordRun counts one capture attempt by outcome.
func (m *Metrics) RecordRun(outcome string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[outcome]++
}

// RecordSealed counts the sealed bytes one stored capture cost.
func (m *Metrics) RecordSealed(sealedBytes int64) {
	if m == nil || sealedBytes <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesSealed += sealedBytes
}

// RecordDownload counts one unsealed reveal.
func (m *Metrics) RecordDownload() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downloads++
}

// RecordPruned counts captures retention removed.
func (m *Metrics) RecordPruned(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruned += int64(n)
}

// SetActive moves the live-capture gauge. delta is +1 on start, -1 on finish;
// the gauge floors at zero so a double-decrement cannot render a negative.
func (m *Metrics) SetActive(delta int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active += int64(delta)
	if m.active < 0 {
		m.active = 0
	}
}

// Snapshot is a flat read of the totals (tests + the status surface).
func (m *Metrics) Snapshot() map[string]int64 {
	out := map[string]int64{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range outcomes {
		out["runs_"+o] = m.runs[o]
	}
	out["bytes_sealed_total"] = m.bytesSealed
	out["downloads_total"] = m.downloads
	out["pruned_total"] = m.pruned
	out["active"] = m.active
	return out
}

// Write emits the module's series in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprint(w, "# HELP netops_pcap_captures_total Packet-capture attempts, by outcome.\n")
	fmt.Fprint(w, "# TYPE netops_pcap_captures_total counter\n")
	seen := map[string]bool{}
	for _, o := range outcomes {
		seen[o] = true
		fmt.Fprintf(w, "netops_pcap_captures_total{outcome=%q} %d\n", o, m.runs[o])
	}
	// Defensive: an outcome outside the closed vocabulary would otherwise vanish
	// silently. Render it (sorted) rather than dropping the count.
	extra := make([]string, 0, 2)
	for o := range m.runs {
		if !seen[o] {
			extra = append(extra, o)
		}
	}
	sort.Strings(extra)
	for _, o := range extra {
		fmt.Fprintf(w, "netops_pcap_captures_total{outcome=%q} %d\n", o, m.runs[o])
	}

	fmt.Fprint(w, "# HELP netops_pcap_bytes_sealed_total Sealed packet-capture bytes written to the capture store.\n")
	fmt.Fprint(w, "# TYPE netops_pcap_bytes_sealed_total counter\n")
	fmt.Fprintf(w, "netops_pcap_bytes_sealed_total %d\n", m.bytesSealed)

	fmt.Fprint(w, "# HELP netops_pcap_downloads_total Sealed captures unsealed and streamed to an operator.\n")
	fmt.Fprint(w, "# TYPE netops_pcap_downloads_total counter\n")
	fmt.Fprintf(w, "netops_pcap_downloads_total %d\n", m.downloads)

	fmt.Fprint(w, "# HELP netops_pcap_pruned_total Captures removed by per-device retention.\n")
	fmt.Fprint(w, "# TYPE netops_pcap_pruned_total counter\n")
	fmt.Fprintf(w, "netops_pcap_pruned_total %d\n", m.pruned)

	fmt.Fprint(w, "# HELP netops_pcap_active Packet captures currently running on devices.\n")
	fmt.Fprint(w, "# TYPE netops_pcap_active gauge\n")
	fmt.Fprintf(w, "netops_pcap_active %d\n", m.active)
}
