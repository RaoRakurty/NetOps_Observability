package configstore

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// metrics.go — the module's Prometheus surface (§10 every service emits
// metrics). Deliberately UNLABELLED by tenant: unlike the security lane (whose
// per-tenant series are admissible because /metrics is platform-owner-only), the
// question this module's metrics answer — "is capture working, how much are we
// storing" — needs no tenant breakdown, and an unlabelled series cannot leak a
// tenant roster (§3a) or blow up cardinality with the fleet.

// Capture outcomes — the CLOSED `outcome` label vocabulary.
const (
	// OutcomeNew is a capture that produced a NEW content-addressed version.
	OutcomeNew = "new"
	// OutcomeUnchanged is a successful capture whose sha already existed: the
	// storage-flat case (the design's "unchanged capture stores no new version").
	OutcomeUnchanged = "unchanged"
	// OutcomeFailed is a capture that could not be taken or stored.
	OutcomeFailed = "failed"
	// OutcomeSkipped is a capture refused because one was already in flight for
	// the device (the 429 condition).
	OutcomeSkipped = "skipped"
)

// outcomes is the closed vocabulary, in a stable render order.
var outcomes = []string{OutcomeNew, OutcomeUnchanged, OutcomeFailed, OutcomeSkipped}

// Metrics counts capture runs, stored versions and sealed bytes.
type Metrics struct {
	mu          sync.Mutex
	runs        map[string]int64
	versions    int64
	bytesSealed int64
	pruned      int64
	redactions  int64
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics {
	return &Metrics{runs: map[string]int64{}}
}

// RecordRun counts one capture attempt by outcome.
func (m *Metrics) RecordRun(outcome string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runs[outcome]++
}

// RecordVersion counts one NEW stored version and the sealed bytes it cost.
func (m *Metrics) RecordVersion(sealedBytes int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.versions++
	if sealedBytes > 0 {
		m.bytesSealed += sealedBytes
	}
}

// RecordPruned counts versions retention removed.
func (m *Metrics) RecordPruned(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruned += int64(n)
}

// RecordRedaction counts one redacted response body (a `sensitive` read).
func (m *Metrics) RecordRedaction() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.redactions++
}

// Snapshot is a flat read of the totals (status endpoint + tests).
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
	out["versions_total"] = m.versions
	out["bytes_sealed_total"] = m.bytesSealed
	out["pruned_total"] = m.pruned
	out["redacted_reads_total"] = m.redactions
	return out
}

// Write emits the module's series in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprint(w, "# HELP netops_config_backup_runs_total Device configuration capture attempts, by outcome.\n")
	fmt.Fprint(w, "# TYPE netops_config_backup_runs_total counter\n")
	seen := map[string]bool{}
	for _, o := range outcomes {
		seen[o] = true
		fmt.Fprintf(w, "netops_config_backup_runs_total{outcome=%q} %d\n", o, m.runs[o])
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
		fmt.Fprintf(w, "netops_config_backup_runs_total{outcome=%q} %d\n", o, m.runs[o])
	}

	fmt.Fprint(w, "# HELP netops_config_backup_versions_total New content-addressed configuration versions stored.\n")
	fmt.Fprint(w, "# TYPE netops_config_backup_versions_total counter\n")
	fmt.Fprintf(w, "netops_config_backup_versions_total %d\n", m.versions)

	fmt.Fprint(w, "# HELP netops_config_backup_bytes_sealed_total Sealed configuration bytes written to the blob store.\n")
	fmt.Fprint(w, "# TYPE netops_config_backup_bytes_sealed_total counter\n")
	fmt.Fprintf(w, "netops_config_backup_bytes_sealed_total %d\n", m.bytesSealed)

	fmt.Fprint(w, "# HELP netops_config_backup_pruned_total Configuration versions removed by per-device retention.\n")
	fmt.Fprint(w, "# TYPE netops_config_backup_pruned_total counter\n")
	fmt.Fprintf(w, "netops_config_backup_pruned_total %d\n", m.pruned)
}
