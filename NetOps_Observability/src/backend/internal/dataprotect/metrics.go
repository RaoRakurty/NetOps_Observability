package dataprotect

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// metrics.go — the module's Prometheus surface (§10 every service emits
// metrics), in the internal/configstore shape: a mutex, a snapshot, and a
// Write(io.Writer) the exporter calls.
//
// The state is CACHED on purpose. The /metrics handler must never make a
// blocking OpenSearch call, so the nightly probe worker refreshes this and the
// handler only formats it.

// Metrics is the cached restorability state the exporter renders.
type Metrics struct {
	mu            sync.Mutex
	restorable    bool
	verifiedAt    time.Time
	lastSuccessAt time.Time

	// The BUNDLE restore drill (scripts/backup-drill.sh). Separate from the
	// OpenSearch probe above and deliberately so: the probe proves the search
	// tier's snapshot repository, the drill proves that a bundle ARTIFACT — the
	// Postgres dump, the ClickHouse export, the VictoriaMetrics snapshot and
	// the sealed custody envelope inside it — comes back. A platform can have
	// one and not the other, and did.
	drillPass  bool
	drillAt    time.Time
	drillLegs  map[string]string
	drillKnown bool

	// repo and probeEnabled are fixed at construction: they are configuration,
	// not observations, and re-reading them per scrape would let the label and
	// the value disagree within one response.
	repo         string
	probeEnabled bool
}

// newMetrics builds the counter set for one repository.
func newMetrics(repo string, probeEnabled bool) *Metrics {
	return &Metrics{repo: repo, probeEnabled: probeEnabled}
}

func (m *Metrics) setVerdict(restorable bool, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restorable, m.verifiedAt = restorable, at
}

// setDrill records the newest bundle drill verdict. known=false means no drill
// report is readable at all, which renders as a zero timestamp — "never", which
// is what the missed-drill rule alerts on.
func (m *Metrics) setDrill(known, pass bool, at time.Time, legs map[string]string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drillKnown, m.drillPass, m.drillAt, m.drillLegs = known, pass, at, legs
}

// DrillSnapshot returns the cached drill verdict, for tests that need to assert
// the cache moved without reaching through the mutex.
func (m *Metrics) DrillSnapshot() (known, pass bool, at time.Time) {
	if m == nil {
		return false, false, time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drillKnown, m.drillPass, m.drillAt
}

func (m *Metrics) setLastSuccess(at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSuccessAt = at
}

// Snapshot returns the cached verdict. Exported so an integration test can
// assert the cache moved without reaching into the mutex.
func (m *Metrics) Snapshot() (restorable bool, verifiedAt, lastSuccessAt time.Time) {
	if m == nil {
		return false, time.Time{}, time.Time{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restorable, m.verifiedAt, m.lastSuccessAt
}

// Write emits the restorability series. 0 means NOT PROVEN RESTORABLE — which
// includes "never probed". The vmalert rule alerts on
// netops_opensearch_snapshot_restorable == 0, so that conflation is the point:
// an unproven backup and a failed probe are the same operational state.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	restorable, verifiedAt, lastSuccessAt := m.Snapshot()
	repo := m.repo
	restorableVal := 0
	if restorable {
		restorableVal = 1
	}
	enabledVal := 0
	if m.probeEnabled {
		enabledVal = 1
	}
	fmt.Fprint(w, "# HELP netops_opensearch_snapshot_restorable Whether the newest probed snapshot was PROVEN restorable by an actual restore + doc-count comparison (0 = not proven, including never probed).\n")
	fmt.Fprint(w, "# TYPE netops_opensearch_snapshot_restorable gauge\n")
	fmt.Fprintf(w, "netops_opensearch_snapshot_restorable{repo=%q} %d\n", repo, restorableVal)

	fmt.Fprint(w, "# HELP netops_opensearch_snapshot_restorable_verified_timestamp_seconds When the restorability probe last produced a verdict (0 = never).\n")
	fmt.Fprint(w, "# TYPE netops_opensearch_snapshot_restorable_verified_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_opensearch_snapshot_restorable_verified_timestamp_seconds{repo=%q} %d\n", repo, unixOrZero(verifiedAt))

	fmt.Fprint(w, "# HELP netops_opensearch_snapshot_probe_enabled Whether the nightly restorability probe worker is enabled (SNAPSHOT_PROBE_ENABLED).\n")
	fmt.Fprint(w, "# TYPE netops_opensearch_snapshot_probe_enabled gauge\n")
	fmt.Fprintf(w, "netops_opensearch_snapshot_probe_enabled{repo=%q} %d\n", repo, enabledVal)

	fmt.Fprint(w, "# HELP netops_opensearch_snapshot_last_success_timestamp_seconds End time of the newest SUCCESS snapshot in the repository (0 = none).\n")
	fmt.Fprint(w, "# TYPE netops_opensearch_snapshot_last_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_opensearch_snapshot_last_success_timestamp_seconds{repo=%q} %d\n", repo, unixOrZero(lastSuccessAt))

	m.mu.Lock()
	drillPass, drillAt, drillKnown := m.drillPass, m.drillAt, m.drillKnown
	legs := make(map[string]string, len(m.drillLegs))
	for k, v := range m.drillLegs {
		legs[k] = v
	}
	m.mu.Unlock()

	drillVal := 0
	if drillKnown && drillPass {
		drillVal = 1
	}
	fmt.Fprint(w, "# HELP netops_backup_drill_pass Whether the newest recorded BUNDLE restore drill passed every leg it ran (0 = failed, or no drill has ever been recorded).\n")
	fmt.Fprint(w, "# TYPE netops_backup_drill_pass gauge\n")
	fmt.Fprintf(w, "netops_backup_drill_pass %d\n", drillVal)

	fmt.Fprint(w, "# HELP netops_backup_drill_last_timestamp_seconds When the newest BUNDLE restore drill ended (0 = never).\n")
	fmt.Fprint(w, "# TYPE netops_backup_drill_last_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_backup_drill_last_timestamp_seconds %d\n", unixOrZero(drillAt))

	// Per-leg, because "the drill passed" hides a drill that ran one leg. The
	// value is the leg's verdict as a number so a rule can name the store that
	// is unproven rather than the run that contained it.
	fmt.Fprint(w, "# HELP netops_backup_drill_leg Per-store verdict of the newest BUNDLE restore drill (1 = pass, 0 = fail, -1 = skipped/not run).\n")
	fmt.Fprint(w, "# TYPE netops_backup_drill_leg gauge\n")
	for _, leg := range []string{DrillLegPostgres, DrillLegClickHouse, DrillLegVictoriaMetrics, DrillLegSealedMaterial} {
		v := -1
		switch legs[leg] {
		case DrillPass:
			v = 1
		case DrillFail:
			v = 0
		}
		fmt.Fprintf(w, "netops_backup_drill_leg{leg=%q} %d\n", leg, v)
	}
}

// unixOrZero renders a zero time as 0 rather than as -6795364578 (the Unix()
// of the zero Time) — a metric that means "never" must READ as never.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
