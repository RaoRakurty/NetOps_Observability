package configdrift

import (
	"fmt"
	"io"
	"sync"
)

// metrics.go — the drift gauge + emission counters (§10).
//
// The gauge is maintained incrementally from the evaluator's own writes rather
// than re-counted from the store at scrape time: a /metrics scrape must not turn
// into a full table scan of every tenant's devices, and the evaluator is the
// only writer, so the counts cannot drift from the rows.
//
// It is UNLABELLED by tenant. The fleet-wide "how many devices are drifted" is
// the operational question; a per-tenant breakdown on /metrics would be a
// tenant-roster disclosure (§3a) for no extra operational value.

// maxTrackedDevices bounds the gauge's book-keeping map so a very large fleet
// cannot grow it without limit (§9). Beyond the cap new devices still count
// toward their state, they just are not individually tracked for transitions —
// which is stated in the metric's HELP text rather than silently fudged.
const maxTrackedDevices = 100000

// Metrics holds the drift gauge and the emission counters.
type Metrics struct {
	mu sync.Mutex
	// byDevice remembers each device's last state so a transition decrements
	// the state it left. Keyed tenant\x00device.
	byDevice map[string]string
	states   map[string]int64

	emitted      int64
	emitFailures int64
	spooled      int64
	lost         int64
}

// NewMetrics builds the counter set.
func NewMetrics() *Metrics {
	return &Metrics{byDevice: map[string]string{}, states: map[string]int64{}}
}

// SetState records a device's current drift state, moving the gauge.
func (m *Metrics) SetState(tenant, deviceID, state string) {
	if m == nil || deviceID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenant + "\x00" + deviceID
	if prev, ok := m.byDevice[key]; ok {
		if prev == state {
			return
		}
		if m.states[prev] > 0 {
			m.states[prev]--
		}
	} else if len(m.byDevice) >= maxTrackedDevices {
		m.states[state]++
		return
	}
	m.byDevice[key] = state
	m.states[state]++
}

func (m *Metrics) bump(f func(*Metrics), n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

// AddEmitted counts ConfigDrift findings published onto the bus.
func (m *Metrics) AddEmitted(n int) { m.bump(func(x *Metrics) { x.emitted += int64(n) }, n) }

// AddEmitFailure counts batches that exhausted the producer's bounded retry.
func (m *Metrics) AddEmitFailure(n int) { m.bump(func(x *Metrics) { x.emitFailures += int64(n) }, n) }

// AddSpooled counts records preserved in the local durable spool.
func (m *Metrics) AddSpooled(n int) { m.bump(func(x *Metrics) { x.spooled += int64(n) }, n) }

// AddLost counts records with NO durable copy anywhere (the 189 contract).
func (m *Metrics) AddLost(n int) { m.bump(func(x *Metrics) { x.lost += int64(n) }, n) }

// Snapshot is a flat read of the totals (tests + a status surface).
func (m *Metrics) Snapshot() map[string]int64 {
	out := map[string]int64{}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range States {
		out["state_"+s] = m.states[s]
	}
	out["emitted_total"] = m.emitted
	out["emit_failures_total"] = m.emitFailures
	out["spooled_total"] = m.spooled
	out["lost_total"] = m.lost
	return out
}

// Write emits the module's series in Prometheus text format.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprint(w, "# HELP netops_config_backup_drift_state Devices in each configuration-sync state (fleet-wide; devices beyond the tracking cap are counted but not transitioned).\n")
	fmt.Fprint(w, "# TYPE netops_config_backup_drift_state gauge\n")
	for _, s := range States {
		fmt.Fprintf(w, "netops_config_backup_drift_state{state=%q} %d\n", s, m.states[s])
	}

	fmt.Fprint(w, "# HELP netops_config_drift_events_total ConfigDrift findings published onto the security evidence bus.\n")
	fmt.Fprint(w, "# TYPE netops_config_drift_events_total counter\n")
	fmt.Fprintf(w, "netops_config_drift_events_total %d\n", m.emitted)

	fmt.Fprint(w, "# HELP netops_config_drift_emit_failures_total ConfigDrift batches that exhausted the bounded retry.\n")
	fmt.Fprint(w, "# TYPE netops_config_drift_emit_failures_total counter\n")
	fmt.Fprintf(w, "netops_config_drift_emit_failures_total %d\n", m.emitFailures)

	fmt.Fprint(w, "# HELP netops_config_drift_spooled_total ConfigDrift records preserved in the local durable spool.\n")
	fmt.Fprint(w, "# TYPE netops_config_drift_spooled_total counter\n")
	fmt.Fprintf(w, "netops_config_drift_spooled_total %d\n", m.spooled)

	fmt.Fprint(w, "# HELP netops_config_drift_lost_total ConfigDrift records with no durable copy anywhere.\n")
	fmt.Fprint(w, "# TYPE netops_config_drift_lost_total counter\n")
	fmt.Fprintf(w, "netops_config_drift_lost_total %d\n", m.lost)
}
