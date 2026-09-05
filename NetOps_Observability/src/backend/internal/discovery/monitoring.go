package discovery

// monitoring.go — WHICH devices Correlix collects from, and the one place that
// decides it.
//
// The device registry owns this because the registry owns the device: the
// monitoring decision is an attribute of the device row, it must be evaluated
// under the SAME lock as every other mutation of that row, and every consumer
// (the collector pool, the licence usage counter, the API) must read one
// answer. Two consumers deriving "is this monitored" independently is how a
// count and a behaviour drift apart.
//
// LOCKING. Everything here runs under a.mu, the aggregator's single lock, and
// that is what makes the entitlement check atomic: the capacity question and
// the write that answers it happen in one hold, so two concurrent activations
// at 24 of 25 cannot both succeed. The MonitorStore is a LEAF — it persists and
// never calls back into the aggregator — so the lock order is always
// a.mu → store, and there is no cycle to deadlock on.
//
// The POLICY (what "monitored" means, and the default for a device with no
// explicit decision) lives in internal/devmon and not here, so the collector
// pool and the licence counter can share it without importing the registry.

import (
	"log"
	"strings"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/models"
)

// MonitorStore persists monitoring decisions. It is OPTIONAL: with no store
// attached the decisions live only in memory, which is what tests and any build
// without the wiring get, and the registry behaves exactly as it did before.
//
// Implementations MUST be safe for concurrent use and MUST NOT call back into
// the aggregator (see the locking note above).
type MonitorStore interface {
	// MonitorRecords returns every stored decision. Called once, at wiring
	// time, to seed the registry — the same shape DeviceStore.Devices has.
	MonitorRecords() []devmon.Record
	// PutMonitor stores one decision durably.
	PutMonitor(devmon.Record) error
	// DeleteMonitor removes a device's decision (used when the device itself is
	// deleted, so a re-created device does not inherit a stale answer).
	DeleteMonitor(tenant, deviceID string) error
}

// ErrUnknownDevice is returned by SetMonitoring for an id the registry does not
// hold. The caller maps it to 404 — never to a create. It is devmon's sentinel,
// not a second one: two sentinels for the same fact do not compare equal under
// errors.Is, and the caller matching on the wrong one is a 500 where a 404
// belongs.
var ErrUnknownDevice = devmon.ErrUnknownDevice

// SetMonitorStore attaches persistence and seeds the in-memory decisions from
// it. Called once at startup, before Start(), like SetStore.
func (a *DiscoveryAggregator) SetMonitorStore(st MonitorStore) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.monitorStore = st
	if st == nil {
		return
	}
	if a.monitor == nil {
		a.monitor = map[string]devmon.Record{}
	}
	for _, rec := range st.MonitorRecords() {
		if strings.TrimSpace(rec.DeviceID) == "" {
			continue
		}
		a.monitor[rec.DeviceID] = rec
	}
}

// SetMonitorGate injects the MONITORED-DEVICE ceiling. `gate(current)` is asked
// before a device that is not monitored becomes monitored, with the number of
// monitored devices there are now; a non-nil error refuses the transition.
//
// nil (the default, and what every test gets) means no ceiling, so this package
// keeps knowing nothing about licensing: it asks a question and honours the
// answer.
func (a *DiscoveryAggregator) SetMonitorGate(gate func(current int) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.monitorGate = gate
}

// monState is one device's evaluated monitoring state.
type monState struct {
	on     bool
	reason string
}

// monitorViewLocked evaluates monitoring for the whole registry in one pass.
//
// It works on the DEDUPED projection, because the deduped record is the device:
// two rows that share an identity token (a NetBox entry and the SNMP scan that
// found the same box) are one physical device and must consume one entitlement,
// never two. Within a group an EXPLICIT decision beats a default, and among
// explicit decisions "on" wins — the conservative direction, because a device
// we are collecting from must be counted.
//
// It returns the deduped devices, their state keyed by canonical id, and the
// raw-id → canonical-id map, so a caller that needs all three pays for ONE
// dedupe pass instead of three.
//
// Caller holds a.mu.
func (a *DiscoveryAggregator) monitorViewLocked() ([]models.Device, map[string]monState, map[string]string) {
	devices, owners := dedupeWithOwners(a.cache)
	type agg struct {
		explicit       bool
		explicitOn     bool
		explicitReason string
		defaultOn      bool
		defaultReason  string
		withheld       string
	}
	groups := make(map[string]*agg, len(devices))
	for rawID, ownerID := range owners {
		d, ok := a.cache[rawID]
		if !ok {
			continue
		}
		g := groups[ownerID]
		if g == nil {
			g = &agg{}
			groups[ownerID] = g
		}
		if r, has := a.monitor[rawID]; has {
			on, why := devmon.Explicit(d, r.Enabled)
			if !g.explicit || (on && !g.explicitOn) {
				g.explicitReason = why
			}
			g.explicit = true
			g.explicitOn = g.explicitOn || on
		} else {
			on, why := devmon.Default(d)
			switch {
			case on && !g.defaultOn:
				g.defaultReason = why
				g.defaultOn = true
			case !on && g.defaultReason == "":
				g.defaultReason = why
			}
		}
		if why := a.withheld[rawID]; why != "" {
			g.withheld = why
		}
	}
	state := make(map[string]monState, len(devices))
	for _, d := range devices {
		g := groups[d.ID]
		if g == nil {
			state[d.ID] = monState{on: false, reason: devmon.ReasonNoAddress}
			continue
		}
		on, reason := g.defaultOn, g.defaultReason
		if g.explicit {
			on, reason = g.explicitOn, g.explicitReason
		}
		if on && g.withheld != "" {
			on, reason = false, g.withheld
		}
		state[d.ID] = monState{on: on, reason: reason}
	}
	return devices, state, owners
}

// monitoredCountLocked is the authoritative usage number: how many DISTINCT
// devices Correlix is collecting from right now. Caller holds a.mu.
func (a *DiscoveryAggregator) monitoredCountLocked() int {
	_, state, _ := a.monitorViewLocked()
	n := 0
	for _, st := range state {
		if st.on {
			n++
		}
	}
	return n
}

// MonitoredCount is the platform-wide count of monitored devices — the number
// the licence ceiling is measured against.
func (a *DiscoveryAggregator) MonitoredCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.monitoredCountLocked()
}

// stampLocked fills the monitoring fields on a copy of d from the evaluated
// state. Caller holds a.mu.
func stampMonitoring(d models.Device, st monState) models.Device {
	d.Monitored = st.on
	d.MonitorReason = st.reason
	if st.on {
		d.MonitorMethods = devmon.Methods(d)
	} else {
		d.MonitorMethods = nil
	}
	return d
}

// SetMonitoring turns monitoring on or off for one device and reports the
// device as it now stands.
//
// This is THE transition point. The ceiling is asked exactly when a device that
// is not monitored is about to become monitored — never when it is already
// monitored (adding a second telemetry method to a counted device is free) and
// never when monitoring is being turned OFF, which can only free capacity.
// The check and the write share one hold of a.mu, so concurrent activations at
// the ceiling serialise instead of both seeing a free slot.
//
// `by` is the principal making the decision, recorded on the stored record.
func (a *DiscoveryAggregator) SetMonitoring(id string, enabled bool, by string) (models.Device, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, ok := a.cache[id]
	if !ok {
		return models.Device{}, ErrUnknownDevice
	}
	// The decision is recorded against the id the caller named; the STATE that
	// matters is the canonical device's, since that is what is counted.
	_, state, owners := a.monitorViewLocked()
	ownerID := owners[id]
	if ownerID == "" {
		ownerID = id
	}
	already := state[ownerID].on
	if enabled && !already {
		if err := a.gateMonitoringLocked(state); err != nil {
			return models.Device{}, err
		}
	}
	rec := devmon.Record{
		TenantID:  deviceTenantKey(raw),
		DeviceID:  id,
		Enabled:   enabled,
		UpdatedBy: by,
		UpdatedAt: time.Now().UTC(),
	}
	if a.monitorStore != nil {
		if err := a.monitorStore.PutMonitor(rec); err != nil {
			// Never claim a decision that did not persist: it would come back
			// undone on the next restart with nobody told.
			return models.Device{}, err
		}
	}
	if a.monitor == nil {
		a.monitor = map[string]devmon.Record{}
	}
	a.monitor[id] = rec
	// An operator decision clears any ceiling withholding for the device: the
	// decision they just made is the one in force.
	delete(a.withheld, id)
	if ownerID != id {
		delete(a.withheld, ownerID)
	}
	after, afterState, _ := a.monitorViewLocked()
	for _, d := range after {
		if d.ID == ownerID {
			return stampMonitoring(d, afterState[d.ID]), nil
		}
	}
	return stampMonitoring(raw, afterState[ownerID]), nil
}

// gateMonitoringLocked asks the injected ceiling whether one more monitored
// device is allowed. Caller holds a.mu.
func (a *DiscoveryAggregator) gateMonitoringLocked(state map[string]monState) error {
	if a.monitorGate == nil {
		return nil
	}
	n := 0
	for _, st := range state {
		if st.on {
			n++
		}
	}
	return a.monitorGate(n)
}

// MonitoringDecision reports the stored decision for a device id, if any.
func (a *DiscoveryAggregator) MonitoringDecision(id string) (devmon.Record, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r, ok := a.monitor[id]
	return r, ok
}

// WithheldMonitoring is one device Correlix WOULD collect from but does not,
// because the licence ceiling is full.
type WithheldMonitoring struct {
	DeviceID string `json:"device_id"`
	TenantID string `json:"tenant_id,omitempty"`
	Name     string `json:"name,omitempty"`
	Reason   string `json:"reason"`
}

// MonitoringWithheld lists them. This is the honest half of the ceiling: these
// devices are in the inventory, nothing about them was deleted or hidden, and
// the operator is told exactly which ones are not being collected from and why.
func (a *DiscoveryAggregator) MonitoringWithheld() []WithheldMonitoring {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]WithheldMonitoring, 0, len(a.withheld))
	for id, reason := range a.withheld {
		w := WithheldMonitoring{DeviceID: id, Reason: reason}
		if d, ok := a.cache[id]; ok {
			w.TenantID = deviceTenantKey(d)
			w.Name = d.Name
		}
		out = append(out, w)
	}
	return out
}

// MonitoringWithheldCount is MonitoringWithheld's size without the copy.
func (a *DiscoveryAggregator) MonitoringWithheldCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.withheld)
}

// admitMonitoringLocked decides, for a device arriving from a SOURCE, whether
// its default-on monitoring may start.
//
// Discovery is NEVER blocked: the device enters the inventory either way. What
// the ceiling can withhold is the COLLECTION, and when it does the device is
// recorded in a.withheld so it is listed rather than quietly inert. A device
// already withheld is re-asked on every poll, so raising the ceiling starts
// collecting from it without the operator touching anything.
//
// `count` is the running monitored count for this poll; the caller increments
// it when this function admits. Caller holds a.mu.
func (a *DiscoveryAggregator) admitMonitoringLocked(d models.Device, count int) (admitted bool) {
	if a.monitorGate == nil {
		return true
	}
	if _, decided := a.monitor[d.ID]; decided {
		// An explicit decision was already gated when it was made.
		return true
	}
	if on, _ := devmon.Default(d); !on {
		return true // nothing to admit: it is not monitored anyway
	}
	if err := a.monitorGate(count); err != nil {
		if a.withheld == nil {
			a.withheld = map[string]string{}
		}
		reason := "monitoring is not enabled for this device: the licence ceiling is full (" + err.Error() +
			") — the device was found, nothing was deleted or hidden, and it is listed on the Licence page"
		if _, told := a.withheld[d.ID]; !told {
			// Once per device, not once per poll: this loop runs every interval
			// and a per-poll line would bury the log.
			log.Printf("discovery: %s not monitored: licence ceiling (%v) — the device IS in the inventory and nothing was deleted or hidden; it is listed on the Licence page", d.ID, err)
		}
		a.withheld[d.ID] = reason
		return false
	}
	delete(a.withheld, d.ID)
	return true
}
