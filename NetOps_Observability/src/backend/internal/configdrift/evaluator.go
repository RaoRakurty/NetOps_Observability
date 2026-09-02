package configdrift

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/configstore"
	"netops/backend/internal/secbus"
	"netops/backend/internal/secfindings"
)

// evaluator.go — the drift state machine and the ConfigDrift bus emission.
//
// ── THE STATE MACHINE (design §4) ───────────────────────────────────────────
//
//	                 ┌───────────────────────────────────────────┐
//	capture failed → │ unknown  (last_error set)                 │
//	never captured → │ unknown  (no row at all)                  │
//	                 └───────────────────────────────────────────┘
//	sha == previous  and (no golden OR sha == golden)   → in_sync
//	sha != golden    (a golden IS set)                  → drifted   ← outranks
//	sha != previous  (no golden, or golden matches)     → changed
//
// `drifted` OUTRANKS `changed` deliberately: a device that has walked away from
// its known-good baseline is the louder operational fact, and collapsing it into
// "changed" would let a fleet sit permanently drifted while every badge reported
// only that something moved recently.
//
// A device with no golden baseline can never be `drifted` — the design is
// explicit that golden is optional per device, and inventing a baseline from the
// first capture would silently declare whatever state the device happened to be
// in as correct.

// Record mirrors secbus.Record so the integrator adapts []configdrift.Record to
// its own transport type in one loop — the wiring layer's only import from this
// package stays this package (the seclane precedent).
type Record struct {
	Key   string
	Value any
}

// DeviceRef is the minimal inventory projection the bulk list renders.
type DeviceRef struct {
	ID       string
	Name     string
	TenantID string
}

// Gate / Principal mirror internal/configstore's: this package states WHAT
// permission a route needs, package backend maps it to the RBAC model.
type Gate int

const (
	// GateRead is per-tenant operator READ access (infrastructure:read).
	GateRead Gate = iota
)

// Principal is the caller's already-authorized scope.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// Deps are the injected collaborators (§5). Every field is REQUIRED unless its
// comment says otherwise.
type Deps struct {
	// Now is the clock (tests pin it). Required.
	Now func() time.Time
	// Store is the drift-state register. Required.
	Store StateStore
	// Publish is the bus transport — the SAME Vector bus-bridge produce path
	// every other Go producer uses. Required for emission; nil disables the bus
	// signal (the badge still works).
	Publish func(ctx context.Context, topic string, recs []Record) (int, error)
	// Spool is the local durable fallback for a batch the bounded retry could
	// not place. Optional: nil means the ladder ends at the producer's retry and
	// an exhausted batch is counted as lost, loudly (§10).
	Spool func(tenant string, recs []Record, cause error) error
	// Versions reads the caller's config versions (the ConfigSource + the badge's
	// golden/sha fields). Required.
	Versions configstore.Store
	// Open unseals one stored version. Required for the hardening ConfigSource.
	Open func(v configstore.Version) (string, error)
	// Devices lists ONE tenant's devices, for the bulk list's device_name.
	// Optional: nil renders an empty name rather than failing the list.
	Devices func(tenant string) []DeviceRef
	// Metrics is the Prometheus surface. Optional.
	Metrics *Metrics
	// Authz resolves the caller for the HTTP surface. Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)
	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn / LogError are the structured loggers (§10). Required.
	LogWarn  func(msg string, fields map[string]any)
	LogError func(msg string, fields map[string]any)
	// Scrub sanitizes an untrusted string before it reaches a log or a stored
	// error (§8 log hygiene). Required.
	Scrub func(string) string
}

func (d Deps) validate() error {
	missing := make([]string, 0, 6)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Now", d.Now != nil)
	check("Store", d.Store != nil)
	check("Versions", d.Versions != nil)
	check("Open", d.Open != nil)
	check("Authz", d.Authz != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	check("LogError", d.LogError != nil)
	check("Scrub", d.Scrub != nil)
	if len(missing) > 0 {
		return fmt.Errorf("configdrift: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Evaluator computes drift verdicts, stores them and emits the bus signal.
type Evaluator struct {
	deps     Deps
	producer *secbus.Producer
}

// New builds an Evaluator, failing CLOSED on an incomplete Deps.
func New(d Deps) (*Evaluator, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	e := &Evaluator{deps: d}
	if d.Publish != nil {
		// The retry ladder (bounded attempts, exponential backoff with FULL
		// jitter, idempotent native ids, drop-to-error) lives in internal/secbus
		// and is REUSED here — it is deliberately not re-implemented.
		p, err := secbus.NewProducer(secbus.PublisherFunc(
			func(ctx context.Context, topic string, recs []secbus.Record) (int, error) {
				out := make([]Record, 0, len(recs))
				for _, r := range recs {
					out = append(out, Record{Key: r.Key, Value: r.Value})
				}
				return d.Publish(ctx, topic, out)
			}))
		if err != nil {
			return nil, err
		}
		e.producer = p
	}
	return e, nil
}

// Metrics exposes the counter set for the /metrics writer.
func (e *Evaluator) Metrics() *Metrics {
	if e == nil {
		return nil
	}
	return e.deps.Metrics
}

// Observe is the configstore.DriftObserver: it is called after every successful
// capture with the current, previous and golden PLAINTEXT in memory. It returns
// the verdict configstore stamps onto the version row.
//
// The text handed in is used ONLY to count the diff. Nothing here persists it,
// logs it or puts it on the bus.
func (e *Evaluator) Observe(ctx context.Context, ev configstore.CaptureEvent) configstore.DriftVerdict {
	state, added, removed := e.classify(ev)

	prev, _, err := e.deps.Store.Get(ctx, ev.Tenant, false, ev.Device.ID)
	if err != nil {
		e.deps.LogWarn("previous drift state unreadable", map[string]any{
			"device": ev.Device.ID, "error": e.deps.Scrub(err.Error())})
	}
	now := e.deps.Now().UTC()
	st := State{
		TenantID: NormTenant(ev.Tenant), DeviceID: ev.Device.ID, State: state,
		LastSHA: ev.SHA, GoldenSHA: ev.GoldenSHA, Added: added, Removed: removed,
		LastCapture: ev.CapturedAt.UTC(), UpdatedAt: now,
		ChangedAt: prev.ChangedAt,
	}
	if state != StateInSync {
		st.ChangedAt = ev.CapturedAt.UTC()
	}
	if err := e.deps.Store.Put(ctx, ev.Tenant, false, st); err != nil {
		e.deps.LogError("drift state was not stored", map[string]any{
			"device": ev.Device.ID, "error": e.deps.Scrub(err.Error())})
	}
	e.deps.Metrics.SetState(NormTenant(ev.Tenant), ev.Device.ID, state)

	// The ConfigDrift signal fires ONLY on a real change: in_sync is the
	// steady state of a healthy fleet and emitting it would flood the evidence
	// lane with non-events.
	if state == StateChanged || state == StateDrifted {
		e.emit(ctx, ev, state, added, removed)
	}
	return configstore.DriftVerdict{State: state, Added: added, Removed: removed}
}

// classify runs the state machine and counts the diff summary.
func (e *Evaluator) classify(ev configstore.CaptureEvent) (state string, added, removed int) {
	switch {
	case ev.HasGolden && ev.GoldenSHA != ev.SHA:
		res := configstore.Diff(ev.Vendor, ev.Golden, ev.Current)
		return StateDrifted, res.Added, res.Removed
	case ev.HasPrevious && ev.PreviousSHA != ev.SHA:
		res := configstore.Diff(ev.Vendor, ev.Previous, ev.Current)
		return StateChanged, res.Added, res.Removed
	case ev.HasPrevious:
		// Identical to the previous capture, and either no golden is set or the
		// golden matches too.
		return StateInSync, 0, 0
	default:
		// The FIRST capture of a device. It is not "in sync" — there is nothing
		// to be in sync with, and a green badge on one data point would be the
		// false-clear this module exists to avoid. It is a change from nothing.
		res := configstore.Diff(ev.Vendor, "", ev.Current)
		return StateChanged, res.Added, res.Removed
	}
}

// OnFailure is the configstore.FailureObserver: a capture that could not be
// taken flips the badge to `unknown` with the reason. It NEVER leaves the last
// green verdict standing — an unreachable device is not a compliant one.
func (e *Evaluator) OnFailure(ctx context.Context, f configstore.CaptureFailure) {
	prev, _, err := e.deps.Store.Get(ctx, f.Tenant, false, f.Device.ID)
	if err != nil {
		e.deps.LogWarn("previous drift state unreadable", map[string]any{
			"device": f.Device.ID, "error": e.deps.Scrub(err.Error())})
	}
	st := State{
		TenantID: NormTenant(f.Tenant), DeviceID: f.Device.ID, State: StateUnknown,
		LastSHA: prev.LastSHA, GoldenSHA: prev.GoldenSHA,
		LastError: f.Reason, LastCapture: prev.LastCapture,
		ChangedAt: prev.ChangedAt, UpdatedAt: e.deps.Now().UTC(),
	}
	if err := e.deps.Store.Put(ctx, f.Tenant, false, st); err != nil {
		e.deps.LogError("drift state was not stored", map[string]any{
			"device": f.Device.ID, "error": e.deps.Scrub(err.Error())})
	}
	e.deps.Metrics.SetState(NormTenant(f.Tenant), f.Device.ID, StateUnknown)
}

// ── the ConfigDrift bus event ───────────────────────────────────────────────

// Finding builds the normalized secfindings.Finding for one drift verdict. It is
// PURE and exported so the bus-event test can assert its shape — in particular
// that NO configuration text appears anywhere in it.
func Finding(ev configstore.CaptureEvent, state string, added, removed int, at time.Time) secfindings.Finding {
	severity, status := secfindings.SeverityMedium, secfindings.StatusWarning
	observed := fmt.Sprintf("running configuration changed since the previous capture (+%d/-%d lines)", added, removed)
	intended := "running configuration unchanged since the previous capture"
	if state == StateDrifted {
		severity, status = secfindings.SeverityHigh, secfindings.StatusFail
		observed = fmt.Sprintf("running configuration differs from the golden baseline (+%d/-%d lines)", added, removed)
		intended = "running configuration matches the golden baseline"
	}
	return secfindings.Finding{
		// The id is deterministic (device + version + state), so a redelivery of
		// the same verdict dedups downstream instead of double-counting.
		ID:            "cfgdrift:" + ev.Device.ID + ":" + ev.SHA + ":" + state,
		TenantID:      NormTenant(ev.Tenant),
		Source:        SourceConfigDrift,
		ScanID:        ev.SHA,
		Time:          at.UTC(),
		EvidenceClass: secfindings.EvidencePosture,
		Status:        status.String(),
		StatusID:      status,
		ControlID:     ControlID,
		// The diff SUMMARY rides in the control title, which secbus carries into
		// the wire attrs. Counts only — never a changed line's text.
		ControlTitle: fmt.Sprintf("Device configuration drift (+%d/-%d lines)", added, removed),
		Category:     ControlCategory,
		Severity:     severity,
		Resource: secfindings.Resource{
			DeviceID:   ev.Device.ID,
			DeviceName: ev.Device.Name,
			Address:    ev.Device.Address,
			Kind:       secfindings.KindNetworkDevice,
			Platform:   ev.Device.Platform(),
		}.ResolvePlatform(), // T9: the registry-resolved profile id rides along
		Observed:    observed,
		Intended:    intended,
		Detail:      observed,
		Remediation: "review the configuration diff and either restore the baseline or promote the current version to golden",
		EvidenceRef: &secfindings.EvidenceRef{
			// BY REFERENCE (§5c): the locator names WHERE the sealed version
			// lives, so an auditor can replay the verdict; the config itself
			// never leaves the sealed store.
			Locator:        "config-version:" + ev.Device.ID + "#" + ev.SHA,
			Kind:           "config-version",
			RulesetVersion: RulesetVersion,
			Digest:         ev.SHA,
		},
		RawRuleID: "config-drift/" + state,
	}
}

// emit produces the ConfigDrift finding onto netops.security through the shared
// secbus producer, falling back to the injected durable spool when the bounded
// retry is exhausted. `lost` moves ONLY when neither the bus nor the spool
// accepted the record (the 189 persist contract).
func (e *Evaluator) emit(ctx context.Context, ev configstore.CaptureEvent, state string, added, removed int) {
	if e.producer == nil {
		return
	}
	f := Finding(ev, state, added, removed, e.deps.Now())
	n, err := e.producer.Publish(ctx, []secfindings.Finding{f})
	if err == nil {
		e.deps.Metrics.AddEmitted(n)
		return
	}
	e.deps.Metrics.AddEmitFailure(1)
	if e.deps.Spool == nil {
		e.deps.Metrics.AddLost(1)
		e.deps.LogError("config drift evidence lost — no durable copy anywhere", map[string]any{
			"device": ev.Device.ID, "error": e.deps.Scrub(err.Error())})
		return
	}
	rec, cerr := busRecord(f)
	if cerr != nil {
		e.deps.Metrics.AddLost(1)
		e.deps.LogError("config drift evidence could not be encoded for the spool", map[string]any{
			"device": ev.Device.ID, "error": e.deps.Scrub(cerr.Error())})
		return
	}
	if serr := e.deps.Spool(f.TenantID, []Record{rec}, err); serr != nil {
		e.deps.Metrics.AddLost(1)
		e.deps.LogError("config drift evidence lost — bus and spool both refused it", map[string]any{
			"device": ev.Device.ID, "error": e.deps.Scrub(serr.Error())})
		return
	}
	e.deps.Metrics.AddSpooled(1)
}

// busRecord renders a finding as the bus record the spool preserves. It goes
// through the SAME secbus.FromFinding conversion the producer uses, so a spooled
// record is byte-identical to the one that would have been published.
func busRecord(f secfindings.Finding) (Record, error) {
	evt, err := secbus.FromFinding(f)
	if err != nil {
		return Record{}, err
	}
	return Record{Key: evt.TenantID, Value: evt}, nil
}

// ErrNoConfig is the ConfigSource's "no capture on file" signal (it is reported
// as ok=false, never as an error, so the hardening engine's fail-closed
// Unknown path is the one that runs).
var ErrNoConfig = errors.New("no configuration on file for this device")
