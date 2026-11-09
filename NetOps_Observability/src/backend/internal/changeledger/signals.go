// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changeledger

// signals.go — the N-D2 producers that bridge the correlation engine's durable
// signal store (netops.corr_signals) into the change ledger:
//
//	device_trap    trap.config.change   — Cisco, Juniper, Nokia notifications
//	device_syslog  syslog.config.change — Cisco, Arista, Juniper lines
//	cloud_audit    cloud_change, cloud_audit, security_policy_change
//
// NOTHING IS RE-PARSED. The parser (telemetry-catalog/events.yaml) already typed
// these and verified_tenant already adjudicated their tenant; a vendor reaches
// the ledger exactly when the catalog types its notification, so widening the
// vendor set is a catalog row and no change here. `syslog.config.change` ships
// SHADOW: it emits nothing today, so device_syslog stays a visible zero until
// the owner's promotion, and then needs no further code.
//
// THE LEDGER IS NOT EVIDENCE TO THE ENGINE. This bridge reads the signal store
// and writes only the ledger. The engine's verdict never reads it back, and the
// experience layer scores a ledger row as a support-only `change_record`, so a
// bridged change can corroborate and can never confirm.
//
// A PROVIDER-OWNED DEVICE HAS A LEDGER (owner decision 2026-11-09). A signal whose
// adjudicated tenant is "" or "global" belongs to the platform realm, and is
// stamped with the one spelling of that owner (internal/owner). Who may read those
// rows is the composition root's rule, changeLedgerTenant. "*" is a scope, not an
// owner, and is refused.
//
// controller_policy_change is REFUSED on purpose. The Versa Concerto mapping
// types it by a substring match on "policy", which also catches violations, and
// no real Concerto sample exists to build the exact allowlist from (plan N-D2c).
// A violation recorded as a change would be a fact the ledger invented.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"netops/backend/internal/dem/experience"
	"netops/backend/internal/owner"
)

// Producer names for the bridged signal lanes.
const (
	ProducerDeviceTrap   = experience.SourceSystemDeviceTrap
	ProducerDeviceSyslog = experience.SourceSystemDeviceSyslog
	ProducerCloudAudit   = experience.SourceSystemCloudAudit
)

// Signal lanes and kinds the bridge accepts — the CLOSED allowlist. Anything else
// a reader hands over is skipped, whatever its query said.
const (
	SignalSourceTrap   = "trap"
	SignalSourceSyslog = "syslog"
	SignalSourceCloud  = "cloud"

	KindDeviceConfigChange   = "device_config_change"
	KindCloudChange          = "cloud_change"
	KindCloudAudit           = "cloud_audit"
	KindSecurityPolicyChange = "security_policy_change"
)

// junosCommitRequested is the `method` the catalog gives UI_COMMIT: the commit
// was REQUESTED. UI_COMMIT_COMPLETED is the same change landing, and a commit
// that fails check never logs it. Only the completion is a change.
const junosCommitRequested = "commit"

// Bounds on one device- or provider-reported string inside a summary.
const (
	maxSignalWordBytes = 128
	maxSignalIDBytes   = 256
)

// SignalChange is one change-shaped signal, as the composition root adapts it
// from a corr_signals row. Tenant is the row's adjudicated column, never a value
// from the signal's attributes. Blank and "global" both mean the platform realm.
type SignalChange struct {
	Tenant     string
	SignalID   string
	At         time.Time // the signal's event time
	DetectedAt time.Time // when the pipeline stored it
	Source     string    // trap | syslog | cloud
	Kind       string
	Entity     string // the device or cloud resource the signal is grounded on
	EntityType string // device | cloud_resource | app | service
	Site       string

	// Device lanes, as the catalog extracted them. All optional: a device that
	// did not say who leaves User empty, and it stays empty.
	User, Origin, Destination, Line, Method string
	// Authenticated is the trap lane's answer. A v1/v2c trap is spoofable, which
	// the summary says. Nil means the lane did not report it.
	Authenticated *bool

	// Cloud lane. RequestID is the provider's own event id (CloudTrail eventID,
	// Activity Log correlation id). ChangeClass is the root's classification of
	// the provider's event name (cloud.ChangeType).
	EventName, EventSource, RequestID, Provider, App, Actor, ChangeClass string
}

// cleanWord strips control characters from a device- or provider-reported string
// and bounds it. The ledger's text reaches operators and the Iris prompt fence,
// so a reported value must not carry line structure of its own.
func cleanWord(s string, limit int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if len(s) <= limit {
		return s
	}
	return strings.ToValidUTF8(s[:limit], "")
}

// signalProducer is the allowlist: the producer a (lane, kind) pair belongs to.
func signalProducer(source, kind string) (string, bool) {
	switch source {
	case SignalSourceTrap:
		return ProducerDeviceTrap, kind == KindDeviceConfigChange
	case SignalSourceSyslog:
		return ProducerDeviceSyslog, kind == KindDeviceConfigChange
	case SignalSourceCloud:
		switch kind {
		case KindCloudChange, KindCloudAudit, KindSecurityPolicyChange:
			return ProducerCloudAudit, true
		}
	}
	return "", false
}

// SignalChangeEvent builds the change one signal represents. ErrNotAChange covers
// everything the ledger does not record; an error means the signal is unusable. The id is deterministic, so re-reading a signal cannot write a second
// row.
func SignalChangeEvent(in SignalChange, dir Directory) (experience.ChangeEvent, error) {
	producer, ok := signalProducer(in.Source, in.Kind)
	if !ok {
		return experience.ChangeEvent{}, fmt.Errorf("%w: %s/%s is not a change lane", ErrNotAChange, in.Source, in.Kind)
	}
	tenant := owner.Of(in.Tenant)
	if tenant == "*" {
		return experience.ChangeEvent{}, fmt.Errorf("%w: a wildcard is a scope, not the owner of a change", ErrNotAChange)
	}
	if in.Method == junosCommitRequested {
		return experience.ChangeEvent{}, fmt.Errorf("%w: the commit was requested, not completed", ErrNotAChange)
	}
	entity := cleanWord(in.Entity, experience.MaxIDBytes)
	signalID := cleanWord(in.SignalID, maxSignalIDBytes)
	if entity == "" || signalID == "" || in.At.IsZero() {
		return experience.ChangeEvent{}, errors.New("changeledger: a change signal needs an entity, an id and a time")
	}
	detected := in.DetectedAt.UTC()
	if detected.IsZero() {
		detected = in.At.UTC()
	}
	ev := experience.ChangeEvent{
		TenantID: tenant, SourceSystem: producer, Object: entity,
		Provenance: experience.Provenance{
			SourceObject: signalID, Producer: "correlation-signals",
			EventAt: in.At.UTC(), ObservedAt: detected,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata,
		},
	}
	var actor Actor
	if producer == ProducerCloudAudit {
		actor = NormalizeActor(dir, SourceActor{Tenant: tenant, Raw: cleanWord(in.Actor, maxSignalWordBytes)})
		fillCloudChange(&ev, in, tenant, entity, signalID)
	} else {
		// A device account is not a Correlix principal: it is kept verbatim and
		// never looked up (a device's "admin" is not the Correlix user "admin").
		actor = NormalizeActor(dir, SourceActor{Tenant: tenant, Raw: cleanWord(in.User, maxSignalWordBytes),
			TypeHint: experience.ChangeActorUser})
		fillDeviceChange(&ev, in, producer, tenant, entity, signalID)
	}
	ev.Actor, ev.ActorType, ev.ActorID, ev.ActorDisplay = actor.Source, actor.Type, actor.ID, actor.Display
	return ev, nil
}

func fillDeviceChange(ev *experience.ChangeEvent, in SignalChange, producer, tenant, entity, signalID string) {
	ev.ID = changeID(producer, tenant, signalID)
	ev.Type, ev.ObjectKind = experience.ChangeConfig, "device"
	ev.Site = in.Site
	ev.Source = experience.SourceCorrelation
	channel := "syslog"
	if producer == ProducerDeviceTrap {
		channel = "an SNMP notification"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s reported a configuration change by %s", entity, channel)
	for _, part := range []struct{ label, value string }{
		{"by", in.User}, {"from", in.Origin}, {"on", in.Line}, {"to", in.Destination},
	} {
		if v := cleanWord(part.value, maxSignalWordBytes); v != "" {
			fmt.Fprintf(&b, " %s %s", part.label, v)
		}
	}
	if in.Authenticated != nil && !*in.Authenticated {
		b.WriteString("; the notification was not authenticated (SNMP v1/v2c)")
	}
	ev.Summary = b.String()
}

func fillCloudChange(ev *experience.ChangeEvent, in SignalChange, tenant, entity, signalID string) {
	// Keyed on the provider's event id. An Activity Log correlation id spans
	// several events of one operation, so the event name and resource stay part
	// of the identity. With no provider id the signal id is the identity: it is
	// content-derived and stable across the ingester's re-emissions.
	request := cleanWord(in.RequestID, maxSignalIDBytes)
	event := cleanWord(in.EventName, maxSignalWordBytes)
	if request != "" {
		ev.ID = changeID(ProducerCloudAudit, tenant, request, event, entity)
	} else {
		ev.ID = changeID(ProducerCloudAudit, tenant, signalID)
	}
	ev.Type = cloudChangeType(in.Kind, in.ChangeClass)
	ev.ObjectKind = "cloud_resource"
	if in.EntityType == "app" || in.EntityType == "service" {
		ev.ObjectKind = "service"
	}
	ev.App = in.App
	ev.Source = experience.SourceCloud
	what := event
	if what == "" {
		what = "A cloud change"
	}
	summary := fmt.Sprintf("%s on %s", what, entity)
	if src := cleanWord(firstNonBlank(in.EventSource, in.Provider), maxSignalWordBytes); src != "" {
		summary += ", recorded by " + src
	}
	ev.Summary = summary
}

// cloudChangeType maps the provider-derived class onto the ledger's types. A
// class with no narrower ledger type stays a cloud change, never a guess.
func cloudChangeType(kind, class string) string {
	if kind == KindSecurityPolicyChange {
		return experience.ChangeSecurityPolicy
	}
	switch class {
	case "security_policy_change":
		return experience.ChangeSecurityPolicy
	case "dns_change":
		return experience.ChangeDNS
	case "route_change":
		return experience.ChangeRoute
	case "deploy":
		return experience.ChangeApplicationDeploy
	}
	return experience.ChangeCloud
}

func firstNonBlank(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// RecordSignal builds and writes one bridged change. A skip is counted and
// returns nil. The returned error is non-nil only when the signal is worth
// retrying; a permanent refusal is counted and logged and returns nil, so the
// bridge does not re-offer it every pass.
func (p *Producer) RecordSignal(ctx context.Context, in SignalChange) error {
	producer, known := signalProducer(in.Source, in.Kind)
	ev, err := SignalChangeEvent(in, p.dir)
	if errors.Is(err, ErrNotAChange) {
		if known {
			p.metrics.record(producer, OutcomeSkipped)
		}
		return nil
	}
	if err != nil {
		p.metrics.record(producer, OutcomeFailed)
		p.logWarn("a change signal could not be turned into a ledger entry", map[string]any{
			"producer": producer, "tenant": in.Tenant, "signal": in.SignalID, "error": err.Error()})
		return nil
	}
	err = p.write(ctx, producer, ev)
	if errors.Is(err, errInvalidChange) || errors.Is(err, experience.ErrChangeTooOld) {
		return nil // already counted and logged; asking again cannot change the answer
	}
	return err
}

// ── the bridge ──────────────────────────────────────────────────────────────

// SignalPage is one bounded keyset read. Rows are ordered by (At, SignalID) and
// start strictly after the cursor when AfterID is set.
type SignalPage struct {
	Since, Until time.Time
	AfterAt      time.Time
	AfterID      string
	Limit        int
}

// SignalReader reads one page of change signals, across tenants, with each row's
// tenant taken from its own column.
type SignalReader func(ctx context.Context, page SignalPage) ([]SignalChange, error)

// Bridge bounds. The lookback outlives the engine's own lateness horizon (516.5 s)
// because a signal is identified by event time and can land late; the startup
// lookback closes an API restart. Re-reading is harmless: the ids are
// deterministic and the ledger inserts ON CONFLICT DO NOTHING.
const (
	DefaultBridgeInterval  = time.Minute
	DefaultBridgeLookback  = 30 * time.Minute
	DefaultBridgeStartup   = 24 * time.Hour
	DefaultBridgePageSize  = 500
	DefaultBridgeMaxPages  = 20
	DefaultBridgeSeenLimit = 50000
	bridgeReadTimeout      = 30 * time.Second
	bridgeMaxBackoff       = 8 // multiples of the interval after repeated read failures
)

// BridgeDeps are the bridge's injected collaborators.
type BridgeDeps struct {
	Producer *Producer                               // required
	Read     SignalReader                            // required
	LogWarn  func(msg string, fields map[string]any) // required
	Now      func() time.Time
	// Zero values use the Default* bounds.
	Interval, Lookback, Startup   time.Duration
	PageSize, MaxPages, SeenLimit int
}

// BridgeMetrics counts the bridge's own passes. Per-producer write outcomes live
// in Metrics.
type BridgeMetrics struct {
	passes, readFailed, backlog, lastSuccess atomic.Int64
}

// Write emits the bridge's series. A bridge that never succeeded is a visible
// zero timestamp, so a silent reader is alertable (§10).
func (m *BridgeMetrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	fmt.Fprint(w, "# HELP netops_change_ledger_bridge_passes_total Change-ledger signal bridge passes, by outcome.\n")
	fmt.Fprint(w, "# TYPE netops_change_ledger_bridge_passes_total counter\n")
	fmt.Fprintf(w, "netops_change_ledger_bridge_passes_total{outcome=\"ok\"} %d\n", m.passes.Load())
	fmt.Fprintf(w, "netops_change_ledger_bridge_passes_total{outcome=\"read_failed\"} %d\n", m.readFailed.Load())
	fmt.Fprintf(w, "netops_change_ledger_bridge_passes_total{outcome=\"backlog\"} %d\n", m.backlog.Load())
	fmt.Fprint(w, "# HELP netops_change_ledger_bridge_last_success_timestamp_seconds When the signal bridge last finished reading.\n")
	fmt.Fprint(w, "# TYPE netops_change_ledger_bridge_last_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_change_ledger_bridge_last_success_timestamp_seconds %d\n", m.lastSuccess.Load())
}

// Bridge polls the signal store and feeds the ledger. It is single-goroutine
// (Run); only Metrics is safe to read concurrently.
type Bridge struct {
	d       BridgeDeps
	metrics *BridgeMetrics
	seen    map[string]struct{}
	order   []string // FIFO over seen; losing an entry costs one idempotent re-write
	head    int
	started bool
	resume  *SignalPage // where to continue after a pass ran out of budget
}

// NewBridge builds a Bridge, refusing an incomplete BridgeDeps.
func NewBridge(d BridgeDeps) (*Bridge, error) {
	if d.Producer == nil || d.Read == nil || d.LogWarn == nil {
		return nil, errors.New("changeledger: Producer, Read and LogWarn are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Interval <= 0 {
		d.Interval = DefaultBridgeInterval
	}
	if d.Lookback <= 0 {
		d.Lookback = DefaultBridgeLookback
	}
	if d.Startup <= 0 {
		d.Startup = DefaultBridgeStartup
	}
	if d.PageSize <= 0 {
		d.PageSize = DefaultBridgePageSize
	}
	if d.MaxPages <= 0 {
		d.MaxPages = DefaultBridgeMaxPages
	}
	if d.SeenLimit <= 0 {
		d.SeenLimit = DefaultBridgeSeenLimit
	}
	return &Bridge{d: d, metrics: &BridgeMetrics{}, seen: map[string]struct{}{}}, nil
}

// Metrics returns the bridge's counters (for /metrics).
func (b *Bridge) Metrics() *BridgeMetrics {
	if b == nil {
		return nil
	}
	return b.metrics
}

func (b *Bridge) markSeen(key string) {
	if _, dup := b.seen[key]; dup {
		return
	}
	b.seen[key] = struct{}{}
	if len(b.order) < b.d.SeenLimit {
		b.order = append(b.order, key)
		return
	}
	delete(b.seen, b.order[b.head])
	b.order[b.head] = key
	b.head = (b.head + 1) % b.d.SeenLimit
}

// signalKey is the seen-set key. The tenant is part of it: two tenants' signals
// never share a slot.
func signalKey(in SignalChange) string { return in.Tenant + "\x00" + in.SignalID }

// Pass reads every change signal in the window, within its page budget, and
// writes the new ones. A signal whose write failed is left unseen, so the next
// pass offers it again while it is in the window. It returns the read error.
func (b *Bridge) Pass(ctx context.Context) error {
	now := b.d.Now().UTC()
	lookback := b.d.Lookback
	if !b.started {
		lookback = b.d.Startup
	}
	page := SignalPage{Since: now.Add(-lookback), Until: now, Limit: b.d.PageSize}
	if b.resume != nil {
		page.Since, page.AfterAt, page.AfterID = b.resume.Since, b.resume.AfterAt, b.resume.AfterID
	}
	for i := 0; i < b.d.MaxPages; i++ {
		rctx, cancel := context.WithTimeout(ctx, bridgeReadTimeout)
		rows, err := b.d.Read(rctx, page)
		cancel()
		if err != nil {
			b.metrics.readFailed.Add(1)
			b.d.LogWarn("the change-ledger bridge could not read the signal store — device and cloud changes are not reaching the ledger",
				map[string]any{"error": err.Error()})
			return err
		}
		for _, row := range rows {
			key := signalKey(row)
			if _, dup := b.seen[key]; !dup {
				if err := b.d.Producer.RecordSignal(ctx, row); err == nil {
					b.markSeen(key)
				}
			}
			page.AfterAt, page.AfterID = row.At, row.SignalID
		}
		if len(rows) < page.Limit {
			b.started, b.resume = true, nil
			b.metrics.passes.Add(1)
			b.metrics.lastSuccess.Store(now.Unix())
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	// Out of budget with rows left: continue from here next pass, rather than
	// restarting the window and starving the newest rows behind the oldest.
	resume := page
	b.started, b.resume = true, &resume
	b.metrics.backlog.Add(1)
	b.metrics.lastSuccess.Store(now.Unix())
	b.d.LogWarn("the change-ledger bridge has more change signals than one pass reads — it will continue from here",
		map[string]any{"pages": b.d.MaxPages, "after": page.AfterAt.Format(time.RFC3339)})
	return nil
}

// Run polls until ctx is done. A failed read is retried on the next tick, and
// repeated failures back off with jitter (§9).
func (b *Bridge) Run(ctx context.Context) {
	if b == nil {
		return
	}
	failures := 0
	for {
		if err := b.Pass(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			if failures < bridgeMaxBackoff {
				failures++
			}
		} else {
			failures = 0
		}
		wait := b.d.Interval * time.Duration(1+failures)
		// #nosec G404 -- poll jitter only, not a security control.
		wait += time.Duration(rand.Int64N(int64(b.d.Interval)/10 + 1))
		if err := sleepCtx(ctx, wait); err != nil {
			return
		}
	}
}
