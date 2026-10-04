// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changeledger

// producer.go — the two N-D2 producers and the one write path they share.
//
//	config_capture  a configuration backup that stored a NEW version of a device
//	                configuration — the device's configuration CHANGED between
//	                two captures. Written synchronously from the capture
//	                goroutine (already off the request path).
//	correlix_audit  an ALLOWED mutation made through this platform whose handler
//	                named the object it changed (SetTarget). Enqueued from the
//	                audit middleware onto a BOUNDED queue and written by Run, so
//	                the request path never waits on the ledger.
//
// Every change carries a DETERMINISTIC id derived from the fact it records, and
// the ledger inserts ON CONFLICT DO NOTHING, so a retried or replayed write is
// idempotent. Every outcome is counted (Metrics) and every failure is logged —
// a change the ledger did not record is never silent (§10).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/dem/experience"
)

// Producer names — the `producer` label and ChangeEvent.SourceSystem.
const (
	ProducerConfigCapture = experience.SourceSystemConfigCapture
	ProducerAudit         = experience.SourceSystemAudit
)

// ScheduledCaptureActor is the system identity a scheduled capture records.
// It names Correlix's own sweep, which is the only actor a scheduled capture
// can vouch for: WHO edited the device between two sweeps is not something a
// configuration diff can tell, and it is not guessed.
const ScheduledCaptureActor = "correlix:config-backup"

// ErrNotAChange is returned by a builder for an input that is not a change the
// ledger records (a device's FIRST capture, a denied or target-less request, a
// platform-scope action). It is a SKIP, counted as such, never a failure.
var ErrNotAChange = errors.New("changeledger: not a recordable change")

// Retry policy for one ledger write (§9: network calls retry with backoff and
// jitter). Three attempts inside one bounded budget.
const (
	writeAttempts   = 3
	writeBaseDelay  = 50 * time.Millisecond
	writeAttemptTTL = 10 * time.Second
	// DefaultQueueSize bounds the audit queue. Audit mutations are
	// operator-rate; a full queue means the ledger is down, not busy.
	DefaultQueueSize = 256
)

// Sink is the ledger write seam (experience.Store satisfies it).
type Sink interface {
	RecordChange(ctx context.Context, in experience.ChangeEvent) (experience.ChangeEvent, error)
}

// Deps are the producer's injected collaborators.
type Deps struct {
	Sink      Sink                                    // required
	Directory Directory                               // optional: nil = no actor is resolved
	LogWarn   func(msg string, fields map[string]any) // required
	Metrics   *Metrics                                // optional: nil = a private set
	QueueSize int                                     // <= 0 uses DefaultQueueSize
	// Sleep waits between retries; it returns early with ctx's error. Tests
	// replace it to keep the retry path instant. nil = a real timer.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Producer writes normalized changes into the ledger.
type Producer struct {
	sink    Sink
	dir     Directory
	logWarn func(string, map[string]any)
	metrics *Metrics
	sleep   func(context.Context, time.Duration) error
	queue   chan experience.ChangeEvent
}

// New builds a Producer, refusing an incomplete Deps.
func New(d Deps) (*Producer, error) {
	if d.Sink == nil || d.LogWarn == nil {
		return nil, errors.New("changeledger: Sink and LogWarn are required")
	}
	if d.Metrics == nil {
		d.Metrics = NewMetrics()
	}
	if d.QueueSize <= 0 {
		d.QueueSize = DefaultQueueSize
	}
	if d.Sleep == nil {
		d.Sleep = sleepCtx
	}
	return &Producer{sink: d.Sink, dir: d.Directory, logWarn: d.LogWarn, metrics: d.Metrics,
		sleep: d.Sleep, queue: make(chan experience.ChangeEvent, d.QueueSize)}, nil
}

// Metrics returns the producer's counters (for /metrics).
func (p *Producer) Metrics() *Metrics {
	if p == nil {
		return nil
	}
	return p.metrics
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryable reports whether another attempt could succeed. A refusal the store
// will repeat verbatim — a record it cannot validate, one past retention, a
// store it will not write — is not retried.
func retryable(err error) bool {
	return !errors.Is(err, experience.ErrChangeTooOld) && !errors.Is(err, experience.ErrStoreUnreadable) &&
		!errors.Is(err, context.Canceled)
}

// write validates, then records with bounded retry. It returns the final error;
// the caller has already been counted by the time it returns.
func (p *Producer) write(ctx context.Context, producer string, ev experience.ChangeEvent) error {
	probe := ev
	if err := probe.Validate(); err != nil {
		p.metrics.record(producer, OutcomeFailed)
		p.logWarn("the change ledger refused an invalid change", map[string]any{
			"producer": producer, "tenant": ev.TenantID, "object": ev.Object, "error": err.Error()})
		return err
	}
	var err error
	for attempt := 0; attempt < writeAttempts; attempt++ {
		if attempt > 0 {
			p.metrics.record(producer, OutcomeRetried)
			backoff := writeBaseDelay << (attempt - 1)
			// #nosec G404 -- retry jitter only, not a security control.
			backoff += time.Duration(rand.Int64N(int64(backoff)/2 + 1))
			if serr := p.sleep(ctx, backoff); serr != nil {
				err = errors.Join(err, serr)
				break
			}
		}
		actx, cancel := context.WithTimeout(ctx, writeAttemptTTL)
		_, err = p.sink.RecordChange(actx, ev)
		cancel()
		if err == nil {
			p.metrics.record(producer, OutcomeRecorded)
			return nil
		}
		if !retryable(err) {
			break
		}
	}
	p.metrics.record(producer, OutcomeFailed)
	p.logWarn("the change ledger did not record a change", map[string]any{
		"producer": producer, "tenant": ev.TenantID, "object": ev.Object, "change_id": ev.ID, "error": err.Error()})
	return err
}

// changeID mints the deterministic ledger id of a fact: "chg-" + 32 hex of a
// SHA-256 over the producer and the fact's identity. The same fact always maps
// to the same id, which is what makes a retried or replayed write idempotent.
func changeID(producer string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(producer))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return "chg-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// ── config_capture ──────────────────────────────────────────────────────────

// ConfigCapture is a stored NEW configuration version, as the composition root
// adapts it from configstore.NewVersionEvent. Metadata only — no configuration
// text is ever part of it.
type ConfigCapture struct {
	Tenant      string
	DeviceID    string
	DeviceName  string
	Site        string // from the device→site binding, when the device has one
	SHA         string
	PreviousSHA string
	HasPrevious bool
	CapturedAt  time.Time
	// TriggerKind is scheduled | manual; TriggerSubject is the principal id a
	// manual capture was asked for by (configstore.SplitTrigger).
	TriggerKind    string
	TriggerSubject string
	Drift          string
	Added, Removed int
}

// ConfigCaptureChange builds the CONFIG_CHANGE a new version represents. A
// device's FIRST capture is ErrNotAChange: it is a baseline, not evidence that
// anything changed, and recording it would flood "what changed" with every
// device the day backups are switched on.
//
// When the change happened is known only to lie between the previous capture
// and this one; EventAt is the capture time (the latest it can have happened)
// and the summary says the change was FOUND by the backup.
func ConfigCaptureChange(in ConfigCapture, dir Directory) (experience.ChangeEvent, error) {
	if !in.HasPrevious || in.PreviousSHA == "" {
		return experience.ChangeEvent{}, fmt.Errorf("%w: the device's first configuration capture is a baseline", ErrNotAChange)
	}
	if in.DeviceID == "" || in.SHA == "" || in.CapturedAt.IsZero() {
		return experience.ChangeEvent{}, errors.New("changeledger: a config capture needs a device, a version and a capture time")
	}
	at := in.CapturedAt.UTC()
	name := in.DeviceName
	if name == "" {
		name = in.DeviceID
	}
	var actor Actor
	automation := false
	how := "a configuration backup"
	switch in.TriggerKind {
	case "scheduled":
		actor = NormalizeActor(dir, SourceActor{Tenant: in.Tenant, Raw: ScheduledCaptureActor,
			TypeHint: experience.ChangeActorSystem})
		actor.Display = "Scheduled configuration backup"
		automation = true
		how = "a scheduled configuration backup"
	case "manual":
		actor = NormalizeActor(dir, SourceActor{Tenant: in.Tenant, Raw: in.TriggerSubject, IsPrincipalID: true})
		how = "a configuration backup an operator ran"
	default:
		actor = Actor{Type: experience.ChangeActorUnknown}
	}
	summary := fmt.Sprintf("%s configuration changed (+%d/-%d lines), found by %s", name, in.Added, in.Removed, how)
	if in.Drift == "drifted" {
		summary += "; it now differs from its golden baseline"
	}
	return experience.ChangeEvent{
		ID: changeID(ProducerConfigCapture, in.Tenant, in.DeviceID, in.PreviousSHA, in.SHA,
			at.Format(time.RFC3339Nano)),
		TenantID: in.Tenant, Type: experience.ChangeConfig,
		Actor: actor.Source, ActorType: actor.Type, ActorID: actor.ID, ActorDisplay: actor.Display,
		Automation: automation, SourceSystem: ProducerConfigCapture,
		Object: in.DeviceID, ObjectKind: "device", Site: in.Site,
		Summary: summary,
		// A change record is a POINTER to a diff, never the configuration: the
		// two content addresses are what /api/devices/{id}/config/diff takes.
		Before: "sha256:" + in.PreviousSHA, After: "sha256:" + in.SHA,
		RollbackRef: in.PreviousSHA,
		Provenance: experience.Provenance{
			Source: experience.SourceConfigDrift, SourceObject: in.SHA, Producer: "config-backup",
			EventAt: at, ObservedAt: at,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata,
		},
	}, nil
}

// RecordConfigCapture builds and writes one config_capture change. A skip
// (ErrNotAChange) is counted and returns nil; a failure is counted, logged and
// returned.
func (p *Producer) RecordConfigCapture(ctx context.Context, in ConfigCapture) error {
	ev, err := ConfigCaptureChange(in, p.dir)
	if errors.Is(err, ErrNotAChange) {
		p.metrics.record(ProducerConfigCapture, OutcomeSkipped)
		return nil
	}
	if err != nil {
		p.metrics.record(ProducerConfigCapture, OutcomeFailed)
		p.logWarn("a configuration change could not be turned into a ledger entry", map[string]any{
			"tenant": in.Tenant, "device": in.DeviceID, "error": err.Error()})
		return err
	}
	return p.write(ctx, ProducerConfigCapture, ev)
}

// ── correlix_audit ──────────────────────────────────────────────────────────

// AuditMutation is one request the audit middleware recorded.
type AuditMutation struct {
	Tenant string
	Cross  bool
	Actor  string // the principal id (JWT sub)
	Method string
	Path   string // already capability-token-masked by the middleware
	Status int
	At     time.Time
	Target Target
	Site   string // the target's site, when the root can resolve one
}

// AuditChange builds the change an allowed mutation represents. It is
// ErrNotAChange unless the request was a mutation, succeeded, was made by a
// principal scoped to ONE tenant, and named its target: a platform-scope action
// has no single tenant whose ledger it belongs in (the audit feed keeps owner
// actions out of tenant feeds for the same reason), and a request whose handler
// did not say what it changed would be a guess.
func AuditChange(in AuditMutation, dir Directory) (experience.ChangeEvent, error) {
	switch in.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "":
		return experience.ChangeEvent{}, fmt.Errorf("%w: not a mutation", ErrNotAChange)
	}
	if in.Status < 200 || in.Status >= 400 {
		return experience.ChangeEvent{}, fmt.Errorf("%w: the request did not succeed", ErrNotAChange)
	}
	tenant := strings.ToLower(strings.TrimSpace(in.Tenant))
	if in.Cross || tenant == "" || tenant == "*" || tenant == "global" {
		return experience.ChangeEvent{}, fmt.Errorf("%w: a platform-scope action belongs to no tenant's ledger", ErrNotAChange)
	}
	if in.Target.ID == "" || in.Target.Kind == "" {
		return experience.ChangeEvent{}, fmt.Errorf("%w: the handler did not name what it changed", ErrNotAChange)
	}
	at := in.At.UTC()
	if at.IsZero() {
		return experience.ChangeEvent{}, errors.New("changeledger: an audit mutation needs a time")
	}
	actor := NormalizeActor(dir, SourceActor{Tenant: tenant, Raw: in.Actor, IsPrincipalID: true})
	path := in.Path
	if len(path) > 200 {
		path = path[:200]
	}
	return experience.ChangeEvent{
		ID: changeID(ProducerAudit, tenant, in.Actor, in.Method, in.Path, in.Target.Kind, in.Target.ID,
			at.Format(time.RFC3339Nano)),
		TenantID: tenant, Type: experience.ChangeInfrastructure,
		Actor: actor.Source, ActorType: actor.Type, ActorID: actor.ID, ActorDisplay: actor.Display,
		SourceSystem: ProducerAudit,
		Object:       in.Target.ID, ObjectKind: in.Target.Kind, Site: in.Site,
		Summary: fmt.Sprintf("%s %s changed through Correlix (%s %s)",
			in.Target.Kind, in.Target.ID, in.Method, path),
		Provenance: experience.Provenance{
			Source: experience.SourceManual, Producer: "correlix-api",
			EventAt: at, ObservedAt: at,
			Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata,
		},
	}, nil
}

// EnqueueAudit hands one audited request to the bounded ledger queue WITHOUT
// blocking the request path. A request that is not a recordable change is
// counted as skipped; a full queue drops the entry, counted and logged — the
// audit trail itself still holds the request.
func (p *Producer) EnqueueAudit(in AuditMutation) {
	if p == nil {
		return
	}
	ev, err := AuditChange(in, p.dir)
	if errors.Is(err, ErrNotAChange) {
		p.metrics.record(ProducerAudit, OutcomeSkipped)
		return
	}
	if err != nil {
		p.metrics.record(ProducerAudit, OutcomeFailed)
		p.logWarn("an audited change could not be turned into a ledger entry", map[string]any{
			"tenant": in.Tenant, "error": err.Error()})
		return
	}
	select {
	case p.queue <- ev:
	default:
		n := p.metrics.record(ProducerAudit, OutcomeDropped)
		if n == 1 || n%100 == 0 {
			p.logWarn("the change-ledger queue is full — an audited change was not recorded (the audit trail still holds it)",
				map[string]any{"dropped_total": n})
		}
	}
}

// Run drains the audit queue until ctx is done. Each write is bounded and
// retried by write(); a failure is counted and logged there.
func (p *Producer) Run(ctx context.Context) {
	if p == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-p.queue:
			// The error is already counted and logged inside write (§10); the
			// queue moves on so one bad row cannot stall the rest.
			if err := p.write(ctx, ProducerAudit, ev); err != nil && ctx.Err() != nil {
				return
			}
		}
	}
}
