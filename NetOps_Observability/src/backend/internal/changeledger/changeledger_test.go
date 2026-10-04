// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package changeledger

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
)

// ── N-D4: actor normalization ───────────────────────────────────────────────

type mapDirectory map[string]Person

func (d mapDirectory) PrincipalByID(id string) (Person, bool) { p, ok := d[id]; return p, ok }

func TestNormalizeActorNeverGuesses(t *testing.T) {
	dir := mapDirectory{
		"u_1":   {ID: "u_1", Display: "Jane Doe", TenantID: "acme"},
		"admin": {ID: "admin", Display: "Platform Admin", TenantID: "global"},
		"u_2":   {ID: "u_2", Display: "Other Tenant", TenantID: "globex"},
	}
	for _, tc := range []struct {
		name string
		in   SourceActor
		want Actor
	}{
		{"a known principal of this tenant resolves to its canonical identity",
			SourceActor{Tenant: "acme", Raw: "u_1", IsPrincipalID: true},
			Actor{Source: "u_1", Type: "user", ID: "u_1", Display: "Jane Doe", Canonical: true}},
		{"tenant comparison is case-insensitive",
			SourceActor{Tenant: "ACME", Raw: "u_1", IsPrincipalID: true},
			Actor{Source: "u_1", Type: "user", ID: "u_1", Display: "Jane Doe", Canonical: true}},
		{"a principal of ANOTHER tenant is withheld, never named",
			SourceActor{Tenant: "acme", Raw: "u_2", IsPrincipalID: true},
			Actor{Type: "user"}},
		{"the platform operator is withheld from a tenant's ledger",
			SourceActor{Tenant: "acme", Raw: "admin", IsPrincipalID: true},
			Actor{Type: "user"}},
		{"an unknown principal id is kept verbatim as a user",
			SourceActor{Tenant: "acme", Raw: "u_gone", IsPrincipalID: true},
			Actor{Source: "u_gone", Type: "user", ID: "u_gone"}},
		{"a device-side name that happens to equal a principal id is NOT looked up",
			SourceActor{Tenant: "acme", Raw: "u_1", TypeHint: ""},
			Actor{Source: "u_1", Type: "unknown", ID: "u_1"}},
		{"a source's vouched type is kept for an unresolved actor",
			SourceActor{Tenant: "acme", Raw: "ci-pipeline", TypeHint: "Service"},
			Actor{Source: "ci-pipeline", Type: "service", ID: "ci-pipeline"}},
		{"an invalid type hint degrades to unknown",
			SourceActor{Tenant: "acme", Raw: "bob", TypeHint: "wizard"},
			Actor{Source: "bob", Type: "unknown", ID: "bob"}},
		{"no actor is no actor",
			SourceActor{Tenant: "acme", Raw: "  ", IsPrincipalID: true},
			Actor{Type: "unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeActor(dir, tc.in); got != tc.want {
				t.Fatalf("NormalizeActor(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
	// No directory: nothing is resolved, the source identity stands.
	if got := NormalizeActor(nil, SourceActor{Tenant: "acme", Raw: "u_1", IsPrincipalID: true}); got.Canonical || got.ID != "u_1" {
		t.Fatalf("with no directory = %+v", got)
	}
}

// ── config_capture ──────────────────────────────────────────────────────────

// captureAt is one fixed, recent instant: recent because the sink applies real
// retention, fixed because the id is a function of it.
var captureAt = time.Now().UTC().Add(-time.Minute).Truncate(time.Second)

func capture(kind, subject string) ConfigCapture {
	return ConfigCapture{
		Tenant: "acme", DeviceID: "dev-1", DeviceName: "edge-1", Site: "dfw",
		SHA: strings.Repeat("b", 64), PreviousSHA: strings.Repeat("a", 64), HasPrevious: true,
		CapturedAt: captureAt, TriggerKind: kind, TriggerSubject: subject,
		Drift: "changed", Added: 3, Removed: 1,
	}
}

func TestConfigCaptureChangeShape(t *testing.T) {
	dir := mapDirectory{"u_1": {ID: "u_1", Display: "Jane Doe", TenantID: "acme"}}
	ev, err := ConfigCaptureChange(capture("scheduled", ""), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("the built change does not validate: %v", err)
	}
	if ev.Type != experience.ChangeConfig || ev.SourceSystem != ProducerConfigCapture ||
		ev.Object != "dev-1" || ev.ObjectKind != "device" || ev.Site != "dfw" {
		t.Fatalf("shape: %+v", ev)
	}
	if ev.ActorType != experience.ChangeActorSystem || !ev.Automation || ev.Actor != ScheduledCaptureActor {
		t.Fatalf("a scheduled capture's actor: type=%q automation=%v actor=%q", ev.ActorType, ev.Automation, ev.Actor)
	}
	if !experience.ValidChangeID(ev.ID) {
		t.Fatalf("id %q is not a ledger id", ev.ID)
	}
	if !strings.Contains(ev.After, strings.Repeat("b", 64)) || !strings.Contains(ev.Before, strings.Repeat("a", 64)) {
		t.Fatalf("the change does not point at its two versions: %q → %q", ev.Before, ev.After)
	}

	manual, err := ConfigCaptureChange(capture("manual", "u_1"), dir)
	if err != nil {
		t.Fatal(err)
	}
	if manual.ActorID != "u_1" || manual.ActorDisplay != "Jane Doe" || manual.ActorType != "user" || manual.Automation {
		t.Fatalf("a manual capture's actor: %+v", manual)
	}
}

func TestConfigCaptureIDIsDeterministicPerFact(t *testing.T) {
	a, _ := ConfigCaptureChange(capture("scheduled", ""), nil)
	b, _ := ConfigCaptureChange(capture("scheduled", ""), nil)
	if a.ID != b.ID {
		t.Fatal("the same capture minted two ids — a retried write would duplicate the change")
	}
	// A→B→A→B: the second A→B flip is a different fact and must not collide
	// with the first, which it would if the id were only (device, prev, sha).
	later := capture("scheduled", "")
	later.CapturedAt = later.CapturedAt.Add(2 * time.Hour)
	c, _ := ConfigCaptureChange(later, nil)
	if c.ID == a.ID {
		t.Fatal("a later identical flip collided with the earlier one and would be dropped as a duplicate")
	}
	other := capture("scheduled", "")
	other.Tenant = "globex"
	d, _ := ConfigCaptureChange(other, nil)
	if d.ID == a.ID {
		t.Fatal("two tenants' captures minted one id")
	}
}

func TestAFirstCaptureIsABaselineNotAChange(t *testing.T) {
	first := capture("scheduled", "")
	first.HasPrevious, first.PreviousSHA = false, ""
	if _, err := ConfigCaptureChange(first, nil); !errors.Is(err, ErrNotAChange) {
		t.Fatalf("a first capture was a change: %v", err)
	}
	sink := &memSink{}
	p := newTestProducer(t, sink)
	if err := p.RecordConfigCapture(context.Background(), first); err != nil {
		t.Fatalf("a skip returned an error: %v", err)
	}
	if len(sink.rows()) != 0 || p.Metrics().Count(ProducerConfigCapture, OutcomeSkipped) != 1 {
		t.Fatalf("first capture: %d rows written, skipped=%d", len(sink.rows()), p.Metrics().Count(ProducerConfigCapture, OutcomeSkipped))
	}
}

// ── the write path ──────────────────────────────────────────────────────────

type memSink struct {
	mu    sync.Mutex
	store *experience.FileStore
	fail  []error // returned, in order, before the store is reached
	calls int
}

func (m *memSink) RecordChange(ctx context.Context, in experience.ChangeEvent) (experience.ChangeEvent, error) {
	m.mu.Lock()
	m.calls++
	if len(m.fail) > 0 {
		err := m.fail[0]
		m.fail = m.fail[1:]
		m.mu.Unlock()
		return experience.ChangeEvent{}, err
	}
	if m.store == nil {
		m.store = experience.NewFileStore("")
	}
	st := m.store
	m.mu.Unlock()
	return st.RecordChange(ctx, in)
}

func (m *memSink) rows() []experience.ChangeEvent {
	m.mu.Lock()
	st := m.store
	m.mu.Unlock()
	if st == nil {
		return nil
	}
	out := []experience.ChangeEvent{}
	for _, tenant := range []string{"acme", "globex"} {
		rows, err := st.ListChanges(context.Background(), tenant, experience.ChangeQuery{})
		if err != nil {
			panic(err)
		}
		out = append(out, rows...)
	}
	return out
}

type logSink struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logSink) warn(msg string, _ map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func newTestProducer(t *testing.T, sink Sink) *Producer {
	t.Helper()
	p, err := New(Deps{Sink: sink, LogWarn: func(string, map[string]any) {},
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewRefusesAnIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{LogWarn: func(string, map[string]any) {}}); err == nil {
		t.Fatal("a producer with no sink was built")
	}
	if _, err := New(Deps{Sink: &memSink{}}); err == nil {
		t.Fatal("a producer with no logger was built")
	}
}

func TestAReplayedCaptureIsRecordedOnce(t *testing.T) {
	sink := &memSink{}
	p := newTestProducer(t, sink)
	in := capture("scheduled", "")
	for i := 0; i < 3; i++ {
		if err := p.RecordConfigCapture(context.Background(), in); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(sink.rows()); n != 1 {
		t.Fatalf("a replayed capture produced %d ledger rows, want 1", n)
	}
}

func TestATransientFailureIsRetriedAndCounted(t *testing.T) {
	sink := &memSink{fail: []error{errors.New("conn reset"), errors.New("conn reset")}}
	p := newTestProducer(t, sink)
	if err := p.RecordConfigCapture(context.Background(), capture("scheduled", "")); err != nil {
		t.Fatalf("two transient failures inside the attempt budget should still record: %v", err)
	}
	m := p.Metrics()
	if m.Count(ProducerConfigCapture, OutcomeRetried) != 2 || m.Count(ProducerConfigCapture, OutcomeRecorded) != 1 {
		t.Fatalf("retried=%d recorded=%d", m.Count(ProducerConfigCapture, OutcomeRetried), m.Count(ProducerConfigCapture, OutcomeRecorded))
	}
}

func TestAPersistentFailureIsCountedLoggedAndReturned(t *testing.T) {
	boom := errors.New("ledger down")
	sink := &memSink{fail: []error{boom, boom, boom, boom}}
	logs := &logSink{}
	p, err := New(Deps{Sink: sink, LogWarn: logs.warn, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.RecordConfigCapture(context.Background(), capture("scheduled", "")); !errors.Is(err, boom) {
		t.Fatalf("the failure was not returned: %v", err)
	}
	if sink.calls != writeAttempts {
		t.Fatalf("attempts = %d, want the bounded %d", sink.calls, writeAttempts)
	}
	if p.Metrics().Count(ProducerConfigCapture, OutcomeFailed) != 1 || len(logs.msgs) != 1 {
		t.Fatalf("failed=%d logs=%v", p.Metrics().Count(ProducerConfigCapture, OutcomeFailed), logs.msgs)
	}
}

func TestADeterministicRefusalIsNotRetried(t *testing.T) {
	sink := &memSink{fail: []error{experience.ErrChangeTooOld}}
	p := newTestProducer(t, sink)
	if err := p.RecordConfigCapture(context.Background(), capture("scheduled", "")); !errors.Is(err, experience.ErrChangeTooOld) {
		t.Fatalf("err = %v", err)
	}
	if sink.calls != 1 {
		t.Fatalf("a refusal the store will repeat was retried %d times", sink.calls-1)
	}
}

// ── correlix_audit ──────────────────────────────────────────────────────────

func mutation() AuditMutation {
	return AuditMutation{Tenant: "acme", Actor: "u_1", Method: http.MethodPut, Path: "/api/devices/dev-1/site",
		Status: http.StatusOK, At: time.Now().UTC(), Target: Target{Kind: "device", ID: "dev-1"}, Site: "dfw"}
}

func TestAuditChangeRecordsTheTarget(t *testing.T) {
	dir := mapDirectory{"u_1": {ID: "u_1", Display: "Jane Doe", TenantID: "acme"}}
	ev, err := AuditChange(mutation(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("does not validate: %v", err)
	}
	if ev.Object != "dev-1" || ev.ObjectKind != "device" || ev.SourceSystem != ProducerAudit || ev.Site != "dfw" {
		t.Fatalf("target not recorded: %+v", ev)
	}
	if ev.ActorID != "u_1" || ev.ActorDisplay != "Jane Doe" || ev.ActorType != "user" {
		t.Fatalf("actor: %+v", ev)
	}
}

func TestAuditChangeSkipsWhatIsNotATenantChange(t *testing.T) {
	for name, mut := range map[string]func(*AuditMutation){
		"a read":                       func(m *AuditMutation) { m.Method = http.MethodGet },
		"a denied request":             func(m *AuditMutation) { m.Status = http.StatusForbidden },
		"a failed request":             func(m *AuditMutation) { m.Status = http.StatusInternalServerError },
		"a platform-scope principal":   func(m *AuditMutation) { m.Cross = true },
		"no tenant":                    func(m *AuditMutation) { m.Tenant = "" },
		"the global tenant":            func(m *AuditMutation) { m.Tenant = "global" },
		"a handler that named nothing": func(m *AuditMutation) { m.Target = Target{} },
	} {
		m := mutation()
		mut(&m)
		if _, err := AuditChange(m, nil); !errors.Is(err, ErrNotAChange) {
			t.Errorf("%s was recorded as a change (err %v)", name, err)
		}
	}
}

func TestTheAuditQueueIsBoundedAndDrainedByRun(t *testing.T) {
	sink := &memSink{}
	logs := &logSink{}
	p, err := New(Deps{Sink: sink, LogWarn: logs.warn, QueueSize: 2,
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		m := mutation()
		m.At = base.Add(time.Duration(i) * time.Second)
		p.EnqueueAudit(m) // never blocks, even with no Run draining it
	}
	if got := p.Metrics().Count(ProducerAudit, OutcomeDropped); got != 3 {
		t.Fatalf("dropped = %d, want 3 (queue of 2, 5 offered)", got)
	}
	if len(logs.msgs) != 1 {
		t.Fatalf("the first drop must be logged once: %v", logs.msgs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for len(sink.rows()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if n := len(sink.rows()); n != 2 {
		t.Fatalf("Run recorded %d rows, want the 2 queued", n)
	}
	skip := mutation()
	skip.Target = Target{}
	p.EnqueueAudit(skip)
	if p.Metrics().Count(ProducerAudit, OutcomeSkipped) != 1 {
		t.Fatal("a target-less mutation was not counted as skipped")
	}
}

// ── the target slot ─────────────────────────────────────────────────────────

func TestTargetSlot(t *testing.T) {
	SetTarget(context.Background(), "device", "dev-1") // no slot: a no-op, no panic
	ctx, slot := WithTargetSlot(context.Background())
	if _, ok := slot.Get(); ok {
		t.Fatal("a fresh slot holds a target")
	}
	SetTarget(ctx, "device", "dev 1; DROP") // not a plain identifier: refused
	if _, ok := slot.Get(); ok {
		t.Fatal("an unsafe target was stored")
	}
	SetTarget(ctx, "device", "dev-1")
	if got, ok := slot.Get(); !ok || got != (Target{Kind: "device", ID: "dev-1"}) {
		t.Fatalf("slot = %+v %v", got, ok)
	}
	var nilSlot *TargetSlot
	if _, ok := nilSlot.Get(); ok {
		t.Fatal("a nil slot reported a target")
	}
}

func TestMetricsRenderEveryProducerAndOutcome(t *testing.T) {
	var b strings.Builder
	NewMetrics().Write(&b)
	for _, want := range []string{
		`netops_change_ledger_writes_total{producer="config_capture",outcome="failed"} 0`,
		`netops_change_ledger_writes_total{producer="correlix_audit",outcome="dropped"} 0`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %s in:\n%s", want, b.String())
		}
	}
}
