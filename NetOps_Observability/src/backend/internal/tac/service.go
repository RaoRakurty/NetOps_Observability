// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// service.go — the escalation's STATE and its long-running work.
//
// One escalation is a small state machine per (tenant, incident): classified →
// planned → collecting → collected → bundled → case prepared. The HTTP surface
// is thin over this file; every rule that matters lives here so it is provable
// without a socket.
//
// WHY IT IS IN-PROCESS AND BOUNDED. A collection takes minutes and an operator
// watches it, so it cannot be a request. It is also not worth a queue: it is
// per-operator, per-device work that must not survive a restart (a half-finished
// capture resumed against a device nobody is watching is worse than an honest
// "start it again"). So the state is an in-memory register, bounded per tenant,
// with the same lifetime as the api — and every response says plainly what state
// it is in, including "this escalation was lost when the api restarted".
//
// TENANT SCOPE. The register is keyed on (tenant, incident) and there is no
// method that lists across tenants. A caller that supplies another tenant's
// incident id simply has no state under its own key — the same answer as an
// incident that was never escalated, which is the answer §3a wants.

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	// maxEscalationsPerTenant bounds the in-memory register (§9).
	maxEscalationsPerTenant = 64
	// maxProgressEvents bounds one job's retained progress log.
	maxProgressEvents = 400
	// jobIdleTTL is how long a finished escalation stays in the register.
	jobIdleTTL = 6 * time.Hour
)

// JobStatus is a collection's lifecycle.
type JobStatus string

const (
	// JobRunning — the collection is in flight.
	JobRunning JobStatus = "running"
	// JobDone — it finished (possibly with per-command failures, which are on
	// the capture, not on the job).
	JobDone JobStatus = "done"
	// JobFailed — it could not start or was cancelled.
	JobFailed JobStatus = "failed"
)

// Job is one collection run.
type Job struct {
	ID         string     `json:"id"`
	Status     JobStatus  `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt time.Time  `json:"finished_at,omitzero"`
	Total      int        `json:"total"`
	Done       int        `json:"done"`
	Progress   []Progress `json:"progress"`
	Err        string     `json:"error,omitempty"`
}

// State is one escalation.
type State struct {
	TenantID   string `json:"-"`
	IncidentID string `json:"incident_id"`

	Classification *Classification `json:"classification,omitempty"`
	Plan           *Plan           `json:"plan,omitempty"`
	Job            *Job            `json:"job,omitempty"`
	Capture        *Capture        `json:"capture,omitempty"`
	Bundles        []StoredBundle  `json:"bundles"`
	Case           *CaseResult     `json:"case,omitempty"`
	// Remembered records that this escalation has already been written into the
	// investigation memory Iris recalls from. It exists so the memory is written
	// ONCE, at the first moment the escalation became real (a bundle was
	// produced), rather than once per download.
	Remembered bool `json:"remembered"`

	UpdatedAt time.Time `json:"updated_at"`
}

// Service holds the register and the injected engines. Every dependency is
// injectable and may be nil; a nil dependency yields an honest refusal at the
// point of use, never a fabricated result.
type Service struct {
	catalog   *Catalog
	collector *Collector
	store     *Store
	narrator  Narrator
	openers   []CaseOpener
	now       func() time.Time
	// validator guards every command an operator types into the review step and
	// every command a template holds. It is built from the same catalog, so the
	// review and the plan cannot disagree about what an output command is.
	validator *TemplateValidator
	// reviews is the per-collection allow set the gate consults. It is nil on a
	// deployment with no live runner (there is nothing to gate), and a nil
	// registry allows nothing.
	reviews *ReviewRegistry
	// learning is where a finished collection files what the parsers could not
	// read (learning.go). Nil means the backlog is not kept on this deployment
	// and a collection simply files nothing — never a failed collection.
	learning LearningStore
	// warn routes a non-fatal problem to the caller's structured log. It always
	// points at something (the constructor sets a process-log default), so a
	// failure here is never silent (§10).
	warn func(msg string, fields map[string]any)

	mu     sync.Mutex
	states map[string]map[string]*State // tenant → incident → state
	cancel map[string]context.CancelFunc
}

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithCollector injects the read-only collector. Nil (the default) is the
// honest "no capture transport on this deployment" path: collect answers 503.
func WithCollector(c *Collector) ServiceOption { return func(s *Service) { s.collector = c } }

// WithStore injects the bundle store. Nil means bundles cannot be persisted and
// the bundle step says so.
func WithStore(st *Store) ServiceOption { return func(s *Service) { s.store = st } }

// WithNarrator injects Iris. Nil means the deterministic problem statement,
// which is a complete artifact.
func WithNarrator(n Narrator) ServiceOption { return func(s *Service) { s.narrator = n } }

// WithOpeners injects the case connectors, in display order. PortalTextOpener is
// always appended, so there is always at least one honest path.
func WithOpeners(o ...CaseOpener) ServiceOption {
	return func(s *Service) { s.openers = append(s.openers, o...) }
}

// WithReviews injects the per-collection allow set the runner's gate consults.
// It MUST be the same registry the gate was built with, or an approved custom
// command will be refused at the wire — which is the safe direction to fail, and
// is what the service's own test asserts.
func WithReviews(r *ReviewRegistry) ServiceOption { return func(s *Service) { s.reviews = r } }

// WithLearning injects the learning store. Nil is the honest "this deployment
// does not keep the backlog" path: a collection still runs, and files nothing.
func WithLearning(l LearningStore) ServiceOption { return func(s *Service) { s.learning = l } }

// WithServiceWarn routes the service's non-fatal problems (a learning record
// that could not be filed) to the caller's structured log.
func WithServiceWarn(fn func(msg string, fields map[string]any)) ServiceOption {
	return func(s *Service) {
		if fn != nil {
			s.warn = fn
		}
	}
}

// WithServiceClock injects the clock.
func WithServiceClock(now func() time.Time) ServiceOption {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// NewService builds the escalation service over a loaded catalog.
func NewService(c *Catalog, opts ...ServiceOption) (*Service, error) {
	if c == nil {
		return nil, errors.New("tac: nil catalog")
	}
	v, err := NewTemplateValidator(c)
	if err != nil {
		return nil, err
	}
	s := &Service{
		catalog: c, now: time.Now, validator: v,
		states: map[string]map[string]*State{}, cancel: map[string]context.CancelFunc{},
		warn: func(msg string, fields map[string]any) { log.Printf("tac: %s %v", msg, fields) },
	}
	for _, o := range opts {
		o(s)
	}
	s.openers = append(s.openers, NewPortalTextOpener())
	return s, nil
}

// Validator exposes the command validator the review step and the template store
// share. There is exactly one per service, built from the loaded catalog.
func (s *Service) Validator() *TemplateValidator { return s.validator }

// Review re-validates an operator-approved command list against the escalation's
// stored plan and REPLACES that plan with the reviewed one.
//
// It is the server-side half of the promise the review UI makes: what runs is
// exactly the list the operator saw, and every line of it was checked here — not
// in the browser — against the output-only policy and the read-only grammar. A
// single refused line fails the whole review, naming the line.
func (s *Service) Review(tenant, incident string, steps []ReviewedStep, ref TemplateRef) (*Plan, ValidationResult, error) {
	s.mu.Lock()
	st := s.states[tenant][incident]
	if st == nil || st.Plan == nil {
		s.mu.Unlock()
		return nil, ValidationResult{}, errors.New("tac: no plan has been built for this escalation")
	}
	if st.Job != nil && st.Job.Status == JobRunning {
		s.mu.Unlock()
		return nil, ValidationResult{}, ErrCollectBusy
	}
	plan := st.Plan
	s.mu.Unlock()

	reviewed, res, err := s.validator.Review(plan, steps, ref)
	if err != nil {
		return nil, res, err
	}
	reviewed.IncidentID = incident
	reviewed.TenantID = tenant
	s.mu.Lock()
	defer s.mu.Unlock()
	st2 := s.stateLocked(tenant, incident)
	st2.Plan = reviewed
	st2.UpdatedAt = s.now().UTC()
	return reviewed, res, nil
}

// Catalog exposes the loaded taxonomy (the Knowledge page reads it).
func (s *Service) Catalog() *Catalog { return s.catalog }

// CanCollect reports whether a live capture transport is wired.
func (s *Service) CanCollect() bool { return s.collector != nil }

// Connectors returns the case connectors' declared capabilities for a tenant.
//
// A connector whose stored configuration could not be READ is an error, not a
// state, so it is logged here — ONCE per read, naming every connector affected
// and the first cause — rather than only being rendered. Before 2026-09-06 the
// UI printed "connector configuration could not be read for this tenant" and
// nothing was logged at all: the api's own log had no trace of a sentence the
// operator was staring at (§10, no silent failures).
func (s *Service) Connectors(ctx context.Context, tenant string) []ConnectorInfo {
	out := make([]ConnectorInfo, 0, len(s.openers))
	var unreadable []string
	cause := ""
	for _, o := range s.openers {
		info := o.Info(ctx, tenant)
		if info.Unavailable {
			unreadable = append(unreadable, info.ID)
			if cause == "" {
				cause = info.StatusNote
			}
		}
		out = append(out, info)
	}
	if len(unreadable) > 0 {
		s.warn("case-connector configuration could not be read — these connectors are shown unavailable, not unconfigured",
			map[string]any{"tenant": tenant, "connectors": strings.Join(unreadable, " "), "cause": cause})
	}
	return out
}

// opener finds a connector by id.
func (s *Service) opener(ctx context.Context, tenant, id string) (CaseOpener, ConnectorInfo, bool) {
	for _, o := range s.openers {
		info := o.Info(ctx, tenant)
		if info.ID == id {
			return o, info, true
		}
	}
	return nil, ConnectorInfo{}, false
}

// ── the register ────────────────────────────────────────────────────────────

// Get returns a COPY of the escalation state, or nil when there is none. The
// copy matters: the caller serialises it while a collection may still be
// appending progress.
func (s *Service) Get(tenant, incident string) *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[tenant][incident]
	if st == nil {
		return nil
	}
	return copyState(st)
}

// stateLocked fetches or creates the state, evicting the tenant's oldest when
// the register is full.
func (s *Service) stateLocked(tenant, incident string) *State {
	byInc := s.states[tenant]
	if byInc == nil {
		byInc = map[string]*State{}
		s.states[tenant] = byInc
	}
	if st, ok := byInc[incident]; ok {
		return st
	}
	s.evictLocked(byInc)
	st := &State{TenantID: tenant, IncidentID: incident, Bundles: []StoredBundle{}}
	byInc[incident] = st
	return st
}

// evictLocked drops finished escalations past the TTL, then the oldest, until
// there is room. A RUNNING job is never evicted.
func (s *Service) evictLocked(byInc map[string]*State) {
	cutoff := s.now().Add(-jobIdleTTL)
	for id, st := range byInc {
		if st.Job != nil && st.Job.Status == JobRunning {
			continue
		}
		if st.UpdatedAt.Before(cutoff) {
			delete(byInc, id)
		}
	}
	for len(byInc) >= maxEscalationsPerTenant {
		var oldestID string
		var oldest time.Time
		for id, st := range byInc {
			if st.Job != nil && st.Job.Status == JobRunning {
				continue
			}
			if oldestID == "" || st.UpdatedAt.Before(oldest) {
				oldestID, oldest = id, st.UpdatedAt
			}
		}
		if oldestID == "" {
			return // everything is running; refuse to evict live work
		}
		delete(byInc, oldestID)
	}
}

// Classify records a classification against an escalation.
func (s *Service) Classify(tenant, incident string, ev Evidence) Classification {
	res := s.catalog.Classify(ev)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stateLocked(tenant, incident)
	c := res
	st.Classification = &c
	// A re-classification invalidates a plan built for the old class.
	if st.Plan != nil && st.Plan.ClassID != res.ClassID {
		st.Plan = nil
	}
	st.UpdatedAt = s.now().UTC()
	return res
}

// Plan builds and records the command plan.
func (s *Service) Plan(tenant, incident, classID string, dev Device, opt PlanOptions) (*Plan, error) {
	p, err := s.catalog.Plan(classID, dev, opt)
	if err != nil {
		return nil, err
	}
	p.IncidentID = incident
	p.TenantID = tenant
	p.ID = planID(p)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stateLocked(tenant, incident)
	st.Plan = p
	st.UpdatedAt = s.now().UTC()
	return p, nil
}

// StartCollect launches the collection in the background and returns the job.
//
// The background context is DELIBERATELY not the request's: an operator's page
// navigation must not kill a collection that is mid-command on a router. The job
// is instead bounded by its own deadline and cancellable through Cancel.
func (s *Service) StartCollect(tenant, incident string, supplied []SuppliedOutput) (*Job, error) {
	if s.collector == nil {
		return nil, ErrNoRunner
	}
	s.mu.Lock()
	st := s.stateLocked(tenant, incident)
	if st.Plan == nil {
		s.mu.Unlock()
		return nil, errors.New("tac: no plan has been built for this escalation")
	}
	if st.Job != nil && st.Job.Status == JobRunning {
		s.mu.Unlock()
		return nil, ErrCollectBusy
	}
	plan := st.Plan
	job := &Job{
		ID:     planID(plan) + "-" + itoaTAC(int(s.now().UnixNano()%1e9)),
		Status: JobRunning, StartedAt: s.now().UTC(),
		Total: len(plan.Steps), Progress: []Progress{},
	}
	st.Job = job
	st.Capture = nil
	st.UpdatedAt = job.StartedAt
	key := tenant + "\x00" + incident
	ctx, cancel := context.WithTimeout(context.Background(), collectionDeadline(plan))
	s.cancel[key] = cancel
	s.mu.Unlock()

	// The reviewed allow set opens HERE, from the plan the server holds — never
	// from a request body — and closes in runCollect's defer. Between those two
	// points, and only for this device, a custom command the operator approved
	// may reach the wire; outside them the authored table is the whole world.
	s.reviews.Register(planDeviceKey(plan), commandsOf(plan))

	go s.runCollect(ctx, cancel, key, tenant, incident, plan, supplied, job)
	return job, nil
}

// planDeviceKey is the registry key for a plan's subject device — the same key
// the collector claims for its one-collection-per-device rule.
func planDeviceKey(p *Plan) string {
	if p == nil {
		return ""
	}
	if p.DeviceID != "" {
		return p.DeviceID
	}
	return p.Hostname
}

// commandsOf lists a plan's step commands (and the teardowns the collector will
// run), which is exactly what may go on a wire for it.
func commandsOf(p *Plan) []string {
	out := make([]string, 0, len(p.Steps)*2)
	for _, st := range p.Steps {
		out = append(out, st.Command)
		if st.Teardown != "" {
			out = append(out, st.Teardown)
		}
	}
	return out
}

// collectionDeadline is the whole-collection ceiling: the sum of the plan's own
// per-command budgets plus a margin, so a stuck collection ends by itself.
func collectionDeadline(p *Plan) time.Duration {
	d := time.Duration(p.EstimatedSeconds)*time.Second + 2*time.Minute
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

func (s *Service) runCollect(ctx context.Context, cancel context.CancelFunc, key, tenant, incident string,
	plan *Plan, supplied []SuppliedOutput, job *Job) {
	defer cancel()
	// From a defer, so a panic or an early return cannot leave a reviewed
	// command allowed after its collection has ended.
	defer s.reviews.Release(planDeviceKey(plan))
	defer func() {
		s.mu.Lock()
		delete(s.cancel, key)
		s.mu.Unlock()
	}()

	capt, err := s.collector.Collect(ctx, plan, supplied, func(pr Progress) {
		s.mu.Lock()
		if len(job.Progress) < maxProgressEvents {
			job.Progress = append(job.Progress, pr)
		}
		if pr.Phase != "start" {
			job.Done++
		}
		s.mu.Unlock()
	})

	// The backlog is filed BEFORE the lock: ObserveCapture runs the parsers over
	// output already on this host, which is CPU work with no IO, and holding the
	// service lock across it would stall every other escalation on this api.
	if err == nil {
		s.fileLearning(ctx, tenant, capt)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[tenant][incident]
	job.FinishedAt = s.now().UTC()
	if err != nil {
		job.Status = JobFailed
		job.Err = err.Error()
	} else {
		job.Status = JobDone
		if st != nil {
			st.Capture = capt
		}
	}
	if st != nil {
		st.UpdatedAt = job.FinishedAt
	}
}

// Cancel stops a running collection. It is a no-op when nothing is running.
func (s *Service) Cancel(tenant, incident string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cancel[tenant+"\x00"+incident]
	if !ok {
		return false
	}
	c()
	return true
}

// Bundle assembles and stores the bundle for a collected escalation.
func (s *Service) Bundle(ctx context.Context, tenant, incident string, in BundleInput) (*Bundle, StoredBundle, error) {
	s.mu.Lock()
	st := s.states[tenant][incident]
	if st == nil || st.Capture == nil {
		s.mu.Unlock()
		return nil, StoredBundle{}, errors.New("tac: nothing has been collected for this escalation yet")
	}
	in.TenantID = tenant
	in.IncidentID = incident
	in.Capture = st.Capture
	in.Plan = st.Plan
	if st.Classification != nil {
		in.Class = *st.Classification
	}
	s.mu.Unlock()

	b, err := BuildBundle(ctx, in, s.narrator, s.now)
	if err != nil {
		return nil, StoredBundle{}, err
	}
	var meta StoredBundle
	if s.store != nil {
		meta, err = s.store.Put(tenant, incident, b)
		if err != nil {
			return nil, StoredBundle{}, err
		}
		s.mu.Lock()
		if st2 := s.states[tenant][incident]; st2 != nil {
			st2.Bundles = append([]StoredBundle{meta}, st2.Bundles...)
			if len(st2.Bundles) > maxBundlesPerIncident {
				st2.Bundles = st2.Bundles[:maxBundlesPerIncident]
			}
			st2.UpdatedAt = s.now().UTC()
		}
		s.mu.Unlock()
	} else {
		meta = StoredBundle{Name: b.Name, Bytes: int64(len(b.Zip)), IncidentID: incident,
			Profile: b.Manifest.Profile, ClassID: b.Manifest.Classification.ClassID}
	}
	return b, meta, nil
}

// PrepareCase returns the pre-filled, human-reviewable case form.
func (s *Service) PrepareCase(ctx context.Context, tenant, connectorID string, req CaseRequest) (CaseForm, ConnectorInfo, error) {
	o, info, ok := s.opener(ctx, tenant, connectorID)
	if !ok {
		return CaseForm{}, ConnectorInfo{}, errors.New("tac: unknown case connector")
	}
	if !info.Configured {
		return CaseForm{}, info, ErrConnectorNotConfigured
	}
	req.Form.Profile = ProfileForConnector(info)
	f, err := o.PrepareCase(ctx, req)
	return f, info, err
}

// SubmitCase performs the human-approved action and records the result.
func (s *Service) SubmitCase(ctx context.Context, tenant, incident, connectorID string, req CaseRequest) (CaseResult, error) {
	o, info, ok := s.opener(ctx, tenant, connectorID)
	if !ok {
		return CaseResult{}, errors.New("tac: unknown case connector")
	}
	if !info.Configured {
		return CaseResult{}, ErrConnectorNotConfigured
	}
	res, err := o.SubmitCase(ctx, req)
	if err != nil {
		return CaseResult{}, err
	}
	s.mu.Lock()
	// The case outcome is recorded even when the escalation is not in the
	// register (an api restart, an operator who downloaded a bundle yesterday):
	// losing the record of a case a human actually opened would be the worst
	// thing this feature could forget.
	st := s.stateLocked(tenant, incident)
	r := res
	st.Case = &r
	st.UpdatedAt = s.now().UTC()
	s.mu.Unlock()
	return res, nil
}

// MarkRemembered claims the one-time investigation-memory write for this
// escalation. It returns true exactly once per escalation, so the caller can
// record the memory without a second store read to check.
func (s *Service) MarkRemembered(tenant, incident string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[tenant][incident]
	if st == nil || st.Remembered {
		return false
	}
	st.Remembered = true
	return true
}

// CaptureSummary is the capture WITHOUT the command outputs: one row per
// command with its size, its timing and its honest error, and nothing else.
//
// It is what the state endpoint returns, and the reason is not only size. The
// UI polls this every couple of seconds while a collection runs; shipping the
// whole redacted capture on every poll would put many copies of a device's
// operational state on the wire and in browser memory for no benefit, when the
// evidence itself belongs in the bundle the operator downloads once.
type CaptureSummary struct {
	IncidentID string `json:"incident_id"`
	PlanID     string `json:"plan_id"`
	ClassID    string `json:"class_id"`
	ClassTitle string `json:"class_title"`
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
	Dialect    string `json:"dialect"`
	Display    string `json:"dialect_display"`
	HasPlan    bool   `json:"has_plan"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitzero"`

	Commands []CommandSummary `json:"commands"`
	Unbound  []Step           `json:"unbound"`
	Topology []TopologyNote   `json:"topology"`

	// Reviewed / Template / Edits mirror the capture's own provenance so the
	// panel can say which template ran without downloading the bundle.
	Reviewed bool        `json:"reviewed"`
	Template TemplateRef `json:"template,omitzero"`
	Edits    []PlanEdit  `json:"edits,omitempty"`

	TotalBytes int64  `json:"total_bytes"`
	Redacted   bool   `json:"redacted"`
	Stopped    string `json:"stopped,omitempty"`

	CatalogVersion string `json:"catalog_version"`
	PlanVersion    string `json:"plan_version,omitempty"`
	EngineVersion  string `json:"engine_version"`
}

// CommandSummary is one command's row without its output.
type CommandSummary struct {
	Intent     string    `json:"intent"`
	Title      string    `json:"title"`
	Section    Section   `json:"section"`
	Command    string    `json:"command"`
	Verified   Verified  `json:"verified,omitempty"`
	Bytes      int       `json:"bytes"`
	Err        string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// Summary renders a capture without its outputs.
func (c *Capture) Summary() *CaptureSummary {
	if c == nil {
		return nil
	}
	out := &CaptureSummary{
		IncidentID: c.IncidentID, PlanID: c.PlanID, ClassID: c.ClassID, ClassTitle: c.ClassTitle,
		DeviceID: c.DeviceID, Hostname: c.Hostname, Platform: c.Platform,
		Dialect: c.Dialect, Display: c.Display, HasPlan: c.HasPlan,
		StartedAt: c.StartedAt, FinishedAt: c.FinishedAt,
		Unbound: c.Unbound, Topology: c.Topology,
		Reviewed: c.Reviewed, Template: c.Template, Edits: c.Edits,
		TotalBytes: c.TotalBytes, Redacted: c.Redacted, Stopped: c.Stopped,
		CatalogVersion: c.CatalogVersion, PlanVersion: c.PlanVersion, EngineVersion: c.EngineVersion,
		Commands: make([]CommandSummary, 0, len(c.Commands)),
	}
	for _, cc := range c.Commands {
		out.Commands = append(out.Commands, CommandSummary{
			Intent: cc.Intent, Title: cc.Title, Section: cc.Section, Command: cc.Command,
			Verified: cc.Verified, Bytes: cc.Bytes, Err: cc.Err,
			StartedAt: cc.StartedAt, DurationMS: cc.DurationMS,
		})
	}
	return out
}

// StateView is the wire form of an escalation: everything a caller needs to
// render the flow, with the capture reduced to its summary.
type StateView struct {
	IncidentID     string          `json:"incident_id"`
	Classification *Classification `json:"classification,omitempty"`
	Plan           *Plan           `json:"plan,omitempty"`
	Job            *Job            `json:"job,omitempty"`
	Capture        *CaptureSummary `json:"capture,omitempty"`
	Bundles        []StoredBundle  `json:"bundles"`
	Case           *CaseResult     `json:"case,omitempty"`
	Remembered     bool            `json:"remembered"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// View renders a state for the wire.
func (st *State) View() *StateView {
	if st == nil {
		return nil
	}
	return &StateView{
		IncidentID: st.IncidentID, Classification: st.Classification, Plan: st.Plan,
		Job: st.Job, Capture: st.Capture.Summary(), Bundles: st.Bundles,
		Case: st.Case, Remembered: st.Remembered, UpdatedAt: st.UpdatedAt,
	}
}

// copyState deep-copies the mutable parts of a state for serialisation.
func copyState(st *State) *State {
	out := *st
	if st.Job != nil {
		j := *st.Job
		j.Progress = append([]Progress(nil), st.Job.Progress...)
		out.Job = &j
	}
	out.Bundles = append([]StoredBundle(nil), st.Bundles...)
	return &out
}

// fileLearning records what this collection's output the parsers could not
// read (learning.go). It is best-effort ON PURPOSE: a backlog that cannot be
// written must never turn a completed collection into a failed one, and the
// operator's bundle is unaffected either way. The failure is not swallowed —
// the record carries an id and the store's own error reaches the integrator's
// log through the caller it is handed to.
//
// A record with NO gaps is still filed. "This collection was fully recognised"
// is the evidence that the coverage is real, and dropping it would make the
// backlog a list of failures with no denominator.
func (s *Service) fileLearning(ctx context.Context, tenant string, capt *Capture) {
	if s.learning == nil || capt == nil {
		return
	}
	id := NewRecordID()
	if id == "" {
		return
	}
	rec := ObserveCapture(capt, id, s.now())
	rec.TenantID = tenant
	// The classification that chose this class is state on the escalation, not
	// on the capture; a class chosen with no signature behind it is itself the
	// seed of a candidate, so it is recorded rather than recomputed later.
	s.mu.Lock()
	if st := s.states[tenant][capt.IncidentID]; st != nil && st.Classification != nil {
		rec.ClassFromSignature = classFromSignature(st.Classification, capt.ClassID)
	}
	s.mu.Unlock()
	// context.WithoutCancel: the collection's deadline has done its job by the
	// time this runs, and losing the backlog because the plan's budget expired
	// would be the silent gap this whole file exists to close.
	if err := s.learning.PutRecord(context.WithoutCancel(ctx), rec); err != nil {
		s.warn("a TAC learning record could not be filed", map[string]any{
			"incident_id": capt.IncidentID, "device_id": capt.DeviceID,
			"gaps": len(rec.Gaps), "error": err.Error(),
		})
	}
}

// classFromSignature reports whether a SIGNATURE, rather than an alert name or
// a hypothesis, is why this class was chosen.
func classFromSignature(c *Classification, classID string) bool {
	if c == nil {
		return false
	}
	if c.ClassID == classID {
		for _, r := range c.Why {
			if r.Kind == "signature" {
				return true
			}
		}
	}
	for _, m := range c.Alternatives {
		if m.ClassID != classID {
			continue
		}
		for _, r := range m.Why {
			if r.Kind == "signature" {
				return true
			}
		}
	}
	return false
}
