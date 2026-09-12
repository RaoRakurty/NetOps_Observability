// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// ingest.go — the experience-event INGEST surface (tracker 254):
//
//	POST /api/dem/events           first-party RUM beacons and agent/API events
//	POST /api/dem/business-events  business outcomes (purchase, booking, claim)
//
// These are the first WRITE routes in this package whose producer is not an
// operator at a keyboard. Three things follow from that, and all three are
// structural rather than advisory.
//
// 1. §3a RULE 2 — THE OWNER COMES FROM THE CREDENTIAL. The wire types below
//    carry NO tenant field at all, so a browser cannot ask for one; the tenant
//    is stamped from the authenticated principal and the decoder refuses
//    unknown fields, so a `tenant_id` in the body is a 400 rather than a
//    silently-ignored attempt.
//
// 2. §9 BOUNDS AND BACKPRESSURE. The body is capped before it is decoded, the
//    batch is capped in events, and the sink is a BOUNDED queue: when it is
//    full the route answers 503 with a Retry-After. A 202 for data that went
//    nowhere would make the lane look healthy while a tenant's evidence
//    disappeared — the failure mode this whole product exists to refuse.
//
// 3. PRIVACY IS ENFORCED, NOT REQUESTED (§M.8). `user_ref` must be a
//    pseudonymous per-tenant reference; [ExperienceEvent.Validate] REFUSES
//    anything that looks like a direct identifier rather than hashing it,
//    because silently pseudonymising a caller's mistake teaches the caller that
//    sending real identifiers is fine. The refusal names the field and says
//    what to do instead.
//
// The route deliberately does NOT read anything. An ingest credential that
// could also read would be a credential that, pasted into a public page, hands
// out a tenant's experience data.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/dem"
	"netops/backend/internal/httppage"
)

// Ingest route paths. Exported so the integrator registers exactly what this
// file serves and a test can pin the registered literals against them.
const (
	EventsPath        = "/api/dem/events"
	BusinessEventPath = "/api/dem/business-events"
)

// Ingest bounds (§9).
const (
	// maxIngestBodyBytes is larger than the operator write routes' cap because
	// a beacon batch is many small records, and smaller than anything that
	// could be used to make the api allocate: 256 KiB holds a full
	// MaxEventsPerRequest batch of realistic events with room to spare.
	maxIngestBodyBytes = 256 << 10
	// MaxEventsPerRequest bounds one POST. A producer with more than this to
	// send makes more than one request, which is what keeps a single body from
	// becoming an unbounded unit of work.
	MaxEventsPerRequest = 200
	// ingestRetryAfterSeconds is what a busy queue tells the producer. Short
	// enough that a real burst drains, long enough that a retry storm does not
	// become the outage.
	ingestRetryAfterSeconds = 2
)

// eventWire is the accepted shape of one experience event.
//
// It is a SEPARATE type from [ExperienceEvent] on purpose: the domain object
// carries `tenant_id` and a whole provenance block, and neither may come from
// the wire. What a producer may state is what it actually observed.
type eventWire struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id,omitempty"`
	UserRef   string `json:"user_ref,omitempty"`

	App         string `json:"app"`
	Environment string `json:"environment,omitempty"`
	Release     string `json:"release,omitempty"`

	Type   string `json:"type"`
	Action string `json:"action,omitempty"`
	Route  string `json:"route,omitempty"`

	Success    bool     `json:"success"`
	DurationMs *float64 `json:"duration_ms,omitempty"`
	Error      string   `json:"error,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`

	Vitals *WebVitals `json:"vitals,omitempty"`

	JourneyID string `json:"journey_id,omitempty"`
	StepID    string `json:"step_id,omitempty"`

	FeatureFlags map[string]string `json:"feature_flags,omitempty"`
	Cohort       Cohort            `json:"cohort,omitempty"`

	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`

	ActorType       string            `json:"actor_type,omitempty"`
	BusinessContext map[string]string `json:"business_context,omitempty"`

	// EventAt is when the thing happened in the PRODUCER's clock. Optional; an
	// absent value means "now", and a value further in the future than
	// maxClockSkew is refused rather than trusted — a browser clock is not a
	// source of truth about when an outage began.
	EventAt string `json:"event_at,omitempty"`
	// ExternalSchema/Version record a foreign schema an adapter translated
	// FROM (OpenTelemetry, a vendor SDK), so an upstream convention change is a
	// diff in these fields rather than a silent change in meaning.
	ExternalSchema  string `json:"external_schema,omitempty"`
	ExternalVersion string `json:"external_version,omitempty"`
}

// businessWire is the accepted shape of one business event.
type businessWire struct {
	ID        string `json:"id"`
	Type      string `json:"business_event_type"`
	App       string `json:"app,omitempty"`
	JourneyID string `json:"journey_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	Success  bool     `json:"success"`
	Value    *float64 `json:"value,omitempty"`
	Currency string   `json:"currency,omitempty"`
	Quantity int      `json:"quantity,omitempty"`

	Cohort     Cohort            `json:"cohort,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`

	EventAt         string `json:"event_at,omitempty"`
	ExternalSchema  string `json:"external_schema,omitempty"`
	ExternalVersion string `json:"external_version,omitempty"`
}

// eventBatch / businessBatch are the request envelopes. A batch, not a bare
// array, so the shape can grow a field without breaking every producer.
type eventBatch struct {
	Events []eventWire `json:"events"`
}

type businessBatch struct {
	Events []businessWire `json:"events"`
}

// maxClockSkew bounds how far ahead of us a producer's clock may be before its
// timestamp is refused. A beacon from the future would place a user's bad
// minute outside every window that could explain it.
const maxClockSkew = 5 * time.Minute

// maxBacklog bounds how far BEHIND a producer's clock may be. A page that was
// open for a week and flushed on unload is real; a month-old beacon is a replay
// or a broken clock, and admitting it would rewrite a window that has already
// been reported on.
const maxBacklog = 7 * 24 * time.Hour

// HandleEvents serves POST /api/dem/events.
func (a *API) HandleEvents(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodPost) {
		return
	}
	if err := httppage.RejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, dem.GateIngest)
	if !ok {
		return
	}
	if !a.sinkReady(w) {
		return
	}
	var body eventBatch
	if !a.decodeIngest(w, r, &body, "experience event") {
		return
	}
	if !a.batchSizeOK(w, len(body.Events)) {
		return
	}
	now := a.deps.Now().UTC()
	events := make([]ExperienceEvent, 0, len(body.Events))
	for i, in := range body.Events {
		at, terr := a.eventTime(in.EventAt, now)
		if terr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("events[%d]: %w", i, terr))
			return
		}
		e := ExperienceEvent{
			TenantID: tenant, // from the CREDENTIAL, never the body
			ID:       in.ID, SessionID: in.SessionID, UserRef: in.UserRef,
			App: in.App, Environment: in.Environment, Release: in.Release,
			Type: in.Type, Action: in.Action, Route: in.Route,
			Success: in.Success, DurationMs: in.DurationMs, Error: in.Error,
			StatusCode: in.StatusCode, Vitals: in.Vitals,
			JourneyID: in.JourneyID, StepID: in.StepID,
			FeatureFlags: in.FeatureFlags, Cohort: in.Cohort,
			TraceID: in.TraceID, SpanID: in.SpanID,
			ActorType: in.ActorType, BusinessContext: in.BusinessContext,
			Provenance: Provenance{
				Source: SourceRUM, Producer: p.Subject,
				EventAt: at, ObservedAt: now,
				Observation:    ObservationObserved,
				ExternalSchema: in.ExternalSchema, ExternalVersion: in.ExternalVersion,
			},
		}
		if err := e.Validate(); err != nil {
			// The refusal is returned VERBATIM: the pseudonymous-user rule's
			// message tells the caller to hash the reference per tenant, and a
			// generic "invalid payload" would hide the one instruction that
			// makes the next request correct.
			a.deps.Counters.IngestRejected.Add(1)
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("events[%d]: %w", i, err))
			return
		}
		events = append(events, e)
	}
	if err := a.deps.Events.WriteEvents(r.Context(), events); err != nil {
		a.writeIngestFailure(w, err, len(events))
		return
	}
	a.deps.Counters.EventsIngested.Add(int64(len(events)))
	a.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"accepted": len(events),
		"note":     "Accepted onto the experience lane. Acceptance means the events are queued for storage, not that they are stored — the lane's own health is on the Data Health screen.",
	})
}

// HandleBusinessEvents serves POST /api/dem/business-events.
func (a *API) HandleBusinessEvents(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if !a.methodIs(w, r, http.MethodPost) {
		return
	}
	if err := httppage.RejectUnknownQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, dem.GateIngest)
	if !ok {
		return
	}
	if !a.sinkReady(w) {
		return
	}
	var body businessBatch
	if !a.decodeIngest(w, r, &body, "business event") {
		return
	}
	if !a.batchSizeOK(w, len(body.Events)) {
		return
	}
	now := a.deps.Now().UTC()
	events := make([]BusinessEvent, 0, len(body.Events))
	for i, in := range body.Events {
		at, terr := a.eventTime(in.EventAt, now)
		if terr != nil {
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("events[%d]: %w", i, terr))
			return
		}
		b := BusinessEvent{
			TenantID: tenant, // from the CREDENTIAL, never the body
			ID:       in.ID, Type: in.Type, App: in.App,
			JourneyID: in.JourneyID, SessionID: in.SessionID,
			Success: in.Success, Value: in.Value, Currency: in.Currency,
			Quantity: in.Quantity, Cohort: in.Cohort, Attributes: in.Attributes,
			Provenance: Provenance{
				Source: SourceManual, Producer: p.Subject,
				EventAt: at, ObservedAt: now,
				Observation:    ObservationObserved,
				ExternalSchema: in.ExternalSchema, ExternalVersion: in.ExternalVersion,
			},
		}
		if err := b.Validate(); err != nil {
			a.deps.Counters.IngestRejected.Add(1)
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("events[%d]: %w", i, err))
			return
		}
		events = append(events, b)
	}
	if err := a.deps.Events.WriteBusinessEvents(r.Context(), events); err != nil {
		a.writeIngestFailure(w, err, len(events))
		return
	}
	a.deps.Counters.BusinessEventsIngested.Add(int64(len(events)))
	a.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"accepted": len(events),
		"note":     "Accepted onto the experience lane. Acceptance means the events are queued for storage, not that they are stored — the lane's own health is on the Data Health screen.",
	})
}

// sinkReady refuses the write when no lane is wired, with the reason. A 202 for
// events with nowhere to go is the lie this whole module is written against.
func (a *API) sinkReady(w http.ResponseWriter) bool {
	if a.deps.Events != nil {
		return true
	}
	a.deps.WriteError(w, http.StatusServiceUnavailable,
		errors.New("the experience event lane is not wired on this deployment, so nothing would store these events; they are refused rather than accepted and dropped"))
	return false
}

func (a *API) batchSizeOK(w http.ResponseWriter, n int) bool {
	if n == 0 {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("events must carry at least one event"))
		return false
	}
	if n > MaxEventsPerRequest {
		a.deps.WriteError(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("a batch carries at most %d events; send more than that as more than one request", MaxEventsPerRequest))
		return false
	}
	return true
}

// decodeIngest is decode() with the ingest body cap. Unknown fields are refused
// here too, which is what makes a `tenant_id` in the body a visible 400 rather
// than an ignored attempt to own someone else's data.
func (a *API) decodeIngest(w http.ResponseWriter, r *http.Request, into any, what string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)
	return a.decodeBounded(w, r, into, what)
}

// eventTime resolves a producer-supplied timestamp against our clock.
func (a *API) eventTime(raw string, now time.Time) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return now, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("event_at must be an RFC3339 timestamp")
	}
	at = at.UTC()
	if at.After(now.Add(maxClockSkew)) {
		return time.Time{}, errors.New("event_at is in the future; a producer's clock is not a source of truth about when an outage began")
	}
	if at.Before(now.Add(-maxBacklog)) {
		return time.Time{}, errors.New("event_at is more than a week old; a beacon that late would rewrite a window that has already been reported on")
	}
	return at, nil
}

// writeIngestFailure turns the sink's refusal into the right status. A FULL
// queue is 503 + Retry-After — honest backpressure a producer can act on — and
// never a 202 for data that went nowhere.
func (a *API) writeIngestFailure(w http.ResponseWriter, err error, n int) {
	if errors.Is(err, ErrIngestBusy) {
		a.deps.Counters.IngestRefused.Add(int64(n))
		w.Header().Set("Retry-After", strconv.Itoa(ingestRetryAfterSeconds))
		a.deps.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	a.deps.Counters.IngestRejected.Add(int64(n))
	a.deps.LogWarn("an experience ingest batch could not be queued",
		map[string]any{"err": err.Error(), "events": n})
	a.deps.WriteError(w, http.StatusBadRequest, err)
}

// ErrIngestBusy is the sentinel a bounded EventSink returns when its queue is
// full. It is declared HERE, next to the route that maps it onto 503, so the
// transport package and the HTTP layer agree on the contract without either
// importing the other.
var ErrIngestBusy = errors.New("the experience ingest queue is full; retry shortly")
