// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// event.go — ExperienceEvent / ExperienceSession / BusinessEvent.
//
// CONTRACTS ONLY IN THIS SLICE, and deliberately so. Correlix has no first-party
// RUM snippet, no desktop agent and no browser runner in production, so nothing
// produces these yet. Phase P is explicit that infrastructure is added when
// there is a requirement, not before; landing the storage lane for a producer
// that does not exist would be exactly the "dozens of empty interfaces" the
// brief warns against.
//
// What DOES land: the canonical shapes, their validation, the pseudonymous-user
// discipline, the actor-type vocabulary that already reserves AI_AGENT (Phase
// N), the external-schema fields an OpenTelemetry adapter fills in (Phase M),
// and the [EventSink] seam the ingest route will attach to. The next slice adds
// the route, the `netops.experience` topic and the ClickHouse table; the shapes
// will not have to change to get there, which is the entire point of writing
// them now.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Actor types (Phase C.2). AI_AGENT is reserved NOW so an agent journey does
// not need a schema change later — and so that a synthetic run can never be
// silently counted as a person.
const (
	ActorHuman     = "HUMAN"
	ActorSynthetic = "SYNTHETIC"
	ActorAPIClient = "API_CLIENT"
	ActorAIAgent   = "AI_AGENT"
)

var knownActorTypes = map[string]bool{
	ActorHuman: true, ActorSynthetic: true, ActorAPIClient: true, ActorAIAgent: true,
}

// ValidActorType reports whether a is a declared actor type.
func ValidActorType(a string) bool { return knownActorTypes[a] }

// Experience event types.
const (
	EventPageView    = "page_view"
	EventInteraction = "interaction"
	EventAPICall     = "api_call"
	EventError       = "error"
	EventNavigation  = "navigation"
	EventVital       = "web_vital"
	EventJourneyStep = "journey_step"
)

// WebVitals are the browser-measured quality numbers. Every field is a pointer:
// an unreported vital is absent, never 0 (a 0 CLS is excellent and a 0 LCP is
// impossible, so a shared zero would be read two different wrong ways).
type WebVitals struct {
	LCPMs  *float64 `json:"lcp_ms,omitempty"`
	INPMs  *float64 `json:"inp_ms,omitempty"`
	CLS    *float64 `json:"cls,omitempty"`
	TTFBMs *float64 `json:"ttfb_ms,omitempty"`
	FCPMs  *float64 `json:"fcp_ms,omitempty"`
}

// AgentContext is the Phase N reservation: the fields an AI-agent journey needs,
// declared now, provider-neutral, and never populated by anything today.
type AgentContext struct {
	AgentID        string   `json:"agent_id,omitempty"`
	AgentVersion   string   `json:"agent_version,omitempty"`
	Model          string   `json:"model,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	ConversationID string   `json:"conversation_id,omitempty"`
	RunID          string   `json:"run_id,omitempty"`
	ToolName       string   `json:"tool_name,omitempty"`
	ToolDurationMs *float64 `json:"tool_duration_ms,omitempty"`
	Retries        int      `json:"retries,omitempty"`
	TokensIn       int      `json:"tokens_in,omitempty"`
	TokensOut      int      `json:"tokens_out,omitempty"`
	CostMicros     int64    `json:"cost_micros,omitempty"`
	Outcome        string   `json:"outcome,omitempty"`
}

// ExperienceEvent is one thing that happened to one actor.
type ExperienceEvent struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`

	SessionID string `json:"session_id,omitempty"`
	// UserRef is a PSEUDONYMOUS user reference — a per-tenant salted digest,
	// never a username, email or raw id. The data class on the provenance says
	// so, and [ExperienceEvent.Validate] refuses anything that looks like a
	// direct identifier reaching this field.
	UserRef string `json:"user_ref,omitempty"`

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
	Cohort       Cohort            `json:"cohort"`

	TraceID string `json:"trace_id,omitempty"`
	SpanID  string `json:"span_id,omitempty"`

	ActorType string        `json:"actor_type"`
	Agent     *AgentContext `json:"agent,omitempty"`

	// BusinessContext is an extensible, tenant-defined map. Deliberately
	// string→string: a typed schema here would hard-code one industry's idea of
	// a transaction, and the owner's Phase C.7 forbids that.
	BusinessContext map[string]string `json:"business_context,omitempty"`

	Provenance `json:"provenance"`
}

// MaxContextEntries bounds the free-form maps. A beacon is a measurement, not a
// document store.
const MaxContextEntries = 24

// Validate normalizes an event and refuses one that carries a direct identifier
// where a pseudonymous reference belongs.
func (e *ExperienceEvent) Validate() error {
	e.ID = clip(strings.TrimSpace(e.ID), MaxIDBytes)
	if e.ID == "" {
		return errors.New("experience event: id is required")
	}
	e.TenantID = strings.ToLower(strings.TrimSpace(e.TenantID))
	if e.TenantID == "" || e.TenantID == "*" {
		return errors.New("experience event: a concrete tenant is required")
	}
	e.SessionID = clip(strings.TrimSpace(e.SessionID), MaxIDBytes)
	e.UserRef = clip(strings.TrimSpace(e.UserRef), MaxIDBytes)
	if err := requirePseudonymous(e.UserRef); err != nil {
		return fmt.Errorf("experience event %s: %w", e.ID, err)
	}
	e.App = labelSafe(e.App)
	if e.App == "" {
		return fmt.Errorf("experience event %s: app is required", e.ID)
	}
	e.Environment, e.Release = labelSafe(e.Environment), labelSafe(e.Release)
	e.Type = strings.ToLower(strings.TrimSpace(e.Type))
	switch e.Type {
	case EventPageView, EventInteraction, EventAPICall, EventError, EventNavigation, EventVital, EventJourneyStep:
	default:
		return fmt.Errorf("experience event %s: unknown type %q", e.ID, clip(e.Type, 40))
	}
	e.Action = clip(strings.TrimSpace(e.Action), MaxLabelBytes)
	e.Route = clip(strings.TrimSpace(e.Route), MaxLabelBytes)
	e.Error = clip(strings.TrimSpace(e.Error), MaxSummaryBytes)
	if e.StatusCode != 0 && (e.StatusCode < 100 || e.StatusCode > 599) {
		return fmt.Errorf("experience event %s: status_code must be 0 or a 100..599 HTTP status", e.ID)
	}
	if e.DurationMs != nil && *e.DurationMs < 0 {
		return fmt.Errorf("experience event %s: duration_ms must not be negative", e.ID)
	}
	e.ActorType = strings.ToUpper(strings.TrimSpace(e.ActorType))
	if e.ActorType == "" {
		e.ActorType = ActorHuman
	}
	if !ValidActorType(e.ActorType) {
		return fmt.Errorf("experience event %s: unknown actor_type %q", e.ID, clip(e.ActorType, 40))
	}
	if e.Agent != nil && e.ActorType != ActorAIAgent {
		return fmt.Errorf("experience event %s: agent context is only valid for an AI_AGENT actor", e.ID)
	}
	e.JourneyID = clip(strings.TrimSpace(e.JourneyID), MaxIDBytes)
	e.StepID = labelSafe(e.StepID)
	if err := boundMap(e.FeatureFlags, "feature_flags"); err != nil {
		return fmt.Errorf("experience event %s: %w", e.ID, err)
	}
	if err := boundMap(e.BusinessContext, "business_context"); err != nil {
		return fmt.Errorf("experience event %s: %w", e.ID, err)
	}
	if e.DataClass == "" {
		// Default-closed: an event carrying a user reference is pseudonymous
		// data unless the producer says otherwise, never "internal".
		if e.UserRef != "" {
			e.DataClass = DataClassPseudonymousUser
		} else {
			e.DataClass = DataClassCustomerMetadata
		}
	}
	if e.UserRef != "" && DataClassRank(e.DataClass) < dataClassRank[DataClassPseudonymousUser] {
		return fmt.Errorf("experience event %s: an event carrying a user reference cannot be classified below %s", e.ID, DataClassPseudonymousUser)
	}
	return e.Provenance.Validate()
}

// ExperienceSession is one session: a person, a synthetic run, an API client or
// an agent, over a span of time.
type ExperienceSession struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`

	ActorType string `json:"actor_type"`
	UserRef   string `json:"user_ref,omitempty"`

	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	App         string `json:"app"`
	Release     string `json:"release,omitempty"`
	Environment string `json:"environment,omitempty"`

	Cohort Cohort `json:"cohort"`

	// ReplayRef is a POINTER to a session replay held elsewhere, never the
	// replay. It is a separate field from everything else on purpose: replay
	// access is role-controlled and audited, and a reference is what an access
	// check can be attached to (Phase L).
	ReplayRef string `json:"replay_ref,omitempty"`

	Events            int `json:"events"`
	Errors            int `json:"errors"`
	JourneysAttempted int `json:"journeys_attempted"`
	JourneysSucceeded int `json:"journeys_succeeded"`

	// Health is the session's aggregate state — good | degraded | failed |
	// unknown. `unknown` is the default and is never rendered as good.
	Health string `json:"health"`

	Agent      *AgentContext `json:"agent,omitempty"`
	Provenance `json:"provenance"`
}

// Session health states.
const (
	SessionGood     = "good"
	SessionDegraded = "degraded"
	SessionFailed   = "failed"
	SessionUnknown  = "unknown"
)

// Validate normalizes a session.
func (s *ExperienceSession) Validate() error {
	s.ID = clip(strings.TrimSpace(s.ID), MaxIDBytes)
	if s.ID == "" {
		return errors.New("experience session: id is required")
	}
	s.TenantID = strings.ToLower(strings.TrimSpace(s.TenantID))
	if s.TenantID == "" || s.TenantID == "*" {
		return errors.New("experience session: a concrete tenant is required")
	}
	s.ActorType = strings.ToUpper(strings.TrimSpace(s.ActorType))
	if s.ActorType == "" {
		s.ActorType = ActorHuman
	}
	if !ValidActorType(s.ActorType) {
		return fmt.Errorf("experience session %s: unknown actor_type %q", s.ID, clip(s.ActorType, 40))
	}
	s.UserRef = clip(strings.TrimSpace(s.UserRef), MaxIDBytes)
	if err := requirePseudonymous(s.UserRef); err != nil {
		return fmt.Errorf("experience session %s: %w", s.ID, err)
	}
	s.App = labelSafe(s.App)
	if s.App == "" {
		return fmt.Errorf("experience session %s: app is required", s.ID)
	}
	s.Release, s.Environment = labelSafe(s.Release), labelSafe(s.Environment)
	if s.StartedAt.IsZero() {
		return fmt.Errorf("experience session %s: started_at is required", s.ID)
	}
	if s.EndedAt != nil && s.EndedAt.Before(s.StartedAt) {
		return fmt.Errorf("experience session %s: ended_at precedes started_at", s.ID)
	}
	s.ReplayRef = clip(strings.TrimSpace(s.ReplayRef), MaxIDBytes)
	switch s.Health {
	case SessionGood, SessionDegraded, SessionFailed:
	case "":
		s.Health = SessionUnknown
	case SessionUnknown:
	default:
		return fmt.Errorf("experience session %s: unknown health %q", s.ID, clip(s.Health, 40))
	}
	if s.DataClass == "" {
		s.DataClass = DataClassPseudonymousUser
	}
	return s.Provenance.Validate()
}

// BusinessEvent is one business outcome. `Type` is a free string on purpose —
// login, purchase, booking, payment, report, claim, an API transaction, or
// whatever this tenant's business actually does. Hard-coding e-commerce
// semantics here would make the model wrong for most customers on day one.
type BusinessEvent struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`

	Type      string `json:"business_event_type"`
	App       string `json:"app,omitempty"`
	JourneyID string `json:"journey_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	Success bool `json:"success"`
	// Value and Currency are optional and travel together. A value with no
	// currency is refused: an unlabelled number is not an amount.
	Value    *float64 `json:"value,omitempty"`
	Currency string   `json:"currency,omitempty"`
	Quantity int      `json:"quantity,omitempty"`

	Cohort     Cohort            `json:"cohort"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Provenance `json:"provenance"`
}

// Validate normalizes a business event.
func (b *BusinessEvent) Validate() error {
	b.ID = clip(strings.TrimSpace(b.ID), MaxIDBytes)
	if b.ID == "" {
		return errors.New("business event: id is required")
	}
	b.TenantID = strings.ToLower(strings.TrimSpace(b.TenantID))
	if b.TenantID == "" || b.TenantID == "*" {
		return errors.New("business event: a concrete tenant is required")
	}
	b.Type = labelSafe(strings.ToLower(b.Type))
	if b.Type == "" {
		return fmt.Errorf("business event %s: business_event_type is required", b.ID)
	}
	b.App = labelSafe(b.App)
	b.JourneyID = clip(strings.TrimSpace(b.JourneyID), MaxIDBytes)
	b.SessionID = clip(strings.TrimSpace(b.SessionID), MaxIDBytes)
	b.Currency = clip(strings.ToUpper(strings.TrimSpace(b.Currency)), 8)
	if b.Value != nil {
		if *b.Value < 0 {
			return fmt.Errorf("business event %s: value must not be negative", b.ID)
		}
		if b.Currency == "" {
			return fmt.Errorf("business event %s: a value needs a currency", b.ID)
		}
	}
	if b.Quantity < 0 {
		return fmt.Errorf("business event %s: quantity must not be negative", b.ID)
	}
	if err := boundMap(b.Attributes, "attributes"); err != nil {
		return fmt.Errorf("business event %s: %w", b.ID, err)
	}
	if b.DataClass == "" {
		b.DataClass = DataClassCustomerMetadata
	}
	return b.Provenance.Validate()
}

// EventSink is the seam the ingest routes will attach to when a producer
// exists: a bounded, backpressure-aware writer onto the platform's existing
// event lane. It is declared here so the shapes above have somewhere to go
// without this package ever learning about Kafka or ClickHouse.
type EventSink interface {
	// WriteEvents accepts a bounded batch. It MUST return an error rather than
	// dropping silently — a dropped experience event is a user whose bad day
	// the product never saw (§10).
	WriteEvents(ctx context.Context, events []ExperienceEvent) error
	WriteBusinessEvents(ctx context.Context, events []BusinessEvent) error
}

// ── privacy helpers (Phase L) ───────────────────────────────────────────────

// directIdentifierMarkers are the shapes a raw identifier has. The check is
// deliberately crude and deliberately REFUSES rather than hashing: silently
// pseudonymising a caller's mistake would teach the caller that sending real
// identifiers is fine.
var directIdentifierMarkers = []string{"@", "+1", "ssn", "passport"}

func requirePseudonymous(ref string) error {
	if ref == "" {
		return nil
	}
	low := strings.ToLower(ref)
	for _, m := range directIdentifierMarkers {
		if strings.Contains(low, m) {
			return errors.New("user_ref must be a pseudonymous reference, not a direct identifier — hash it per tenant before sending it")
		}
	}
	return nil
}

func boundMap(m map[string]string, name string) error {
	if len(m) > MaxContextEntries {
		return fmt.Errorf("%s carries more than %d entries", name, MaxContextEntries)
	}
	for k, v := range m {
		if len(k) > MaxLabelBytes || len(v) > MaxLabelBytes {
			return fmt.Errorf("%s entry %q is too long", name, clip(k, 40))
		}
	}
	return nil
}
