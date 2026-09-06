// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package integration is the pluggable, bidirectional ITSM/collaboration
// integration core for the NMS — the "integration control plane" described in
// docs/design/itsm-integration-platform.md.
//
// This package is PURE and ISOLATED: it has no dependency on the main server,
// the database, or net/http handlers beyond reading an inbound *http.Request for
// signature verification. It defines the canonical event model, the provider
// plugin interface, the causality/ordering engine, and the state-reconciliation
// engine. The main package wires these into HTTP endpoints, the PG job queue,
// and the incident lifecycle in a later phase (P2); nothing here is live yet.
//
// Layering (the orchestrator is a 6-layer pipeline; this package owns 2,4,5):
//
//	1 Outbound Router          (main: enqueue)
//	2 Provider Adapter         (this: Provider)         <—
//	3 Inbound Ingestion        (main: webhook handler)
//	4 Normalization + Ordering (this: Provider.Normalize + Orderer)  <—
//	5 State Reconciler         (this: MappingEngine)    <—
//	6 Incident Lifecycle       (main: incident.Transition)
package integration

import (
	"errors"
	"net/http"
	"time"
)

// ErrNotImplemented is returned by capability methods a provider does not support
// (e.g. Slack has no Poll). Callers gate on Capabilities() and never see this in
// the normal path.
var ErrNotImplemented = errors.New("integration: not implemented for this provider")

// ErrSignatureInvalid is returned by VerifyWebhook on a failed signature / replay
// check. The inbound layer maps it to a 401 and drops the event (fail-closed).
var ErrSignatureInvalid = errors.New("integration: webhook signature invalid")

// EventType is the canonical, provider-independent classification of an inbound
// change. Providers normalize their native payloads into these.
type EventType string

const (
	EventCreated      EventType = "incident.created"
	EventUpdated      EventType = "incident.updated"
	EventAcknowledged EventType = "incident.acknowledged"
	EventResolved     EventType = "incident.resolved"
	EventAssigned     EventType = "incident.assigned"
	EventCommentAdded EventType = "incident.comment_added"
)

// InternalState is the NMS-side incident state the reconciler targets. These
// mirror the incident lifecycle in the main package (translated at the wiring
// layer) but are defined here so this package stays dependency-free.
type InternalState string

const (
	StateOpen          InternalState = "open"
	StateAcknowledged  InternalState = "acknowledged"
	StateInvestigating InternalState = "investigating"
	StateResolved      InternalState = "resolved"
	StateClosed        InternalState = "closed"
)

// IsTerminal reports whether a state is terminal (resolved/closed). Terminal
// states are owned by NMS in the conflict ladder (§4c).
func (s InternalState) IsTerminal() bool { return s == StateResolved || s == StateClosed }

// IntegrationEvent is the canonical inbound event after normalization. The three
// idempotency keys (§4d) and the ordering key (§4a) are first-class.
type IntegrationEvent struct {
	Provider string
	Tenant   string

	// 3-level idempotency keys (§4d).
	ProviderEvtID string // (1) raw dedup — provider delivery/event id
	ExternalID    string // (2) logical dedup — ticket id in the external system
	AlertID       string // (3) business dedup — internal alert/incident id (if known)

	// Ordering / causality (§4a).
	ExternalSeq int64     // provider monotonic version (SN sys_mod_count, Jira changelog id…); 0 if absent
	OccurredAt  time.Time // provider event time; tie-breaker only (clock-skew unsafe alone)

	// Payload.
	Type          EventType
	ExternalState string // raw external state ("In Progress", "6", "resolved", …)
	Actor         string
	Comment       string
	Assignee      string
	Raw           []byte
}

// Capabilities declares what a provider supports, so the orchestrator can gate
// behavior without type-switching on the concrete provider.
type Capabilities struct {
	Ticketing   bool // SN/Jira: yes; PagerDuty: partial; Slack: no
	Webhooks    bool // accepts inbound webhooks
	Polling     bool // supports drift reconciliation polling
	Interactive bool // Slack Block Kit actions / PagerDuty ack
}

// Provider is a pluggable ITSM/collaboration integration. Registered by type; the
// orchestrator core never imports a concrete provider (CLAUDE.md §4/§7). P1
// implements the INBOUND surface (the genuinely new translation work); the
// outbound Apply path keeps using the existing notify connectors until P2.
type Provider interface {
	Type() string
	Capabilities() Capabilities

	// VerifyWebhook authenticates a raw inbound request (signature + replay
	// window) and returns the verified body. Returns ErrSignatureInvalid on
	// failure. It must NOT mutate global state.
	VerifyWebhook(r *http.Request, body []byte, secret string) error

	// Normalize parses a verified provider payload into zero or more canonical
	// events (a single webhook may carry several changes).
	Normalize(tenant string, body []byte) ([]IntegrationEvent, error)
}

// Registry maps provider type → Provider. Adding a provider is one Register call;
// the core stays provider-agnostic.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{providers: map[string]Provider{}} }

// Register adds a provider, keyed by its Type(). A duplicate type overwrites
// (last registration wins) so a deployment can substitute an implementation.
func (r *Registry) Register(p Provider) { r.providers[p.Type()] = p }

// Get returns the provider for a type, or (nil,false).
func (r *Registry) Get(typ string) (Provider, bool) {
	p, ok := r.providers[typ]
	return p, ok
}

// Types returns the registered provider types (unordered).
func (r *Registry) Types() []string {
	out := make([]string, 0, len(r.providers))
	for t := range r.providers {
		out = append(out, t)
	}
	return out
}

// DefaultRegistry returns a registry with all built-in providers registered.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewServiceNowProvider())
	r.Register(NewJiraProvider())
	r.Register(NewPagerDutyProvider())
	r.Register(NewSlackProvider())
	return r
}
