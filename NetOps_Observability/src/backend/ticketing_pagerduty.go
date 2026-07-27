package main

// ticketing_pagerduty.go — PagerDuty as an RCA incident-policy destination
// (#103). This is the CUSTOMER paging lane: one PagerDuty incident per
// correlated RCA object, driven by the same per-tenant incident policies,
// outbox, and worker as ServiceNow (#78) — never by raw alerts. The platform
// self-health lane (notify/pagerduty.go behind the global routing key +
// layer allowlist) is deliberately separate and engine-independent.
//
// Identity: dedup_key = "correlix:" + dedupeKey(tenant, corrObjectID,
// "pagerduty") — immutable tenant id + stable RCA object UUID + destination.
// Titles, severity, verdict, device names, and tenant slugs never change it.
// Events API v2 dedup semantics make trigger/update/resolve idempotent on
// that key, so a worker retry or crash-after-send can never page twice.
//
// Lifecycle mapping (Events API v2):
//   create  -> event_action=trigger            (opens the PD incident)
//   update  -> trigger, SAME dedup_key         (updates payload/severity)
//   resolve -> event_action=resolve, SAME key  (closes it)
//   add_work_note -> no-op success: Events v2 has no notes; the note stays in
//     the Correlix audit trail (documented — PD is paging, not ITSM).
// Policy-exit (severity/verdict drops below the policy) follows ServiceNow
// semantics: the ticket/incident stays open until the RCA object resolves —
// exit never silently resolves a page.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"netops/backend/internal/noclabel"
	"strconv"
	"strings"
	"time"

	"netops/backend/safehttp"
)

const pdDefaultEventsBase = "https://events.pagerduty.com"

// pagerDutyTicketAdapter implements ticketAdapter against Events API v2.
// httpClient injectable for tests (fake PD server); the events base URL comes
// from cfg.InstanceURL (resolver defaults it) so tests need no globals.
type pagerDutyTicketAdapter struct {
	httpClient *http.Client
}

func newPagerDutyTicketAdapter() *pagerDutyTicketAdapter {
	return &pagerDutyTicketAdapter{httpClient: safehttp.Client(10 * time.Second)}
}

func (a *pagerDutyTicketAdapter) Name() string { return "pagerduty" }

func (a *pagerDutyTicketAdapter) ValidateConfig(cfg ticketSystemConfig) error {
	if strings.TrimSpace(cfg.APIToken) == "" {
		return errors.New("pagerduty: routing key is required")
	}
	return nil
}

// HealthCheck: Events API v2 is send-only (no read endpoint) and a probe would
// page a human. Config-shape validation is the honest health check here.
func (a *pagerDutyTicketAdapter) HealthCheck(_ context.Context, cfg ticketSystemConfig) error {
	return a.ValidateConfig(cfg)
}

// pdTicketDedupKey is the stable per-destination incident identity.
func pdTicketDedupKey(tenantID, corrObjectID string) string {
	return "correlix:" + dedupeKey(tenantID, corrObjectID, "pagerduty")
}

func (a *pagerDutyTicketAdapter) CreateIncident(ctx context.Context, cfg ticketSystemConfig, p ticketPayload) (ticketRef, error) {
	key := pdTicketDedupKey(cfg.TenantID, p.CorrObjectID)
	if err := a.send(ctx, cfg, "trigger", key, &p); err != nil {
		return ticketRef{}, err
	}
	// PD has no sys_id/number; the dedup key IS the incident identity. Stored
	// in SysID so linkRef/updates/resolves round-trip through the same field
	// the worker already uses. Number carries a short operator-visible tail.
	return ticketRef{Number: shortPDRef(key), SysID: key, URL: ""}, nil
}

func (a *pagerDutyTicketAdapter) UpdateIncident(ctx context.Context, cfg ticketSystemConfig, ref ticketRef, p ticketPayload) error {
	return a.send(ctx, cfg, "trigger", ref.SysID, &p)
}

// AddWorkNote: Events v2 has no work-note concept. Success no-op — the note
// remains in Correlix's ticket_audit_log; re-triggering just to carry a note
// would re-page responders.
func (a *pagerDutyTicketAdapter) AddWorkNote(_ context.Context, _ ticketSystemConfig, _ ticketRef, _ string) error {
	return nil
}

func (a *pagerDutyTicketAdapter) ResolveIncident(ctx context.Context, cfg ticketSystemConfig, ref ticketRef, _ string) error {
	return a.send(ctx, cfg, "resolve", ref.SysID, nil)
}

// LookupByCorrelationID: Events v2 cannot query. Safe: create retries reuse
// the same deterministic dedup_key, so a duplicate trigger is an update at
// PagerDuty, never a second incident.
func (a *pagerDutyTicketAdapter) LookupByCorrelationID(_ context.Context, _ ticketSystemConfig, _ string) (ticketRef, bool, error) {
	return ticketRef{}, false, nil
}

// FetchIncident: no read API on Events v2. Inbound ack-sync is OUT OF SCOPE by
// design (#103, owner 2026-07-12): Correlix→PD is one-way — telemetry is the
// resolution authority, the ITSM records human-response phases. If ever needed,
// poll the PD REST API with a read-only token (like the SN inbound poller).
func (a *pagerDutyTicketAdapter) FetchIncident(_ context.Context, _ ticketSystemConfig, _ ticketRef) (snowIncident, bool, error) {
	return snowIncident{}, false, nil
}

// pdEventSeverity maps the policy-mapped urgency (1 highest..3) + verdict to
// the Events v2 severity enum. Deterministic; PD-side urgency derives from
// this via the PD service's own rules.
func pdEventSeverity(p ticketPayload) string {
	switch {
	case p.Urgency <= 1:
		return "critical"
	case p.Urgency == 2:
		return "error"
	default:
		return "warning"
	}
}

func (a *pagerDutyTicketAdapter) send(ctx context.Context, cfg ticketSystemConfig, action, dedupKey string, p *ticketPayload) error {
	if err := a.ValidateConfig(cfg); err != nil {
		return permanentDeliveryError{err}
	}
	body := map[string]any{
		"routing_key":  cfg.APIToken,
		"event_action": action,
		"dedup_key":    dedupKey,
	}
	if p != nil {
		// Lead with the friendly Correlix Problem ID (P-XXXXXX) — one handle
		// across PagerDuty, ServiceNow, Slack and the RCA Inspector (#103 UX-2:
		// no raw hex in the operator-facing summary; the UUID stays canonical in
		// dedup_key / custom_details.correlation_id).
		pid := noclabel.ProblemDisplayID(p.CorrObjectID)
		summary := orDefault(p.Title, "Correlix RCA incident")
		if pid != "" {
			summary = "[" + pid + "] " + summary
		}
		details := map[string]any{
			"verdict":            p.Verdict,
			"confidence":         fmt.Sprintf("%.2f", p.Confidence),
			"correlation_id":     p.CorrObjectID,
			"problem_id":         pid,
			"summary":            p.Summary,
			"recommended_action": p.RecommendedAction,
			"suspected_owner":    p.Owner,
			"affected_scope":     p.AffectedScope,
		}
		body["payload"] = map[string]any{
			"summary":        summary,
			"source":         "correlix",
			"severity":       pdEventSeverity(*p),
			"component":      p.AffectedScope,
			"class":          p.Signature,
			"custom_details": details,
		}
		if p.RCAURL != "" {
			body["links"] = []map[string]string{{"href": p.RCAURL, "text": "Correlix RCA Inspector"}}
		}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return permanentDeliveryError{err}
	}
	base := strings.TrimRight(orDefault(cfg.InstanceURL, pdDefaultEventsBase), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v2/enqueue", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return err // transient: worker backoff
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		delay := 30 * time.Second
		if ra, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && ra > 0 && ra <= 3600 {
			delay = time.Duration(ra) * time.Second
		}
		return rateLimitedError{After: delay}
	case resp.StatusCode == http.StatusBadRequest:
		// Payload rejected — retrying identical bytes cannot succeed.
		return permanentDeliveryError{fmt.Errorf("pagerduty: events API rejected payload (400)")}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// Routing key revoked/invalid — retry won't fix it; secret-safe error.
		return permanentDeliveryError{fmt.Errorf("pagerduty: routing key rejected (%d)", resp.StatusCode)}
	default:
		return fmt.Errorf("pagerduty: events API status %d", resp.StatusCode)
	}
}

func (a *pagerDutyTicketAdapter) client() *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return safehttp.Client(10 * time.Second)
}

func shortPDRef(dedupKey string) string {
	if len(dedupKey) <= 20 {
		return dedupKey
	}
	return "PD-" + dedupKey[len(dedupKey)-12:]
}
