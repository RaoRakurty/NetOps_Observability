// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// adapter_teams.go — Microsoft Teams as a tenant-scoped problem destination,
// beside PagerDuty and Slack. Same lane as Slack (adapter_slack.go): one card
// per correlated RCA object lifecycle transition (opened / updated / resolved),
// driven by the tenant's own incident policy, outbox and worker — never by raw
// alerts. Distinct from the platform-global Teams notification channel
// (notify/teams.go), which serves the operator.
//
// The card and the POST are notify's (notify/teams_card.go), shared with the
// tenant watch and cloud-notice lanes, so every tenant Teams post has one
// format and one egress path (safehttp: the resolved address is checked at
// dial time, on every redirect hop).
//
// A webhook cannot edit or thread a card, so updates post a follow-up; noise
// is bounded upstream by the sweeper's payload-hash gate. Identity lives in
// correlix_ticket_links (one row per (tenant, corr object, "teams")) — Teams
// has no server-side dedup.
//
// SECURITY: the webhook URL is a bearer secret. It travels only in
// cfg.APIToken (write-only, json:"-"), is never stored on the ticket link
// (that keeps cfg.InstanceURL, the fixed TeamsOrigin label) and never appears
// in an error.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/noclabel"
	"netops/backend/notify"
	"netops/backend/safehttp"
)

// TeamsOrigin is the non-secret label a Teams ticket link carries as its
// instance URL. It is never derived from the tenant's webhook.
const TeamsOrigin = "https://teams.microsoft.com"

type TeamsAdapter struct {
	httpClient *http.Client
}

// NewTeamsAdapterWithClient injects the HTTP client (tests).
func NewTeamsAdapterWithClient(c *http.Client) *TeamsAdapter { return &TeamsAdapter{httpClient: c} }

func NewTeamsAdapter() *TeamsAdapter {
	return &TeamsAdapter{httpClient: safehttp.Client(10 * time.Second)}
}

func (a *TeamsAdapter) Name() string { return "teams" }

func (a *TeamsAdapter) ValidateConfig(cfg SystemConfig) error {
	return notify.ValidateTeamsWebhookURL(cfg.APIToken)
}

func (a *TeamsAdapter) HealthCheck(_ context.Context, cfg SystemConfig) error {
	return a.ValidateConfig(cfg) // a real probe would post a visible card
}

func (a *TeamsAdapter) CreateIncident(ctx context.Context, cfg SystemConfig, p Payload) (Ref, error) {
	if err := a.post(ctx, cfg, teamsTicketMessage("opened", p)); err != nil {
		return Ref{}, err
	}
	key := DedupeKey(cfg.TenantID, p.CorrObjectID, "teams")
	return Ref{Number: shortPDRef(key), SysID: key, URL: ""}, nil
}

func (a *TeamsAdapter) UpdateIncident(ctx context.Context, cfg SystemConfig, _ Ref, p Payload) error {
	return a.post(ctx, cfg, teamsTicketMessage("updated", p))
}

func (a *TeamsAdapter) AddWorkNote(ctx context.Context, cfg SystemConfig, ref Ref, note string) error {
	if strings.TrimSpace(note) == "" {
		return nil
	}
	return a.post(ctx, cfg, notify.TeamsMessage{
		Title: "Note on " + teamsRefHandle(ref), Text: Truncate(note, 800), Accent: "accent", Footer: "Correlix RCA",
	})
}

func (a *TeamsAdapter) ResolveIncident(ctx context.Context, cfg SystemConfig, ref Ref, _ string) error {
	return a.post(ctx, cfg, notify.TeamsMessage{
		Title:  "Resolved — " + teamsRefHandle(ref) + " cleared in Correlix.",
		Accent: "good",
		Footer: "Correlix RCA",
	})
}

func (a *TeamsAdapter) LookupByCorrelationID(_ context.Context, _ SystemConfig, _ string) (Ref, bool, error) {
	return Ref{}, false, nil // webhooks cannot query; the link store is the identity
}

func (a *TeamsAdapter) FetchIncident(_ context.Context, _ SystemConfig, _ Ref) (RemoteIncident, bool, error) {
	return RemoteIncident{}, false, nil
}

// teamsRefHandle names the problem by its friendly Problem ID, never the raw
// dedupe hash (#103 UX-2). The correlation UUID is the middle segment of the
// dedupe key (tenant:corr:system) this adapter stores as SysID.
func teamsRefHandle(ref Ref) string {
	if parts := strings.Split(ref.SysID, ":"); len(parts) == 3 && parts[1] != "" {
		if pid := noclabel.ProblemDisplayID(parts[1]); pid != "" {
			return "problem " + pid
		}
	}
	return "problem " + orDefault(ref.Number, "(unknown)")
}

// teamsTicketMessage renders one lifecycle card: the Problem ID first (the
// same handle the RCA view, Iris and the other destinations carry), the
// verdict, scope and the recommended action, and a link to the RCA.
func teamsTicketMessage(phase string, p Payload) notify.TeamsMessage {
	pid := noclabel.ProblemDisplayID(p.CorrObjectID)
	head := strings.ToUpper(phase[:1]) + phase[1:]
	title := head + ": " + p.Title
	if pid != "" {
		title = head + ": [" + pid + "] " + p.Title
	}
	accent := map[string]string{"opened": "attention", "updated": "warning"}[phase]
	if accent == "" {
		accent = "good"
	}
	facts := []notify.TeamsFact{
		{Title: "Verdict", Value: p.Verdict + fmt.Sprintf(" (%.0f%%)", p.Confidence*100)},
		{Title: "Scope", Value: orDefault(p.AffectedScope, "—")},
	}
	if p.RecommendedAction != "" && phase != "resolved" {
		facts = append(facts, notify.TeamsFact{Title: "Recommended action", Value: Truncate(p.RecommendedAction, 300)})
	}
	return notify.TeamsMessage{
		Title:   title,
		Text:    Truncate(p.Summary, 600),
		Facts:   facts,
		LinkURL: p.RCAURL,
		Accent:  accent,
		Footer:  "Correlix RCA · " + orDefault(pid, p.CorrObjectID),
	}
}

// post sends one card and classifies the answer for the outbox: 2xx sent,
// 429 rate-limited (Retry-After honoured), other 4xx permanent (the same bytes
// cannot succeed: a deleted workflow, a revoked webhook), 5xx and transport
// failures transient.
func (a *TeamsAdapter) post(ctx context.Context, cfg SystemConfig, m notify.TeamsMessage) error {
	if err := a.ValidateConfig(cfg); err != nil {
		return PermanentDeliveryError{err}
	}
	res, err := notify.PostTeamsMessage(ctx, a.client(), cfg.APIToken, m)
	if err != nil {
		return err // transient; secret-free by construction
	}
	switch {
	case res.Status < 300:
		return nil
	case res.Status == http.StatusTooManyRequests:
		delay := res.RetryAfter
		if delay <= 0 {
			delay = 30 * time.Second
		}
		return RateLimitedError{After: delay}
	case res.Status >= 400 && res.Status < 500:
		return PermanentDeliveryError{fmt.Errorf("teams: webhook rejected the card (%d)", res.Status)}
	default:
		return fmt.Errorf("teams: webhook status %d", res.Status)
	}
}

func (a *TeamsAdapter) client() *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return safehttp.Client(10 * time.Second)
}
