// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// ticketing_slack.go — Slack as a tenant-scoped RCA incident-policy
// destination (#103-E). Human-collaboration lane: one rich message per
// correlated RCA object lifecycle transition (opened / updated / resolved),
// driven by the same per-tenant policies, outbox, and worker as ServiceNow
// and PagerDuty — never by raw alerts. Distinct from the platform-global
// Slack notification channel (notify/slack.go), which serves the operator.
//
// Incoming webhooks cannot edit or thread without a bot token, so lifecycle
// updates post follow-up messages; noise is bounded upstream by the sweeper's
// payload-hash gate (an update only enqueues when the RCA state materially
// changed). Identity/dedup lives in correlix_ticket_links (one link per
// (tenant, corr object, system)) — Slack itself has no server-side dedup.
//
// SECURITY: the webhook URL embeds a bearer secret. It travels in
// cfg.APIToken (write-only, json:"-") and is NEVER stored on the ticket link
// (upsertLink persists cfg.InstanceURL, which for Slack is the non-secret
// API origin) nor echoed in errors.

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

const SlackHooksOrigin = "https://hooks.slack.com"

type SlackAdapter struct {
	httpClient *http.Client
}

// NewSlackAdapterWithClient injects the HTTP client (integrator tests).
func NewSlackAdapterWithClient(c *http.Client) *SlackAdapter { return &SlackAdapter{httpClient: c} }

func NewSlackAdapter() *SlackAdapter {
	return &SlackAdapter{httpClient: safehttp.Client(10 * time.Second)}
}

func (a *SlackAdapter) Name() string { return "slack" }

func (a *SlackAdapter) ValidateConfig(cfg SystemConfig) error {
	u := strings.TrimSpace(cfg.APIToken)
	if u == "" {
		return errors.New("slack: webhook URL is required")
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return errors.New("slack: webhook URL must be http(s)")
	}
	return nil
}

func (a *SlackAdapter) HealthCheck(_ context.Context, cfg SystemConfig) error {
	return a.ValidateConfig(cfg) // a real probe would post a visible message
}

func (a *SlackAdapter) CreateIncident(ctx context.Context, cfg SystemConfig, p Payload) (Ref, error) {
	if err := a.post(ctx, cfg, slackTicketMessage("opened", p)); err != nil {
		return Ref{}, err
	}
	key := DedupeKey(cfg.TenantID, p.CorrObjectID, "slack")
	return Ref{Number: shortPDRef(key), SysID: key, URL: ""}, nil
}

func (a *SlackAdapter) UpdateIncident(ctx context.Context, cfg SystemConfig, _ Ref, p Payload) error {
	return a.post(ctx, cfg, slackTicketMessage("updated", p))
}

func (a *SlackAdapter) AddWorkNote(ctx context.Context, cfg SystemConfig, _ Ref, note string) error {
	if strings.TrimSpace(note) == "" {
		return nil
	}
	return a.post(ctx, cfg, map[string]any{"text": ":memo: " + Truncate(note, 800)})
}

func (a *SlackAdapter) ResolveIncident(ctx context.Context, cfg SystemConfig, ref Ref, _ string) error {
	// Name the incident by its friendly Problem ID, never the raw dedupe-hash ref
	// (#103 UX-2). The correlation UUID is the middle segment of the dedupe key
	// (tenant:corr:system) this adapter stores as SysID.
	handle := ref.Number
	if parts := strings.Split(ref.SysID, ":"); len(parts) == 3 && parts[1] != "" {
		handle = noclabel.ProblemDisplayID(parts[1])
	}
	return a.post(ctx, cfg, map[string]any{
		"text": ":white_check_mark: *Resolved* — incident " + handle + " cleared in Correlix.",
	})
}

func (a *SlackAdapter) LookupByCorrelationID(_ context.Context, _ SystemConfig, _ string) (Ref, bool, error) {
	return Ref{}, false, nil // webhooks cannot query; link store is the identity
}

func (a *SlackAdapter) FetchIncident(_ context.Context, _ SystemConfig, _ Ref) (RemoteIncident, bool, error) {
	return RemoteIncident{}, false, nil
}

// slackTicketMessage renders the lifecycle message (classic attachment format —
// the one incoming webhooks fully support).
func slackTicketMessage(phase string, p Payload) map[string]any {
	color := map[string]string{"opened": "#d63031", "updated": "#f39c12"}[phase]
	if color == "" {
		color = "#2eaa60"
	}
	// Lead with the friendly Correlix Problem ID (P-XXXXXX) — the SAME handle the
	// RCA Inspector, Iris AI and ServiceNow tickets carry (#103 UX-2: no raw hex
	// identifiers in notifications; the UUID stays canonical in the dedupe key).
	pid := noclabel.ProblemDisplayID(p.CorrObjectID)
	title := strings.ToUpper(phase[:1]) + phase[1:] + ": " + p.Title
	if pid != "" {
		title = strings.ToUpper(phase[:1]) + phase[1:] + ": [" + pid + "] " + p.Title
	}
	fields := []map[string]any{
		{"title": "Verdict", "value": p.Verdict + fmt.Sprintf(" (%.0f%%)", p.Confidence*100), "short": true},
		{"title": "Scope", "value": orDefault(p.AffectedScope, "—"), "short": true},
	}
	if p.RecommendedAction != "" && phase != "resolved" {
		fields = append(fields, map[string]any{"title": "Recommended action", "value": Truncate(p.RecommendedAction, 300), "short": false})
	}
	att := map[string]any{
		"color":      color,
		"title":      title,
		"title_link": p.RCAURL,
		"text":       Truncate(p.Summary, 600),
		"fields":     fields,
		"footer":     "Correlix RCA · " + orDefault(pid, p.CorrObjectID),
	}
	return map[string]any{"text": title, "attachments": []map[string]any{att}}
}

func (a *SlackAdapter) post(ctx context.Context, cfg SystemConfig, body map[string]any) error {
	if err := a.ValidateConfig(cfg); err != nil {
		return PermanentDeliveryError{err}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return PermanentDeliveryError{err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(cfg.APIToken), bytes.NewReader(buf))
	if err != nil {
		return PermanentDeliveryError{errors.New("slack: invalid webhook URL")}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return err // transient
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048)) // best-effort: drain for connection reuse
	switch {
	case resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		delay := 30 * time.Second
		if ra, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && ra > 0 && ra <= 3600 {
			delay = time.Duration(ra) * time.Second
		}
		return RateLimitedError{After: delay}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// no_service / invalid_payload / channel_is_archived — retrying the
		// same bytes cannot succeed. Secret-safe: never echo the URL.
		return PermanentDeliveryError{fmt.Errorf("slack: webhook rejected message (%d)", resp.StatusCode)}
	default:
		return fmt.Errorf("slack: webhook status %d", resp.StatusCode)
	}
}

func (a *SlackAdapter) client() *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return safehttp.Client(10 * time.Second)
}
