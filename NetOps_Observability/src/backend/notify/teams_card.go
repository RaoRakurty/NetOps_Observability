// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// teams_card.go — the Microsoft Teams message every Teams destination sends:
// a tenant's problems (internal/ticketing TeamsAdapter), its own watch alerts
// (tenant_watch.go) and cloud notices (cloud_notify.go), and the
// platform-global Teams channel (teams.go, the operator's own).
//
// Format: an Adaptive Card inside the {"type":"message","attachments":[…]}
// envelope. Both kinds of Teams webhook a customer can paste accept it —
// a Workflows ("When a Teams webhook request is received") URL, which is what
// Microsoft offers since the Office 365 connectors were retired, and a classic
// Incoming Webhook. A bare MessageCard only renders on the classic kind.
//
// Egress goes through the caller's SSRF-hardened client (safehttp): the dial
// hook checks the resolved address, so a webhook pointed at an internal host
// fails at connect, on every redirect hop.
//
// SECRETS: a Teams webhook URL is a bearer credential (the path, or the `sig`
// query parameter of a Workflows URL). PostTeamsMessage never returns it: a
// transport error loses its URL, and status errors carry only the code.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/safehttp"
)

// TeamsFact is one name/value row of the card.
type TeamsFact struct {
	Title string
	Value string
}

// TeamsMessage is the content of one Teams post. Every field is plain text
// from Correlix; lengths are bounded when the card is built.
type TeamsMessage struct {
	Title   string
	Text    string
	Facts   []TeamsFact
	LinkURL string // shown as "Open in Correlix"; dropped unless https
	Accent  string // an Adaptive Card colour: attention | warning | good | accent | default
	Footer  string
}

// Teams card bounds (Teams refuses posts over ~28 KB; these keep a card far
// below it whatever the RCA text holds).
const (
	teamsTitleMax = 250
	teamsTextMax  = 1500
	teamsFactMax  = 400
	teamsFactsMax = 8
)

// TeamsAccent maps the platform severity vocabulary onto Adaptive Card colours.
func TeamsAccent(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "error":
		return "attention"
	case "warning", "major", "minor":
		return "warning"
	case "ok", "resolved", "cleared":
		return "good"
	case "info":
		return "accent"
	}
	return "default"
}

func teamsClip(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Envelope renders the message as the webhook body.
func (m TeamsMessage) Envelope() map[string]any {
	accent := m.Accent
	if accent == "" {
		accent = "default"
	}
	body := []map[string]any{{
		"type": "TextBlock", "text": teamsClip(m.Title, teamsTitleMax),
		"weight": "Bolder", "size": "Medium", "wrap": true, "color": accent,
	}}
	if t := teamsClip(m.Text, teamsTextMax); t != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": t, "wrap": true})
	}
	facts := make([]map[string]any, 0, len(m.Facts))
	for _, f := range m.Facts {
		if len(facts) == teamsFactsMax {
			break
		}
		v := teamsClip(f.Value, teamsFactMax)
		if strings.TrimSpace(f.Title) == "" || v == "" {
			continue
		}
		facts = append(facts, map[string]any{"title": teamsClip(f.Title, 60), "value": v})
	}
	if len(facts) > 0 {
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	if f := teamsClip(m.Footer, 200); f != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": f, "isSubtle": true, "size": "Small", "wrap": true})
	}
	card := map[string]any{
		"type":    "AdaptiveCard",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"version": "1.4",
		"body":    body,
		"msteams": map[string]any{"width": "Full"},
	}
	if u, err := url.Parse(strings.TrimSpace(m.LinkURL)); err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in Correlix", "url": u.String()}}
	}
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	}
}

// ValidateTeamsWebhookURL is the shape check every tenant Teams destination
// applies before it stores or posts a URL: https, a host, no userinfo. The
// address check is the caller's (save-time) and safehttp's (dial-time).
func ValidateTeamsWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("teams: webhook URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("teams: webhook URL must be an https URL")
	}
	return nil
}

// TeamsPostResult is what the destination answered.
type TeamsPostResult struct {
	Status int
	// RetryAfter is the server's Retry-After on a 429 (0 when absent or out of
	// the 1 s–1 h range).
	RetryAfter time.Duration
}

// PostTeamsMessage sends one message. A non-nil error is a transport failure
// (no response); any response, success or refusal, comes back as its status
// for the caller to classify. Neither ever carries the webhook URL.
func PostTeamsMessage(ctx context.Context, c *http.Client, webhookURL string, m TeamsMessage) (TeamsPostResult, error) {
	if err := ValidateTeamsWebhookURL(webhookURL); err != nil {
		return TeamsPostResult{}, err
	}
	buf, err := json.Marshal(m.Envelope())
	if err != nil {
		return TeamsPostResult{}, fmt.Errorf("teams: encode message: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(webhookURL), bytes.NewReader(buf))
	if err != nil {
		return TeamsPostResult{}, errors.New("teams: invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	if c == nil {
		c = safehttp.Client(10 * time.Second)
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			return TeamsPostResult{}, fmt.Errorf("teams: %s request failed: %s", ue.Op, scrubTeamsURL(ue.Err.Error(), webhookURL))
		}
		return TeamsPostResult{}, fmt.Errorf("teams: request failed: %s", scrubTeamsURL(err.Error(), webhookURL))
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection is reused; the body is never
	// read into an error (a refusal page can echo the request URL).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) // best-effort: a failed drain changes nothing about the status we got
	out := TeamsPostResult{Status: resp.StatusCode}
	if resp.StatusCode == http.StatusTooManyRequests {
		if ra, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && ra > 0 && ra <= 3600 {
			out.RetryAfter = time.Duration(ra) * time.Second
		}
	}
	return out, nil
}

// scrubTeamsURL removes the webhook URL, its path and its query from text that
// is about to leave this file. Defence in depth: the dial errors that reach it
// name only host:port today.
func scrubTeamsURL(msg, webhookURL string) string {
	raw := strings.TrimSpace(webhookURL)
	if raw == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, raw, "[redacted]")
	if u, err := url.Parse(raw); err == nil {
		if u.RawQuery != "" {
			msg = strings.ReplaceAll(msg, u.RawQuery, "[redacted]")
		}
		if u.Path != "" && u.Path != "/" {
			msg = strings.ReplaceAll(msg, u.Path, "[redacted]")
		}
	}
	return msg
}

// TeamsCard is the notify Channel over a TENANT's Teams webhook: the tenant
// watch router and the cloud notice sweeper send alerts through it.
type TeamsCard struct {
	webhookURL string
	client     *http.Client
}

// NewTeamsCard builds the channel with the SSRF-hardened client.
func NewTeamsCard(webhookURL string) *TeamsCard {
	return &TeamsCard{webhookURL: webhookURL, client: safehttp.Client(10 * time.Second)}
}

// NewTeamsCardWithClient injects the HTTP client (tests).
func NewTeamsCardWithClient(webhookURL string, c *http.Client) *TeamsCard {
	return &TeamsCard{webhookURL: webhookURL, client: c}
}

func (t *TeamsCard) Name() string { return "teams" }

// TeamsAlertMessage renders a platform alert as a Teams message.
func TeamsAlertMessage(a models.Alert) TeamsMessage {
	title := strings.TrimSpace(a.Summary)
	if title == "" {
		title = a.Rule
	}
	m := TeamsMessage{Title: title, Text: a.Description, Accent: TeamsAccent(a.Severity), Footer: "Correlix"}
	if a.Severity != "" {
		m.Facts = append(m.Facts, TeamsFact{Title: "Severity", Value: a.Severity})
	}
	if a.Rule != "" && a.Rule != title {
		m.Facts = append(m.Facts, TeamsFact{Title: "Rule", Value: a.Rule})
	}
	return m
}

// Send posts one alert. Any non-2xx is an error so the delivery layer retries
// and counts it; the error carries the status only.
func (t *TeamsCard) Send(a models.Alert) error {
	return sendTeamsAlert(t.client, t.webhookURL, a)
}

// sendTeamsAlert is the one alert-post path of both Teams channels (TeamsCard
// over a tenant's webhook, Teams over the platform's): the Adaptive Card from
// TeamsAlertMessage, a bounded request, and an error for any non-2xx that
// carries the status code only, never the webhook URL.
func sendTeamsAlert(c *http.Client, webhookURL string, a models.Alert) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := PostTeamsMessage(ctx, c, webhookURL, TeamsAlertMessage(a))
	if err != nil {
		return err
	}
	if res.Status >= 300 {
		return fmt.Errorf("teams: webhook returned %d", res.Status)
	}
	return nil
}
