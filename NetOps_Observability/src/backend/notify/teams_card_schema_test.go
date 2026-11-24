// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// teams_card_schema_test.go — tracker 455, closed on simulation (owner,
// 2026-11-24): every Teams card is validated against Microsoft's official
// Adaptive Card 1.4 schema (internal/adaptivecard, vendored unmodified), and the
// POST is replayed against stand-ins for both kinds of Teams webhook — a
// Workflows ("When a Teams webhook request is received") URL and a classic
// Incoming Webhook — with the answers each really gives.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/adaptivecard"
	"netops/backend/models"
)

// teamsWorstCase fills every field to (and past) its bound.
func teamsWorstCase() TeamsMessage {
	facts := make([]TeamsFact, 0, 12)
	for i := 0; i < 12; i++ {
		facts = append(facts, TeamsFact{Title: strings.Repeat("T", 90), Value: strings.Repeat("v\"<>&", 200)})
	}
	return TeamsMessage{
		Title:   strings.Repeat("Ω", 600),
		Text:    strings.Repeat("**markdown** _text_ with \"quotes\" and <html> & ", 120),
		Facts:   facts,
		LinkURL: "https://correlix.example/#/investigate/rca/" + strings.Repeat("a", 300),
		Accent:  "attention",
		Footer:  strings.Repeat("f", 400),
	}
}

func teamsCardOf(t *testing.T, env map[string]any) any {
	t.Helper()
	atts, ok := env["attachments"].([]map[string]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("envelope has no single attachment: %v", env)
	}
	return atts[0]["content"]
}

func TestEveryTeamsCardIsValidAgainstTheOfficialSchema(t *testing.T) {
	v, err := adaptivecard.New14(adaptivecard.TeamsHostExtensions...)
	if err != nil {
		t.Fatal(err)
	}
	alert := func(sev, summary, desc, rule string) models.Alert {
		return models.Alert{Severity: sev, Summary: summary, Description: desc, Rule: rule}
	}
	cases := map[string]TeamsMessage{
		"alert critical":            TeamsAlertMessage(alert("critical", "cEDGE-81 BGP peer down", "Peer 192.168.200.34 went Idle", "BGPPeerDown")),
		"alert warning":             TeamsAlertMessage(alert("warning", "CPU high on vEdge-100", "96 %", "DeviceCPUHigh")),
		"alert resolved":            TeamsAlertMessage(alert("resolved", "BGP peer back up", "", "BGPPeerDown")),
		"alert info":                TeamsAlertMessage(alert("info", "Maintenance window opened", "", "")),
		"alert unknown severity":    TeamsAlertMessage(alert("", "", "", "SomeRule")),
		"title only, no link":       {Title: "Resolved — problem P-1A2B3C cleared in Correlix.", Accent: "good", Footer: "Correlix RCA"},
		"every field at its bound":  teamsWorstCase(),
		"non-https link is dropped": {Title: "x", LinkURL: "http://insecure.example/"},
		"empty accent":              {Title: "x", Text: "y"},
	}
	for name, m := range cases {
		if errs := v.ValidateCard(teamsCardOf(t, m.Envelope())); errs != nil {
			t.Errorf("%s: card refused by the Adaptive Card 1.4 schema:\n  %s", name, strings.Join(errs, "\n  "))
		}
	}
	// Every accent the senders can produce is a schema colour.
	for _, sev := range []string{"critical", "error", "warning", "major", "minor", "ok", "resolved", "cleared", "info", "", "weird"} {
		m := TeamsMessage{Title: "x", Accent: TeamsAccent(sev)}
		if errs := v.ValidateCard(teamsCardOf(t, m.Envelope())); errs != nil {
			t.Errorf("accent for severity %q refused: %v", sev, errs)
		}
	}
}

// Teams refuses a post over ~28 KB. The bounds in teams_card.go must keep even
// the worst-case card well under it.
func TestTheWorstCaseTeamsPostFitsUnderTheTeamsSizeLimit(t *testing.T) {
	buf, err := json.Marshal(teamsWorstCase().Envelope())
	if err != nil {
		t.Fatal(err)
	}
	const teamsLimit = 28 * 1024
	if len(buf) >= teamsLimit {
		t.Fatalf("worst-case Teams post is %d bytes, at or over the %d-byte Teams limit", len(buf), teamsLimit)
	}
	t.Logf("worst-case Teams post: %d bytes (limit %d)", len(buf), teamsLimit)
}

// teamsReceiver is a stand-in for one kind of Teams webhook: it checks what
// Teams itself checks before accepting a post, then answers the way that kind
// of webhook really answers.
type teamsReceiver struct {
	t      *testing.T
	v      *adaptivecard.Validator
	status int
	body   string
	header map[string]string
	got    int
	gotQS  string
}

func (r *teamsReceiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.got++
	r.gotQS = req.URL.RawQuery
	if req.Method != http.MethodPost {
		r.t.Errorf("method = %s, want POST", req.Method)
	}
	if ct := req.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		r.t.Errorf("Content-Type = %q, want application/json", ct)
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, 64*1024))
	if err != nil {
		r.t.Fatal(err)
	}
	var env struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string          `json:"contentType"`
			Content     json.RawMessage `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		r.t.Errorf("body is not JSON: %v", err)
	}
	if env.Type != "message" || len(env.Attachments) != 1 || env.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		r.t.Errorf("not the message envelope both webhook kinds accept: %s", raw)
	} else {
		var card any
		if err := json.Unmarshal(env.Attachments[0].Content, &card); err != nil {
			r.t.Errorf("attachment content is not JSON: %v", err)
		} else if errs := r.v.ValidateCard(card); errs != nil {
			r.t.Errorf("posted card refused by the schema: %v", errs)
		}
	}
	for k, val := range r.header {
		w.Header().Set(k, val)
	}
	w.WriteHeader(r.status)
	_, _ = io.WriteString(w, r.body) // best-effort: a stand-in answer
}

func TestTeamsPostsAreAcceptedByBothKindsOfWebhook(t *testing.T) {
	v, err := adaptivecard.New14(adaptivecard.TeamsHostExtensions...)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []struct {
		name   string
		path   string
		status int
		body   string
	}{
		// Workflows answers 202 Accepted with an empty body.
		{"workflows", "/workflows/0123456789abcdef/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=SECRETsig", http.StatusAccepted, ""},
		// The classic Incoming Webhook answers 200 with the body "1".
		{"classic incoming webhook", "/webhookb2/0000-1111@2222/IncomingWebhook/abcdef/3333", http.StatusOK, "1"},
	}
	msgs := []TeamsMessage{
		TeamsAlertMessage(models.Alert{Severity: "critical", Summary: "cEDGE-81 BGP peer down", Description: "Peer went Idle", Rule: "BGPPeerDown"}),
		teamsWorstCase(),
	}
	for _, k := range kinds {
		rx := &teamsReceiver{t: t, v: v, status: k.status, body: k.body}
		srv := httptest.NewTLSServer(rx)
		for _, m := range msgs {
			res, err := PostTeamsMessage(context.Background(), srv.Client(), srv.URL+k.path, m)
			if err != nil {
				t.Fatalf("%s: transport error: %v", k.name, err)
			}
			if res.Status != k.status {
				t.Errorf("%s: status = %d, want %d", k.name, res.Status, k.status)
			}
		}
		// The alert channel treats both answers as delivered.
		if err := NewTeamsCardWithClient(srv.URL+k.path, srv.Client()).Send(models.Alert{Severity: "warning", Summary: "x"}); err != nil {
			t.Errorf("%s: a %d answer must count as delivered: %v", k.name, k.status, err)
		}
		if rx.got != len(msgs)+1 {
			t.Errorf("%s: receiver saw %d posts, want %d", k.name, rx.got, len(msgs)+1)
		}
		if k.name == "workflows" && !strings.Contains(rx.gotQS, "sig=SECRETsig") {
			t.Errorf("workflows: the signed query (sig) must reach the receiver unchanged, got %q", rx.gotQS)
		}
		srv.Close()
	}
}

// The refusals each webhook kind really gives, as the senders classify them:
// a 429 carries Retry-After back, any non-2xx is a delivery failure that never
// carries the webhook URL.
func TestTeamsRefusalsAreReportedWithoutTheWebhook(t *testing.T) {
	v, err := adaptivecard.New14(adaptivecard.TeamsHostExtensions...)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		status     int
		body       string
		header     map[string]string
		retryAfter time.Duration
	}{
		{"workflows throttled", http.StatusTooManyRequests, `{"error":{"code":"WorkflowTriggerIsThrottled"}}`, map[string]string{"Retry-After": "7"}, 7 * time.Second},
		{"workflows bad request", http.StatusBadRequest, `{"error":{"code":"InvalidRequestContent"}}`, nil, 0},
		{"workflow deleted", http.StatusNotFound, `{"error":{"code":"WorkflowNotFound"}}`, nil, 0},
		{"classic webhook removed", http.StatusGone, "Webhook not found", nil, 0},
		{"classic payload too large", http.StatusRequestEntityTooLarge, "Webhook message delivery failed with error: Microsoft Teams endpoint returned HTTP error 413", nil, 0},
		{"teams outage", http.StatusServiceUnavailable, "", nil, 0},
	}
	for _, c := range cases {
		rx := &teamsReceiver{t: t, v: v, status: c.status, body: c.body, header: c.header}
		srv := httptest.NewTLSServer(rx)
		hook := srv.URL + "/webhookb2/SECRET-PATH/IncomingWebhook/abc?sig=SECRET-SIG"
		res, err := PostTeamsMessage(context.Background(), srv.Client(), hook, TeamsMessage{Title: "x"})
		if err != nil {
			t.Fatalf("%s: a refusal is a status, not a transport error: %v", c.name, err)
		}
		if res.Status != c.status || res.RetryAfter != c.retryAfter {
			t.Errorf("%s: got status %d retry %v, want %d %v", c.name, res.Status, res.RetryAfter, c.status, c.retryAfter)
		}
		sendErr := NewTeamsCardWithClient(hook, srv.Client()).Send(models.Alert{Severity: "critical", Summary: "x"})
		if sendErr == nil {
			t.Errorf("%s: a %d must be a delivery failure", c.name, c.status)
		} else if s := sendErr.Error(); strings.Contains(s, "SECRET") || strings.Contains(s, srv.URL) {
			t.Errorf("%s: the error carries the webhook: %q", c.name, s)
		}
		srv.Close()
	}
}
