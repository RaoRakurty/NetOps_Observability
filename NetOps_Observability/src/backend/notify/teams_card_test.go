// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// teams_card_test.go — the tenant Teams message: an Adaptive Card in the
// message envelope both kinds of Teams webhook accept, bounded, https-only
// links, and a POST whose errors never carry the webhook (the secret).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

func TestTeamsEnvelopeIsAnAdaptiveCardMessage(t *testing.T) {
	m := TeamsMessage{
		Title: "Opened: [P-1A2B3C] BGP down", Text: "summary", Accent: "attention", Footer: "Correlix RCA",
		Facts:   []TeamsFact{{Title: "Verdict", Value: "confirmed (90%)"}, {Title: "", Value: "dropped"}, {Title: "Empty", Value: " "}},
		LinkURL: "https://correlix.example/#/investigate/rca/x",
	}
	buf, err := json.Marshal(m.Envelope())
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Type        string `json:"type"`
		Attachments []struct {
			ContentType string `json:"contentType"`
			Content     struct {
				Type    string           `json:"type"`
				Version string           `json:"version"`
				Body    []map[string]any `json:"body"`
				Actions []map[string]any `json:"actions"`
			} `json:"content"`
		} `json:"attachments"`
	}
	if err := json.Unmarshal(buf, &env); err != nil {
		t.Fatal(err)
	}
	if env.Type != "message" || len(env.Attachments) != 1 || env.Attachments[0].ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("not the Teams message envelope: %s", buf)
	}
	c := env.Attachments[0].Content
	if c.Type != "AdaptiveCard" || c.Version == "" {
		t.Fatalf("not an Adaptive Card: %s", buf)
	}
	if c.Body[0]["text"] != m.Title || c.Body[0]["color"] != "attention" {
		t.Fatalf("title block = %v", c.Body[0])
	}
	var facts []any
	for _, b := range c.Body {
		if b["type"] == "FactSet" {
			facts = b["facts"].([]any)
		}
	}
	if len(facts) != 1 {
		t.Fatalf("blank facts must be dropped, got %v", facts)
	}
	if len(c.Actions) != 1 || c.Actions[0]["url"] != m.LinkURL {
		t.Fatalf("https RCA link must become the one action: %v", c.Actions)
	}
}

func TestTeamsEnvelopeDropsNonHTTPSLinksAndBoundsText(t *testing.T) {
	for _, link := range []string{"http://correlix.example/x", "javascript:alert(1)", "https://user:pw@correlix.example/x", ""} {
		buf, _ := json.Marshal(TeamsMessage{Title: "t", LinkURL: link}.Envelope())
		if strings.Contains(string(buf), `"actions"`) {
			t.Fatalf("link %q must not become an action: %s", link, buf)
		}
	}
	long := strings.Repeat("x", 10000)
	buf, _ := json.Marshal(TeamsMessage{Title: long, Text: long, Facts: []TeamsFact{{Title: "a", Value: long}}}.Envelope())
	if len(buf) > 4000 {
		t.Fatalf("card is not bounded: %d bytes", len(buf))
	}
}

func TestValidateTeamsWebhookURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://contoso.webhook.office.com/webhookb2/a/IncomingWebhook/b/c":                                        true,
		"https://prod-27.westus.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=s": true,
		"http://contoso.webhook.office.com/webhookb2/a":                                                             false,
		"https://user:pw@contoso.webhook.office.com/x":                                                              false,
		"":           false,
		"not a url":  false,
		"https:///x": false,
	} {
		if err := ValidateTeamsWebhookURL(raw); (err == nil) != ok {
			t.Errorf("ValidateTeamsWebhookURL(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestPostTeamsMessageStatusAndRetryAfter(t *testing.T) {
	var got []byte
	status, retry := http.StatusAccepted, ""
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %q", r.Header.Get("Content-Type"))
		}
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("refusal page echoing " + r.URL.String()))
	}))
	defer srv.Close()
	hook := srv.URL + "/workflows/SECRETPATH/invoke?sig=SECRETSIG"

	res, err := PostTeamsMessage(context.Background(), srv.Client(), hook, TeamsMessage{Title: "hello"})
	if err != nil || res.Status != http.StatusAccepted {
		t.Fatalf("Workflows answers 202: res=%+v err=%v", res, err)
	}
	if !strings.Contains(string(got), `"AdaptiveCard"`) {
		t.Fatalf("posted body is not the card: %s", got)
	}
	status, retry = http.StatusTooManyRequests, "42"
	res, err = PostTeamsMessage(context.Background(), srv.Client(), hook, TeamsMessage{Title: "hello"})
	if err != nil || res.Status != 429 || res.RetryAfter != 42*time.Second {
		t.Fatalf("429 + Retry-After: res=%+v err=%v", res, err)
	}
	retry = "999999"
	if res, _ = PostTeamsMessage(context.Background(), srv.Client(), hook, TeamsMessage{Title: "hello"}); res.RetryAfter != 0 {
		t.Fatalf("an out-of-range Retry-After is ignored, got %v", res.RetryAfter)
	}
}

func TestPostTeamsMessageErrorsNeverCarryTheWebhook(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	hook := srv.URL + "/webhookb2/SECRETPATH/IncomingWebhook/x?sig=SECRETSIG"
	client := srv.Client()
	srv.Close() // connection refused from here on

	_, err := PostTeamsMessage(context.Background(), client, hook, TeamsMessage{Title: "t"})
	if err == nil {
		t.Fatal("a closed server must be a transport error")
	}
	for _, leak := range []string{"SECRETPATH", "SECRETSIG", hook} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("transport error leaked %q: %v", leak, err)
		}
	}
	if _, err := PostTeamsMessage(context.Background(), client, "http://plain.example/SECRETPATH", TeamsMessage{}); err == nil || strings.Contains(err.Error(), "SECRETPATH") {
		t.Fatalf("an http URL is refused before any request, without echoing it: %v", err)
	}
}

func TestTeamsCardSendFailsOnRefusal(t *testing.T) {
	code := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
	defer srv.Close()
	ch := NewTeamsCardWithClient(srv.URL+"/SECRETPATH", srv.Client())
	if ch.Name() != "teams" {
		t.Fatalf("name %q", ch.Name())
	}
	a := models.Alert{ID: "x", Rule: "bgp_origin_change", Severity: "critical", Summary: "origin changed"}
	if err := ch.Send(a); err != nil {
		t.Fatalf("2xx must succeed: %v", err)
	}
	code = http.StatusNotFound
	err := ch.Send(a)
	if err == nil || strings.Contains(err.Error(), "SECRETPATH") {
		t.Fatalf("a 404 must fail without the URL: %v", err)
	}
}

func TestTeamsAlertMessage(t *testing.T) {
	m := TeamsAlertMessage(models.Alert{Rule: "cloud_monitor", Severity: "warning", Summary: "Latency high", Description: "p95 400 ms"})
	if m.Title != "Latency high" || m.Text != "p95 400 ms" || m.Accent != "warning" {
		t.Fatalf("message = %+v", m)
	}
	if m := TeamsAlertMessage(models.Alert{Rule: "r", Severity: "resolved"}); m.Title != "r" || m.Accent != "good" {
		t.Fatalf("summary-less alert falls back to the rule; resolved is good: %+v", m)
	}
}

// The Teams lane is a chat lane: a start message, a "cleared" message at the
// end (no resolve call), and Iris notices — like Slack, never like PagerDuty.
func TestTenantWatchTeamsLaneIsAChatLane(t *testing.T) {
	r, _, rec, _ := newRouterUnderTest(t, map[string][]TenantLane{
		"acme": {{System: TenantLaneTeams, Secret: "https://teams.example/A"}, {System: TenantLanePagerDuty, Secret: "rk-acme"}},
	})
	a := watchAlert("bgp:acme:198.51.100.0/24:rpki_invalid")
	r.Fire("acme", a)
	waitUntil(t, "fire delivered to both lanes", func() bool { return len(rec.hits()) == 2 })
	r.Resolve("acme", a) // summary does not say it cleared
	waitUntil(t, "resolve delivered", func() bool { return len(rec.hits()) == 4 })
	var teamsClear, pdResolve int
	for _, h := range rec.hits() {
		if h.system == TenantLaneTeams && strings.HasPrefix(h.summary, "Resolved: ") && !h.resolve {
			teamsClear++
		}
		if h.system == TenantLanePagerDuty && h.resolve {
			pdResolve++
		}
	}
	if teamsClear != 1 || pdResolve != 1 {
		t.Fatalf("want one Teams 'Resolved:' message and one PagerDuty resolve: %+v", rec.hits())
	}
	if n := r.Notice("acme", models.Alert{ID: "iris:1", Summary: "investigation done"}); n != 1 {
		t.Fatalf("a notice goes to the Teams lane only, got %d lanes", n)
	}
	waitUntil(t, "notice delivered", func() bool { return len(rec.hits()) == 5 })
	if last := rec.hits()[4]; last.system != TenantLaneTeams {
		t.Fatalf("notice reached %q", last.system)
	}
	if got := buildTenantLaneSender(TenantLane{System: TenantLaneTeams, Secret: "https://teams.example/A"}); got == nil || got.Name() != "teams" {
		t.Fatalf("production Teams lane sender = %v", got)
	}
}
