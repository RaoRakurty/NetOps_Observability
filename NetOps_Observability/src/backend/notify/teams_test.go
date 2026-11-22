// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// teams_test.go — the platform-global Teams channel (teams.go). Since tracker
// 455 it posts the Adaptive Card message envelope (teams_card.go) that both
// kinds of Teams webhook render, through the production SSRF-hardened client,
// behind the severity gate, and its errors never carry the webhook URL.

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// Webhook URL shapes an operator can paste. SECRETPATH / SECRETSIG stand for
// the bearer credential each kind carries (the path, or the `sig` query).
const (
	teamsClassicHookPath  = "/webhookb2/SECRETPATH@tenant/IncomingWebhook/abc/def"
	teamsWorkflowHookPath = "/workflows/SECRETPATH/triggers/manual/paths/invoke?api-version=2016-06-01&sig=SECRETSIG"
)

// teamsRecorder is a TLS fake Teams endpoint that records every request.
type teamsRecorder struct {
	mu     sync.Mutex
	status int
	reqs   []teamsRecordedRequest
}

type teamsRecordedRequest struct {
	method, contentType, requestURI string
	body                            []byte
}

func newTeamsRecorder(t *testing.T) (*teamsRecorder, *httptest.Server) {
	t.Helper()
	rec := &teamsRecorder{status: http.StatusAccepted}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		rec.mu.Lock()
		rec.reqs = append(rec.reqs, teamsRecordedRequest{r.Method, r.Header.Get("Content-Type"), r.RequestURI, b})
		status := rec.status
		rec.mu.Unlock()
		w.WriteHeader(status)
		// A refusal page that echoes the request URL: it must never reach an error.
		if _, err := w.Write([]byte("refused " + r.RequestURI)); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return rec, srv
}

func (r *teamsRecorder) requests() []teamsRecordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]teamsRecordedRequest(nil), r.reqs...)
}

func (r *teamsRecorder) setStatus(code int) {
	r.mu.Lock()
	r.status = code
	r.mu.Unlock()
}

// trustTeamsTestServer makes the channel's PRODUCTION client (safehttp, with
// its dial guard) trust the fake's self-signed certificate — nothing else about
// the client changes, so the egress path under test is the real one.
func trustTeamsTestServer(t *testing.T, ch *Teams, srv *httptest.Server) {
	t.Helper()
	tr, ok := ch.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("teams client transport is %T, want the safehttp *http.Transport", ch.client.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("teams client has no guarded dialer: it is not the safehttp client")
	}
	tr.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
}

// teamsGateInner digs the *Teams out of what BuildTeamsChannel returns.
func teamsGateInner(t *testing.T, ch Channel) *Teams {
	t.Helper()
	g, ok := ch.(*SeverityGate)
	if !ok {
		t.Fatalf("BuildTeamsChannel returned %T, want *SeverityGate", ch)
	}
	tm, ok := g.Unguarded().(*Teams)
	if !ok {
		t.Fatalf("gated channel is %T, want *Teams", g.Unguarded())
	}
	return tm
}

// teamsEnvelope is the strict shape of the posted body. Decoding uses
// DisallowUnknownFields at the envelope level, so a stray MessageCard field
// (@type, themeColor, title, text, summary) fails the test.
type teamsEnvelope struct {
	Type        string `json:"type"`
	Attachments []struct {
		ContentType string          `json:"contentType"`
		ContentURL  json.RawMessage `json:"contentUrl"`
		Content     struct {
			Type    string           `json:"type"`
			Schema  string           `json:"$schema"`
			Version string           `json:"version"`
			Body    []map[string]any `json:"body"`
			Actions []map[string]any `json:"actions"`
			MSTeams map[string]any   `json:"msteams"`
		} `json:"content"`
	} `json:"attachments"`
}

func decodeTeamsEnvelope(t *testing.T, b []byte) teamsEnvelope {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var env teamsEnvelope
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("posted body is not the strict Teams message envelope: %v\n%s", err, b)
	}
	if env.Type != "message" || len(env.Attachments) != 1 {
		t.Fatalf("envelope type=%q attachments=%d, want message/1: %s", env.Type, len(env.Attachments), b)
	}
	att := env.Attachments[0]
	if att.ContentType != "application/vnd.microsoft.card.adaptive" || string(att.ContentURL) != "null" {
		t.Fatalf("attachment contentType=%q contentUrl=%s: %s", att.ContentType, att.ContentURL, b)
	}
	c := att.Content
	if c.Type != "AdaptiveCard" || c.Schema != "http://adaptivecards.io/schemas/adaptive-card.json" || c.Version != "1.4" {
		t.Fatalf("not an Adaptive Card 1.4: %s", b)
	}
	if c.MSTeams["width"] != "Full" {
		t.Fatalf("msteams.width = %v, want Full", c.MSTeams["width"])
	}
	return env
}

// TestTeamsSendPostsAnAdaptiveCard proves the platform channel POSTs the
// Adaptive Card message envelope — not the legacy MessageCard, which only a
// classic Incoming Webhook renders — to both URL kinds, unchanged, through the
// production client.
func TestTeamsSendPostsAnAdaptiveCard(t *testing.T) {
	for kind, hookPath := range map[string]string{"classic": teamsClassicHookPath, "workflows": teamsWorkflowHookPath} {
		t.Run(kind, func(t *testing.T) {
			rec, srv := newTeamsRecorder(t)
			tm := NewTeams(srv.URL + hookPath)
			trustTeamsTestServer(t, tm, srv)
			a := models.Alert{Rule: "ContainerDown", Severity: "critical", Summary: "kafka restarting", Description: "3 restarts in 5m"}
			if err := tm.Send(a); err != nil {
				t.Fatalf("Send: %v", err)
			}
			reqs := rec.requests()
			if len(reqs) != 1 {
				t.Fatalf("webhook calls = %d, want 1", len(reqs))
			}
			r := reqs[0]
			if r.method != http.MethodPost || r.contentType != "application/json" {
				t.Fatalf("method=%q content-type=%q, want POST application/json", r.method, r.contentType)
			}
			if r.requestURI != hookPath {
				t.Fatalf("posted to %q, want the webhook path+query unchanged %q", r.requestURI, hookPath)
			}
			body := decodeTeamsEnvelope(t, r.body).Attachments[0].Content.Body
			if len(body) != 4 {
				t.Fatalf("card body has %d blocks, want title, text, facts, footer: %v", len(body), body)
			}
			if body[0]["type"] != "TextBlock" || body[0]["text"] != "kafka restarting" || body[0]["color"] != "attention" || body[0]["weight"] != "Bolder" {
				t.Errorf("title block = %v", body[0])
			}
			if body[1]["type"] != "TextBlock" || body[1]["text"] != "3 restarts in 5m" {
				t.Errorf("text block = %v", body[1])
			}
			wantFacts := []any{
				map[string]any{"title": "Severity", "value": "critical"},
				map[string]any{"title": "Rule", "value": "ContainerDown"},
			}
			if body[2]["type"] != "FactSet" || !reflect.DeepEqual(body[2]["facts"], wantFacts) {
				t.Errorf("fact set = %v, want %v", body[2], wantFacts)
			}
			if body[3]["text"] != "Correlix" || body[3]["isSubtle"] != true {
				t.Errorf("footer block = %v", body[3])
			}
			for _, legacy := range []string{`"@type"`, `"@context"`, `"themeColor"`, `"MessageCard"`} {
				if strings.Contains(string(r.body), legacy) {
					t.Errorf("body still carries MessageCard field %s: %s", legacy, r.body)
				}
			}
		})
	}
}

// TestTeamsSendAccentFollowsSeverity: the severity colour moved from a hex
// themeColor to the Adaptive Card colour vocabulary on the title block.
func TestTeamsSendAccentFollowsSeverity(t *testing.T) {
	rec, srv := newTeamsRecorder(t)
	tm := NewTeams(srv.URL + teamsClassicHookPath)
	trustTeamsTestServer(t, tm, srv)
	cases := []struct{ sev, color string }{
		{"critical", "attention"}, {"error", "attention"}, {"warning", "warning"}, {"info", "accent"}, {"ok", "good"}, {"", "default"},
	}
	for _, c := range cases {
		if err := tm.Send(models.Alert{Rule: "R", Severity: c.sev, Summary: "s"}); err != nil {
			t.Fatalf("Send(%q): %v", c.sev, err)
		}
	}
	reqs := rec.requests()
	if len(reqs) != len(cases) {
		t.Fatalf("webhook calls = %d, want %d", len(reqs), len(cases))
	}
	for i, c := range cases {
		title := decodeTeamsEnvelope(t, reqs[i].body).Attachments[0].Content.Body[0]
		if title["color"] != c.color {
			t.Errorf("severity %q: title colour = %v, want %q", c.sev, title["color"], c.color)
		}
	}
}

func TestTeamsSendRequiresWebhook(t *testing.T) {
	for _, hook := range []string{"", "   "} {
		if err := NewTeams(hook).Send(models.Alert{Rule: "X", Severity: "critical"}); err == nil {
			t.Fatalf("an unconfigured Teams channel (%q) must return an error, not silently succeed", hook)
		}
	}
}

// TestTeamsSendSurfacesHTTPFailure: a refusal is an error naming the status —
// and only the status: the refusal page echoes the URL, which stays out.
func TestTeamsSendSurfacesHTTPFailure(t *testing.T) {
	for kind, hookPath := range map[string]string{"classic": teamsClassicHookPath, "workflows": teamsWorkflowHookPath} {
		t.Run(kind, func(t *testing.T) {
			rec, srv := newTeamsRecorder(t)
			rec.setStatus(http.StatusBadGateway)
			hook := srv.URL + hookPath
			tm := NewTeams(hook)
			trustTeamsTestServer(t, tm, srv)
			err := tm.Send(models.Alert{Rule: "X", Severity: "critical"})
			if err == nil || !strings.Contains(err.Error(), "502") {
				t.Fatalf("want a 502-bearing error, got %v", err)
			}
			assertNoTeamsSecret(t, err, hook)
		})
	}
}

// TestTeamsSendErrorsNeverCarryTheWebhook covers every failure the platform
// channel can return before or instead of a status: a transport failure, an
// http:// URL (refused before any request), and the SSRF guard of the
// production client refusing a non-public address.
func TestTeamsSendErrorsNeverCarryTheWebhook(t *testing.T) {
	a := models.Alert{Rule: "X", Severity: "critical", Summary: "s"}

	t.Run("transport failure", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		hook := srv.URL + teamsWorkflowHookPath
		tm := NewTeams(hook)
		trustTeamsTestServer(t, tm, srv)
		srv.Close() // connection refused from here on
		err := tm.Send(a)
		if err == nil {
			t.Fatal("a closed server must be a transport error")
		}
		assertNoTeamsSecret(t, err, hook)
	})

	t.Run("plaintext URL refused before any request", func(t *testing.T) {
		var hits int
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			mu.Lock()
			hits++
			mu.Unlock()
		}))
		defer srv.Close()
		hook := srv.URL + teamsClassicHookPath
		err := NewTeams(hook).Send(a)
		if err == nil {
			t.Fatal("an http:// webhook must be refused: it would send the bearer URL in clear text")
		}
		assertNoTeamsSecret(t, err, hook)
		mu.Lock()
		defer mu.Unlock()
		if hits != 0 {
			t.Fatalf("an http:// webhook reached the server %d time(s)", hits)
		}
	})

	t.Run("SSRF guard on the production client", func(t *testing.T) {
		t.Setenv("SSRF_ALLOW_PRIVATE", "false") // TestMain opts the package in; undo it here
		t.Setenv("SSRF_ALLOWED_HOSTS", "")
		rec, srv := newTeamsRecorder(t)
		hook := srv.URL + teamsWorkflowHookPath
		tm := NewTeams(hook)
		trustTeamsTestServer(t, tm, srv)
		err := tm.Send(a)
		if err == nil || !strings.Contains(err.Error(), "SSRF") {
			t.Fatalf("a loopback webhook must be refused by the safehttp dial guard, got %v", err)
		}
		assertNoTeamsSecret(t, err, hook)
		if n := len(rec.requests()); n != 0 {
			t.Fatalf("the guarded client reached a loopback webhook %d time(s)", n)
		}
	})
}

// TestBuildTeamsChannelKeepsTheSeverityFloor: the gate BuildTeamsChannel wraps
// around the Adaptive Card sender still filters, and what passes is the card.
func TestBuildTeamsChannelKeepsTheSeverityFloor(t *testing.T) {
	rec, srv := newTeamsRecorder(t)
	ch := BuildTeamsChannel(TeamsConfig{Enabled: true, WebhookURL: srv.URL + teamsWorkflowHookPath, MinSeverity: "error"})
	trustTeamsTestServer(t, teamsGateInner(t, ch), srv)
	if err := ch.Send(models.Alert{Rule: "LinkFlap", Severity: "warning", Summary: "flapping"}); err != nil {
		t.Fatalf("a below-floor alert is filtered, not an error: %v", err)
	}
	if n := len(rec.requests()); n != 0 {
		t.Fatalf("a warning reached an error-floored Teams channel (%d posts)", n)
	}
	if err := ch.Send(models.Alert{Rule: "HostOOM", Severity: "critical", Summary: "host memory exhausted"}); err != nil {
		t.Fatalf("Send critical: %v", err)
	}
	reqs := rec.requests()
	if len(reqs) != 1 {
		t.Fatalf("webhook calls = %d, want 1", len(reqs))
	}
	if title := decodeTeamsEnvelope(t, reqs[0].body).Attachments[0].Content.Body[0]; title["text"] != "host memory exhausted" {
		t.Fatalf("title block = %v", title)
	}
}

func assertNoTeamsSecret(t *testing.T, err error, hook string) {
	t.Helper()
	for _, leak := range []string{hook, "SECRETPATH", "SECRETSIG", "IncomingWebhook", "/workflows/"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaked %q: %v", leak, err)
		}
	}
}
