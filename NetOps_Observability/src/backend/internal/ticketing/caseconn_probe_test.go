// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_probe_test.go — the connection test. What has to hold:
//
//	· it READS. A probe must never reach a path that creates, updates, attaches
//	  to or closes a case — proven by recording every request the fake vendor
//	  received and asserting the whole list.
//	· it is BOUNDED. A vendor that never answers ends as timed_out, on time.
//	· its outcome is NAMED. A refusal, an outage and an unconfigured connector
//	  are three different words with three different next steps.
//	· a path with no read-only check says so, with the published reason.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingJira is a fake Jira that remembers every path it was asked for.
type recordingJira struct {
	mu     sync.Mutex
	paths  []string
	status int
	delay  time.Duration
	srv    *httptest.Server
}

func newRecordingJira(t *testing.T) *recordingJira {
	t.Helper()
	f := &recordingJira{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		status, delay := f.status, f.delay
		f.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errorMessages":["injected"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"accountId":"5b10a2","displayName":"Correlix Bot"}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *recordingJira) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *recordingJira) cfg() TACConnectorConfig {
	return TACConnectorConfig{
		Jira: JiraAttachConfig{Enabled: true, Deployment: "cloud"},
		ITSM: SystemConfig{System: "jira", InstanceURL: f.srv.URL, AuthType: "basic",
			User: "noc@acme.example", APIToken: "TOK", ProjectKey: "NOC"},
	}
}

func TestTheJiraProbeOnlyEverReads(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newRecordingJira(t)
	c := NewJiraCaseConnector(NewJiraAdapterWithClient(f.srv.Client()))

	res := ProbeConnector(context.Background(), c, f.cfg(), 5*time.Second, nil)
	if res.Outcome != ProbeOK {
		t.Fatalf("outcome = %q (%s), want ok", res.Outcome, res.Note)
	}
	if res.ConnectorID != "jira" {
		t.Fatalf("connector id = %q", res.ConnectorID)
	}
	// THE assertion of this file: the whole conversation was one GET of /myself.
	if got := f.seen(); len(got) != 1 || got[0] != "GET /rest/api/2/myself" {
		t.Fatalf("the probe talked to Jira beyond a read: %v", got)
	}
}

func TestARejectedCredentialIsRefusedNotUnreachable(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newRecordingJira(t)
	f.status = http.StatusUnauthorized
	c := NewJiraCaseConnector(NewJiraAdapterWithClient(f.srv.Client()))

	res := ProbeConnector(context.Background(), c, f.cfg(), 5*time.Second, nil)
	if res.Outcome != ProbeRefused {
		t.Fatalf("a 401 must read as refused, got %q (%s)", res.Outcome, res.Note)
	}
	if strings.Contains(res.Note, "TOK") {
		t.Fatalf("the note carries the credential: %q", res.Note)
	}
}

// A vendor that never answers must end as timed_out, on the caller's bound —
// not hang the browser and not read as a refusal.
func TestAProbeIsBoundedByItsTimeout(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newRecordingJira(t)
	f.delay = 5 * time.Second
	c := NewJiraCaseConnector(NewJiraAdapterWithClient(f.srv.Client()))

	start := time.Now()
	res := ProbeConnector(context.Background(), c, f.cfg(), 150*time.Millisecond, nil)
	elapsed := time.Since(start)
	if res.Outcome != ProbeTimedOut {
		t.Fatalf("outcome = %q (%s), want timed_out", res.Outcome, res.Note)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the probe ran %s past a 150ms bound", elapsed)
	}
}

// A connector with no stored settings is a STATE with a next step, and asking
// the vendor about it would only turn a clear answer into a network error.
func TestAnUnconfiguredConnectorIsNotProbedAtAll(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newRecordingJira(t)
	c := NewJiraCaseConnector(NewJiraAdapterWithClient(f.srv.Client()))

	res := ProbeConnector(context.Background(), c, TACConnectorConfig{}, time.Second, nil)
	if res.Outcome != ProbeNotConfigured {
		t.Fatalf("outcome = %q, want not_configured", res.Outcome)
	}
	if got := f.seen(); len(got) != 0 {
		t.Fatalf("an unconfigured connector still reached the vendor: %v", got)
	}
}

// The paths that publish no read-only check say so, with the reason, rather than
// reporting a failure the operator cannot act on.
func TestAPathWithNoReadOnlyCheckSaysSo(t *testing.T) {
	reg := DefaultCaseConnectorRegistry()
	for _, id := range []string{"cisco-cxd", "cisco-smart-bonding", "portal-nokia"} {
		e, ok := reg.Get(id)
		if !ok {
			t.Fatalf("connector %q is not registered", id)
		}
		res := ProbeConnector(context.Background(), e.Connector, TACConnectorConfig{}, time.Second, nil)
		if res.Outcome != ProbeUnsupported {
			t.Fatalf("%s outcome = %q, want unsupported", id, res.Outcome)
		}
		if strings.TrimSpace(res.Note) == "" {
			t.Fatalf("%s gave no reason for having no check", id)
		}
	}
}

// The email probe stops at the greeting: the injected transport proves the
// connector calls the PROBE path and never the sender.
func TestTheEmailProbeUsesTheProbePathNotTheSender(t *testing.T) {
	var probed int
	c, err := NewEmailCaseConnectorWithProbe("arista", func(_ context.Context, cfg EmailConnectorConfig) error {
		probed++
		if cfg.Host != "smtp.acme.example:587" {
			return errors.New("wrong relay")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	c.sendFn = func(context.Context, EmailConnectorConfig, string, []byte) error {
		t.Fatal("THE PROBE SENT MAIL")
		return nil
	}
	cfg := TACConnectorConfig{Email: EmailConnectorConfig{
		Enabled: true, Host: "smtp.acme.example:587", From: "noc@acme.example",
	}}
	res := ProbeConnector(context.Background(), c, cfg, time.Second, nil)
	if res.Outcome != ProbeOK || probed != 1 {
		t.Fatalf("outcome = %q (%s), probes = %d", res.Outcome, res.Note, probed)
	}
}

// A relay that offers no STARTTLS is refused by the probe exactly as the sender
// refuses it: a test that passed against a plaintext relay would certify a path
// the sender will not use.
func TestTheEmailProbeRefusesARelayWithoutTLS(t *testing.T) {
	// The package's own fake relay, advertising no STARTTLS.
	f := newFakeSMTP(t, []string{"fake"}, "")
	c, err := NewEmailCaseConnector("arista")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cfg := TACConnectorConfig{Email: EmailConnectorConfig{
		Enabled: true, Host: f.addr(), From: "noc@acme.example",
	}}
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	res := ProbeConnector(context.Background(), c, cfg, 3*time.Second, nil)
	if res.Outcome != ProbeRefused || !strings.Contains(res.Note, "STARTTLS") {
		t.Fatalf("outcome = %q (%s), want a refusal naming STARTTLS", res.Outcome, res.Note)
	}
}
