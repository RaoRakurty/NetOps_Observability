// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// logs_credscrub_test.go — the configured SNMP communities are masked BY VALUE on
// every read path (internal/credscrub). ConfD names a v1/v2c SNMP session by its
// community (found live 2026-11-11), in a slot that holds a real account on every
// other session, so the stored records carry it in audit_user, title, summary and
// message, and no pattern can find it. The fake OpenSearch ignores everything the
// request asks for, so these tests fail if the response-side mask is removed.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/credscrub"
	"netops/backend/internal/ratelimit"
	"netops/backend/internal/snmpcred"
)

// A fabricated community, built at run time.
var labCommunityFixture = "fixture-comm-" + strings.Repeat("q", 6)

func withCommunities(t *testing.T, s *server, values ...string) {
	t.Helper()
	s.credScrub = credscrub.New(func(context.Context) ([]string, error) { return values, nil })
	if err := s.credScrub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// confdSessionReply is one poll's three ConfD records as the packs stored them
// before the parse fix (the community as the session user), plus a person's CLI
// session, which must stay readable (owner D7).
func confdSessionReply(community string) string {
	doc := func(id, eventType, user, title, message string) string {
		return `{"_index":"netops-syslog-acme-2026.11.11","_id":"` + id + `","sort":[1,"` + id + `"],"_source":{` +
			`"timestamp":"2026-11-11T09:00:00Z","hostname":"acme-core","appname":"confd","tenant_id":"acme",` +
			`"event_type":"` + eventType + `","event_category":"management_audit","audit_user":"` + user + `",` +
			`"title":"` + title + `","summary":"Session of ` + user + `",` +
			`"message":"` + message + `","message_original":"<190>Nov 11 09:00:00 acme-core confd[1]: ` + message + `"}}`
	}
	return `{"took":1,"hits":{"total":{"value":4,"relation":"eq"},"hits":[` +
		doc("1", "audit_session_created_snmp", community, "SNMP session on acme-core by "+community+" from 127.0.0.1 (poll)",
			"audit user: "+community+"/49119 created new session via snmp from 127.0.0.1:54873 with udp") + `,` +
		doc("2", "audit_session_groups", community, "Session groups assigned on acme-core to "+community,
			"audit user: "+community+"/49119 assigned to groups: basic") + `,` +
		doc("3", "audit_session_terminated", community, "Session closed on acme-core for "+community+" (normal)",
			"audit user: "+community+"/49119 terminated session (reason: normal)") + `,` +
		doc("4", "audit_session_created_cli", "fixture-person", "Session opened via cli on acme-core by fixture-person",
			"audit user: fixture-person/7 created new session via cli from 192.0.2.7:51234 with ssh") +
		`]}}`
}

func TestLogSearchMasksAConfiguredCommunityInEveryField(t *testing.T) {
	fakeOS(t, confdSessionReply(labCommunityFixture))
	s := logsTestServer(t)
	withCommunities(t, s, labCommunityFixture)
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=syslog&include_routine_mgmt=true", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, labCommunityFixture) {
		t.Fatalf("the log search served a configured community:\n%s", body)
	}
	var resp struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Hits.Hits) != 4 {
		t.Fatalf("hits = %d, want all four records served", len(resp.Hits.Hits))
	}
	for i, h := range resp.Hits.Hits[:3] {
		if h.Source["audit_user"] != credscrub.Mask {
			t.Errorf("hit %d audit_user = %v, want the mask", i, h.Source["audit_user"])
		}
		for _, f := range []string{"title", "summary", "message", "message_original"} {
			if s, _ := h.Source[f].(string); !strings.Contains(s, credscrub.Mask) {
				t.Errorf("hit %d %s = %q, want the mask in it", i, f, s)
			}
		}
	}
	if person := resp.Hits.Hits[3].Source; person["audit_user"] != "fixture-person" ||
		!strings.Contains(person["message"].(string), "fixture-person") {
		t.Errorf("a person's session must stay attributable (owner D7): %v", person)
	}
}

func TestLogExportMasksAConfiguredCommunity(t *testing.T) {
	for _, format := range []string{"json", "ndjson", "csv"} {
		t.Run(format, func(t *testing.T) {
			fakeOS(t, confdSessionReply(labCommunityFixture))
			s := logsTestServer(t)
			s.exportLimiter = ratelimit.New()
			withCommunities(t, s, labCommunityFixture)
			w := httptest.NewRecorder()
			s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=syslog&mode=sync&format="+format, "", acme()))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), labCommunityFixture) {
				t.Fatalf("the %s export served a configured community:\n%s", format, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "fixture-person") {
				t.Errorf("the export lost a person's session: %s", w.Body.String())
			}
		})
	}
}

// §3a: the mask only rewrites what comes back. The request the store receives,
// its index pattern and its per-document tenant clause, is byte-identical with
// and without a scrubber.
func TestCommunityMaskDoesNotChangeTheTenantScopedQuery(t *testing.T) {
	run := func(scrub bool) (string, string) {
		paths, bodies := fakeOS(t, confdSessionReply(labCommunityFixture))
		s := logsTestServer(t)
		if scrub {
			withCommunities(t, s, labCommunityFixture)
		}
		w := httptest.NewRecorder()
		s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=syslog&as_tenant=globex", "", acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		return (*paths)[0], (*bodies)[0]
	}
	plainPath, plainBody := run(false)
	maskedPath, maskedBody := run(true)
	if plainPath != maskedPath || plainBody != maskedBody {
		t.Fatalf("the scrubber changed the store request:\n%s %s\n%s %s", plainPath, plainBody, maskedPath, maskedBody)
	}
	if !strings.Contains(maskedPath, "netops-syslog-acme-*") || strings.Contains(maskedPath, "globex") {
		t.Errorf("index pattern not tenant-scoped: %q", maskedPath)
	}
	if !strings.Contains(maskedBody, `"tenant_id":"acme"`) || strings.Contains(maskedBody, "globex") {
		t.Errorf("per-document tenant clause wrong: %s", maskedBody)
	}
}

// Iris: a tool result is what Iris shows AND what the agent loop sends to an
// external provider. The pattern dialect already masks a ConfD "audit user:"
// slot as an identifier, so the line below is one only the value can catch.
func TestIrisLogSearchMasksAConfiguredCommunity(t *testing.T) {
	lines := []string{
		"audit user: " + labCommunityFixture + "/49119 assigned to groups: basic",
		"poller " + labCommunityFixture + " answered from 127.0.0.1",
	}
	var hits []map[string]any
	for i, l := range lines {
		hits = append(hits, map[string]any{"_id": fmt.Sprint(i), "_source": map[string]any{"message": l, "timestamp": "2026-11-11T00:00:00Z", "host": "acme-core"}})
	}
	reply, err := json.Marshal(map[string]any{"hits": map[string]any{"total": map[string]any{"value": 2}, "hits": hits}})
	if err != nil {
		t.Fatal(err)
	}
	fakeOS(t, string(reply))
	s := idpServer(t)
	withCommunities(t, s, labCommunityFixture)
	claims := acme()
	d := aiDataSource{srv: s, ctx: context.Background(), claims: claims}
	tr, err := d.ModuleQuery(context.Background(), s.aiPrincipal(claims), "search_logs", ai.ToolArgs{"window": "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Items) != len(lines) {
		t.Fatalf("items: %+v", tr.Items)
	}
	for _, it := range tr.Items {
		if strings.Contains(it.Text, labCommunityFixture) {
			t.Errorf("a configured community reached the tool result (LLM06): %q", it.Text)
		}
	}
	// What the agent loop renders into the conversation, i.e. what is sent.
	if rendered := ai.RenderToolReply(&tr); strings.Contains(rendered, labCommunityFixture) {
		t.Errorf("a configured community reached the rendered tool reply: %s", rendered)
	}
	// The grounded-prompt redactor masks it too.
	if got := s.irisRedactor()("prompt: poller " + labCommunityFixture + " answered"); strings.Contains(got, labCommunityFixture) {
		t.Errorf("irisRedactor left the community: %q", got)
	}
}

// LLM06 last line: a provider payload sent under a request context carries no
// configured community even from an assembler that masked nothing.
func TestProviderPayloadUnderARequestContextMasksAConfiguredCommunity(t *testing.T) {
	s := &server{}
	withCommunities(t, s, labCommunityFixture)
	cap := &capturingTransport{}
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: cap})
	defer restore()
	ctx := ai.WithEgressScrub(context.Background(), s.credScrub.MaskJSON)
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"poller ` + labCommunityFixture + ` answered"}],"max_tokens":12345678901234567890}`)
	if _, err := ai.ProviderDo(ctx, "https://api.openai.com/v1/chat/completions", nil, raw, "openai"); err != nil {
		t.Fatalf("ProviderDo: %v", err)
	}
	payload := string(cap.body)
	if payload == "" {
		t.Fatal("no payload captured")
	}
	if strings.Contains(payload, labCommunityFixture) {
		t.Fatalf("the provider payload carries a configured community:\n%s", payload)
	}
	if !strings.Contains(payload, `"model":"m"`) || !strings.Contains(payload, "12345678901234567890") {
		t.Errorf("the mask corrupted the payload: %s", payload)
	}
}

// A community saved through the API is masked from the very next read, before
// the periodic refresh runs; a deleted one stays masked.
func TestACredentialWriteRefreshesTheMask(t *testing.T) {
	dir := t.TempDir()
	rs, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := snmpcred.NewStore(filepath.Join(dir, "snmp.json"), nil, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	s := &server{roles: rs, snmpCreds: cs}
	s.credScrub = credscrub.New(snmpCommunityValues(cs, nil))
	if err := s.credScrub.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	line := "audit user: " + labCommunityFixture + "/1 terminated session (reason: normal)"
	if got := s.credScrub.Mask(line); got != line {
		t.Fatalf("masked before it was configured: %q", got)
	}
	admin := jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: "acme"}
	w := httptest.NewRecorder()
	s.handleSNMPCreds(w, req(http.MethodPost, "/api/snmp/credentials", `{"name":"edge-ro","version":"v2c","community":"`+labCommunityFixture+`"}`, admin))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), labCommunityFixture) {
		t.Fatalf("the API answer carries the community: %s", w.Body.String())
	}
	if got := s.credScrub.Mask(line); strings.Contains(got, labCommunityFixture) {
		t.Fatalf("a saved community is not masked on the next read: %q", got)
	}
	w = httptest.NewRecorder()
	s.handleSNMPCredByID(w, req(http.MethodDelete, "/api/snmp/credentials/edge-ro", "", admin))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if got := s.credScrub.Mask(line); strings.Contains(got, labCommunityFixture) {
		t.Fatalf("a deleted community became readable in stored lines: %q", got)
	}
}

// The community sources: every tenant's profiles, an operator-set
// SNMP_COMMUNITY, and a discovery community still awaiting migration. The
// protocol default is not one of them.
func TestSNMPCommunityValuesReadsEveryConfiguredSource(t *testing.T) {
	dir := t.TempDir()
	cs, err := snmpcred.NewStore(filepath.Join(dir, "snmp.json"), nil, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	a, b := "fixture-a-"+"qqqq", "fixture-b-"+"zzzz"
	if _, err := cs.Upsert(snmpcred.Credential{Name: "acme", TenantID: "acme", Version: "v2c", Community: a}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Upsert(snmpcred.Credential{Name: "globex", TenantID: "globex", Version: "v2c", Community: b}); err != nil {
		t.Fatal(err)
	}
	disc := &discoveryConfigStore{legacyCommunity: "fixture-legacy1, fixture-legacy2"}

	t.Setenv("SNMP_COMMUNITY", "")
	got, err := snmpCommunityValues(cs, disc)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{a: true, b: true, "fixture-legacy1": true, "fixture-legacy2": true}
	if len(got) != len(want) {
		t.Fatalf("got %d values, want %d", len(got), len(want))
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected source value of length %d", len(v))
		}
	}

	t.Setenv("SNMP_COMMUNITY", "fixture-env-"+"cccc")
	got, err = snmpCommunityValues(cs, nil)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "fixture-env-cccc" {
		t.Errorf("SNMP_COMMUNITY not read: %d values", len(got))
	}
}
