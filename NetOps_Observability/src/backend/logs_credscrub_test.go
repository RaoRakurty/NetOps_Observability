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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/credscrub"
	"netops/backend/internal/logexport"
	"netops/backend/internal/ratelimit"
	"netops/backend/internal/snmpcred"
)

// A fabricated community, built at run time.
var labCommunityFixture = "fixture-comm-" + strings.Repeat("q", 6)

// withCommunities configures values as acme's own communities (the tests'
// caller is acme()).
func withCommunities(t *testing.T, s *server, values ...string) {
	t.Helper()
	vs := make([]credscrub.Value, 0, len(values))
	for _, v := range values {
		vs = append(vs, credscrub.Value{Tenant: "acme", Text: v})
	}
	withTenantCommunities(t, s, vs...)
}

func withTenantCommunities(t *testing.T, s *server, values ...credscrub.Value) {
	t.Helper()
	s.credScrub = credscrub.New(func(context.Context) ([]credscrub.Value, error) { return values, nil })
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
	if got := s.irisRedactor(claims)("prompt: poller " + labCommunityFixture + " answered"); strings.Contains(got, labCommunityFixture) {
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
	ctx := ai.WithEgressScrub(context.Background(), s.credScrub.Union().MaskJSON)
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
	if got := s.credScrub.For("acme", false).Mask(line); got != line {
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
	if got := s.credScrub.For("acme", false).Mask(line); strings.Contains(got, labCommunityFixture) {
		t.Fatalf("a saved community is not masked on the next read: %q", got)
	}
	w = httptest.NewRecorder()
	s.handleSNMPCredByID(w, req(http.MethodDelete, "/api/snmp/credentials/edge-ro", "", admin))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if got := s.credScrub.For("acme", false).Mask(line); strings.Contains(got, labCommunityFixture) {
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
	// Each profile keeps its tenant; platform configuration is global ("").
	want := map[credscrub.Value]bool{
		{Tenant: "acme", Text: a}: true, {Tenant: "globex", Text: b}: true,
		{Text: "fixture-legacy1"}: true, {Text: "fixture-legacy2"}: true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d values, want %d", len(got), len(want))
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected source value (tenant %q, length %d)", v.Tenant, len(v.Text))
		}
	}

	t.Setenv("SNMP_COMMUNITY", "fixture-env-"+"cccc")
	got, err = snmpCommunityValues(cs, nil)(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != (credscrub.Value{Text: "fixture-env-cccc"}) {
		t.Errorf("SNMP_COMMUNITY not read as a global value: %d values", len(got))
	}
}

// ---- §3a: each caller masks with its own set -------------------------------

// fourTenantValuesReply holds acme's community, globex's, and a platform one in
// one acme record. The fake store ignores scoping on purpose: this is about the
// mask set, not the query.
func fourTenantValuesReply(acmeV, globexV, globalV string) string {
	msg := "poller " + acmeV + " and " + globexV + " and " + globalV
	return `{"took":1,"hits":{"total":{"value":1,"relation":"eq"},"hits":[` +
		`{"_index":"netops-syslog-acme-2026.11.11","_id":"1","sort":[1,"1"],"_source":{"timestamp":"2026-11-11T09:00:00Z",` +
		`"hostname":"acme-core","tenant_id":"acme","audit_user":"` + globexV + `","message":"` + msg + `"}}]},` +
		`"aggregations":{"users":{"buckets":[{"key":"` + acmeV + `"},{"key":"` + globexV + `"}]}}}`
}

func tenantMaskFixture(t *testing.T, s *server) (acmeV, globexV, globalV string) {
	t.Helper()
	acmeV = "fixture-acme-" + strings.Repeat("a", 5)
	globexV = "fixture-globex-" + strings.Repeat("b", 5)
	globalV = "fixture-platform-" + strings.Repeat("c", 5)
	withTenantCommunities(t, s,
		credscrub.Value{Tenant: "acme", Text: acmeV},
		credscrub.Value{Tenant: "globex", Text: globexV},
		credscrub.Value{Tenant: "", Text: globalV})
	return acmeV, globexV, globalV
}

// Masking another tenant's value would answer "is this string some tenant's
// community?" for any string a tenant can get into its own logs. acme's search
// masks acme's own value and the platform's; globex's value stays as text.
func TestLogSearchMasksOnlyTheCallersOwnCommunities(t *testing.T) {
	s := logsTestServer(t)
	acmeV, globexV, globalV := tenantMaskFixture(t, s)
	fakeOS(t, fourTenantValuesReply(acmeV, globexV, globalV))

	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=syslog&include_routine_mgmt=true", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, acmeV) || strings.Contains(body, globalV) {
		t.Errorf("acme's own or the platform's community was served to acme:\n%s", body)
	}
	if strings.Count(body, globexV) != 3 {
		t.Errorf("CROSS-TENANT ORACLE: globex's value must reach acme unmasked (audit_user, message, bucket), got %d:\n%s",
			strings.Count(body, globexV), body)
	}

	// as_tenant cannot borrow another tenant's set.
	w = httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=syslog&as_tenant=globex", "", acme()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), globexV) || strings.Contains(w.Body.String(), acmeV) {
		t.Errorf("as_tenant changed acme's mask set: %d %s", w.Code, w.Body.String())
	}
}

// The platform owner reads every tenant's records, so it masks every tenant's
// communities.
func TestLogSearchCrossTenantCallerMasksEveryTenantsCommunities(t *testing.T) {
	s := logsTestServer(t)
	acmeV, globexV, globalV := tenantMaskFixture(t, s)
	fakeOS(t, fourTenantValuesReply(acmeV, globexV, globalV))
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=syslog", "", superA()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	for _, v := range []string{acmeV, globexV, globalV} {
		if strings.Contains(w.Body.String(), v) {
			t.Errorf("a cross-tenant caller was served a community:\n%s", w.Body.String())
		}
	}
}

// The export freezes the requester's principal, so the queued worker masks with
// the REQUESTER's set, not the union and not nothing.
func TestExportFreezesTheRequestersMaskSet(t *testing.T) {
	s := logsTestServer(t)
	acmeV, globexV, globalV := tenantMaskFixture(t, s)

	spec := s.exportSpecFor(acme(), "", "", "", "syslog", "json")
	if spec.MaskTenant != "acme" || spec.MaskCross {
		t.Fatalf("acme's spec froze mask scope %q/%v", spec.MaskTenant, spec.MaskCross)
	}
	if owner := s.exportSpecFor(superA(), "", "", "", "syslog", "json"); !owner.MaskCross {
		t.Fatal("the platform owner's spec did not freeze a cross-tenant mask scope")
	}
	// Round-trip the spec the way the queue does, then fetch as the worker does.
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var frozen logexport.Spec
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	reply := fourTenantValuesReply(acmeV, globexV, globalV)
	calls := 0
	search := func(_, _ string, _ any) (*http.Response, error) {
		calls++
		r := `{"hits":{"hits":[]}}`
		if calls == 1 {
			r = reply
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(r))}, nil
	}
	start, end := time.Now().Add(-time.Hour), time.Now()
	data, err := logexport.FetchBounded(context.Background(), search, frozen, start, end, 100, 1<<20,
		s.logValueMasker(frozen.MaskTenant, frozen.MaskCross))
	if err != nil {
		t.Fatal(err)
	}
	out := string(data.Raw[0])
	if strings.Contains(out, acmeV) || strings.Contains(out, globalV) || !strings.Contains(out, globexV) {
		t.Errorf("the queued export did not mask with acme's set: %s", out)
	}

	// And the sync door, end to end.
	fakeOS(t, reply)
	s.exportLimiter = ratelimit.New()
	w := httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=syslog&mode=sync&format=json", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if b := w.Body.String(); strings.Contains(b, acmeV) || !strings.Contains(b, globexV) {
		t.Errorf("the sync export did not mask with acme's set: %s", b)
	}
}

// Iris: acme's tool result and grounded prompt mask acme's set only.
func TestIrisMasksOnlyTheCallersOwnCommunities(t *testing.T) {
	s := idpServer(t)
	acmeV, globexV, globalV := tenantMaskFixture(t, s)
	line := "poller " + acmeV + " and " + globexV + " and " + globalV
	reply, err := json.Marshal(map[string]any{"hits": map[string]any{"total": map[string]any{"value": 1},
		"hits": []map[string]any{{"_id": "0", "_source": map[string]any{"message": line, "timestamp": "2026-11-11T00:00:00Z", "host": "acme-core"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	fakeOS(t, string(reply))
	claims := acme()
	d := aiDataSource{srv: s, ctx: context.Background(), claims: claims}
	tr, err := d.ModuleQuery(context.Background(), s.aiPrincipal(claims), "search_logs", ai.ToolArgs{"window": "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Items) != 1 {
		t.Fatalf("items: %+v", tr.Items)
	}
	text := tr.Items[0].Text
	if strings.Contains(text, acmeV) || strings.Contains(text, globalV) || !strings.Contains(text, globexV) {
		t.Errorf("the tool result was not masked with acme's set: %q", text)
	}
	got := s.irisRedactor(claims)(line)
	if strings.Contains(got, acmeV) || strings.Contains(got, globalV) || !strings.Contains(got, globexV) {
		t.Errorf("irisRedactor did not mask with acme's set: %q", got)
	}
	if got := s.irisRedactor(superA())(line); strings.Contains(got, acmeV) || strings.Contains(got, globexV) {
		t.Errorf("the platform owner's redactor did not mask every tenant's value: %q", got)
	}
}

// LLM06 last line without a request: a background job's provider call is
// still scrubbed by the boot-time default (every tenant's values).
func TestProviderPayloadFromABackgroundContextIsScrubbed(t *testing.T) {
	s := &server{}
	acmeV, globexV, _ := tenantMaskFixture(t, s)
	ai.SetDefaultEgressScrub(func(b []byte) []byte { return s.credScrub.Union().MaskJSON(b) })
	t.Cleanup(func() { ai.SetDefaultEgressScrub(nil) })
	cap := &capturingTransport{}
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: cap})
	defer restore()
	raw := []byte(`{"model":"m","messages":[{"role":"user","content":"poller ` + acmeV + ` and ` + globexV + `"}]}`)
	if _, err := ai.ProviderDo(context.Background(), "https://api.openai.com/v1/chat/completions", nil, raw, "openai"); err != nil {
		t.Fatalf("ProviderDo: %v", err)
	}
	if p := string(cap.body); p == "" || strings.Contains(p, acmeV) || strings.Contains(p, globexV) {
		t.Fatalf("a background provider call was not scrubbed:\n%s", p)
	}
}
