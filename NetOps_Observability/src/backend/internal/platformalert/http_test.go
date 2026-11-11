// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/notify"
)

type apiRig struct {
	api    *API
	store  *Store
	kv     *memKV
	audits *[]AuditEntry
	auditE *error
	caller *Caller
	allow  *bool
	logs   *logSpy
}

func newAPIRig(t *testing.T) *apiRig {
	t.Helper()
	kv, logs := newMemKV(), &logSpy{}
	store := newTestStore(t, kv, logs)
	router := NewRouter(RouterDeps{Store: store, Budgets: notify.NewPushBudgets(30, 10, nil)})
	var (
		mu     sync.Mutex
		audits []AuditEntry
		auditE error
		caller = Caller{Subject: "platform-owner"}
		allow  = true
	)
	api := NewAPI(store, router, Deps{
		Authz: func(w http.ResponseWriter, _ *http.Request) (Caller, bool) {
			if !allow {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return Caller{}, false
			}
			return caller, true
		},
		AuditStrict: func(e AuditEntry) error {
			mu.Lock()
			defer mu.Unlock()
			if auditE != nil {
				return auditE
			}
			audits = append(audits, e)
			return nil
		},
		Audit: func(e AuditEntry) { mu.Lock(); audits = append(audits, e); mu.Unlock() },
		WriteJSON: func(w http.ResponseWriter, status int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v) // test harness
		},
		WriteErr: func(w http.ResponseWriter, status int, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) // test harness
		},
		Log:        logs.log,
		Now:        func() time.Time { return time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC) },
		IgnoredEnv: []string{"PLATFORM_ALERTS_NTFY_TOPIC"},
	})
	return &apiRig{api: api, store: store, kv: kv, audits: &audits, auditE: &auditE, caller: &caller, allow: &allow, logs: logs}
}

func (a *apiRig) do(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	if path == TestPath {
		a.api.HandleTest(w, req)
	} else {
		a.api.HandleRoute(w, req)
	}
	return w.Code, w.Body.String()
}

func updateJSON(t *testing.T, u Update) string {
	t.Helper()
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fullUpdate() Update {
	return Update{
		Ntfy: NtfyUpdate{Enabled: true, Server: "https://ntfy.sh", Topic: "corr-platform-x", Token: fakeSecret("ntfy"), Tiers: Tiers{Page: true, Warning: true}},
		SMS: SMSUpdate{Enabled: true, AccountSID: fakeSID(), AuthToken: fakeSecret("twilio"), From: phoneFrom,
			To: []string{phoneA, phoneB}, Tiers: Tiers{Page: true}, MaxPerHour: 10},
	}
}

// Secrets are WRITE-ONLY: never in a GET, a PUT answer, the audit trail or a
// log line — only *_set booleans. The topic and phone numbers stay out of the
// audit/log as well.
func TestAPISecretsAreWriteOnlyAndNeverAudited(t *testing.T) {
	a := newAPIRig(t)
	st, body := a.do(t, http.MethodPut, Path, updateJSON(t, fullUpdate()))
	if st != http.StatusOK {
		t.Fatalf("PUT = %d %s", st, body)
	}
	st, get := a.do(t, http.MethodGet, Path, "")
	if st != http.StatusOK {
		t.Fatalf("GET = %d", st)
	}
	for _, secret := range []string{fakeSecret("ntfy"), fakeSecret("twilio")} {
		if strings.Contains(body, secret) || strings.Contains(get, secret) {
			t.Fatalf("a secret was returned over the API:\n%s\n%s", body, get)
		}
	}
	var v View
	if err := json.Unmarshal([]byte(get), &v); err != nil {
		t.Fatal(err)
	}
	if !v.Ntfy.TokenSet || !v.SMS.AuthTokenSet || !v.PageRouted || v.StoreStatus != "ok" {
		t.Fatalf("view: %+v", v)
	}
	if len(v.IgnoredEnv) != 1 || v.IgnoredEnv[0] != "PLATFORM_ALERTS_NTFY_TOPIC" {
		t.Fatalf("ignored env must be shown on the page: %v", v.IgnoredEnv)
	}
	trail := fmt.Sprint(*a.audits) + a.logs.all()
	for _, never := range []string{fakeSecret("ntfy"), fakeSecret("twilio"), "corr-platform-x", phoneA, phoneB} {
		if strings.Contains(trail, never) {
			t.Fatalf("%q reached the audit trail or the log:\n%s", never, trail)
		}
	}
	if len(*a.audits) != 1 || (*a.audits)[0].Detail["action"] != "platform_alert_route_set" ||
		(*a.audits)[0].Detail["ntfy_token_change"] != true || (*a.audits)[0].Detail["sms_recipients"] != 2 {
		t.Fatalf("audit: %+v", *a.audits)
	}
	if got := a.store.Current(); got.UpdatedBy != "platform-owner" {
		t.Fatalf("owner stamp from the principal: %q", got.UpdatedBy)
	}
}

// A PUT that omits a secret keeps it; clear_* removes it.
func TestAPIOmittedSecretIsPreservedAndClearRemovesIt(t *testing.T) {
	a := newAPIRig(t)
	if st, b := a.do(t, http.MethodPut, Path, updateJSON(t, fullUpdate())); st != 200 {
		t.Fatal(b)
	}
	u := fullUpdate()
	u.Ntfy.Token, u.SMS.AuthToken = "", ""
	u.SMS.MaxPerHour = 20
	if st, b := a.do(t, http.MethodPut, Path, updateJSON(t, u)); st != 200 {
		t.Fatal(b)
	}
	c := a.store.Current()
	if c.Ntfy.Token != fakeSecret("ntfy") || c.SMS.AuthToken != fakeSecret("twilio") || c.SMS.MaxPerHour != 20 {
		t.Fatalf("omitted secrets must be preserved: %+v", c)
	}
	u.Ntfy.ClearToken = true
	if st, b := a.do(t, http.MethodPut, Path, updateJSON(t, u)); st != 200 {
		t.Fatal(b)
	}
	if a.store.Current().Ntfy.Token != "" {
		t.Fatal("clear_token must remove the stored token")
	}
	// Clearing the SMS token while SMS is enabled is refused (incomplete).
	u.SMS.ClearAuthToken = true
	if st, _ := a.do(t, http.MethodPut, Path, updateJSON(t, u)); st != 400 {
		t.Fatalf("clearing a required secret of an enabled channel = %d, want 400", st)
	}
	if a.store.Current().SMS.AuthToken == "" {
		t.Fatal("a refused PUT changed the record")
	}
}

func TestAPIValidationAndBodyBounds(t *testing.T) {
	a := newAPIRig(t)
	bad := fullUpdate()
	bad.SMS.To = []string{"555-0100"}
	st, body := a.do(t, http.MethodPut, Path, updateJSON(t, bad))
	if st != 400 || !strings.Contains(body, "international format") {
		t.Fatalf("bad number = %d %s", st, body)
	}
	if len(*a.audits) != 0 {
		t.Fatal("a refused input is not a change and must not be audited as one")
	}
	for _, b := range []string{
		`{"ntfy":{"enabled":true},"extra":1}`, // unknown field
		`not json`,
		`{"ntfy":{"enabled":"yes"}}`,
		`{"ntfy":{"topic":"` + strings.Repeat("a", maxBody) + `"}}`, // over the cap
	} {
		if st, _ := a.do(t, http.MethodPut, Path, b); st != 400 {
			t.Errorf("%.40s… = %d, want 400", b, st)
		}
	}
	if st, _ := a.do(t, http.MethodDelete, Path, ""); st != 405 {
		t.Errorf("DELETE = %d, want 405", st)
	}
	if st, _ := a.do(t, http.MethodGet, TestPath, ""); st != 405 {
		t.Errorf("GET test = %d, want 405", st)
	}
	if st, _ := a.do(t, http.MethodPost, TestPath, `{"channel":"email"}`); st != 400 {
		t.Errorf("unknown test channel = %d, want 400", st)
	}
}

// The gate is the integrator's (requirePlatformAdmin): a refused caller never
// reaches the record; an API-key principal may read but never change or test.
func TestAPIGateAndAPIKeyPrincipal(t *testing.T) {
	a := newAPIRig(t)
	*a.allow = false
	for _, c := range []struct{ m, p, b string }{
		{http.MethodGet, Path, ""}, {http.MethodPut, Path, updateJSON(t, fullUpdate())}, {http.MethodPost, TestPath, `{"channel":"ntfy"}`},
	} {
		if st, _ := a.do(t, c.m, c.p, c.b); st != 403 {
			t.Errorf("%s %s by a refused caller = %d", c.m, c.p, st)
		}
	}
	if a.kv.saves != 0 {
		t.Fatal("a refused caller wrote the record")
	}
	*a.allow = true
	*a.caller = Caller{Subject: "apikey:ci", APIKey: true}
	if st, _ := a.do(t, http.MethodGet, Path, ""); st != 200 {
		t.Error("an API key may read")
	}
	if st, _ := a.do(t, http.MethodPut, Path, updateJSON(t, fullUpdate())); st != 403 {
		t.Error("an API key must not change platform alert settings")
	}
	if st, _ := a.do(t, http.MethodPost, TestPath, `{"channel":"ntfy"}`); st != 403 {
		t.Error("an API key must not send test messages")
	}
}

// A change the audit trail cannot record does not happen; a test send is
// audited too (it sends a real message, and an SMS costs money).
func TestAPIAuditFirst(t *testing.T) {
	a := newAPIRig(t)
	*a.auditE = errors.New("audit store down")
	if st, _ := a.do(t, http.MethodPut, Path, updateJSON(t, fullUpdate())); st != 500 {
		t.Fatal("PUT with a failing audit must be refused")
	}
	if a.kv.saves != 0 || a.store.Current().PageRouted() {
		t.Fatal("the record changed although the audit failed")
	}
	if st, _ := a.do(t, http.MethodPost, TestPath, `{"channel":"ntfy"}`); st != 500 {
		t.Fatal("a test with a failing audit must not be sent")
	}
	*a.auditE = nil
	st, body := a.do(t, http.MethodPost, TestPath, `{"channel":"sms"}`)
	if st != 200 || !strings.Contains(body, `"verdict":"not_configured"`) {
		t.Fatalf("test of an unconfigured channel = %d %s", st, body)
	}
	if (*a.audits)[len(*a.audits)-1].Detail["action"] != "platform_alert_route_test" {
		t.Fatal("test send not audited")
	}
}

// Saving a record that routes pages nowhere is allowed (an administrator may
// switch everything off) but it is LOUD.
func TestAPISavingNoPageChannelIsLoud(t *testing.T) {
	a := newAPIRig(t)
	u := fullUpdate()
	u.Ntfy.Enabled, u.SMS.Enabled = false, false
	if st, b := a.do(t, http.MethodPut, Path, updateJSON(t, u)); st != 200 {
		t.Fatal(b)
	}
	if a.logs.count("reach nobody") != 1 {
		t.Fatalf("saving with no page channel must warn:\n%s", a.logs.all())
	}
	_, get := a.do(t, http.MethodGet, Path, "")
	if !strings.Contains(get, `"page_routed":false`) {
		t.Fatal(get)
	}
}

// A never-read store: GET says so, PUT is 409 until the administrator ticks
// "replace".
func TestAPIUnreadableStoreFlow(t *testing.T) {
	a := newAPIRig(t)
	a.kv.setLoadErr(errors.New("pg: down"))
	// Simulate a boot that could never read.
	a.store = newTestStore(t, a.kv, a.logs)
	a.api.store = a.store
	_, get := a.do(t, http.MethodGet, Path, "")
	if !strings.Contains(get, `"store_status":"unreadable"`) {
		t.Fatal(get)
	}
	a.kv.setLoadErr(nil)
	if st, body := a.do(t, http.MethodPut, Path, updateJSON(t, fullUpdate())); st != 409 || !strings.Contains(body, "Replace the saved settings") {
		t.Fatalf("PUT over an unreadable record = %d %s", st, body)
	}
	u := fullUpdate()
	u.ReplaceUnreadable = true
	if st, body := a.do(t, http.MethodPut, Path, updateJSON(t, u)); st != 200 {
		t.Fatalf("PUT with replace = %d %s", st, body)
	}
}
