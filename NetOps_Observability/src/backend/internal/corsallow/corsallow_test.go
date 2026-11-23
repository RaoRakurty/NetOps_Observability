// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package corsallow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeAcceptsOnlyABrowserOrigin(t *testing.T) {
	ok := map[string]string{
		"https://app.example.com":       "https://app.example.com",
		"  HTTPS://App.Example.COM/ ":   "https://app.example.com",
		"https://app.example.com:443":   "https://app.example.com",
		"https://app.example.com:8443":  "https://app.example.com:8443",
		"https://app.example.com:08443": "https://app.example.com:8443",
		"http://localhost:5173":         "http://localhost:5173",
		"http://127.0.0.1":              "http://127.0.0.1",
		"http://[::1]:3000":             "http://[::1]:3000",
		"https://10.0.0.5":              "https://10.0.0.5",
		"https://[2001:db8::1]:8443":    "https://[2001:db8::1]:8443",
		"https://xn--bcher-kva.example": "https://xn--bcher-kva.example",
	}
	for in, want := range ok {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "*", "https://*", "https://*.example.com", "null",
		"app.example.com",                 // no scheme
		"http://app.example.com",          // plain http off localhost
		"ftp://app.example.com",           // wrong scheme
		"javascript:alert(1)",             // opaque
		"https://user:pw@app.example.com", // credentials
		"https://app.example.com/path",    // path
		"https://app.example.com?x=1",     // query
		"https://app.example.com#frag",    // fragment
		"https://app.example.com:0",       // port range
		"https://app.example.com:70000",
		"https://app.example.com:", // empty port
		"https://app.example.com.", // trailing dot
		"https://bücher.example",   // not punycode
		"https://-bad.example.com", // label rule
		"https://app example.com",  // space
		"https://" + strings.Repeat("a", MaxOriginLen),
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q; want a refusal", in, got)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("Normalize(%q) error %v does not wrap ErrInvalid", in, err)
		}
	}
}

func TestValidateListRefusesTheWholeListAndNamesEveryBadEntry(t *testing.T) {
	_, err := ValidateList([]string{"https://ok.example.com", "*", "http://evil.example.com"})
	if err == nil {
		t.Fatal("a list with bad entries must be refused whole")
	}
	for _, want := range []string{`"*"`, `"http://evil.example.com"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	got, err := ValidateList([]string{"https://a.example.com", "HTTPS://A.example.com/", "https://b.example.com"})
	if err != nil || fmt.Sprint(got) != "[https://a.example.com https://b.example.com]" {
		t.Fatalf("dedupe/order: got %v, %v", got, err)
	}
	many := make([]string, MaxOrigins+1)
	for i := range many {
		many[i] = fmt.Sprintf("https://app%d.example.com", i)
	}
	if _, err := ValidateList(many); err == nil {
		t.Fatalf("more than %d origins must be refused", MaxOrigins)
	}
}

// memStore is an in-memory Store.
type memStore struct {
	mu      sync.Mutex
	b       []byte
	loadErr error
	saveErr error
	saves   int
}

func (m *memStore) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.b == nil {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), m.b...), nil
}

func (m *memStore) Save(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.b, m.saves = append([]byte(nil), b...), m.saves+1
	return nil
}

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func TestTheInstallValueIsTheSeedAndBadEnvEntriesAreDroppedLoudly(t *testing.T) {
	a := New(&memStore{}, " https://app.example.com/ , *, http://evil.example.com, https://app.example.com ")
	if err := a.Load(); err != nil {
		t.Fatal(err)
	}
	v := a.View()
	if v.Source != SourceEnv || fmt.Sprint(v.Origins) != "[https://app.example.com]" {
		t.Fatalf("seed view = %+v", v)
	}
	if len(v.EnvDropped) != 2 || len(a.EnvDropped()) != 2 {
		t.Fatalf("dropped = %v, want the two bad entries", v.EnvDropped)
	}
	if !a.Allowed("https://app.example.com") || a.Allowed("https://evil.example.com") || a.Allowed("*") {
		t.Fatal("only the valid install origin may be allowed")
	}
	if New(&memStore{}, "").View().Source != SourceNone {
		t.Fatal("no install value and nothing saved = none")
	}
}

func TestASavedListWinsOverTheInstallValueAndAppliesLive(t *testing.T) {
	st := &memStore{}
	a := New(st, "https://env.example.com")
	if _, _, err := a.Set([]string{"https://rum.example.com"}, "owner", t0); err != nil {
		t.Fatal(err)
	}
	// Live: no restart, no reload — the very next check sees it.
	if !a.Allowed("https://rum.example.com") || a.Allowed("https://env.example.com") {
		t.Fatal("the saved list must replace the install value immediately")
	}
	// Durable: a fresh process reads it back.
	b := New(st, "https://env.example.com")
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	if v := b.View(); v.Source != SourceSaved || v.UpdatedBy != "owner" || !v.UpdatedAt.Equal(t0) {
		t.Fatalf("reloaded view = %+v", v)
	}
	// An empty saved list means NONE — not "fall back to the install value".
	if _, _, err := a.Set([]string{}, "owner", t0); err != nil {
		t.Fatal(err)
	}
	if v := a.View(); v.Source != SourceSaved || len(v.Origins) != 0 || a.Allowed("https://env.example.com") {
		t.Fatalf("empty saved list = %+v", v)
	}
	// Reset returns to the install value.
	if _, after, err := a.Reset("owner", t0); err != nil || fmt.Sprint(after) != "[https://env.example.com]" {
		t.Fatalf("reset: %v %v", after, err)
	}
	if a.View().Source != SourceEnv || !a.Allowed("https://env.example.com") {
		t.Fatal("reset must put the install value back in force")
	}
}

func TestNothingChangesWhenTheListIsInvalidOrTheSaveFails(t *testing.T) {
	st := &memStore{}
	a := New(st, "https://env.example.com")
	if _, _, err := a.Set([]string{"*"}, "owner", t0); err == nil {
		t.Fatal("* must be refused")
	}
	st.saveErr = errors.New("disk full")
	if _, _, err := a.Set([]string{"https://rum.example.com"}, "owner", t0); err == nil {
		t.Fatal("a failed save must be an error")
	}
	if a.View().Source != SourceEnv || a.Allowed("https://rum.example.com") || st.saves != 0 {
		t.Fatal("a refused or unsaved change must leave the list in force untouched")
	}
}

func TestAStoredRecordIsRevalidatedOnRead(t *testing.T) {
	for name, blob := range map[string]string{
		"wildcard":  `{"v":1,"origins":["*"]}`,
		"plainhttp": `{"v":1,"origins":["http://evil.example.com"]}`,
		"garbage":   `{not json`,
	} {
		a := New(&memStore{b: []byte(blob)}, "https://env.example.com")
		if err := a.Load(); err == nil {
			t.Errorf("%s: a bad stored record must be refused", name)
		}
		if a.View().Source != SourceEnv || a.Allowed("http://evil.example.com") {
			t.Errorf("%s: a refused record must leave the install value in force", name)
		}
	}
	a := New(&memStore{loadErr: errors.New("pg down")}, "https://env.example.com")
	if err := a.Load(); err == nil || !a.Allowed("https://env.example.com") {
		t.Fatal("an unreadable store is an error and keeps the install value")
	}
}

func TestAllowedMatchesTheBrowserOriginNotLooserForms(t *testing.T) {
	a := New(&memStore{}, "https://app.example.com:8443")
	for origin, want := range map[string]bool{
		"https://app.example.com:8443":      true,
		"HTTPS://APP.EXAMPLE.COM:8443":      true,
		"https://app.example.com":           false,
		"https://evil.app.example.com:8443": false,
		"https://app.example.com.evil.com":  false,
		"null":                              false,
		"":                                  false,
	} {
		if got := a.Allowed(origin); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", origin, got, want)
		}
	}
	var nilList *Allowlist
	if nilList.Allowed("https://app.example.com:8443") {
		t.Fatal("a nil allowlist allows nothing")
	}
}

// --- HTTP ------------------------------------------------------------------

type harness struct {
	api      *API
	list     *Allowlist
	store    *memStore
	audits   []AuditEntry
	auditErr error
	caller   Caller
	deny     bool
}

func newHarness(env string) *harness {
	h := &harness{store: &memStore{}, caller: Caller{Subject: "platform-owner"}}
	h.list = New(h.store, env)
	h.api = NewAPI(h.list, Deps{
		Authz: func(w http.ResponseWriter, r *http.Request) (Caller, bool) {
			if h.deny {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Caller{}, false
			}
			return h.caller, true
		},
		AuditStrict: func(e AuditEntry) error {
			if h.auditErr != nil {
				return h.auditErr
			}
			h.audits = append(h.audits, e)
			return nil
		},
		Audit:     func(e AuditEntry) { h.audits = append(h.audits, e) },
		WriteJSON: func(w http.ResponseWriter, s int, v any) { w.WriteHeader(s); _ = json.NewEncoder(w).Encode(v) },
		WriteErr:  func(w http.ResponseWriter, s int, err error) { http.Error(w, err.Error(), s) },
		LogInfo:   func(string, map[string]any) {},
		Now:       func() time.Time { return t0 },
	})
	return h
}

func (h *harness) do(method, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/platform/cors-origins", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.api.Handle(w, r)
	return w
}

func TestHTTPRefusesWhenNotThePlatformAdmin(t *testing.T) {
	h := newHarness("")
	h.deny = true
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if w := h.do(m, `{"origins":["https://a.example.com"]}`); w.Code != http.StatusForbidden {
			t.Fatalf("%s by a non-platform-admin = %d, want 403", m, w.Code)
		}
	}
	if h.list.View().Source != SourceNone || len(h.audits) != 0 {
		t.Fatal("a refused caller must change nothing")
	}
}

func TestHTTPSetIsAuditedFirstWithOldAndNew(t *testing.T) {
	h := newHarness("https://env.example.com")
	w := h.do(http.MethodPut, `{"origins":["https://rum.example.com","HTTPS://RUM.example.com/"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	var v View
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.Source != SourceSaved || fmt.Sprint(v.Origins) != "[https://rum.example.com]" {
		t.Fatalf("response view = %+v, %v", v, err)
	}
	if len(h.audits) != 1 {
		t.Fatalf("audits = %d, want 1", len(h.audits))
	}
	d := h.audits[0].Detail
	if h.audits[0].Subject != "platform-owner" || d["action"] != "cors_origins_set" ||
		fmt.Sprint(d["from"]) != "[https://env.example.com]" || fmt.Sprint(d["to"]) != "[https://rum.example.com]" || d["from_source"] != "env" {
		t.Fatalf("audit = %+v", h.audits[0])
	}
}

func TestHTTPNoAuditNoChange(t *testing.T) {
	h := newHarness("")
	h.auditErr = errors.New("audit store down")
	if w := h.do(http.MethodPut, `{"origins":["https://rum.example.com"]}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("PUT with the audit down = %d, want 500", w.Code)
	}
	if h.list.Allowed("https://rum.example.com") || h.store.saves != 0 {
		t.Fatal("a change the audit could not record must not happen")
	}
}

func TestHTTPRefusesBadInput(t *testing.T) {
	h := newHarness("")
	cases := map[string]string{
		"wildcard":    `{"origins":["*"]}`,
		"plain http":  `{"origins":["http://app.example.com"]}`,
		"path":        `{"origins":["https://app.example.com/x"]}`,
		"both":        `{"origins":[],"reset":true}`,
		"neither":     `{}`,
		"unknown key": `{"origins":[],"allow_all":true}`,
		"not json":    `origins=*`,
		"wrong type":  `{"origins":"https://app.example.com"}`,
	}
	for name, body := range cases {
		if w := h.do(http.MethodPut, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT %s = %d, want 400", name, body, w.Code)
		}
	}
	big := `{"origins":["https://` + strings.Repeat("a", maxBody) + `.example.com"]}`
	if w := h.do(http.MethodPut, big); w.Code != http.StatusBadRequest {
		t.Errorf("oversized body = %d, want 400", w.Code)
	}
	if len(h.audits) != 0 || h.store.saves != 0 {
		t.Fatal("refused input must not be audited as a change or saved")
	}
}

func TestHTTPRefusesAnAPIKeyAndUnknownMethods(t *testing.T) {
	h := newHarness("")
	h.caller.APIKey = true
	if w := h.do(http.MethodPut, `{"origins":["https://a.example.com"]}`); w.Code != http.StatusForbidden {
		t.Fatalf("API key PUT = %d, want 403", w.Code)
	}
	h.caller.APIKey = false
	if w := h.do(http.MethodDelete, ``); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, PUT" {
		t.Fatalf("DELETE = %d allow=%q, want 405 GET, PUT", w.Code, w.Header().Get("Allow"))
	}
}

func TestHTTPResetReturnsToTheInstallValue(t *testing.T) {
	h := newHarness("https://env.example.com")
	h.do(http.MethodPut, `{"origins":[]}`)
	w := h.do(http.MethodPut, `{"reset":true}`)
	if w.Code != http.StatusOK || h.list.View().Source != SourceEnv || !h.list.Allowed("https://env.example.com") {
		t.Fatalf("reset = %d %s", w.Code, w.Body)
	}
	if last := h.audits[len(h.audits)-1]; last.Detail["action"] != "cors_origins_reset" || fmt.Sprint(last.Detail["to"]) != "[https://env.example.com]" {
		t.Fatalf("reset audit = %+v", last)
	}
}

func TestHTTPSaveFailureIsAuditedAsAnErrorAndChangesNothing(t *testing.T) {
	h := newHarness("")
	h.store.saveErr = errors.New("pg down")
	if w := h.do(http.MethodPut, `{"origins":["https://rum.example.com"]}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("PUT with a failing store = %d", w.Code)
	}
	if len(h.audits) != 2 || h.audits[1].Outcome != "error" || h.list.Allowed("https://rum.example.com") {
		t.Fatalf("audits = %+v", h.audits)
	}
}
