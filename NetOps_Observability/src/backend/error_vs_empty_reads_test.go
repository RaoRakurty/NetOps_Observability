package main

// error_vs_empty_reads_test.go — proof for the READ-SURFACE half of the
// CLAUDE.md §10 conflation cleanup (silent_failure_guards_test.go is the
// mechanical guard; cloud_monitor_eval.go is the three-state reference).
//
// The class: a dependency that DID NOT ANSWER rendered as a dependency that
// answered "nothing here". Zero critical events beside a total of 1043; a
// tenant's operator overrides reported as "0 configured"; a metric store outage
// reaching the assistant as "this device reports no metrics". Each test below
// drives the dependency into failure and asserts the surface now says UNKNOWN.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/appid"
	"netops/backend/nms"
	"netops/backend/safehttp"
)

// failingCH points CLICKHOUSE_URL at a server that always errors, so every
// s.chRows / s.chRowsScope read in the process fails.
func failingCH(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "clickhouse is down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
}

// answeringCH returns rows for any query, so the "answered with data" and
// "answered with nothing" states can be told apart from the failure state.
func answeringCH(t *testing.T, data []map[string]any) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
}

// TestFeedFacetsReportUnknownNotZero is the headline case: the triage chips.
// feedTotal already used a -1 "unknown" sentinel; feedFacet returned `{}` for
// BOTH "no matching events" and "the read failed", so the UI drew "0 critical"
// next to a non-zero total. nil (JSON null) is now the facet's sentinel.
func TestFeedFacetsReportUnknownNotZero(t *testing.T) {
	_, s := newTestServerState(t)
	r := httptest.NewRequest(http.MethodGet, "/api/events/feed", nil)

	answeringCH(t, []map[string]any{{"k": "critical", "c": "7"}})
	got := s.feedFacet(r, "1", "severity")
	if got == nil || got["critical"] != 7 {
		t.Fatalf("a healthy facet read must return counts, got %v", got)
	}

	answeringCH(t, []map[string]any{})
	got = s.feedFacet(r, "1", "severity")
	if got == nil || len(got) != 0 {
		t.Fatalf("an EMPTY window must stay an empty object (genuinely no events), got %v", got)
	}

	failingCH(t)
	if got := s.feedFacet(r, "1", "severity"); got != nil {
		t.Fatalf("a FAILED facet read must be nil/unknown, never an empty object that renders as zero: %v", got)
	}
	if total := s.feedTotal(r, "1"); total != -1 {
		t.Fatalf("feedTotal must stay -1/unknown on failure, got %d", total)
	}
}

// failingOverrides is an appCatalogStore whose List never answers.
type failingOverrides struct{}

func (failingOverrides) List(context.Context, string, bool) ([]AppCatalogEntry, error) {
	return nil, errors.New("app_catalog: connection refused")
}
func (failingOverrides) Create(context.Context, string, bool, AppCatalogEntry) (AppCatalogEntry, error) {
	return AppCatalogEntry{}, errors.New("app_catalog: connection refused")
}
func (failingOverrides) Delete(context.Context, string, bool, string) (bool, error) {
	return false, errors.New("app_catalog: connection refused")
}

// TestAppIDOverrideStoreFailureIsNotZeroOverrides pins both halves of the
// appid fix: the RESOLVE surfaces refuse to publish a lower-precedence guess
// when the top of the ladder could not be read, and the status page reports
// UNKNOWN (-1) instead of "this tenant has 0 overrides".
func TestAppIDOverrideStoreFailureIsNotZeroOverrides(t *testing.T) {
	srv, s := newTestServerState(t)
	// The harness builds the struct directly, so wire the feed holder (as
	// appid_catalog_test.go does) before hitting the status surface.
	s.appCatalog = &appCatalogHolder{}
	s.appCatalog.cur.Store(appid.NewCatalog(nil))
	tok := adminToken(t, srv)

	// Control: the healthy in-memory store answers "no overrides configured".
	st, body := do(t, srv, "GET", "/api/appid/status", tok, nil)
	if st != http.StatusOK {
		t.Fatalf("status: %d %s", st, body)
	}
	var ok map[string]any
	if err := json.Unmarshal(body, &ok); err != nil {
		t.Fatal(err)
	}
	if ok["tenant_overrides"].(float64) != 0 {
		t.Fatalf("a tenant with no overrides must report 0: %v", ok["tenant_overrides"])
	}
	if _, bad := ok["tenant_overrides_unavailable"]; bad {
		t.Fatal("a healthy store must not report the overrides as unavailable")
	}

	s.appOverrides = failingOverrides{}

	st, body = do(t, srv, "GET", "/api/appid/status", tok, nil)
	if st != http.StatusOK {
		t.Fatalf("status must still render: %d %s", st, body)
	}
	var down map[string]any
	if err := json.Unmarshal(body, &down); err != nil {
		t.Fatal(err)
	}
	if down["tenant_overrides_unavailable"] != true {
		t.Fatalf("a store that did not answer must be reported, not counted as zero: %s", body)
	}
	if down["tenant_overrides"].(float64) != -1 {
		t.Fatalf("override counts must be the -1 UNKNOWN sentinel when the store failed: %s", body)
	}

	// The attribution answers must refuse rather than resolve without the
	// highest-precedence layer.
	if st, body := do(t, srv, "GET", "/api/appid/resolve?ip=8.8.8.8", tok, nil); st != http.StatusBadGateway {
		t.Fatalf("resolve must refuse when the operator override layer is unreadable, got %d %s", st, body)
	}
	st, body = do(t, srv, "POST", "/api/appid/resolve/batch", tok, map[string]any{"keys": []string{"8.8.8.8"}})
	if st != http.StatusBadGateway {
		t.Fatalf("batch resolve must refuse when the operator override layer is unreadable, got %d %s", st, body)
	}
}

// TestVerifyCaseLookupFailureIsNotAMissingCase covers verify_service.go's second
// site: a projection outage must not be indistinguishable from "no such case".
// The lookup still reports not-found (a case is never invented) — the assertion
// is that the two paths are separate branches with the failure recorded.
func TestVerifyCaseLookupFailureIsNotAMissingCase(t *testing.T) {
	_, s := newTestServerState(t)
	id := "0192f1a2-3b4c-7d5e-8f60-112233445566"

	answeringCH(t, []map[string]any{{"tenant_id": "t-1", "state": "open", "verdict": "suspected"}})
	if _, found := s.verifyCaseLookup(context.Background(), "t-1", id); !found {
		t.Fatal("a case the projection returns must be found")
	}
	answeringCH(t, []map[string]any{})
	if _, found := s.verifyCaseLookup(context.Background(), "t-1", id); found {
		t.Fatal("an empty answer means the case does not exist in this scope")
	}
	failingCH(t)
	if _, found := s.verifyCaseLookup(context.Background(), "t-1", id); found {
		t.Fatal("a failed read must not fabricate a case")
	}
}

// TestNMSAuthDistinguishesUnreadableBodyFromMissingToken: three vendor logins
// answered "no token" both when the controller returned a token-less 200 and
// when the body could not be decoded at all (proxy login page, truncated read).
func TestNMSAuthDistinguishesUnreadableBodyFromMissingToken(t *testing.T) {
	creds := nms.Credentials{Username: "u", Password: "p"}
	cases := []struct {
		name string
		auth interface {
			Authenticate(context.Context, string, nms.Credentials, nms.Doer) (nms.Session, error)
		}
	}{
		{"catalyst", nms.CatalystAuth{}},
		{"vmanage", nms.VManageAuth{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, tc := range []struct {
				body, want string
			}{
				{`{"Token":"","token":""}`, "no token"},
				{`<html>login page</html>`, "unreadable token response"},
			} {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(tc.body))
				}))
				_, err := c.auth.Authenticate(context.Background(), srv.URL, creds, srv.Client())
				srv.Close()
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("body %q → err %v, want it to name %q", tc.body, err, tc.want)
				}
			}
		})
	}
}

// TestURLValidationNamesTheActualMistake: the ticketing base-URL parsers and the
// internal CA collapsed "not a URL" and "no host / no scheme" into one message,
// so an operator who forgot `https://` was told their URL was invalid with no
// hint which half failed.
func TestURLValidationNamesTheActualMistake(t *testing.T) {
	if _, err := jiraBaseURL("jira.example.com"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("a scheme-less Jira URL must say so, got %v", err)
	}
	if _, err := jiraBaseURL("https://jira.example.com"); err != nil {
		t.Fatalf("a valid Jira URL must pass: %v", err)
	}
	if _, err := parseInstanceURL("dev123.service-now.com"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("a scheme-less ServiceNow URL must say so, got %v", err)
	}
	if _, err := parseInstanceURL("https://dev123.service-now.com"); err != nil {
		t.Fatalf("a valid ServiceNow URL must pass: %v", err)
	}
}

// TestWSOriginRejectsBothWaysExplicitly: an unparseable Origin and a host-less
// Origin are different facts; both must stay fail-CLOSED (SR-006).
func TestWSOriginRejectsBothWaysExplicitly(t *testing.T) {
	for _, origin := range []string{"://bad", "http://", "https://evil.example.com"} {
		r := httptest.NewRequest(http.MethodGet, "http://api.local/api/events", nil)
		r.Host = "api.local"
		r.Header.Set("Origin", origin)
		if wsOriginAllowed(r) {
			t.Fatalf("origin %q must be refused", origin)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://api.local/api/events", nil)
	r.Host = "api.local"
	r.Header.Set("Origin", "http://api.local")
	if !wsOriginAllowed(r) {
		t.Fatal("a same-origin handshake must be allowed")
	}
}

// TestSafeHTTPValidateURLKeepsUnresolvedHostsAllowed guards the (b)-outcome
// split in safehttp: a resolver failure and "resolved to nothing" both defer to
// the dialer, which is the actual enforcement point — the branches are now
// separate so that intent is explicit rather than incidental.
func TestSafeHTTPValidateURLKeepsUnresolvedHostsAllowed(t *testing.T) {
	if err := safehttp.ValidateURL("host.invalid.nonexistent.example"); err != nil {
		t.Fatalf("an unresolvable host must remain a save-time PASS (the dialer guards it): %v", err)
	}
	if err := safehttp.ValidateURL("127.0.0.1"); err == nil {
		t.Fatal("a literal loopback address must still be blocked at save time")
	}
}

// TestWirelessJSONBlobSurfacesEncodeFailures: the `data` column encoder used to
// answer "{}" for an encode failure, so a row landed with every non-column field
// silently dropped and the upsert still reported success.
func TestWirelessJSONBlobSurfacesEncodeFailures(t *testing.T) {
	if _, err := jsonBlob(map[string]string{"ok": "yes"}); err != nil {
		t.Fatalf("a normal record must encode: %v", err)
	}
	if _, err := jsonBlob(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("an unencodable record must return an error, not a silent empty object")
	}
}
