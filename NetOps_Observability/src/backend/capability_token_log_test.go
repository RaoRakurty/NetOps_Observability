package main

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/reports"
)

// capability_token_log_test.go — audit PIPE-HIGH-2: signed capability tokens
// were written into the searchable log store.
//
// /api/reports/view/{token} and /api/exports/view/{token} authenticate with a
// signed, expiring, tenant-bound token carried in the URL PATH. withLogging
// logged r.URL.Path on every request and nginx logged "$request"; both streams
// land in OpenSearch with no redaction. A report token lives 7 DAYS — that is a
// bearer credential for a tenant's report artifact, persisted in plaintext,
// searchable, and replayable from any log copy or backup.
//
// The fix is both halves — a header form so programmatic clients never put the
// token in a URL, and masking at both log boundaries for the emailed-link case
// that genuinely needs a plain browser navigation. These tests hold both, plus
// the invariant that the masking did not weaken the authorization itself.
//
// NB: this file quotes several scoped API route prefixes as MASKING FIXTURES
// (they are inputs to a string function, not routes under test). It therefore
// deliberately avoids the marker phrases that isolationTestCorpus in
// route_isolation_coverage_test.go greps for — being pulled into that corpus
// would falsely register tenant-isolation coverage for every route named here.

// captureAppLog swaps the structured logger's sink for the duration of a test.
func captureAppLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	t.Cleanup(applog.SwapWriterForTest(buf))
	return buf
}

// TestCapabilityTokenIsNotWrittenToTheRequestLog is the PIPE-HIGH-2 regression
// test: drive a real request carrying a real, currently-VALID capability token
// through the real logging middleware and assert the emitted log line contains
// nothing an attacker could replay.
func TestCapabilityTokenIsNotWrittenToTheRequestLog(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "log-test-secret")

	reportTok := signReportLink("exec-1", "acme", reportLinkTTL)
	exportTok := signExportLink("exec-2", "acme")

	cases := []struct {
		name  string
		route string
		token string
	}{
		{"report link (7-day bearer)", "/api/reports/view/", reportTok},
		{"export link (short fuse, bulk data)", "/api/exports/view/", exportTok},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureAppLog(t)
			h := withLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.route+tc.token, nil))

			line := buf.String()
			if line == "" {
				t.Fatal("no log line emitted — the test proved nothing")
			}
			if strings.Contains(line, tc.token) {
				t.Fatalf("the request log contains the RAW capability token — it is now a searchable, "+
					"replayable bearer credential in OpenSearch:\n%s", line)
			}
			// A partial token is still a leak: assert no long fragment survives.
			for _, part := range strings.Split(tc.token, ".") {
				if len(part) >= 8 && strings.Contains(line, part) {
					t.Fatalf("the request log contains a token fragment %q:\n%s", part, line)
				}
			}
			// …and the line must still be useful for triage.
			if !strings.Contains(line, maskedTokenSegment) {
				t.Errorf("expected the masked marker %q in the log line:\n%s", maskedTokenSegment, line)
			}
			if !strings.Contains(line, tc.route) {
				t.Errorf("the route %q was lost from the log line — masking must keep the path useful for triage:\n%s", tc.route, line)
			}
		})
	}
}

// TestCapabilityTokenInAHeaderIsNeverLoggedAtAll — the preferred form. When the
// caller presents X-Link-Token the path carries nothing, so there is nothing to
// mask and nothing for a proxy, a browser history, or a Referer to carry either.
func TestCapabilityTokenInAHeaderIsNeverLoggedAtAll(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "log-test-secret")
	tok := signReportLink("exec-1", "acme", reportLinkTTL)

	buf := captureAppLog(t)
	h := withLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	r := httptest.NewRequest(http.MethodGet, "/api/reports/view/", nil)
	r.Header.Set(linkTokenHeader, tok)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if line := buf.String(); strings.Contains(line, tok) {
		t.Fatalf("a header-borne token reached the log line:\n%s", line)
	}
}

// TestMaskCapabilityTokenPath pins the masking rule itself, including the
// non-token paths it must leave completely alone (an over-eager mask would
// blind the request log for the whole API).
func TestMaskCapabilityTokenPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/api/reports/view/AAAA.BBBB.CCCC.DDDD", "/api/reports/view/" + maskedTokenSegment},
		{"/api/exports/view/AAAA.BBBB.CCCC.DDDD", "/api/exports/view/" + maskedTokenSegment},
		// The webhook routes are the same class: an opaque, long-lived path token.
		// The provider segment is safe and stays (it is what makes the line useful).
		{"/api/nms/webhook/opaque-token-123", "/api/nms/webhook/" + maskedTokenSegment},
		{"/api/integrations/webhook/servicenow/opaque-token-123", "/api/integrations/webhook/servicenow/" + maskedTokenSegment},
		// Header form / bare prefix — nothing to mask.
		{"/api/reports/view/", "/api/reports/view/"},
		// Everything else is untouched.
		{"/api/reports/executions/abc-123", "/api/reports/executions/abc-123"},
		{"/api/devices", "/api/devices"},
		{"/api/exports/exec-9", "/api/exports/exec-9"},
		{"/", "/"},
	}
	for _, tc := range cases {
		if got := maskCapabilityTokenPath(tc.in); got != tc.want {
			t.Errorf("maskCapabilityTokenPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestLinkTokenFromRequestPrefersTheHeader — the header wins so a client that
// adopts it stops emitting the path form, and the path form still works so the
// emailed link a human clicks keeps working.
func TestLinkTokenFromRequestPrefersTheHeader(t *testing.T) {
	const prefix = "/api/reports/view/"

	r := httptest.NewRequest(http.MethodGet, prefix+"path-token", nil)
	if got := linkTokenFromRequest(r, prefix); got != "path-token" {
		t.Fatalf("path form: got %q", got)
	}
	r.Header.Set(linkTokenHeader, "header-token")
	if got := linkTokenFromRequest(r, prefix); got != "header-token" {
		t.Fatalf("header must win: got %q", got)
	}
	empty := httptest.NewRequest(http.MethodGet, prefix, nil)
	if got := linkTokenFromRequest(empty, prefix); got != "" {
		t.Fatalf("no token anywhere: got %q", got)
	}
}

// TestReportLinkStillAuthorizesAfterTokenRelocation — the point of the change
// was to stop LOGGING the capability, not to weaken it. A valid token still
// serves the artifact (path form AND header form); expired, forged and
// tokens bound to a different tenant are still refused, as is an absent token.
func TestReportLinkStillAuthorizesAfterTokenRelocation(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "relocation-secret")

	rec := reports.ExecutionRecord{
		ID: "exec-1", TenantID: "acme", Status: "completed",
		Artifacts: []reports.ArtifactRef{{Format: "html", ContentType: "text/html", Key: "exec-1"}},
	}
	art := reports.Artifact{Format: "html", ContentType: "text/html", Bytes: []byte("<h1>report</h1>")}
	s := viewServer(rec, true, art)
	valid := signReportLink("exec-1", "acme", time.Hour)

	// Path form (the emailed browser link) — unchanged behaviour.
	if w := doView(s, valid); w.Code != http.StatusOK || w.Body.String() != "<h1>report</h1>" {
		t.Fatalf("path-form valid link: code=%d body=%q", w.Code, w.Body.String())
	}

	// Header form — same authorization, no token in the URL at all.
	viaHeader := func(tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/reports/view/", nil)
		if tok != "" {
			r.Header.Set(linkTokenHeader, tok)
		}
		w := httptest.NewRecorder()
		s.handleReportView(w, r)
		return w
	}
	if w := viaHeader(valid); w.Code != http.StatusOK || w.Body.String() != "<h1>report</h1>" {
		t.Fatalf("header-form valid link: code=%d body=%q", w.Code, w.Body.String())
	}
	for name, tok := range map[string]string{
		"expired":      signReportLink("exec-1", "acme", -time.Minute),
		"forged":       valid[:len(valid)-1] + "X",
		"other tenant": signReportLink("exec-1", "evil", time.Hour),
		"absent":       "",
	} {
		if w := viaHeader(tok); w.Code != http.StatusForbidden {
			t.Errorf("%s token via header: want 403, got %d", name, w.Code)
		}
	}
}

// TestExportLinkStillAuthorizesAfterTokenRelocation — the export half. Export
// links are the same class on a 5–15 minute fuse and carry BULK raw log data,
// so the same three properties are asserted at the verification seam.
func TestExportLinkStillAuthorizesAfterTokenRelocation(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "relocation-secret")

	valid := signExportLink("exec-2", "acme")
	if id, tenant, err := verifyExportLink(valid); err != nil || id != "exec-2" || tenant != "acme" {
		t.Fatalf("valid export token must verify: id=%q tenant=%q err=%v", id, tenant, err)
	}
	if _, _, err := verifyExportLink(valid[:len(valid)-1] + "X"); err == nil {
		t.Error("a forged export token was accepted")
	}
	if _, _, err := verifyExportLink(""); err == nil {
		t.Error("an absent export token was accepted")
	}
	// Expiry: re-sign with the clamp bypassed by verifying an explicitly stale
	// signature built from the same secret.
	if _, _, err := verifyExportLink(staleExportToken("exec-2", "acme")); err == nil {
		t.Error("an expired export token was accepted")
	}
	// The header form resolves for exports too.
	r := httptest.NewRequest(http.MethodGet, "/api/exports/view/", nil)
	r.Header.Set(linkTokenHeader, valid)
	if got := linkTokenFromRequest(r, "/api/exports/view/"); got != valid {
		t.Errorf("export header form: got %q", got)
	}
}

// staleExportToken mints a correctly-SIGNED export token whose expiry is in the
// past. It has to be built by hand because signExportLink clamps the TTL to a
// 5-minute minimum — the point is to prove that a valid signature alone does
// not authorize once the clock has passed the embedded expiry.
func staleExportToken(execID, tenant string) string {
	exp := "1000000000" // 2001-09-09
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(execID)) + "." + enc([]byte(tenant)) + "." + enc([]byte(exp)) + "." + exportLinkSig(execID, tenant, exp)
}

// ---- the other log boundary: nginx -----------------------------------------

// TestNginxAccessLogDoesNotCaptureCapabilityTokens guards the SECOND stream.
// Masking only the Go request log would have left nginx writing the same token
// to the same OpenSearch index, so the defect would have been half-fixed and
// looked closed. This is a config assertion because nginx is the component; the
// masking itself was verified against a live nginx before landing.
func TestNginxAccessLogDoesNotCaptureCapabilityTokens(t *testing.T) {
	const path = "../../deployment/docker/nginx/nginx.conf"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (the access-log format is part of this fix and must exist)", path, err)
	}
	conf := string(b)

	fmtRe := regexp.MustCompile(`(?s)log_format\s+main\s+(.*?);`)
	m := fmtRe.FindStringSubmatch(conf)
	if m == nil {
		t.Fatal("no `log_format main` found in nginx.conf — the guard cannot verify the access log")
	}
	format := m[1]

	// $request is the raw request line: "GET /api/reports/view/<token> HTTP/1.1".
	if regexp.MustCompile(`\$request\b`).MatchString(format) {
		t.Error("the nginx access log still captures the raw $request — a capability token in the " +
			"path is written verbatim to OpenSearch (PIPE-HIGH-2). Log $request_redacted instead.")
	}
	// A Referer from a report/export view page carries the token onward.
	if regexp.MustCompile(`\$http_referer\b`).MatchString(format) {
		t.Error("the nginx access log still captures the raw $http_referer — a browser navigating " +
			"away from a view link leaks the token in the Referer. Log $referer_redacted instead.")
	}
	for _, want := range []string{"$request_redacted", "$referer_redacted"} {
		if !strings.Contains(format, want) {
			t.Errorf("log_format does not use %s", want)
		}
	}
	// The masking maps that define those variables must exist and must cover
	// both token routes.
	for _, want := range []string{
		"map $request $request_redacted",
		"map $http_referer $referer_redacted",
		"/api/(?<ltk>reports|exports)/view/",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf is missing the redaction plumbing: %q", want)
		}
	}
}
