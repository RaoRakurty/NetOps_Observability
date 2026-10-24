// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// push_redact_test.go — tracker 367: VICTORIA_URL carries the vmauth credential
// as URL userinfo, and a failed push quoted the full URL into the log and the
// stored last error. The password must appear in neither.

func TestRedactUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"https://svc-api:s3cr3t@vmauth:8427/api/v1/import/prometheus: HTTP 503": "https://<redacted>@vmauth:8427/api/v1/import/prometheus: HTTP 503",
		"http://user@host/x":                     "http://<redacted>@host/x",
		"https://vmauth:8427/no-cred":            "https://vmauth:8427/no-cred",
		"two https://a:b@h1/ and http://c:d@h2/": "two https://<redacted>@h1/ and http://<redacted>@h2/",
	} {
		if got := redactUserinfo(in); got != want {
			t.Errorf("redactUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFailedPushNeverLogsTheCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	const secret = "Sup3rS3cretPushPassword"
	t.Setenv("VICTORIA_URL", strings.Replace(srv.URL, "://", "://svc-api:"+secret+"@", 1))

	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()
	metricsPushMu.Lock()
	metricsPushLogged = metricsPushLogged.AddDate(-1, 0, 0) // let this failure log
	metricsPushMu.Unlock()

	emitMetrics(t.Context(), "x 1\n")

	_, _, _, lastErr := MetricsPushStats()
	if !strings.Contains(lastErr, "HTTP 503") {
		t.Fatalf("the push did not fail as staged: lastErr=%q", lastErr)
	}
	if strings.Contains(lastErr, secret) {
		t.Fatalf("stored last error carries the password: %q", lastErr)
	}
	if strings.Contains(buf.String(), secret) {
		t.Fatalf("log carries the password: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "<redacted>@") {
		t.Fatalf("expected the redacted URL in the log, got %q", buf.String())
	}
}
