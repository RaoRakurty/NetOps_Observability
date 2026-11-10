// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// SEC-010 / tracker 367 layer 1: the WIRING of backendHTTPClient to
// internal/backendauth — every internal-backend call rides the credential
// transport, and initBackendCredentials turns env into a published set.
// The transport's own rules (origin scoping, redirects, fail-closed, file
// wins, legacy flagging) are tested in internal/backendauth.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/backendauth"
	"netops/backend/internal/credfile"
)

// keepCreds restores the process-global credential set after the test.
func keepCreds(t *testing.T) {
	t.Helper()
	prev := backendCreds.Load()
	t.Cleanup(func() { backendCreds.Store(prev) })
}

type authSeen struct {
	hits int
	auth string
	user string
}

func authServer(t *testing.T) (*httptest.Server, *authSeen) {
	t.Helper()
	seen := &authSeen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.hits++
		seen.auth = r.Header.Get("Authorization")
		seen.user = r.URL.User.String()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func doGet(t *testing.T, raw string) error {
	t.Helper()
	resp, err := backendHTTPClient(5 * time.Second).Get(raw)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return err
}

func secretFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Legacy behaviour through the real client: userinfo becomes Basic auth and
// never reaches the wire.
func TestBackendClientAppliesURLUserinfoAsBasicAuth(t *testing.T) {
	keepCreds(t)
	backendCreds.Store(nil)
	srv, seen := authServer(t)
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("svc-api", "sekret")
	if err := doGet(t, u.String()); err != nil {
		t.Fatalf("get: %v", err)
	}
	if seen.auth != backendauth.BasicHeader("svc-api", "sekret") {
		t.Fatalf("Authorization = %q — want basic svc-api:sekret", seen.auth)
	}
	if seen.user != "" {
		t.Fatalf("userinfo leaked to the wire: %q", seen.user)
	}
}

func TestBackendClientNoUserinfoPassthrough(t *testing.T) {
	keepCreds(t)
	backendCreds.Store(nil)
	srv, seen := authServer(t)
	if err := doGet(t, srv.URL); err != nil {
		t.Fatalf("get: %v", err)
	}
	if seen.auth != "" {
		t.Fatalf("unexpected Authorization header %q on a credential-less URL", seen.auth)
	}
}

// Tracker 384: the cloud metric reads go where every other VictoriaMetrics read
// goes, with the same credential. They used a bare client against plain
// victoria:8428, past vmauth. The PromQL is passed through untouched: its tenant
// scope comes from the handlers' selectors, and moving the upstream must not
// change it (the §3a behaviour is cloud_metrics_series_isolation_test.go).
func TestCloudMetricReadsPresentTheBackendCredential(t *testing.T) {
	keepCreds(t)
	var gotAuth, gotQuery, gotPath []string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		gotQuery = append(gotQuery, r.URL.Query().Get("query"))
		gotPath = append(gotPath, r.URL.Path)
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[]}}`))
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)
	t.Setenv("METRICS_URL", "")
	t.Setenv("VICTORIA_AUTH_USER", "svc-api")
	t.Setenv("VICTORIA_AUTH_PASSWORD_FILE", secretFile(t, "api-pw\n"))
	if err := initBackendCredentials(); err != nil {
		t.Fatal(err)
	}

	const instant = `max by (provider) (cloud_cpu_util{resource_id=~"i-a"})`
	if got := vmQueryBy(context.Background(), instant, "provider"); got == nil {
		t.Fatal("vmQueryBy degraded against a healthy store")
	}
	const ranged = `cloud_cpu_util{resource_id=~"i-a"}`
	if _, err := vmQueryRangeBy(context.Background(), ranged, 1, 2, 60, "resource_id"); err != nil {
		t.Fatal(err)
	}

	want := backendauth.BasicHeader("svc-api", "api-pw")
	if len(gotAuth) != 2 || gotAuth[0] != want || gotAuth[1] != want {
		t.Fatalf("Authorization = %q, want the svc-api credential on both reads", gotAuth)
	}
	if gotQuery[0] != instant || gotQuery[1] != ranged {
		t.Fatalf("the upstream must receive the handler's PromQL unchanged, got %q", gotQuery)
	}
	if gotPath[0] != "/api/v1/query" || gotPath[1] != "/api/v1/query_range" {
		t.Fatalf("paths = %q", gotPath)
	}

	// A credential that never loaded refuses the read; it never goes anonymous.
	t.Setenv("VICTORIA_AUTH_PASSWORD_FILE", filepath.Join(t.TempDir(), "absent"))
	if err := initBackendCredentials(); err != nil {
		t.Fatal(err)
	}
	before := len(gotAuth)
	if _, err := vmQueryRangeBy(context.Background(), ranged, 1, 2, 60, "resource_id"); !errors.Is(err, backendauth.ErrCredentialUnavailable) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if got := vmQueryBy(context.Background(), instant, "provider"); got != nil {
		t.Fatalf("instant read with no credential = %v, want nil (degraded)", got)
	}
	if len(gotAuth) != before {
		t.Fatal("an anonymous request reached the metrics store")
	}
}

// initBackendCredentials end to end: env in, every backendHTTPClient call
// authenticated, the boot path never fatal on a not-yet-rendered file, and a
// half configuration refused.
func TestInitBackendCredentialsFromEnv(t *testing.T) {
	keepCreds(t)
	vm, vmSeen := authServer(t)
	osrv, osSeen := authServer(t)
	t.Setenv("VICTORIA_URL", vm.URL)
	t.Setenv("METRICS_URL", "")
	t.Setenv("VICTORIA_AUTH_USER", "svc-prober")
	t.Setenv("VICTORIA_AUTH_PASSWORD_FILE", secretFile(t, "probe-pw\n"))
	t.Setenv("OPENSEARCH_URL", osrv.URL)
	t.Setenv("OPENSEARCH_AUTH_USER", "svc_api")
	t.Setenv("OPENSEARCH_AUTH_PASSWORD_FILE", filepath.Join(t.TempDir(), "not-yet"))
	if err := initBackendCredentials(); err != nil {
		t.Fatalf("a not-yet-rendered file must not fail boot: %v", err)
	}
	if err := doGet(t, vm.URL); err != nil {
		t.Fatal(err)
	}
	if vmSeen.auth != backendauth.BasicHeader("svc-prober", "probe-pw") {
		t.Fatalf("Authorization = %q", vmSeen.auth)
	}
	// The OpenSearch file never loaded: refused, unsent.
	if err := doGet(t, osrv.URL); !errors.Is(err, backendauth.ErrCredentialUnavailable) || !errors.Is(err, credfile.ErrNotLoaded) {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if osSeen.hits != 0 {
		t.Fatal("an anonymous request reached OpenSearch")
	}

	var buf bytes.Buffer
	writeBackendCredentialMetrics(&buf)
	for _, want := range []string{
		`netops_backend_credential_loaded{backend="victoria"} 1`,
		`netops_backend_credential_loaded{backend="opensearch"} 0`,
		`netops_config_url_credential{var="VICTORIA_URL"} 0`,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("/metrics missing %q:\n%s", want, buf.String())
		}
	}

	t.Setenv("OPENSEARCH_AUTH_PASSWORD_FILE", "")
	if err := initBackendCredentials(); err == nil {
		t.Fatal("half an OpenSearch credential must fail boot")
	}
}
