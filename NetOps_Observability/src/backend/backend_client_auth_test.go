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
