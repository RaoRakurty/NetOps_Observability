// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bgp_aspa_leak_test.go — the ASPA route must not hand an operator's provider
// credential to every reader in the tenant.
//
// The defect this guards (3.4-04): the web fetcher returned net/http's
// *url.Error verbatim, and that error prints the FULL request URL.
// HTTPProvider.ASPA wrapped it, and handleBGPASPA put it in a 200 body for any
// infrastructure:read caller. BGP_ASPA_PROVIDER_URL points at the operator's
// own RPKI validator, which may authenticate with a query-string token.
//
// Every credential here is fabricated.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/bgpdepth"
)

const (
	aspaProviderURL   = "https://validator.example.net/aspa?token=FAKE-ASPA-TOKEN-0000"
	aspaProviderCred  = "FAKE-ASPA-TOKEN-0000"
	aspaProviderHost  = "validator.example.net"
	aspaProviderQuery = "token="
)

// deadTransport fails every request, which is how net/http produces the
// *url.Error that carries the URL.
type deadTransport struct{}

func (deadTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connect: connection refused")
}

// deadWebFetcher is the real fetcher with a transport that cannot connect, so
// the error travels the real code path rather than a hand-built one.
func deadWebFetcher() *bgpFetcher {
	f := newBGPFetcher()
	f.webClient = &http.Client{Transport: deadTransport{}}
	return f
}

// THE BOUNDARY: an arbitrary outbound fetch must not report the URL it was
// given. Every present and future caller of Fetcher.Get depends on this.
func TestBGPWebFetchErrorNeverCarriesTheURLOrItsCredential(t *testing.T) {
	f := deadWebFetcher()
	_, err := f.Get(context.Background(), aspaProviderURL, 4096)
	if err == nil {
		t.Fatal("a dead transport produced no error")
	}
	msg := err.Error()
	for _, banned := range []string{aspaProviderCred, aspaProviderQuery, aspaProviderURL, "?"} {
		if strings.Contains(msg, banned) {
			t.Errorf("the fetch error carries %q: %q", banned, msg)
		}
	}
	if !strings.Contains(msg, aspaProviderHost) {
		t.Errorf("the fetch error does not name the host that failed, so it is not actionable: %q", msg)
	}
}

// THE RESPONSE an infrastructure:read caller actually receives.
func TestBGPASPAFailureResponseNeverCarriesTheProviderCredential(t *testing.T) {
	t.Setenv(bgpdepth.EnvASPAProviderURL, aspaProviderURL)
	s, _ := depthServer(t, "")
	s.bgpASPA = bgpdepth.HTTPProvider{Base: aspaProviderURL, F: deadWebFetcher(), Now: time.Now}

	w := httptest.NewRecorder()
	s.handleBGPASPA(w, req("GET", "/api/bgp/aspa?resource=AS64500", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, banned := range []string{aspaProviderCred, aspaProviderQuery, aspaProviderURL} {
		if strings.Contains(body, banned) {
			t.Fatalf("the response body carries %q", banned)
		}
	}
	// The operator must still learn that the provider failed, and which one.
	if !strings.Contains(body, aspaProviderHost) {
		t.Errorf("the response does not name the provider host: %s", body)
	}
	out := decodeBody(t, w)
	if _, fabricated := out["aspa"]; fabricated {
		t.Fatalf("a failed provider produced a verdict: %v", out)
	}
	if !strings.Contains(strings.ToLower(body), "did not answer") {
		t.Errorf("the response does not say the provider failed: %s", body)
	}
}
