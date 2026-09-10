// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bgp_ops_ssrf_test.go — the post-DNS half of the SSRF gate on the third-party
// web client (newBGPWebClient).
//
// The gate has two halves. bgpdepth.SafeOutboundURL screens the URL, which
// catches an IP LITERAL only; the dialer's address check is what catches a
// hostname that RESOLVES to an internal address. The second half used to be
// switched off, process-wide, by any of four environment variables — including
// ALL_PROXY, which http.ProxyFromEnvironment has never read. Setting it turned
// the gate off while every request was still dialled direct.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/internal/bgpdepth"
)

// webClientDial reaches the exact dial closure newBGPWebClient installed, so the
// test exercises the production decision rather than a re-implementation of it.
func webClientDial(t *testing.T, address string) error {
	t.Helper()
	tr, ok := newBGPWebClient(nil).Transport.(*http.Transport)
	if !ok {
		t.Fatal("the BGP web client no longer uses an *http.Transport")
	}
	if tr.DialContext == nil {
		t.Fatal("the BGP web client has no DialContext — the address gate cannot be applied")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tr.DialContext(ctx, "tcp", address)
	if c != nil {
		_ = c.Close()
	}
	return err
}

// TestBGPWebClientGateSurvivesAnEnvVarTheProxyResolverIgnores is the regression.
// ALL_PROXY (and all_proxy) buy no exemption, because nothing in net/http reads
// them: the dial to a loopback address must still be REFUSED.
func TestBGPWebClientGateSurvivesAnEnvVarTheProxyResolverIgnores(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	for _, name := range []string{"ALL_PROXY", "all_proxy"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("http_proxy", "")
			t.Setenv("HTTPS_PROXY", "")
			t.Setenv("https_proxy", "")
			t.Setenv(name, "http://"+addr)

			err := webClientDial(t, addr)
			if err == nil {
				t.Fatalf("%s=http://%s disabled the address gate: the dial to a loopback address SUCCEEDED", name, addr)
			}
			if !errors.Is(err, bgpdepth.ErrUnsafeURL) {
				t.Fatalf("dial refused with %v, want the SSRF gate's %v", err, bgpdepth.ErrUnsafeURL)
			}
		})
	}
}

// TestBGPWebClientGateIsOnWithNoProxyAtAll pins the baseline: with nothing set,
// the address gate refuses a non-public dial.
func TestBGPWebClientGateIsOnWithNoProxyAtAll(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "")
	}
	if err := webClientDial(t, "127.0.0.1:9"); !errors.Is(err, bgpdepth.ErrUnsafeURL) {
		t.Fatalf("dial to loopback returned %v, want the SSRF gate's refusal", err)
	}
}

// TestBGPWebClientStillDialsAConfiguredProxy keeps the narrow exemption honest:
// the address that IS the configured egress proxy is dialled, private or not,
// because for that dial the proxy is the destination and it resolves the host.
func TestBGPWebClientStillDialsAConfiguredProxy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	for _, name := range []string{"HTTP_PROXY", "https_proxy"} {
		t.Run(name, func(t *testing.T) {
			for _, clear := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
				t.Setenv(clear, "")
			}
			t.Setenv(name, "http://"+addr)
			if err := webClientDial(t, addr); err != nil {
				t.Fatalf("the configured proxy at %s was refused: %v", addr, err)
			}
		})
	}
	// And a DIFFERENT private address is still refused while that proxy is set:
	// the exemption is one address, not a switch.
	for _, clear := range []string{"http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(clear, "")
	}
	t.Setenv("HTTP_PROXY", "http://"+addr)
	if err := webClientDial(t, "127.0.0.1:9"); !errors.Is(err, bgpdepth.ErrUnsafeURL) {
		t.Fatalf("a proxy setting widened the gate to every private address: %v", err)
	}
}

// TestProxyDialTargetsReadsOnlyWhatTheResolverReads is the rule in one place:
// the skip set is derived from HTTP_PROXY / HTTPS_PROXY only, in the spelling
// net/http dials, and every other variable contributes nothing.
func TestProxyDialTargetsReadsOnlyWhatTheResolverReads(t *testing.T) {
	for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(name, "")
	}
	t.Setenv("ALL_PROXY", "http://proxy.corp:3128")
	t.Setenv("all_proxy", "socks5://proxy.corp:1080")
	if got := proxyDialTargets(); len(got) != 0 {
		t.Fatalf("ALL_PROXY contributed %v — net/http never reads it, so it must buy no exemption", got)
	}

	t.Setenv("HTTP_PROXY", "http://proxy.corp")    // default port 80
	t.Setenv("HTTPS_PROXY", "https://secure.corp") // default port 443
	t.Setenv("https_proxy", "proxy.corp:8080")     // no scheme, as the stdlib also accepts
	targets := proxyDialTargets()
	for _, want := range []string{"proxy.corp:80", "secure.corp:443"} {
		if _, ok := targets[want]; !ok {
			t.Errorf("proxyDialTargets missing %q: %v", want, targets)
		}
	}
	// HTTPS_PROXY wins over https_proxy in the stdlib, but naming both is not an
	// error and both spellings are safe to admit.
	if _, ok := targets["proxy.corp:8080"]; !ok {
		t.Errorf("a bare host:port proxy was not understood: %v", targets)
	}
}

// TestProxyDialAddrMatchesTheStdlibSpelling covers the renderings directly,
// including the IPv6 bracket form net.JoinHostPort produces.
func TestProxyDialAddrMatchesTheStdlibSpelling(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"http://proxy.corp:3128", "proxy.corp:3128"},
		{"http://proxy.corp", "proxy.corp:80"},
		{"https://proxy.corp", "proxy.corp:443"},
		{"socks5://proxy.corp", "proxy.corp:1080"},
		{"proxy.corp:3128", "proxy.corp:3128"},
		{"http://[2001:db8::1]:3128", net.JoinHostPort("2001:db8::1", "3128")},
		{"http://%zz", ""},
	}
	for _, c := range cases {
		if got := proxyDialAddr(c.in); got != c.want {
			t.Errorf("proxyDialAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
