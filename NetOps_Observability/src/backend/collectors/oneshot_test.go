// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
)

func splitServer(t *testing.T, raw string) (netip.Addr, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return netip.MustParseAddr(host), p
}

// TestOneShotHTTPPinsTheAddressAndNeverFollowsRedirects: the request goes to
// the pinned address whatever host it names, a redirect is reported and not
// followed, and the Host header is the declared name.
func TestOneShotHTTPPinsTheAddressAndNeverFollowsRedirects(t *testing.T) {
	var followed atomic.Bool
	var gotHost atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/latest/meta-data/":
			followed.Store(true)
		case "/ok":
			w.WriteHeader(http.StatusNoContent)
		case "/broken":
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	addr, port := splitServer(t, srv.Listener.Addr().String())

	res := RunOneShot(context.Background(), OneShotRequest{Kind: OneShotHTTP, Addr: addr, Port: port,
		Scheme: "http", Host: "portal.example"})
	if followed.Load() {
		t.Fatal("the redirect was followed")
	}
	if res.StatusCode != http.StatusFound || res.FailClass != "redirect" || !res.Up {
		t.Fatalf("redirect: %+v", res)
	}
	if h, _ := gotHost.Load().(string); h != "portal.example:"+strconv.Itoa(port) {
		t.Fatalf("Host header %q, want the declared name", h)
	}
	if res := RunOneShot(context.Background(), OneShotRequest{Kind: OneShotHTTP, Addr: addr, Port: port,
		Scheme: "http", Host: "portal.example", Path: "/ok"}); !res.Up || res.StatusCode != 204 || res.Kind != OneShotHTTP {
		t.Fatalf("2xx: %+v", res)
	}
	if res := RunOneShot(context.Background(), OneShotRequest{Kind: OneShotHTTP, Addr: addr, Port: port,
		Scheme: "http", Host: "portal.example", Path: "/broken"}); res.Up || res.StatusCode != 502 {
		t.Fatalf("5xx must not be up: %+v", res)
	}
}

// TestOneShotHTTPVerifiesTLS: a certificate that does not verify is a failed
// check classified as tls — never silently accepted.
func TestOneShotHTTPVerifiesTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	addr, port := splitServer(t, srv.Listener.Addr().String())
	res := RunOneShot(context.Background(), OneShotRequest{Kind: OneShotHTTP, Addr: addr, Port: port, Host: "portal.example"})
	if res.Up || res.FailClass != "tls" {
		t.Fatalf("an unverifiable certificate: %+v", res)
	}
}

func TestOneShotRefusesWhatItCannotMeasure(t *testing.T) {
	ctx := context.Background()
	for _, req := range []OneShotRequest{
		{Kind: OneShotPing},
		{Kind: OneShotPing, Addr: netip.MustParseAddr("2001:db8::1")},
		{Kind: OneShotTraceroute},
		{Kind: OneShotDNS},
		{Kind: OneShotHTTP, Addr: netip.MustParseAddr("192.0.2.1")},
		{Kind: "bogus"},
	} {
		if res := RunOneShot(ctx, req); res.Unavailable == "" {
			t.Errorf("%+v: measured something it cannot (%+v)", req, res)
		}
	}
}

func TestOneShotHTTPConnectRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr, port := splitServer(t, l.Addr().String())
	if cerr := l.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	res := RunOneShot(context.Background(), OneShotRequest{Kind: OneShotHTTP, Addr: addr, Port: port, Scheme: "http", Host: "x.example"})
	if res.Up || res.FailClass != "connect_refused" {
		t.Fatalf("closed port: %+v", res)
	}
}
