// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tlsconfig

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClientConfigSecureDefaults(t *testing.T) {
	ca := newTestCA(t)
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	cfg, err := HTTPClientConfig(ClientOptions{RootCAs: bundle})
	if err != nil {
		t.Fatalf("HTTPClientConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify must never be set")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x", cfg.MinVersion)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs must be set (explicit trust)")
	}
	if cfg.ServerName != "" {
		t.Error("ServerName must be left empty for net/http to fill per-request")
	}
	// RootCAs is mandatory.
	if _, err := HTTPClientConfig(ClientOptions{}); err == nil {
		t.Error("HTTPClientConfig must require RootCAs")
	}
}

// TestHTTPTransportRoundTrip proves an https GET to a server using our CA's cert
// succeeds with the hardened transport (net/http verifies the 127.0.0.1 SAN), and
// that a client trusting a DIFFERENT CA is rejected (no InsecureSkipVerify escape).
func TestHTTPTransportRoundTrip(t *testing.T) {
	ca := newTestCA(t)
	serverCert := ca.issuePair(t, "backend", leafOpts{ips: []net.IP{net.ParseIP("127.0.0.1")}, dns: []string{"localhost"}})

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	srv.StartTLS()
	defer srv.Close()

	// Trusted client.
	bundle, _ := LoadTrustBundle(ca.bundlePath())
	tr, err := HTTPTransport(ClientOptions{RootCAs: bundle})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatalf("trusted GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	// Client trusting a different CA must reject the server.
	other := newTestCA(t)
	ob, _ := LoadTrustBundle(other.bundlePath())
	otr, _ := HTTPTransport(ClientOptions{RootCAs: ob})
	if _, err := (&http.Client{Transport: otr}).Get(srv.URL); err == nil {
		t.Fatal("client trusting a different CA must reject the server cert")
	}
}
