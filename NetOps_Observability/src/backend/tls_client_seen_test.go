// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"strings"
	"testing"
	"time"
)

// tls_client_seen_test.go — tracker 351: the api exports the expiry of the
// client certificate each mTLS caller presents, so a start-loaded client SVID
// (vmalert, 2026-10-14→17) is visible BEFORE it expires.

func leafFor(t *testing.T, uri string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	l := &x509.Certificate{Subject: pkix.Name{CommonName: "cn"}, NotAfter: notAfter}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		l.URIs = []*url.URL{u}
	}
	return l
}

func TestClientCertSeenExportsPerIdentityExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var c clientCertSeen
	c.observe(leafFor(t, "spiffe://netops/ns/default/sa/vmalert", now.Add(10*time.Hour)), now)
	c.observe(leafFor(t, "spiffe://netops/ns/default/sa/nginx", now.Add(100*time.Hour)), now)
	// A renewed cert from the same caller replaces the old value.
	c.observe(leafFor(t, "spiffe://netops/ns/default/sa/vmalert", now.Add(160*time.Hour)), now.Add(time.Minute))

	got := c.snapshot(now.Add(time.Minute))
	if len(got) != 2 {
		t.Fatalf("want 2 identities, got %v", got)
	}
	if got[0][0] != "spiffe://netops/ns/default/sa/nginx" || got[1][0] != "spiffe://netops/ns/default/sa/vmalert" {
		t.Fatalf("unexpected identities/order: %v", got)
	}
	if got[1][1] != "575940" { // 160h − 1m
		t.Fatalf("vmalert expiry seconds = %s, want the renewed cert's 575940", got[1][1])
	}
}

func TestClientCertSeenDropsRetiredCallers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var c clientCertSeen
	c.observe(leafFor(t, "spiffe://netops/ns/default/sa/gone", now.Add(time.Hour)), now)
	if got := c.snapshot(now.Add(clientCertSeenTTL + time.Second)); len(got) != 0 {
		t.Fatalf("a caller unseen for longer than the TTL must stop being exported: %v", got)
	}
}

func TestClientCertSeenIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var c clientCertSeen
	for i := 0; i < clientCertSeenMax+10; i++ {
		c.observe(leafFor(t, "spiffe://netops/ns/default/sa/s"+strings.Repeat("x", i), now.Add(time.Hour)), now.Add(time.Duration(i)*time.Second))
	}
	got := c.snapshot(now.Add(time.Hour))
	if len(got) != clientCertSeenMax {
		t.Fatalf("map not bounded: %d identities", len(got))
	}
	for _, kv := range got {
		if kv[0] == "spiffe://netops/ns/default/sa/s" {
			t.Fatal("least-recently-seen identity was not the one evicted")
		}
	}
}

func TestWriteTLSMetricsIncludesClientCertExpiry(t *testing.T) {
	m := &tlsMetrics{}
	m.clients.observe(leafFor(t, "spiffe://netops/ns/default/sa/vmalert", time.Now().Add(time.Hour)), time.Now())
	ts := &tlsServer{metrics: m}
	var b bytes.Buffer
	ts.writeClientCertMetrics(&b)
	out := b.String()
	if !strings.Contains(out, `netops_tls_client_cert_expiry_seconds{identity="spiffe://netops/ns/default/sa/vmalert"} `) {
		t.Fatalf("client cert expiry series missing:\n%s", out)
	}
}

func TestPromLabelValueNeutralisesPeerText(t *testing.T) {
	for in, want := range map[string]string{
		"spiffe://netops/ns/default/sa/api": `"spiffe://netops/ns/default/sa/api"`,
		"x\"} 1\nnetops_fake 9":             `"x___1_netops_fake_9"`,
		`back\slash`:                        `"back_slash"`,
	} {
		if got := promLabelValue(in); got != want {
			t.Errorf("promLabelValue(%q) = %s, want %s", in, got, want)
		}
	}
}
