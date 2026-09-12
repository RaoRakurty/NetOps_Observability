// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tlsprobe

// tls_peer_probe_test.go — SEC-019.1 regression guards. The property under
// test is the incident's exact shape: the prober must report the certificate
// an endpoint SERVES — including one that is expired, one behind a
// client-cert-required handshake, and one behind postgres's SSLRequest
// preamble — and must fail LOUD (boot error) on a malformed endpoint list.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSigned mints a throwaway server certificate with the given validity.
func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "probe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newProberForTest() *Prober {
	return &Prober{
		interval: time.Minute,
		timeout:  3 * time.Second,
		results:  map[string]peerProbeResult{},
	}
}

// serveTLSOnce accepts one connection and runs the TLS handshake with cfg.
func serveTLSOnce(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tc := tls.Server(conn, cfg)
		_ = tc.Handshake()
		_ = tc.Close()
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestProbeCapturesServedExpiry(t *testing.T) {
	notAfter := time.Now().Add(90 * time.Minute).Truncate(time.Second)
	ln := serveTLSOnce(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, notAfter)}})

	p := newProberForTest()
	res := p.probe(context.Background(), peerEndpoint{Name: "t", Addr: ln.Addr().String()})
	if !res.ok {
		t.Fatal("probe did not capture a certificate from a plain TLS server")
	}
	if !res.notAfter.Equal(notAfter) {
		t.Fatalf("captured NotAfter %v, served %v", res.notAfter, notAfter)
	}
}

func TestProbeCapturesExpiredCertificate(t *testing.T) {
	// The incident case: the server presents an ALREADY-EXPIRED certificate.
	// The probe must still report it — a verifying client would refuse the
	// handshake and learn nothing, which is exactly the blind spot.
	notAfter := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	ln := serveTLSOnce(t, &tls.Config{Certificates: []tls.Certificate{selfSigned(t, notAfter)}})

	p := newProberForTest()
	res := p.probe(context.Background(), peerEndpoint{Name: "t", Addr: ln.Addr().String()})
	if !res.ok {
		t.Fatal("probe must capture an expired served certificate (the 2026-08-05 incident shape)")
	}
	if time.Until(res.notAfter) > 0 {
		t.Fatal("captured cert should read as expired")
	}
}

func TestProbeCapturesBehindClientCertRequirement(t *testing.T) {
	// correlation:8443 / kafka:9094 shape: the server demands a client
	// certificate the probe does not present. The handshake fails — AFTER
	// the server presented its own cert, which is all the probe needs.
	notAfter := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	pool := x509.NewCertPool() // empty pool: any client cert would be refused anyway
	ln := serveTLSOnce(t, &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t, notAfter)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})

	p := newProberForTest()
	res := p.probe(context.Background(), peerEndpoint{Name: "t", Addr: ln.Addr().String()})
	if !res.ok {
		t.Fatal("probe must capture the server cert even when the server requires a client certificate")
	}
	if !res.notAfter.Equal(notAfter) {
		t.Fatalf("captured NotAfter %v, served %v", res.notAfter, notAfter)
	}
}

func TestProbePostgresPreamble(t *testing.T) {
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	cert := selfSigned(t, notAfter)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Speak the postgres side: read the 8-byte SSLRequest, check the
		// magic, answer 'S', then hand the socket to TLS.
		var req [8]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}
		if binary.BigEndian.Uint32(req[0:4]) != 8 || binary.BigEndian.Uint32(req[4:8]) != 80877103 {
			_ = conn.Close()
			return
		}
		if _, err := conn.Write([]byte{'S'}); err != nil {
			return
		}
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = tc.Handshake()
		_ = tc.Close()
	}()

	p := newProberForTest()
	res := p.probe(context.Background(), peerEndpoint{Name: "pg", Addr: ln.Addr().String(), Preamble: "postgres"})
	if !res.ok {
		t.Fatal("postgres-preamble probe did not capture the served certificate")
	}
	if !res.notAfter.Equal(notAfter) {
		t.Fatalf("captured NotAfter %v, served %v", res.notAfter, notAfter)
	}
}

func TestProbeUnreachableIsNotOK(t *testing.T) {
	p := newProberForTest()
	p.timeout = 500 * time.Millisecond
	res := p.probe(context.Background(), peerEndpoint{Name: "t", Addr: "127.0.0.1:1"})
	if res.ok {
		t.Fatal("an unreachable endpoint must report ok=false")
	}
}

func TestParsePeerEndpoints(t *testing.T) {
	eps, err := parsePeerEndpoints("")
	if err != nil || len(eps) != len(defaultPeerEndpoints) {
		t.Fatalf("empty spec must yield the default set (err=%v, n=%d)", err, len(eps))
	}
	eps, err = parsePeerEndpoints("pg=db.example:5432/postgres, kafka=broker:9094")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[0].Preamble != "postgres" || eps[1].Addr != "broker:9094" {
		t.Fatalf("parsed %+v", eps)
	}
	// Malformed entries are BOOT failures, never silent skips: a typo that
	// un-watches an endpoint recreates the incident this feature closes.
	for _, bad := range []string{"noequals", "x=", "x=hostnoport", "x=h:1/ftp"} {
		if _, err := parsePeerEndpoints(bad); err == nil {
			t.Fatalf("spec %q must be rejected", bad)
		}
	}
}

func TestPeerMetricsOutput(t *testing.T) {
	p := newProberForTest()
	p.results["clickhouse:8443"] = peerProbeResult{ok: true, notAfter: time.Now().Add(time.Hour)}
	p.results["postgres:5432"] = peerProbeResult{ok: false}
	var sb strings.Builder
	p.WriteMetrics(&sb)
	out := sb.String()
	for _, want := range []string{
		`netops_tls_peer_cert_expiry_seconds{endpoint="clickhouse:8443"}`,
		`netops_tls_peer_probe_ok{endpoint="clickhouse:8443"} 1`,
		`netops_tls_peer_probe_ok{endpoint="postgres:5432"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, out)
		}
	}
	// A failed probe must NOT emit a stale expiry gauge — absence is the
	// honest value; the probe_ok series carries the failure.
	if strings.Contains(out, `netops_tls_peer_cert_expiry_seconds{endpoint="postgres:5432"}`) {
		t.Fatal("failed probe leaked an expiry gauge")
	}
}
