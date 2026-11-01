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

// serveMTLSOnce accepts one connection on a server that REQUIRES a client
// certificate chaining to clientCA, and reports the server-side handshake
// outcome — the thing vector's syslog_in counts as an error when it fails.
func serveMTLSOnce(t *testing.T, server tls.Certificate, clientCA *x509.Certificate) (net.Listener, <-chan error) {
	t.Helper()
	pool := x509.NewCertPool()
	if clientCA != nil {
		pool.AddCert(clientCA)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		tc := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{server},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS12,
		})
		done <- tc.Handshake()
		_ = tc.Close()
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln, done
}

func TestProbePresentsClientSVIDWhenConfigured(t *testing.T) {
	// 2026-10-31: the probe with NO client cert made vector's syslog_in log
	// "peer did not return a certificate" and bump component_errors every
	// sweep — VectorComponentErrors fired permanently. With the api's SVID
	// offered, the SERVER-side handshake must SUCCEED, and the served cert
	// must still be captured.
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	client := selfSigned(t, time.Now().Add(24*time.Hour))
	clientLeaf, err := x509.ParseCertificate(client.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	ln, serverErr := serveMTLSOnce(t, selfSigned(t, notAfter), clientLeaf)

	var calls int
	p := newProberForTest()
	WithClientCertificate(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		calls++
		return &client, nil
	})(p)
	res := p.probe(context.Background(), peerEndpoint{Name: "syslog", Addr: ln.Addr().String()})
	if !res.ok || !res.notAfter.Equal(notAfter) {
		t.Fatalf("served cert not captured: %+v", res)
	}
	if calls != 1 {
		t.Fatalf("client-cert getter called %d times, want 1 (consulted per dial)", calls)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server-side handshake failed with the SVID presented: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake never completed")
	}
}

func TestProbeWithoutSVIDStillRefusedButCaptures(t *testing.T) {
	// The unchanged default: no getter → no client cert → the server refuses,
	// and the probe STILL reports the served cert (the original design).
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	ln, serverErr := serveMTLSOnce(t, selfSigned(t, notAfter), nil)
	p := newProberForTest()
	WithClientCertificate(nil)(p) // nil getter is ignored
	if p.clientCert != nil {
		t.Fatal("a nil getter must leave the probe presenting nothing")
	}
	res := p.probe(context.Background(), peerEndpoint{Name: "syslog", Addr: ln.Addr().String()})
	if !res.ok || !res.notAfter.Equal(notAfter) {
		t.Fatalf("served cert not captured: %+v", res)
	}
	select {
	case err := <-serverErr:
		if err == nil {
			t.Fatal("server accepted a handshake with no client certificate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake never completed")
	}
}

func TestProbeSVIDGetterFailureDegradesLoudly(t *testing.T) {
	// The api's own identity being unavailable must never cost the datum:
	// present nothing (crypto/tls needs a non-nil cert), capture anyway, and
	// say so through warnf.
	notAfter := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	ln, _ := serveMTLSOnce(t, selfSigned(t, notAfter), nil)
	var warned []string
	p := newProberForTest()
	p.warnf = func(msg string, _ map[string]any) { warned = append(warned, msg) }
	WithClientCertificate(func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return nil, io.ErrUnexpectedEOF
	})(p)
	res := p.probe(context.Background(), peerEndpoint{Name: "syslog", Addr: ln.Addr().String()})
	if !res.ok || !res.notAfter.Equal(notAfter) {
		t.Fatalf("served cert not captured after a getter failure: %+v", res)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "client SVID unavailable") {
		t.Fatalf("getter failure was not reported: %v", warned)
	}
}

func TestNewAppliesOptions(t *testing.T) {
	get := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	p, err := New("", nil, WithClientCertificate(get))
	if err != nil {
		t.Fatal(err)
	}
	if p.clientCert == nil {
		t.Fatal("New dropped the client-certificate option")
	}
	p2, err := New("", nil)
	if err != nil || p2.clientCert != nil {
		t.Fatalf("default prober must present no client certificate (err=%v)", err)
	}
}
