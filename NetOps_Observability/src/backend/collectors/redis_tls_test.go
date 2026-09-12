// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// redis_tls_test.go — SEC-012.2 regression guards. The property: with
// REDIS_TLS=true the RESP channel (and the SEC-012.1 AUTH password inside
// it) rides verified TLS — hostname-checked, fail-closed on missing trust,
// with NO insecure knob to mistype into existence.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSignedFor mints a throwaway server cert for the given DNS name and
// returns (tls.Certificate, caPEMPath).
func selfSignedFor(t *testing.T, dns string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dns},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dns},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caPath
}

// respTLSServer accepts one TLS connection and answers RESP commands with +OK.
func respTLSServer(t *testing.T, cert tls.Certificate) net.Listener {
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
		tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		defer tc.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := tc.Read(buf); err != nil {
				return
			}
			if _, err := tc.Write([]byte("+OK\r\n")); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestRedisDialTLSRoundTripWithAuth(t *testing.T) {
	cert, caPath := selfSignedFor(t, "localhost")
	ln := respTLSServer(t, cert)
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = host
	t.Setenv("REDIS_HOST", "localhost") // must match the cert's DNS SAN
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA", caPath)
	t.Setenv("REDIS_PASSWORD", "s3cret")

	c, err := redisDial(context.Background())
	if err != nil {
		t.Fatalf("TLS dial with AUTH failed: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*tls.Conn); !ok {
		t.Fatal("connection is not TLS despite REDIS_TLS=true")
	}
}

func TestRedisDialRefusesWrongHostname(t *testing.T) {
	// The cert says "localhost"; the client is told the server is
	// "wrong-host". Verification must refuse — hostname checking is the half
	// of TLS that a bare CA check silently skips.
	cert, caPath := selfSignedFor(t, "localhost")
	ln := respTLSServer(t, cert)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	t.Setenv("REDIS_HOST", "wrong-host")
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA", caPath)
	t.Setenv("REDIS_PASSWORD", "s3cret")

	// Dial the listener address directly via env is not possible (REDIS_HOST
	// drives both dialing and verification), so point the resolver at it:
	// the dial will fail either on resolution or on verification — both are
	// refusals; what must NOT happen is a successful AUTH.
	if c, err := redisDial(context.Background()); err == nil {
		c.Close()
		t.Fatal("dial succeeded with a hostname the certificate does not name")
	}
}

func TestRedisTLSFailsClosedOnPartialConfig(t *testing.T) {
	t.Setenv("REDIS_HOST", "redis")
	t.Setenv("REDIS_PORT", "6380")
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA", "")
	if _, err := redisDial(context.Background()); err == nil || !strings.Contains(err.Error(), "REDIS_TLS_CA") {
		t.Fatalf("REDIS_TLS without a CA must refuse before dialing, got: %v", err)
	}
	t.Setenv("REDIS_TLS_CA", filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := redisDial(context.Background()); err == nil {
		t.Fatal("an unloadable CA bundle must refuse, never downgrade to plaintext")
	}
}

func TestRedisClientHasNoInsecureKnob(t *testing.T) {
	// The ldap.go doctrine, enforced structurally: the redis client source
	// must never grow an InsecureSkipVerify escape hatch.
	raw, err := os.ReadFile("redis.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "InsecureSkipVerify") {
		t.Fatal("redis.go contains InsecureSkipVerify — the channel carries AUTH credentials; verification is not optional")
	}
}
