// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chhttp

// SEC-009.1: a TLS verification failure against ClickHouse must surface as a
// transport error the caller sees — never a swallowed nil or a misclassified
// success. The client under test gets a plain http.Client (system roots), and
// the server presents a self-signed cert it cannot verify.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTLSVerificationFailureIsSurfaced(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // never reached by a verifying client
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: &http.Client{Timeout: 5 * time.Second}}
	_, err := c.Exec(context.Background(), Request{SQL: "SELECT 1", Op: "tls-test", Scope: "__none__"})
	if err == nil {
		t.Fatal("query against an unverifiable TLS server must fail — it returned nil")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "tls") {
		t.Fatalf("error must identify the TLS failure, got: %v", err)
	}
}
