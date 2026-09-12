// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// gotenberg_client_guard_test.go — structural guards for the api → gotenberg
// hop (tenant RCA/report PDF content).
//
// The 2026-08-05 mesh-client incident class: a bare &http.Client{} literal at
// a call site bypasses the hardened backend transport (mesh-CA trust + api
// SVID presentation + authURLTransport, backend_client.go) and silently trusts
// the system pool — or, on an https sidecar URL, fails verification and
// tempts an InsecureSkipVerify "fix". Both gotenberg call sites must ride
// backendHTTPClient (or an injected client wired from it); the ONLY permitted
// http.Client construction on this path is the named nil-default helper in
// reports/sidecar_client.go, which this guard deliberately does not scan.
//
// Same doctrine as TestRedisClientHasNoInsecureKnob (collectors/redis_tls_test.go).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGotenbergCallSitesHaveNoBareHTTPClient(t *testing.T) {
	for _, f := range []string{"rca_report_http.go", filepath.Join("reports", "render_pdf.go")} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(raw)
		if strings.Contains(src, "InsecureSkipVerify") {
			t.Errorf("%s contains InsecureSkipVerify — the hop carries tenant document content; verification is not optional", f)
		}
		if strings.Contains(src, "http.Client{") {
			t.Errorf("%s constructs a bare http.Client — the gotenberg path must use the shared mesh transport (backendHTTPClient / injected client), never an ad-hoc client (2026-08-05 incident class)", f)
		}
	}
}

func TestGotenbergReportsPackageHasNoInsecureKnob(t *testing.T) {
	entries, err := os.ReadDir("reports")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("reports", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "InsecureSkipVerify") {
			t.Errorf("reports/%s contains InsecureSkipVerify — no insecure knob may ever grow in the reports package", e.Name())
		}
	}
}
