// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_glossary_isolation_test.go — CLAUDE.md §3a rule 5 for Iris's generated
// vocabulary (internal/irisglossary via server.aiGlossary): the names one
// tenant's network uses must never reach another tenant's prompts, an
// as_tenant parameter must not widen a non-cross caller, and no device address
// is ever rendered.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/irisglossary"
	"netops/backend/models"
)

func glossaryServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	seed := []models.Device{
		{ID: "acme-dal-edge", Name: "acme-dallas-edge", TenantID: "acme", Vendor: "cisco", Model: "c8000v", Labels: map[string]string{"role": "wan_edge"}},
		{ID: "acme-core", Name: "acme-core-1", TenantID: "acme", Vendor: "juniper", Labels: map[string]string{"role": "core"}},
		{ID: "globex-secret", Name: "globex-secret-router", TenantID: "globex", Vendor: "arista", Labels: map[string]string{"role": "spine"}},
		{ID: "acme-ipname", Name: "10.20.30.40", TenantID: "acme", Vendor: "cisco"}, // named by its address
	}
	for i, dev := range seed {
		dev.Address = fmt.Sprintf("10.9.0.%d", i+1)
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed %s: %v", dev.ID, err)
		}
	}
	return &server{roles: roles, discovery: d, aiGlossaryCache: irisglossary.NewCache(16, time.Minute)}
}

func glossaryFor(t *testing.T, s *server, claims jwtClaims, target string) string {
	t.Helper()
	r := httptest.NewRequest("POST", target, nil)
	return s.aiGlossary(r, claims)(context.Background(), aiTSPrincipal())
}

func TestIrisGlossaryIsTheCallersOwn(t *testing.T) {
	s := glossaryServer(t)
	a := glossaryFor(t, s, acme(), "/api/ai/ask")
	if !strings.Contains(a, "acme-dallas-edge") || !strings.Contains(a, "acme-core-1") {
		t.Fatalf("acme's glossary must name acme's devices:\n%s", a)
	}
	if strings.Contains(a, "globex") || strings.Contains(a, "arista") || strings.Contains(a, "spine") {
		t.Fatalf("acme's glossary carries globex's vocabulary:\n%s", a)
	}
	g := glossaryFor(t, s, globex(), "/api/ai/ask")
	if !strings.Contains(g, "globex-secret-router") {
		t.Fatalf("globex's glossary must name globex's device:\n%s", g)
	}
	if strings.Contains(g, "acme") || strings.Contains(g, "juniper") {
		t.Fatalf("globex's glossary carries acme's vocabulary:\n%s", g)
	}
	// The cache is per scope: a cached acme glossary is never served to globex.
	if again := glossaryFor(t, s, globex(), "/api/ai/ask"); again != g {
		t.Fatalf("globex's second read differs from its first")
	}
	if s.aiGlossaryCache.Len() != 2 {
		t.Fatalf("one cache entry per scope, got %d", s.aiGlossaryCache.Len())
	}
}

// as_tenant into another org is ignored for a non-cross caller.
func TestIrisGlossaryAsTenantDoesNotWiden(t *testing.T) {
	s := glossaryServer(t)
	a := glossaryFor(t, s, acme(), "/api/ai/ask?as_tenant=globex")
	if strings.Contains(a, "globex") {
		t.Fatalf("as_tenant widened acme's glossary:\n%s", a)
	}
}

// No address is ever rendered: neither the device address nor a device whose
// NAME is an address.
func TestIrisGlossaryCarriesNoAddress(t *testing.T) {
	s := glossaryServer(t)
	a := glossaryFor(t, s, acme(), "/api/ai/ask")
	for _, bad := range []string{"10.9.0.", "10.20.30.40"} {
		if strings.Contains(a, bad) {
			t.Fatalf("address %q reached the glossary:\n%s", bad, a)
		}
	}
	if irisglossary.HasAddress(a) {
		t.Fatalf("the glossary carries an address:\n%s", a)
	}
}

// An inventory change is seen on the next question (the fingerprint moves).
func TestIrisGlossarySeesAnInventoryChange(t *testing.T) {
	s := glossaryServer(t)
	before := glossaryFor(t, s, acme(), "/api/ai/ask")
	if err := s.discovery.Upsert(models.Device{ID: "acme-new", Name: "acme-houston-edge", Address: "10.9.9.9", TenantID: "acme", Vendor: "cisco"}); err != nil {
		t.Fatal(err)
	}
	after := glossaryFor(t, s, acme(), "/api/ai/ask")
	if strings.Contains(before, "acme-houston-edge") || !strings.Contains(after, "acme-houston-edge") {
		t.Fatalf("a new device must appear on the next read:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
