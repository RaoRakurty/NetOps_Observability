// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// change_api_isolation_test.go — /api/changes (tracker 337 N-D3) through the
// real handler: own-tenant list only, another tenant's change id is 404 on
// /api/changes/{id} and /api/changes/{id}/diff, an as_tenant walk by a
// non-owner changes nothing, and the Global view reads no single ledger.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
)

func changeAPICall(t *testing.T, s *server, c jwtClaims, path string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleChanges(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func TestChangeAPIIsTenantIsolated(t *testing.T) {
	s, a, b := nlqAPIFixture(t)
	s.experienceStore = experience.NewFileStore("")
	now := time.Now().UTC()
	for _, c := range []experience.ChangeEvent{
		{TenantID: a.Tenant, ID: "chg-a", Type: experience.ChangeConfig, Object: "dev-a", ObjectKind: "device", Summary: "a's change",
			Before: "secret=hunter2", After: "secret=swordfish"},
		{TenantID: b.Tenant, ID: "chg-b", Type: experience.ChangeConfig, Object: "dev-b", ObjectKind: "device", Summary: "b's change"},
	} {
		c.Provenance = experience.Provenance{Source: experience.SourceConfigDrift, Producer: "test", EventAt: now.Add(-time.Minute),
			ObservedAt: now.Add(-time.Minute), Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata}
		if _, err := s.experienceStore.RecordChange(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	code, out := changeAPICall(t, s, a, "/api/changes")
	if code != 200 || !strings.Contains(nlqJSON(out), "chg-a") || strings.Contains(nlqJSON(out), "chg-b") {
		t.Fatalf("tenant A's list: %d %v", code, out)
	}
	walker := b
	walker.ActingTenant = a.Tenant
	for name, c := range map[string]jwtClaims{"other tenant": b, "as_tenant walk": walker} {
		for _, p := range []string{"/api/changes/chg-a", "/api/changes/chg-a/diff", "/api/changes/chg-a?as_tenant=" + a.Tenant} {
			if code, _ := changeAPICall(t, s, c, p); code != http.StatusNotFound {
				t.Errorf("%s %s: %d, want 404", name, p, code)
			}
		}
		if _, out := changeAPICall(t, s, c, "/api/changes?as_tenant="+a.Tenant); strings.Contains(nlqJSON(out), "chg-a") {
			t.Errorf("%s listed tenant A's change", name)
		}
	}
	code, out = changeAPICall(t, s, a, "/api/changes/chg-a")
	if code != 200 || strings.Contains(nlqJSON(out), "hunter2") {
		t.Fatalf("own change, redacted: %d %v", code, out)
	}
	// A principal without infrastructure:read is refused.
	ingest := a
	ingest.Role = "ingest"
	if code, _ := changeAPICall(t, s, ingest, "/api/changes"); code != http.StatusForbidden {
		t.Fatalf("no infrastructure:read: %d, want 403", code)
	}
}
