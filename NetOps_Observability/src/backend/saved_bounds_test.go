// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Server-side bounds on saved objects: the builder's 40-cell cap was the only
// limit (client-side), so a body could be as large as the global request cap
// and a tenant could keep any number of objects.

func TestSavedObjectBodyOverTheCapIsRefused(t *testing.T) {
	s := tenantServer(t)
	big := `{"type":"dashboard","name":"big","body":{"cells":"` + strings.Repeat("x", savedMaxRequestBytes) + `"}}`
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", big, acme()))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized create: %d %s, want 413", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "64 KiB") {
		t.Fatalf("the refusal does not name the limit: %s", w.Body.String())
	}

	obj := seedSaved(t, s, "dashboard")
	w = httptest.NewRecorder()
	s.handleSavedByID(w, req("PUT", "/api/saved/"+obj.ID, big, acme()))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized update: %d, want 413", w.Code)
	}
	if o, _ := s.saved.Get(obj.ID); o.Name != "seed" {
		t.Fatalf("a refused update changed the object: %+v", o)
	}
}

func TestSavedObjectNameOverTheCapIsRefused(t *testing.T) {
	s := tenantServer(t)
	long := strings.Repeat("é", savedMaxNameRunes+1) // runes, not bytes
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"dashboard","name":"`+long+`","body":{}}`, acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an over-long name: %d, want 400", w.Code)
	}
	ok := strings.Repeat("é", savedMaxNameRunes)
	w = httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"dashboard","name":"`+ok+`","body":{}}`, acme()))
	if w.Code != http.StatusCreated {
		t.Fatalf("a name at the cap was refused: %d %s", w.Code, w.Body.String())
	}
}

func TestSavedObjectsPerTenantCountIsCapped(t *testing.T) {
	s := tenantServer(t)
	for i := 0; i < savedMaxPerTenantType; i++ {
		w := httptest.NewRecorder()
		s.handleSaved(w, req("POST", "/api/saved", fmt.Sprintf(`{"type":"dashboard","name":"d%d","body":{}}`, i), acme()))
		if w.Code != http.StatusCreated {
			t.Fatalf("create %d: %d", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"dashboard","name":"one too many","body":{}}`, acme()))
	if w.Code != http.StatusConflict {
		t.Fatalf("past the cap: %d, want 409", w.Code)
	}
	// The cap is per tenant and per kind: another kind, and another tenant, still save.
	w = httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"saved_search","name":"q","body":{}}`, acme()))
	if w.Code != http.StatusCreated {
		t.Fatalf("another kind in the same tenant was refused: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"dashboard","name":"g","body":{}}`, globex()))
	if w.Code != http.StatusCreated {
		t.Fatalf("another tenant was refused by acme's count: %d", w.Code)
	}
}
