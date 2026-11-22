// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/internal/saved"
)

// The saved-object routes (dashboards, saved searches, report objects) carried
// no permission check: any authenticated principal of a tenant could list,
// change or delete them — including an `ingest:*` API key, which customers
// publish inside their web pages for the RUM snippet (2026-11-22).

func savedAs(role string) jwtClaims {
	return jwtClaims{Sub: role + "@acme", Role: role, Tenant: "acme"}
}

func seedSaved(t *testing.T, s *server, typ string) saved.Object {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"`+typ+`","name":"seed","body":{}}`, acme()))
	if w.Code != http.StatusCreated {
		t.Fatalf("operator seed %s: %d %s", typ, w.Code, w.Body.String())
	}
	var o saved.Object
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestSavedObjectsRefuseAnIngestKeyEntirely(t *testing.T) {
	s := tenantServer(t)
	dash := seedSaved(t, s, "dashboard")
	rpt := seedSaved(t, s, "report")
	ingest := savedAs(RoleIngest)

	w := httptest.NewRecorder()
	s.handleSaved(w, req("GET", "/api/saved", "", ingest))
	if w.Code == http.StatusOK {
		t.Fatalf("an ingest key LISTED saved objects: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"dashboard","name":"x","body":{}}`, ingest))
	if w.Code != http.StatusForbidden {
		t.Fatalf("an ingest key created a dashboard: %d", w.Code)
	}
	for _, o := range []saved.Object{dash, rpt} {
		for _, m := range []string{"GET", "PUT", "DELETE"} {
			w = httptest.NewRecorder()
			s.handleSavedByID(w, req(m, "/api/saved/"+o.ID, `{"name":"pwned"}`, ingest))
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s %s by an ingest key: %d, want 404 (never reveal the id)", m, o.Type, w.Code)
			}
		}
		if _, ok := s.saved.Get(o.ID); !ok {
			t.Fatalf("the ingest key deleted %s", o.Type)
		}
	}
}

func TestSavedObjectsReadOnlyReadsButNeverWrites(t *testing.T) {
	s := tenantServer(t)
	dash := seedSaved(t, s, "dashboard")
	for _, role := range []string{RoleReadOnly, RoleAuditor} {
		ro := savedAs(role)
		w := httptest.NewRecorder()
		s.handleSaved(w, req("GET", "/api/saved?type=dashboard", "", ro))
		if w.Code != http.StatusOK {
			t.Fatalf("%s could not list dashboards: %d", role, w.Code)
		}
		w = httptest.NewRecorder()
		s.handleSavedByID(w, req("GET", "/api/saved/"+dash.ID, "", ro))
		if w.Code != http.StatusOK {
			t.Fatalf("%s could not open a dashboard: %d", role, w.Code)
		}
		w = httptest.NewRecorder()
		s.handleSaved(w, req("POST", "/api/saved", `{"type":"dashboard","name":"x","body":{}}`, ro))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s created a dashboard: %d", role, w.Code)
		}
		for _, m := range []string{"PUT", "DELETE"} {
			w = httptest.NewRecorder()
			s.handleSavedByID(w, req(m, "/api/saved/"+dash.ID, `{"name":"changed"}`, ro))
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s %s a dashboard: %d, want 403", role, m, w.Code)
			}
		}
	}
	if o, ok := s.saved.Get(dash.ID); !ok || o.Name != "seed" {
		t.Fatalf("a read-only principal changed or removed the dashboard: %+v %v", o, ok)
	}
}

func TestSavedObjectsAnAPIClientCannotReadReports(t *testing.T) {
	s := tenantServer(t)
	rpt := seedSaved(t, s, "report")
	seedSaved(t, s, "saved_search")
	api := savedAs(RoleAPIClient)
	w := httptest.NewRecorder()
	s.handleSavedByID(w, req("GET", "/api/saved/"+rpt.ID, "", api))
	if w.Code != http.StatusNotFound {
		t.Fatalf("an api-client opened a report object: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleSaved(w, req("GET", "/api/saved", "", api))
	if w.Code != http.StatusOK {
		t.Fatalf("an api-client could not list what it may read: %d", w.Code)
	}
	var got []saved.Object
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, o := range got {
		if o.Type == "report" {
			t.Fatalf("the list showed an api-client a report object: %+v", got)
		}
	}
}

func TestSavedObjectsOperatorStillSavesAndEdits(t *testing.T) {
	s := tenantServer(t)
	dash := seedSaved(t, s, "dashboard") // seeded as operator
	w := httptest.NewRecorder()
	s.handleSavedByID(w, req("PUT", "/api/saved/"+dash.ID, `{"name":"renamed"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("operator could not edit: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleSavedByID(w, req("DELETE", "/api/saved/"+dash.ID, "", acme()))
	if w.Code != http.StatusNoContent {
		t.Fatalf("operator could not delete: %d", w.Code)
	}
}
