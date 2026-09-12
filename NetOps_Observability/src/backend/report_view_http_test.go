// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/reports"
)

// fakeExecStore implements reports.ExecutionStore; only Get is exercised by the
// view handler, so the embedded nil interface covers the rest (a call to any
// other method would panic, surfacing an unexpected code path).
type fakeExecStore struct {
	reports.ExecutionStore
	rec   reports.ExecutionRecord
	found bool
}

func (f fakeExecStore) Get(_ context.Context, _ string, _ bool, id string) (reports.ExecutionRecord, []reports.ExecEvent, bool, error) {
	if !f.found || id != f.rec.ID {
		return reports.ExecutionRecord{}, nil, false, nil
	}
	return f.rec, nil, true, nil
}

type fakeArtifactStore struct {
	reports.ArtifactStore
	art reports.Artifact
}

func (f fakeArtifactStore) Load(_ context.Context, _ reports.ArtifactRef) (reports.Artifact, error) {
	return f.art, nil
}

// viewServer wires a server whose report pipeline serves one stored execution.
func viewServer(rec reports.ExecutionRecord, found bool, art reports.Artifact) *server {
	return &server{reportPipeline: &reportPipeline{
		execs:     fakeExecStore{rec: rec, found: found},
		artifacts: fakeArtifactStore{art: art},
	}}
}

func doView(s *server, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/reports/view/"+token, nil)
	w := httptest.NewRecorder()
	s.handleReportView(w, r)
	return w
}

func TestHandleReportView(t *testing.T) {
	t.Setenv("REPORT_LINK_SECRET", "view-test-secret")

	rec := reports.ExecutionRecord{
		ID: "exec-1", TenantID: "acme", Status: "completed",
		Artifacts: []reports.ArtifactRef{{Format: "html", ContentType: "text/html", Key: "exec-1"}},
	}
	art := reports.Artifact{Format: "html", ContentType: "text/html", Bytes: []byte("<h1>report</h1>")}
	s := viewServer(rec, true, art)

	// 1. A valid token for the owning tenant serves the artifact bytes.
	tok := signReportLink("exec-1", "acme", time.Hour)
	if w := doView(s, tok); w.Code != http.StatusOK || w.Body.String() != "<h1>report</h1>" {
		t.Fatalf("valid link: code=%d body=%q", w.Code, w.Body.String())
	}

	// 2. SR-018: a token bound to a DIFFERENT tenant must not open acme's
	//    execution — even though the execution id is correct.
	cross := signReportLink("exec-1", "evil", time.Hour)
	if w := doView(s, cross); w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant token: want 403, got %d", w.Code)
	}

	// 3. An expired token is rejected before any store lookup.
	if w := doView(s, signReportLink("exec-1", "acme", -time.Minute)); w.Code != http.StatusForbidden {
		t.Fatalf("expired token: want 403, got %d", w.Code)
	}

	// 4. A tampered/forged token fails signature verification.
	if w := doView(s, tok[:len(tok)-1]+"X"); w.Code != http.StatusForbidden {
		t.Fatalf("tampered token: want 403, got %d", w.Code)
	}

	// 5. A valid token for a non-existent execution → 404.
	if w := doView(s, signReportLink("nope", "acme", time.Hour)); w.Code != http.StatusNotFound {
		t.Fatalf("missing execution: want 404, got %d", w.Code)
	}

	// 6. A format the execution didn't render → 404 (not silently the html one).
	rq := httptest.NewRequest(http.MethodGet, "/api/reports/view/"+tok+"?format=xlsx", nil)
	wq := httptest.NewRecorder()
	s.handleReportView(wq, rq)
	if wq.Code != http.StatusNotFound {
		t.Fatalf("missing format: want 404, got %d", wq.Code)
	}
}

func TestHandleReportViewNoPipeline(t *testing.T) {
	// File backend (no async pipeline) → links unavailable, honest 409.
	s := &server{}
	w := doView(s, "anything")
	if w.Code != http.StatusConflict {
		t.Fatalf("no pipeline: want 409, got %d", w.Code)
	}
}
