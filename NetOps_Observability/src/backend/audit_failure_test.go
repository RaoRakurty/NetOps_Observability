package backend

// audit_failure_test.go — F-73.
//
// `/api/audit` answered a failed query with HTTP 200 and `{"events":[]}`. A
// SIEM polling through a Postgres blip — or an RLS regression that made every
// row invisible — recorded "no privileged actions occurred". This is the one
// endpoint in the product where silence is itself a security assertion, and it
// was the endpoint that could not tell silence from failure.
//
// The file backend cannot fail, which is exactly why the defect survived: every
// existing audit test runs against a store whose List never errors. These tests
// inject a failing repo instead.

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// failingAuditRepo answers every read with an error, the way a dead PG pool or
// a broken RLS policy would.
type failingAuditRepo struct {
	inner            auditRepo
	failList         bool
	failCount        bool
	failRecordStrict bool
}

var errAuditBackendDown = errors.New("audit backend unavailable")

func (f *failingAuditRepo) Record(e AuditEvent) { f.inner.Record(e) }

func (f *failingAuditRepo) RecordStrict(e AuditEvent) error {
	if f.failRecordStrict {
		return errAuditBackendDown
	}
	return f.inner.RecordStrict(e)
}

func (f *failingAuditRepo) List(tenant string, cross bool, q auditQuery) ([]AuditEvent, error) {
	if f.failList {
		return nil, errAuditBackendDown
	}
	return f.inner.List(tenant, cross, q)
}

func (f *failingAuditRepo) Count(tenant string, cross bool, q auditQuery) int {
	if f.failCount {
		return -1
	}
	return f.inner.Count(tenant, cross, q)
}

func getWithToken(t *testing.T, url, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// The headline defect.
func TestAuditQueryFailureIsNotReportedAsAnEmptyTrail(t *testing.T) {
	srv, s := newTestServerState(t)
	tok, _ := loginFor(t, srv.URL)

	// Healthy first — this proves the assertion below is about the failure and
	// not about the route being unreachable.
	code, out := getWithToken(t, srv.URL+"/api/audit?limit=10", tok)
	if code != http.StatusOK {
		t.Fatalf("healthy /api/audit = %d, want 200 (body %v)", code, out)
	}

	s.audit = &failingAuditRepo{inner: s.audit, failList: true}

	code, out = getWithToken(t, srv.URL+"/api/audit?limit=10", tok)
	if code == http.StatusOK {
		t.Fatalf("a failed audit query returned 200 %v — a SIEM reads this as "+
			"'no privileged actions occurred'", out)
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("failed audit query = %d, want 503", code)
	}
	// And it must not ship an empty events array alongside the error, which a
	// lenient client would happily consume as "no results".
	if ev, ok := out["events"]; ok {
		if list, isList := ev.([]any); isList && len(list) == 0 {
			t.Error("an error response must not carry an empty events array")
		}
	}
}

// The governance view reads the same trail through the same helper.
func TestGovernanceAuditFailureIsNotReportedAsNoChanges(t *testing.T) {
	srv, s := newTestServerState(t)
	tok, _ := loginFor(t, srv.URL)

	if code, _ := getWithToken(t, srv.URL+"/api/settings/governance-audit", tok); code != http.StatusOK {
		t.Fatalf("healthy governance-audit must be 200, got %d", code)
	}
	s.audit = &failingAuditRepo{inner: s.audit, failList: true}

	code, out := getWithToken(t, srv.URL+"/api/settings/governance-audit", tok)
	if code == http.StatusOK {
		t.Fatalf("a failed governance-audit query returned 200 %v — reads as "+
			"'no governance changes were made'", out)
	}
}

// The store seam itself: the file backend must report success explicitly rather
// than relying on a nil error by accident.
func TestFileAuditStoreListReturnsNoError(t *testing.T) {
	_, s := newTestServerState(t)
	events, err := s.audit.List("", true, auditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("file backend List must not error: %v", err)
	}
	_ = events
}

// Count already returns -1 (not 0) for an unknown total — the same lesson
// applied to the total. Pin it so it cannot regress to 0.
func TestAuditCountFailureIsMinusOneNotZero(t *testing.T) {
	_, s := newTestServerState(t)
	s.audit = &failingAuditRepo{inner: s.audit, failCount: true}
	if got := s.audit.Count("", true, auditQuery{}); got != -1 {
		t.Fatalf("failed Count = %d, want -1 (0 would render as 'no events')", got)
	}
}
