// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// parsercov_restriction_test.go — the CLAUDE.md §3a rule-5 isolation test for the
// per-tenant OPERATOR-VISIBILITY restriction (Tenant.OperatorRestricted) on the
// parser-coverage routes (programme A6).
//
// This lane reads RAW, UNPARSED log lines: the documents the engine would not
// admit, sampled verbatim into every response. The interactive log search
// (logs.go) already honours the restriction. This is a SECOND door onto
// substantially the same data, so it must honour it too, or the switch is
// decorative.
//
// Run through the REAL parserCovAuthz gate mapping and a REAL tenant store, so
// the switch under test is the production one (Tenant.OperatorRestricted →
// effectiveRestrictedIDs → operatorTelemetryRestriction). The OpenSearch
// stand-in RECORDS every request, because the index pattern and the query body
// are the two halves of the boundary, and it answers with a real unrecognized
// line so the test can name exactly what crossed.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/parsercov"
)

// the raw line the fake index serves. If this string reaches a restricted
// tenant's reader, a customer's log line has crossed.
const pcRestrictedLine = `%SEC-6-IPACCESSLOGP: list acme-edge-in denied tcp 203.0.113.77(51514) dst 10.1.0.1(22)`

type pcRestrictedOS struct {
	mu     sync.Mutex
	tenant string // the tenant that owns the one document this index holds
	calls  []pcOSCall
}

func (f *pcRestrictedOS) all() []pcOSCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pcOSCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// serves reports whether the one document in this index would MATCH the query
// body. The stand-in has to behave like an index, not like a yes-man: a test
// whose fake answers the same hit whatever the clause says can never prove that
// the clause is what keeps the line out.
//
// Two rules, which are the two the real clause expresses:
//   - a must_not terms on tenant_id naming this document's tenant excludes it
//     (the operator-visibility exclusion, in the Global view);
//   - a term on tenant_id naming a DIFFERENT tenant excludes it (the ordinary
//     scoped clause).
func (f *pcRestrictedOS) serves(body string) bool {
	if ids, ok := jsonArrayAfter(body, `"must_not":[{"terms":{"tenant_id":[`); ok &&
		strings.Contains(ids, `"`+f.tenant+`"`) {
		return false
	}
	const scoped = `"term":{"tenant_id":"`
	if i := strings.Index(body, scoped); i >= 0 {
		rest := body[i+len(scoped):]
		j := strings.Index(rest, `"`)
		if j >= 0 && rest[:j] != f.tenant {
			return false
		}
	}
	return true
}

// jsonArrayAfter returns the text of the array that opens right after `prefix`.
func jsonArrayAfter(body, prefix string) (string, bool) {
	i := strings.Index(body, prefix)
	if i < 0 {
		return "", false
	}
	rest := body[i+len(prefix):]
	j := strings.Index(rest, "]")
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// pcStartLiveFakeOS answers a window that HAS unrecognized content: the stamp
// probe reports stamped documents (so the lane does not refuse with "no
// admission verdict"), and the scan returns one real, unparsed line — but only
// when the query would actually match it.
func pcStartLiveFakeOS(t *testing.T, ownerTenant string) *pcRestrictedOS {
	t.Helper()
	fake := &pcRestrictedOS{tenant: ownerTenant}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		body := string(raw)
		index := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_search")
		fake.mu.Lock()
		fake.calls = append(fake.calls, pcOSCall{Index: index, Body: body})
		fake.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		match := fake.serves(body)
		switch {
		case !strings.Contains(body, `"size":0`):
			// the scan: the unrecognized document, served verbatim.
			if !match {
				_, _ = w.Write([]byte(`{"took":1,"timed_out":false,` +
					`"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"took":1,"timed_out":false,"hits":{` +
				`"total":{"value":1,"relation":"eq"},"hits":[{"_source":{` +
				`"timestamp":"2026-09-01T12:00:00Z",` +
				`"message":"` + pcRestrictedLine + `",` +
				`"hostname":"acme-core","host":"acme-core","appname":"SEC",` +
				`"severity":"6"},"sort":[1,"a"]}]}}`))
		case strings.Contains(body, `"aggs"`):
			// the stamp probe: the lane IS publishing its verdict.
			n := "0"
			if match {
				n = "9"
			}
			_, _ = w.Write([]byte(`{"took":1,"timed_out":false,` +
				`"hits":{"total":{"value":` + n + `,"relation":"eq"},"hits":[]},` +
				`"aggregations":{"versions":{"buckets":[{"key":"2026.09.01","doc_count":` + n + `}]}}}`))
		default:
			// the window total.
			n := "0"
			if match {
				n = "10"
			}
			_, _ = w.Write([]byte(`{"took":1,"timed_out":false,` +
				`"hits":{"total":{"value":` + n + `,"relation":"eq"},"hits":[]}}`))
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	return fake
}

type restrictedParserCovFixture struct {
	t      *testing.T
	s      *server
	os     *pcRestrictedOS
	acme   string
	globex string
}

func newRestrictedParserCovFixture(t *testing.T) *restrictedParserCovFixture {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	tenants, err := newTenantStore(dir + "/tenants.json")
	if err != nil {
		t.Fatalf("tenantStore: %v", err)
	}
	acme, err := tenants.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := tenants.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	fake := pcStartLiveFakeOS(t, acme.ID)
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme.ID})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex.ID})
	s := &server{roles: roles, tenants: tenants, discovery: d}
	s.parserCovMetrics = parsercov.NewMetrics()
	s.parserCov = parsercov.New(s.parserCovDeps())
	return &restrictedParserCovFixture{t: t, s: s, os: fake, acme: acme.ID, globex: globex.ID}
}

func (f *restrictedParserCovFixture) mine(claims jwtClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.s.parserCov.HandleUnrecognized(w, req(http.MethodGet, "/api/telemetry/unrecognized", "", claims))
	return w
}

// templateIDOf pulls the first mined template id out of a response, so the
// propose route can be exercised on an id that really resolves.
func templateIDOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	const key = `"template_id":"`
	body := w.Body.String()
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("no template id in the mined response: %s", body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("malformed template id in: %s", body)
	}
	return rest[:j]
}

// TestParserCovHonoursTheOperatorVisibilityRestriction is the §3a rule-5 test for
// the compliance switch on this lane. It asserts BOTH halves: the restricted
// tenant's raw lines are absent from the platform owner's Global mining run, and
// an as_tenant run into that tenant mines nothing and reads no store.
func TestParserCovHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedParserCovFixture(t)
	owner := platformOwner()

	// Before anything is restricted the platform owner mines the line, so the
	// test cannot pass by serving nothing.
	pre := f.mine(owner)
	if pre.Code != http.StatusOK || !strings.Contains(pre.Body.String(), pcRestrictedLine) {
		t.Fatalf("owner (nothing restricted) did not mine the seeded line: %d %s", pre.Code, pre.Body.String())
	}
	templateID := templateIDOf(t, pre)

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// Global view: the query must EXCLUDE the restricted tenant at the source,
	// so the raw line never comes back.
	before := len(f.os.all())
	w := f.mine(owner)
	if w.Code != http.StatusOK {
		t.Fatalf("owner Global mine = %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), pcRestrictedLine) {
		t.Errorf("RESTRICTION LEAK: the platform owner's Global run carried the restricted tenant's raw log line: %s",
			w.Body.String())
	}
	var sawExclusion bool
	for _, c := range f.os.all()[before:] {
		if strings.Contains(c.Body, `"must_not"`) && strings.Contains(c.Body, f.acme) {
			sawExclusion = true
		}
	}
	if !sawExclusion {
		t.Errorf("RESTRICTION LEAK: no query in the Global run excluded tenant %q; bodies: %+v",
			f.acme, f.os.all()[before:])
	}

	// The as_tenant half: the operator walking into the restricted tenant mines
	// nothing, and touches no store at all.
	scoped := ownerActing(owner, f.acme)
	before = len(f.os.all())
	w = f.mine(scoped)
	if w.Code != http.StatusOK {
		t.Fatalf("owner→acme mine = %d, want 200 with nothing in it: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), pcRestrictedLine) {
		t.Errorf("RESTRICTION LEAK: owner→acme read the restricted tenant's raw log line: %s", w.Body.String())
	}
	if n := len(f.os.all()) - before; n != 0 {
		t.Errorf("a denied run issued %d OpenSearch queries; a deny must return before any store is read", n)
	}

	// The propose route is the same door with a different shape: an id that
	// resolved a moment ago must now 404, the same answer another tenant's id
	// gets, and it must not carry the line in its body.
	for _, claims := range []jwtClaims{owner, scoped} {
		pw := httptest.NewRecorder()
		f.s.parserCov.HandlePropose(pw,
			req(http.MethodPost, "/api/telemetry/unrecognized/"+templateID+"/propose", "", claims))
		if pw.Code != http.StatusNotFound {
			t.Errorf("RESTRICTION LEAK: propose (acting=%q) = %d, want 404: %s",
				claims.ActingTenant, pw.Code, pw.Body.String())
		}
		if strings.Contains(pw.Body.String(), pcRestrictedLine) {
			t.Errorf("RESTRICTION LEAK: propose (acting=%q) carried the raw line: %s",
				claims.ActingTenant, pw.Body.String())
		}
	}

	// The operator scoped into the UNRESTRICTED tenant still runs: it is not
	// denied, and it does reach the store. (It finds nothing, because the one
	// document in this index belongs to acme.)
	before = len(f.os.all())
	if gw := f.mine(ownerActing(owner, f.globex)); gw.Code != http.StatusOK {
		t.Errorf("the unrestricted tenant's mining run broke: %d %s", gw.Code, gw.Body.String())
	}
	if len(f.os.all())-before == 0 {
		t.Error("the unrestricted tenant's run was short-circuited — the restriction spilled onto globex")
	}

	// And acme's OWN operator is never restricted from acme's own lines.
	acmeOwn := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
	if ow := f.mine(acmeOwn); ow.Code != http.StatusOK ||
		!strings.Contains(ow.Body.String(), pcRestrictedLine) {
		t.Fatalf("acme's own operator lost its own unrecognized lines: %d %s", ow.Code, ow.Body.String())
	}
}
