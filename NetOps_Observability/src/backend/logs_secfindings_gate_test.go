// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// logs_secfindings_gate_test.go — the security-findings index family is NOT
// reachable through log search (review 2026-09-08, finding H9).
//
// WHAT WENT WRONG. oslog.IndexBase maps the caller-supplied signals
// `secfindings` and `security` onto the netops-secfindings-* family. Log search
// calls requirePerm zero times: logsScope gates only `applogs`, on platform
// ownership. So `GET /api/logs/search?signal=security` served the tenant's CTEM
// findings — severities, control ids, device names — to any principal that
// merely authenticated, including a zero-permission RoleIngest key from the
// first-party RUM snippet.
//
// The dedicated door is gated twice: infrastructure:read plus
// licenceFeature(FeatureSecurityFindings). The router indexes findings
// unconditionally, so on Community tier the paid surface answered 402 while
// this one answered 200. A permission and licence bypass within the tenant.
//
// GATE CHOICE (CLAUDE.md §3a rule 3). Findings ARE per-tenant operator data, so
// the right gate for them is requirePerm(infrastructure:read) plus the licence
// feature — and that gate already exists, on /api/security/findings, together
// with the tenant filter and the per-doc isolation clause. Adding a second
// permission gate here would build a SECOND door onto the same data with its
// own copy of the isolation rules, which is exactly what §3a rule 4 (the
// storage layer enforces it, in ONE place) forbids; it would also still miss
// the licence check. So log search REFUSES the family outright at logsScope,
// the one chokepoint the interactive search, the retention read and the
// pipeline-debug replay all resolve through, and callers are pointed at the
// door that has both gates. Log search for every other signal is untouched.
//
// Pinned here:
//   - every spelling of the signal is refused, at logsScope and at each handler;
//   - the refusal message NAMES the reason (§10: an operator asking for security
//     findings must not be told "app logs are restricted");
//   - not one byte reaches OpenSearch on a refused request;
//   - the REACHABLE signal set never resolves to netops-secfindings, whatever
//     the caller sends — the pin is on the resolved index, not on a name list;
//   - legitimate log search still works for the signals that are log lines.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/oslog"
	"netops/backend/internal/ratelimit"
)

// secSignalSpellings is every way a caller can name the findings family, plus
// the casing and padding a hostile caller would try.
var secSignalSpellings = []string{
	"security", "secfindings",
	"SECURITY", "SecFindings", "Security",
	" security ", "\tsecfindings\n",
}

// ingestKey is the zero-permission machine identity the RUM snippet ships with:
// a credential the code itself describes as printed on a billboard. It must
// reach nothing.
func ingestKey() jwtClaims {
	return jwtClaims{Sub: "rum-key", Role: RoleIngest, Tenant: "acme"}
}

func TestLogsScopeRefusesTheSecurityFindingsFamily(t *testing.T) {
	s := logsTestServer(t)
	callers := map[string]jwtClaims{
		"scoped tenant operator": acme(),
		"platform owner":         superA(),
		"zero-permission ingest": ingestKey(),
	}
	for who, claims := range callers {
		for _, signal := range secSignalSpellings {
			index, _, _, _, forbidden := s.logsScope(req(http.MethodGet, "/api/logs/search", "", claims), signal)
			if !forbidden {
				t.Errorf("%s, signal %q: logsScope allowed the read (index %q) — security findings are not log lines", who, signal, index)
			}
			if index != "" {
				t.Errorf("%s, signal %q: a refused scope must resolve no index at all, got %q", who, signal, index)
			}
		}
	}
}

// The pin on the REACHABLE set. It asserts on the RESOLVED INDEX rather than on
// a list of signal names, so a new alias added to oslog.IndexBase is caught here
// instead of opening a new door quietly.
func TestLogsScopeNeverResolvesTheSecFindingsIndexForAnySignal(t *testing.T) {
	s := logsTestServer(t)
	signals := []string{
		"", "all", "applogs", "app", "syslog", "snmptrap", "trap", "traps",
		"flows", "netflow", "flow", "cloud", "cloudlogs", "cloudlog",
		"security", "secfindings", "SECURITY",
		"netops-secfindings", "netops-secfindings-*", "../secfindings", "junk",
	}
	for _, claims := range []jwtClaims{acme(), globex(), superA(), ingestKey()} {
		for _, signal := range signals {
			index, _, _, _, forbidden := s.logsScope(req(http.MethodGet, "/api/logs/search", "", claims), signal)
			if forbidden {
				continue
			}
			if strings.Contains(index, oslog.SecFindingsIndexBase) {
				t.Errorf("caller %q, signal %q resolved to %q — log search reached the findings family", claims.Sub, signal, index)
			}
		}
	}
}

func TestLogSearchRefusesTheSecurityFindingsSignal(t *testing.T) {
	for _, signal := range secSignalSpellings {
		t.Run(strings.TrimSpace(signal), func(t *testing.T) {
			_, bodies := fakeOS(t, `{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`)
			s := logsTestServer(t)
			w := httptest.NewRecorder()
			s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
				`{"signal":"`+strings.TrimSpace(signal)+`","query":"*"}`, acme()))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %s)", w.Code, w.Body.String())
			}
			if len(*bodies) != 0 {
				t.Fatalf("a refused request reached OpenSearch %d time(s): %v", len(*bodies), *bodies)
			}
			// §10: the refusal has to say what was refused and where to go.
			msg := w.Body.String()
			if !strings.Contains(msg, "security findings") || !strings.Contains(msg, "/api/security/findings") {
				t.Fatalf("the refusal does not name the reason or the right door: %s", msg)
			}
			if strings.Contains(msg, "app logs") {
				t.Fatalf("the refusal blames the wrong boundary: %s", msg)
			}
		})
	}
}

func TestLogsRetentionRefusesTheSecurityFindingsSignal(t *testing.T) {
	_, bodies := fakeOS(t, osAggReply)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsRetention(w, req(http.MethodGet, "/api/logs/retention?signal=security", "", acme()))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %s)", w.Code, w.Body.String())
	}
	if len(*bodies) != 0 {
		t.Fatalf("a refused retention read reached OpenSearch: %v", *bodies)
	}
}

// The export door is the SAME data through a different handler: it builds its
// own spec instead of resolving logsScope, so it needs its own refusal or the
// fix is cosmetic.
func TestLogsExportRefusesTheSecurityFindingsSignal(t *testing.T) {
	for _, signal := range []string{"security", "secfindings"} {
		t.Run(signal, func(t *testing.T) {
			_, bodies := fakeOS(t, `{"count":0}`)
			s := logsTestServer(t)
			s.exportLimiter = ratelimit.New()
			w := httptest.NewRecorder()
			s.handleLogsExport(w, req(http.MethodGet,
				"/api/logs/export?format=csv&signal="+signal+"&query=*", "", acme()))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %s)", w.Code, w.Body.String())
			}
			if len(*bodies) != 0 {
				t.Fatalf("a refused export reached OpenSearch: %v", *bodies)
			}
		})
	}
}

// Do not break legitimate log search. Every signal that IS log lines still
// resolves and still serves.
func TestLogSearchStillServesTheRealLogSignals(t *testing.T) {
	cases := []struct {
		signal string
		claims jwtClaims
		want   string
	}{
		{"syslog", acme(), "netops-syslog-acme-*"},
		{"flows", acme(), "netops-flows-acme-*"},
		{"cloud", acme(), "netops-cloudlogs-acme-*"},
		// "all" is an explicit union of the two LOG bases, never a wildcard, so
		// it cannot reach the findings family by accident either.
		{"", acme(), "netops-syslog-acme-*,netops-syslog-untagged-*,netops-snmptrap-acme-*,netops-snmptrap-untagged-*"},
		{"applogs", superA(), "netops-applogs-*"},
	}
	for _, tc := range cases {
		t.Run(tc.signal+"/"+tc.claims.Sub, func(t *testing.T) {
			paths, bodies := fakeOS(t, `{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`)
			s := logsTestServer(t)
			w := httptest.NewRecorder()
			s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search",
				`{"signal":"`+tc.signal+`","query":"*"}`, tc.claims))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body.String())
			}
			if len(*bodies) != 1 {
				t.Fatalf("want 1 OpenSearch request, got %d", len(*bodies))
			}
			if !strings.Contains((*paths)[0], tc.want) {
				t.Fatalf("index pattern %q does not carry %q", (*paths)[0], tc.want)
			}
		})
	}
}

// The other half of the gate choice: closing the ungated door must NOT close the
// gated one. Findings stay readable at /api/security/findings, which checks
// infrastructure:read and scopes to the caller's own tenant — and refuses a
// caller that lacks the permission, which is exactly what log search never did.
func TestSecurityFindingsStayReadableAtTheGatedDoor(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		secPatternFor("acme"):   "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") + "]",
		secPatternFor("globex"): "[" + secDoc("g1", "globex", "high", "Fail", "ISP", "globex-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	// A caller WITH infrastructure:read still gets its own findings.
	w := httptest.NewRecorder()
	s.secAPI.HandleFindings(w, req(http.MethodGet, "/api/security/findings", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("the gated door refused a permitted caller: %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"id":"a1"`) {
		t.Fatalf("acme's own finding is missing from the gated read: %s", w.Body.String())
	}

	// Cross-tenant: globex's own read never carries acme's row, and never names
	// acme's index family (§3a rule 1 + rule 4).
	before := len(fake.all())
	gw := httptest.NewRecorder()
	s.secAPI.HandleFindings(gw, req(http.MethodGet, "/api/security/findings", "", globex()))
	if gw.Code != http.StatusOK {
		t.Fatalf("globex read = %d (%s)", gw.Code, gw.Body.String())
	}
	if strings.Contains(gw.Body.String(), "a1") || strings.Contains(gw.Body.String(), "acme") {
		t.Fatalf("TENANT LEAK: globex's findings read carried acme data: %s", gw.Body.String())
	}
	if idx := fake.all()[before].Index; idx != secPatternFor("globex") {
		t.Fatalf("globex named index pattern %q, want %q", idx, secPatternFor("globex"))
	}

	// A caller WITHOUT infrastructure:read is refused before any query is issued
	// — the check log search skipped entirely.
	before = len(fake.all())
	nw := httptest.NewRecorder()
	noPerm := jwtClaims{Sub: "rum-key", Role: RoleIngest, Tenant: "acme"}
	s.secAPI.HandleFindings(nw, req(http.MethodGet, "/api/security/findings", "", noPerm))
	if nw.Code != http.StatusForbidden && nw.Code != http.StatusUnauthorized {
		t.Fatalf("a zero-permission key reached the findings door: %d (%s)", nw.Code, nw.Body.String())
	}
	if len(fake.all()) != before {
		t.Fatal("a refused caller must not have reached the findings index at all")
	}
}
