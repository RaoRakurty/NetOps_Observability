package backend

// ai_troubleshoot_deps_test.go — CLAUDE.md §3a rule 5 for the IRIS Phase-A
// assistant seams (org_isolation_test.go is the template; this is its
// non-HTTP sibling, because these reads are reached from the orchestrator with
// already-resolved claims rather than from a route).
//
// The contract every seam below must hold:
//
//   - tenant A resolves ONLY tenant A's devices; a name that exists only in
//     tenant B is ai.ErrNotFound — the same answer a name that exists nowhere
//     gets, so existence is never revealed;
//   - a cross-tenant device id passed straight to ProtocolDiagnostic or
//     TopologyContext is ai.ErrNotFound, not a 403 and not an empty success;
//   - a correlation case belonging to another tenant (or to the untagged
//     platform namespace) is ai.ErrNotFound on CaseTimeline, and the read
//     carries the caller's OWN tenant_scope on the wire;
//   - `as_tenant` never widens: a non-owner's selector is ignored, and the
//     platform owner's selector NARROWS them into that tenant only;
//   - the platform owner (cross-tenant) reaches every tenant.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// ---- fixtures ---------------------------------------------------------------

// aiTSRequest is the request the deps are built for. Only ProtocolDiagnostic
// uses it (for the audit line); every scoping decision comes from the claims.
func aiTSRequest(claims jwtClaims) *http.Request {
	return req(http.MethodPost, "/api/ai/ask", "", claims)
}

func aiTSDeps(t *testing.T, s *server, claims jwtClaims) ai.TroubleshootDeps {
	t.Helper()
	return s.aiTroubleshootDeps(aiTSRequest(claims), claims)
}

// aiTSPrincipal is the ai.Principal the orchestrator would build. The seams
// deliberately do NOT trust it for scoping (they re-derive from the claims), so
// the tests pass a DELIBERATELY WRONG one: if any seam scoped by the argument
// instead of the token, these tests would leak.
func aiTSPrincipal() ai.Principal {
	return ai.Principal{Tenant: "wrong-tenant", Cross: true}
}

// aiTSServer is the two-tenant server the seams read: acme owns acme-core and
// acme-edge, globex owns globex-core, and shared-dns is untagged/platform.
func aiTSServer(t *testing.T) *server {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme", Vendor: "cisco", OS: "ios-xe"},
		{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.2", TenantID: "acme"},
		{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex", Vendor: "juniper"},
		{ID: "shared-dns", Name: "shared-dns", Address: "10.9.0.1"},
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed %s: %v", dev.ID, err)
		}
	}
	return &server{roles: roles, discovery: d}
}

// ---- ResolveDevice ----------------------------------------------------------

func TestAITroubleshootResolveDeviceIsTenantScoped(t *testing.T) {
	s := aiTSServer(t)
	cases := []struct {
		name   string
		claims jwtClaims
		ref    string
		wantID string // "" = must be ErrNotFound
	}{
		{"acme resolves its own device by name", acme(), "acme-core", "acme-core"},
		{"acme resolves its own device by id", acme(), "acme-edge", "acme-edge"},
		{"lookup is case-insensitive", acme(), "ACME-CORE", "acme-core"},
		{"acme cannot resolve globex's device", acme(), "globex-core", ""},
		{"globex cannot resolve acme's device", globex(), "acme-core", ""},
		{"globex resolves its own", globex(), "globex-core", "globex-core"},
		{"an unknown name reads exactly like a foreign one", acme(), "does-not-exist", ""},
		{"an empty reference resolves nothing", acme(), "", ""},
		{"the platform owner reaches acme", superA(), "acme-core", "acme-core"},
		{"the platform owner reaches globex", superA(), "globex-core", "globex-core"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := aiTSDeps(t, s, tc.claims)
			ref, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), tc.ref)
			if tc.wantID == "" {
				if !errors.Is(err, ai.ErrNotFound) {
					t.Fatalf("err = %v (ref %+v), want ai.ErrNotFound", err, ref)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveDevice(%q): %v", tc.ref, err)
			}
			if ref.ID != tc.wantID {
				t.Fatalf("resolved %q, want %q", ref.ID, tc.wantID)
			}
		})
	}
}

// A non-owner's as_tenant selector must be ignored (it is never a widening
// path); the platform owner's must NARROW them out of the other tenant.
func TestAITroubleshootResolveDeviceIgnoresAsTenantWidening(t *testing.T) {
	s := aiTSServer(t)

	sneaky := acme()
	sneaky.ActingTenant = "globex"
	deps := aiTSDeps(t, s, sneaky)
	if _, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), "globex-core"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("TENANT LEAK: as_tenant widened a non-owner into globex (err = %v)", err)
	}
	if _, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), "acme-core"); err != nil {
		t.Fatalf("the selector must not break the caller's OWN scope: %v", err)
	}

	narrowed := superA()
	narrowed.ActingTenant = "acme"
	deps = aiTSDeps(t, s, narrowed)
	if _, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), "acme-core"); err != nil {
		t.Fatalf("a narrowed owner must still see the selected tenant: %v", err)
	}
	if _, err := deps.ResolveDevice(context.Background(), aiTSPrincipal(), "globex-core"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("a narrowed owner must NOT see the other tenant (err = %v)", err)
	}
}

// ---- ProtocolDiagnostic -----------------------------------------------------

func TestAITroubleshootProtocolDiagnosticIsTenantScoped(t *testing.T) {
	s := aiTSServer(t)
	deps := aiTSDeps(t, s, acme())

	_, err := deps.ProtocolDiagnostic(context.Background(), aiTSPrincipal(), ai.DiagnosticRequest{
		DeviceID: "globex-core", Protocol: "bgp",
	})
	if !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("cross-tenant diagnostic err = %v, want ai.ErrNotFound", err)
	}

	rep, err := deps.ProtocolDiagnostic(context.Background(), aiTSPrincipal(), ai.DiagnosticRequest{
		DeviceID: "acme-core", Protocol: "bgp", IssueID: "bgp-session-down",
	})
	if err != nil {
		t.Fatalf("own-tenant diagnostic: %v", err)
	}
	if rep.DeviceID != "acme-core" || rep.IssueID != "bgp-session-down" {
		t.Fatalf("unexpected report subject: %+v", rep)
	}
	// No collector is wired on this deployment: the report must be HONEST —
	// commands to run, no capture, no cause.
	if rep.Collected {
		t.Fatal("no CommandRunner is wired, yet the report claims a capture happened")
	}
	if rep.NotWired == "" {
		t.Fatal("an uncollected report must say WHY it did not collect")
	}
	if len(rep.Commands) == 0 {
		t.Fatal("an uncollected report must hand back the read-only command bundle")
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("no output was captured, so there can be no findings: %+v", rep.Findings)
	}
}

func TestAITroubleshootProtocolDiagnosticIssueSelection(t *testing.T) {
	s := aiTSServer(t)
	deps := aiTSDeps(t, s, acme())
	cases := []struct {
		name     string
		protocol string
		issue    string
		wantErr  bool
		wantProt string
	}{
		{name: "default scenario for bgp", protocol: "bgp", wantProt: "bgp"},
		{name: "default scenario for ospf", protocol: "ospf", wantProt: "ospf"},
		{name: "default scenario for isis", protocol: "isis", wantProt: "isis"},
		{name: "named scenario", protocol: "ospf", issue: "ospf-neighbor-stuck", wantProt: "ospf"},
		{name: "unknown scenario is refused", protocol: "bgp", issue: "no-such-issue", wantErr: true},
		{name: "scenario from another protocol is refused", protocol: "bgp", issue: "ospf-neighbor-stuck", wantErr: true},
		{name: "unknown protocol is refused", protocol: "rip", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := deps.ProtocolDiagnostic(context.Background(), aiTSPrincipal(), ai.DiagnosticRequest{
				DeviceID: "acme-core", Protocol: tc.protocol, IssueID: tc.issue,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected a refusal, got %+v", rep)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProtocolDiagnostic: %v", err)
			}
			if rep.Protocol != tc.wantProt {
				t.Fatalf("protocol = %q, want %q", rep.Protocol, tc.wantProt)
			}
			if tc.issue != "" && rep.IssueID != tc.issue {
				t.Fatalf("issue = %q, want %q", rep.IssueID, tc.issue)
			}
		})
	}
}

// ---- TopologyContext --------------------------------------------------------

func TestAITroubleshootTopologyContextIsTenantScoped(t *testing.T) {
	s := aiTSServer(t)

	deps := aiTSDeps(t, s, acme())
	if _, err := deps.TopologyContext(context.Background(), aiTSPrincipal(), "globex-core"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("cross-tenant topology err = %v, want ai.ErrNotFound", err)
	}
	if _, err := deps.TopologyContext(context.Background(), aiTSPrincipal(), "no-such-device"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("unknown device err = %v, want ai.ErrNotFound", err)
	}
	tc, err := deps.TopologyContext(context.Background(), aiTSPrincipal(), "acme-core")
	if err != nil {
		t.Fatalf("own-tenant topology: %v", err)
	}
	if tc.DeviceID != "acme-core" {
		t.Fatalf("subject = %q, want acme-core", tc.DeviceID)
	}
	// Neither the seam register nor the path graph is wired here — the answer
	// must SAY the context is unknown, never imply the device sits on nothing.
	notes := strings.ToLower(strings.Join(tc.Notes, " | "))
	if !strings.Contains(notes, "seam register is not enabled") {
		t.Errorf("an absent seam register must be disclosed: %q", notes)
	}
	if !strings.Contains(notes, "path measurement is not enabled") {
		t.Errorf("absent path measurement must be disclosed: %q", notes)
	}
	for _, n := range tc.Neighbors {
		if strings.Contains(strings.ToLower(n.PeerName), "globex") {
			t.Fatalf("TENANT LEAK: a globex device resolved as an acme neighbour: %+v", n)
		}
	}

	// The platform owner reaches both.
	owner := aiTSDeps(t, s, superA())
	for _, id := range []string{"acme-core", "globex-core"} {
		if _, err := owner.TopologyContext(context.Background(), aiTSPrincipal(), id); err != nil {
			t.Fatalf("cross-tenant principal must reach %s: %v", id, err)
		}
	}
}

func TestAISeamTouchesDevice(t *testing.T) {
	dev := models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1"}
	cases := []struct {
		name      string
		endpoints map[string]string
		want      bool
	}{
		{"matches on address", map[string]string{"on_prem": "10.1.0.1"}, true},
		{"matches on name", map[string]string{"on_prem": "ACME-CORE"}, true},
		{"matches on id", map[string]string{"device": "acme-core"}, true},
		{"no match", map[string]string{"on_prem": "10.2.0.1", "provider_edge": "203.0.113.1"}, false},
		{"blank endpoints never match", map[string]string{"on_prem": "  "}, false},
		{"nil endpoints never match", nil, false},
	}
	for _, tc := range cases {
		if got := aiSeamTouchesDevice(tc.endpoints, dev); got != tc.want {
			t.Errorf("%s: aiSeamTouchesDevice = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---- CaseTimeline -----------------------------------------------------------

// aiTSFakeCH behaves like the ClickHouse row policies: it answers ONLY the rows
// tagged with the tenant_scope on the request, so "the seam sent the wrong
// scope" surfaces as a visible cross-tenant leak rather than a silent one.
type aiTSFakeCH struct {
	mu     sync.Mutex
	scopes []string
	// caseTenant maps a correlation id to its owning tenant ("" = untagged).
	caseTenant map[string]string
}

func (f *aiTSFakeCH) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("tenant_scope")
		body, _ := io.ReadAll(r.Body)
		sql := string(body)
		f.mu.Lock()
		f.scopes = append(f.scopes, scope)
		f.mu.Unlock()

		id := ""
		for cid := range f.caseTenant {
			if strings.Contains(sql, cid) {
				id = cid
				break
			}
		}
		rows := []map[string]any{}
		switch {
		case id == "":
			// unknown id — no rows, whatever the query
		case strings.Contains(sql, "FROM netops.corr_objects"):
			tenant := f.caseTenant[id]
			if scope == "__all__" || scope == tenant {
				rows = append(rows, map[string]any{
					"version": 1, "tenant_id": tenant, "state": "open", "merged_into": "",
					"window_start": "2026-09-01T10:00:00.000Z", "window_end": "2026-09-01T11:00:00.000Z",
					"trigger_signal": "sig-1", "verdict_tier": "suspected", "top_hypothesis": "bgp_session_loss",
					"top_confidence": 0.7, "evidence_missing": "[]",
				})
			}
		case strings.Contains(sql, "max(archived_version)"):
			rows = append(rows, map[string]any{"av": float64(1)})
		case strings.Contains(sql, "FROM netops.corr_signals_archive"):
			rows = append(rows,
				map[string]any{"signal_id": "s-2", "ts_iso": "2026-09-01T10:30:00.000Z", "kind": "metric",
					"entity_id": "dev-" + f.caseTenant[id], "metric_name": "if_errors", "severity": "warning",
					"value": "42", "baseline": "1"},
				map[string]any{"signal_id": "s-1", "ts_iso": "2026-09-01T10:05:00.000Z", "kind": "log",
					"entity_id": "dev-" + f.caseTenant[id], "severity": "err", "phase": "onset"},
			)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": rows})
	}
}

func (f *aiTSFakeCH) lastScope(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) == 0 {
		t.Fatal("the seam issued no ClickHouse read — the isolation contract is untested")
	}
	return f.scopes[len(f.scopes)-1]
}

const (
	aiTSAcmeCase   = "11111111-1111-4111-8111-111111111111"
	aiTSGlobexCase = "22222222-2222-4222-8222-222222222222"
	aiTSPlatCase   = "33333333-3333-4333-8333-333333333333"
)

func aiTSStartFakeCH(t *testing.T) *aiTSFakeCH {
	t.Helper()
	fake := &aiTSFakeCH{caseTenant: map[string]string{
		aiTSAcmeCase: "acme", aiTSGlobexCase: "globex", aiTSPlatCase: "",
	}}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	return fake
}

func TestAITroubleshootCaseTimelineIsTenantScoped(t *testing.T) {
	fake := aiTSStartFakeCH(t)
	s := aiTSServer(t)

	cases := []struct {
		name      string
		claims    jwtClaims
		id        string
		wantScope string
		wantFound bool
	}{
		{"acme reads its own case", acme(), aiTSAcmeCase, "acme", true},
		{"acme cannot read globex's case", acme(), aiTSGlobexCase, "acme", false},
		{"acme cannot read untagged platform intel", acme(), aiTSPlatCase, "acme", false},
		{"globex reads its own case", globex(), aiTSGlobexCase, "globex", true},
		{"globex cannot read acme's case", globex(), aiTSAcmeCase, "globex", false},
		{"the platform owner reads any case", superA(), aiTSGlobexCase, "__all__", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := aiTSDeps(t, s, tc.claims)
			events, err := deps.CaseTimeline(context.Background(), aiTSPrincipal(), tc.id)
			if got := fake.lastScope(t); got != tc.wantScope {
				t.Fatalf("the read carried tenant_scope %q, want %q", got, tc.wantScope)
			}
			if !tc.wantFound {
				if !errors.Is(err, ai.ErrNotFound) {
					t.Fatalf("err = %v (%d events), want ai.ErrNotFound", err, len(events))
				}
				if len(events) != 0 {
					t.Fatalf("TENANT LEAK: %d events returned for a case the caller may not see", len(events))
				}
				return
			}
			if err != nil {
				t.Fatalf("CaseTimeline: %v", err)
			}
			if len(events) != 2 {
				t.Fatalf("want 2 timeline events, got %d (%+v)", len(events), events)
			}
			// Oldest first: the ORDER is the whole value of a timeline.
			if events[0].At > events[1].At {
				t.Fatalf("timeline is not oldest-first: %+v", events)
			}
			if events[0].Text == "" {
				t.Errorf("an event with no text teaches nothing: %+v", events[0])
			}
		})
	}
}

func TestAITroubleshootCaseTimelineRejectsMalformedIDs(t *testing.T) {
	aiTSStartFakeCH(t)
	deps := aiTSDeps(t, aiTSServer(t), acme())
	for _, id := range []string{"", "not-a-uuid", "'; DROP TABLE netops.corr_objects; --", strings.Repeat("a", 200)} {
		if _, err := deps.CaseTimeline(context.Background(), aiTSPrincipal(), id); !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("CaseTimeline(%q) err = %v, want ai.ErrNotFound (no id ever reaches SQL unvalidated)", id, err)
		}
	}
}

// ---- SecurityFindings -------------------------------------------------------

// With no secapi on the deployment the seam is NIL, so the tool is not
// registered and the assistant cannot answer from a capability that is absent.
func TestAITroubleshootSecurityFindingsUnwiredIsNil(t *testing.T) {
	deps := aiTSDeps(t, aiTSServer(t), acme())
	if deps.SecurityFindings != nil {
		t.Fatal("no secapi is wired, so the findings seam must stay nil (the tool is then not registered)")
	}
	reg := ai.Tools(aiDataSource{srv: aiTSServer(t), ctx: context.Background(), claims: acme()})
	reg.AddTroubleshootTools(nil, deps)
	if _, ok := reg.Get("get_security_findings"); ok {
		t.Fatal("get_security_findings must not be registered without a findings read path")
	}
}

func TestAITroubleshootSecurityFindingsIsTenantScoped(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		secPatternFor("acme"):   "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") + "]",
		secPatternFor("globex"): "[" + secDoc("g1", "globex", "high", "Fail", "ISP", "globex-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)

	deps := aiTSDeps(t, s, acme())
	if deps.SecurityFindings == nil {
		t.Fatal("secapi is wired, so the findings seam must be filled")
	}
	rows, err := deps.SecurityFindings(context.Background(), aiTSPrincipal(), ai.FindingsQuery{Current: true, Limit: 10})
	if err != nil {
		t.Fatalf("SecurityFindings: %v", err)
	}
	calls := fake.all()
	if len(calls) != 1 {
		t.Fatalf("want exactly 1 OpenSearch query, got %d", len(calls))
	}
	if calls[0].Index != secPatternFor("acme") {
		t.Fatalf("index pattern = %q, want %q", calls[0].Index, secPatternFor("acme"))
	}
	if strings.Contains(calls[0].Index, "globex") {
		t.Fatal("TENANT LEAK: the assistant's query NAMED another tenant's index family")
	}
	if !strings.Contains(calls[0].Body, `{"term":{"tenant_id":"acme"}}`) {
		t.Fatalf("the per-doc tenant clause is missing: %s", calls[0].Body)
	}
	if len(rows) != 1 || rows[0].ID != "a1" {
		t.Fatalf("acme must see exactly its own finding, got %+v", rows)
	}
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Entity+r.ID+r.Title), "globex") {
			t.Fatalf("TENANT LEAK: globex data reached acme's assistant: %+v", r)
		}
	}

	// globex sees its own and nothing else.
	gdeps := aiTSDeps(t, s, globex())
	grows, err := gdeps.SecurityFindings(context.Background(), aiTSPrincipal(), ai.FindingsQuery{Current: true})
	if err != nil {
		t.Fatalf("SecurityFindings(globex): %v", err)
	}
	if len(grows) != 1 || grows[0].ID != "g1" {
		t.Fatalf("globex must see exactly its own finding, got %+v", grows)
	}

	// A read-only-less role is refused outright, before any query is issued.
	before := len(fake.all())
	noAccess := jwtClaims{Sub: "nobody@acme", Role: "no-such-role", Tenant: "acme"}
	ndeps := aiTSDeps(t, s, noAccess)
	if _, err := ndeps.SecurityFindings(context.Background(), aiTSPrincipal(), ai.FindingsQuery{}); !errors.Is(err, ai.ErrForbidden) {
		t.Fatalf("a caller without infrastructure:read must be refused, got %v", err)
	}
	if len(fake.all()) != before {
		t.Fatal("a refused caller must not have reached the findings index at all")
	}
}

func TestAITroubleshootSecurityFindingsBoundsTheLimit(t *testing.T) {
	fake := &secFakeOS{docs: map[string]string{
		secPatternFor("acme"): "[" + secDoc("a1", "acme", "critical", "Fail", "ISP", "acme-core") + "]",
	}}
	secStartFakeOS(t, fake)
	s := secTestServer(t)
	deps := aiTSDeps(t, s, acme())
	if _, err := deps.SecurityFindings(context.Background(), aiTSPrincipal(), ai.FindingsQuery{Limit: 100000}); err != nil {
		t.Fatalf("SecurityFindings: %v", err)
	}
	body := fake.all()[0].Body
	if !strings.Contains(body, `"size":`+strconv.Itoa(aiFindingsMaxLimit)) {
		t.Fatalf("an oversized limit must be clamped to %d: %s", aiFindingsMaxLimit, body)
	}
}
