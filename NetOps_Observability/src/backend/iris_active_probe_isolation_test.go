// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_active_probe_isolation_test.go — CLAUDE.md §3a rule 5 and the safety
// table for Iris's active probes (tracker 337 N-I3): run_ping, run_traceroute,
// run_dns_test, run_http_test. org_isolation_test.go is the template;
// iris_probe_results_isolation_test.go is the sibling.
//
// The fixture: two tenants (acme, globex), each with an inventory device on an
// internal address and declared probes — including one whose name resolves
// into internal space nobody owns (the rebinding shape) and one aimed at the
// cloud metadata address. The measurement itself is FAKED: no test here sends
// a packet. What is proved:
//
//   - a target resolves only inside the caller's tenant (another tenant's
//     device or probe is not found, a forged acting tenant does not widen, the
//     platform scope sends nothing, a restricted tenant is unreachable);
//   - an unsafe target is refused before anything is sent;
//   - the per-target limit holds;
//   - with the workspace opt-in, the probe switch or investigations off, the
//     Policy Engine denies the tool and says why;
//   - a model-named probe is refused and the refusal is ledgered;
//   - a collector that cannot measure says so;
//   - no address ever reaches the rendered evidence.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/collectors"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/dem"
	"netops/backend/internal/probetarget"
)

// probeRecorder is the fake measurement: it records what it was asked to dial.
type probeRecorder struct {
	mu          sync.Mutex
	reqs        []collectors.OneShotRequest
	unavailable string
}

func (r *probeRecorder) run(_ context.Context, req collectors.OneShotRequest) collectors.OneShotResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	if r.unavailable != "" {
		return collectors.OneShotResult{Kind: req.Kind, Unavailable: r.unavailable}
	}
	return collectors.OneShotResult{Kind: req.Kind, Up: true, Sent: 3, Received: 3, RTTms: 2, StatusCode: 200, Answers: 1, Reached: true,
		Hops: []collectors.OneShotHop{{TTL: 1, Replied: true, RTTms: 1}, {TTL: 2, Replied: true, RTTms: 2}}}
}

func (r *probeRecorder) sent() []collectors.OneShotRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]collectors.OneShotRequest(nil), r.reqs...)
}

func fakeProbeLookup(_ context.Context, host string) ([]netip.Addr, error) {
	m := map[string]string{
		"portal.acme.example":   "93.184.216.34",
		"rebind.example":        "10.9.9.9",
		"portal.globex.example": "93.184.216.35",
		"intranet.acme.example": "10.1.0.53",
	}
	if a, ok := m[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return nil, errors.New("no such host")
}

type activeProbeFix struct {
	*restrictedAIFixture
	rec   *probeRecorder
	acmeU jwtClaims
	globU jwtClaims
}

func activeProbeFixture(t *testing.T) *activeProbeFix {
	t.Helper()
	f := newRestrictedAIFixture(t)
	f.s.demTargets = dem.NewFileStore(filepath.Join(t.TempDir(), "dem_targets.json"))
	ctx := context.Background()
	for _, tg := range []dem.Target{
		{TenantID: f.acme, Name: "acme-portal", Kind: dem.KindHTTP, Host: "https://portal.acme.example/health?token=s3cret"},
		{TenantID: f.acme, Name: "acme-rebind", Kind: dem.KindHTTP, Host: "https://rebind.example/"},
		{TenantID: f.acme, Name: "acme-meta", Kind: dem.KindICMP, Host: "169.254.169.254"},
		{TenantID: f.acme, Name: "acme-dns", Kind: dem.KindDNS, Host: "intranet.acme.example", Resolver: "169.254.169.253"},
		{TenantID: f.globex, Name: "globex-portal", Kind: dem.KindHTTP, Host: "https://portal.globex.example/"},
	} {
		tg.IntervalSec = 60
		if _, err := f.s.demTargets.Create(ctx, tg); err != nil {
			t.Fatalf("seed %s: %v", tg.Name, err)
		}
	}
	setAIModelsForTest(t, f.s, true, true)
	if _, err := f.s.features.Seed(aientitlement.SwitchProbes, true, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	f.s.aiTenantCfg = newAITenantConfigStore(filepath.Join(t.TempDir(), "ai_tenant_config.json"), nil)
	for _, tn := range []string{f.acme, f.globex} {
		if _, err := f.s.aiTenantCfg.SetEntitlement(tn, false, true, 0, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.aiTenantCfg.SetProbeTools(tn, true); err != nil {
			t.Fatal(err)
		}
	}
	rec := &probeRecorder{}
	f.s.aiProbe = aiProbeExec{run: rec.run, lookup: fakeProbeLookup,
		limiter: probetarget.NewLimiter(func() time.Time { return time.Unix(1_000, 0) }), slots: probetarget.NewSlots(2)}
	return &activeProbeFix{restrictedAIFixture: f, rec: rec,
		acmeU: jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme},
		globU: jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: f.globex}}
}

func probeVia(t *testing.T, s *server, claims jwtClaims, req ai.ActiveProbeRequest) (ai.ActiveProbeReport, error) {
	t.Helper()
	deps := s.aiTroubleshootDeps(aiTSRequest(claims), claims)
	if deps.ActiveProbe == nil {
		t.Fatal("the active-probe seam must be wired when there is an inventory")
	}
	// aiTSPrincipal is deliberately WRONG: the seam must scope by the token.
	return deps.ActiveProbe(context.Background(), aiTSPrincipal(), req)
}

func renderedText(rep ai.ActiveProbeReport) string {
	return fmt.Sprintf("%+v", ai.RenderActiveProbe(rep))
}

// noAddress fails if any address the fixture knows leaks into the evidence.
func noAddress(t *testing.T, text string) {
	t.Helper()
	for _, a := range []string{"10.1.0.1", "10.2.0.1", "93.184.216.34", "93.184.216.35", "10.9.9.9", "169.254.169.254", "s3cret"} {
		if strings.Contains(text, a) {
			t.Fatalf("an address or URL secret reached the evidence (%s): %s", a, text)
		}
	}
}

func TestIrisActiveProbeStaysInsideTheCallersTenant(t *testing.T) {
	f := activeProbeFixture(t)

	rep, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-core"})
	if err != nil || !rep.Scoped || len(rep.Results) != 1 || rep.Results[0].Refused != "" {
		t.Fatalf("acme pings its own device: %+v %v", rep, err)
	}
	sent := f.rec.sent()
	if len(sent) != 1 || sent[0].Addr.String() != "10.1.0.1" || sent[0].Kind != collectors.OneShotPing {
		t.Fatalf("the probe must dial acme's own device address, pinned: %+v", sent)
	}
	noAddress(t, renderedText(rep))

	// Another tenant's device and another tenant's declared probe read exactly
	// like a missing target, and nothing is sent.
	for _, other := range []string{"globex-core", "globex-portal", "no-such-thing"} {
		if _, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: other}); !errors.Is(err, ai.ErrNotFound) {
			t.Fatalf("acme probing %q: got %v, want ErrNotFound", other, err)
		}
		if _, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbeHTTP, Target: other}); !errors.Is(err, ai.ErrNotFound) {
			t.Fatalf("acme web-testing %q: got %v, want ErrNotFound", other, err)
		}
	}
	if n := len(f.rec.sent()); n != 1 {
		t.Fatalf("a refused cross-tenant target still sent traffic (%d probes)", n)
	}

	// The web test re-runs only acme's own web probes; globex's never appears.
	rep, err = probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbeHTTP})
	if err != nil || len(rep.Results) != 2 {
		t.Fatalf("acme's two web probes: %+v %v", rep, err)
	}
	text := renderedText(rep)
	if strings.Contains(text, "globex") {
		t.Fatalf("TENANT LEAK: globex's probe reached acme: %s", text)
	}
	noAddress(t, text)
	var portalReq *collectors.OneShotRequest
	for _, r := range f.rec.sent() {
		r := r
		if r.Kind == collectors.OneShotHTTP && r.Host == "portal.acme.example" {
			portalReq = &r
		}
	}
	if portalReq == nil || portalReq.Addr.String() != "93.184.216.34" || portalReq.Path != "/health" {
		t.Fatalf("the web test must dial the pinned address with the path and no query string: %+v", portalReq)
	}

	// globex, symmetrically.
	rep, err = probeVia(t, f.s, f.globU, ai.ActiveProbeRequest{Kind: ai.ProbeHTTP})
	if err != nil || len(rep.Results) != 1 || rep.Results[0].Target != "globex-portal" {
		t.Fatalf("globex's own web probe only: %+v %v", rep, err)
	}
}

// The safety table at the seam: metadata space and an unowned internal
// resolution are refused BEFORE anything is sent; a pinned resolver in
// link-local space is refused too.
func TestIrisActiveProbeRefusesUnsafeTargets(t *testing.T) {
	f := activeProbeFixture(t)
	before := len(f.rec.sent())

	rep, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-meta"})
	if err != nil || len(rep.Results) != 1 || !strings.Contains(rep.Results[0].Refused, "never probed") {
		t.Fatalf("the metadata address must be refused: %+v %v", rep, err)
	}
	rep, err = probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbeHTTP, Target: "acme-rebind"})
	if err != nil || len(rep.Results) != 1 || !strings.Contains(rep.Results[0].Refused, "internal address that is not a device") {
		t.Fatalf("a declared name resolving into unowned internal space must be refused: %+v %v", rep, err)
	}
	rep, err = probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbeDNS, Target: "acme-dns"})
	if err != nil || len(rep.Results) != 1 || rep.Results[0].Refused == "" {
		t.Fatalf("a link-local pinned resolver must be refused: %+v %v", rep, err)
	}
	if n := len(f.rec.sent()); n != before {
		t.Fatalf("an unsafe target still sent traffic (%d probes)", n-before)
	}
	noAddress(t, renderedText(rep))
}

func TestIrisActiveProbePerTargetLimit(t *testing.T) {
	f := activeProbeFixture(t)
	for i := 0; i < aiProbePerTargetPerMin; i++ {
		rep, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-core"})
		if err != nil || rep.Results[0].Refused != "" {
			t.Fatalf("probe %d refused under the limit: %+v %v", i+1, rep, err)
		}
	}
	rep, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-core"})
	if err != nil || !strings.Contains(rep.Results[0].Refused, "already tested") {
		t.Fatalf("the per-target limit did not hold: %+v %v", rep, err)
	}
	if n := len(f.rec.sent()); n != aiProbePerTargetPerMin {
		t.Fatalf("%d probes sent, the limit is %d", n, aiProbePerTargetPerMin)
	}
	// A different target is a different budget.
	if rep, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbeTraceroute, Target: "acme-core"}); err != nil || rep.Results[0].Refused != "" {
		t.Fatalf("a different measurement of the same device shares the budget: %+v %v", rep, err)
	}
}

// A forged acting tenant on a NON-owner token never widens; the platform
// scope sends nothing; the owner narrowed into a workspace probes only it.
func TestIrisActiveProbeScopes(t *testing.T) {
	f := activeProbeFixture(t)
	forged := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme, ActingTenant: f.globex}
	if _, err := probeVia(t, f.s, forged, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "globex-core"}); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("a forged acting tenant reached globex's device: %v", err)
	}

	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	rep, err := probeVia(t, f.s, owner, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-core"})
	if err != nil || rep.Scoped || len(rep.Results) != 0 {
		t.Fatalf("the All-tenants view must send nothing: %+v %v", rep, err)
	}
	if g := f.s.aiNetProbeGate(owner); g.Allow || !strings.Contains(g.Reason, "one workspace") {
		t.Fatalf("the platform scope must not open the probe gate: %+v", g)
	}
	if n := len(f.rec.sent()); n != 0 {
		t.Fatalf("the platform scope sent %d probes", n)
	}

	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	restricted := ownerActing(owner, f.acme)
	if deps := f.s.aiTroubleshootDeps(aiTSRequest(restricted), restricted); deps.ActiveProbe != nil {
		rep, err := deps.ActiveProbe(context.Background(), aiTSPrincipal(), ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-core"})
		if err == nil && (rep.Scoped || len(rep.Results) > 0) {
			t.Fatalf("RESTRICTION LEAK: the owner probed acme: %+v", rep)
		}
	}
	if n := len(f.rec.sent()); n != 0 {
		t.Fatalf("a restricted tenant was probed (%d probes)", n)
	}
}

// With any switch off the Policy Engine denies every probe tool and says why;
// the orchestrator's own toolbox is the gate under test.
func TestIrisActiveProbeGateNamesWhatIsOff(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*activeProbeFix)
		reason string
	}{
		{"workspace opt-in off", func(f *activeProbeFix) {
			if _, err := f.s.aiTenantCfg.SetProbeTools(f.acme, false); err != nil {
				t.Fatal(err)
			}
		}, "has not turned active probes on"},
		{"probe switch off", func(f *activeProbeFix) {
			if _, _, err := f.s.features.Set(aientitlement.SwitchProbes, false, "", "owner", time.Now()); err != nil {
				t.Fatal(err)
			}
		}, "turned off on this installation"},
		{"investigations off for the workspace", func(f *activeProbeFix) {
			if _, err := f.s.aiTenantCfg.SetEntitlement(f.acme, false, false, 0, 0); err != nil {
				t.Fatal(err)
			}
		}, "investigations are not turned on for this workspace"},
		{"investigations off on the installation", func(f *activeProbeFix) {
			setAIModelsForTest(t, f.s, true, false)
		}, "investigations are off on this installation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := activeProbeFixture(t)
			tc.mutate(f)
			g := f.s.aiNetProbeGate(f.acmeU)
			if g.Allow || !strings.Contains(g.Reason, tc.reason) {
				t.Fatalf("gate: %+v, want a denial naming %q", g, tc.reason)
			}
			o := f.s.newOrchestrator(httptest.NewRequest("POST", "/api/ai/ask", nil), f.acmeU)
			for _, n := range []string{"run_ping", "run_traceroute", "run_dns_test", "run_http_test"} {
				iv := o.Toolbox().Invoke(context.Background(), f.s.aiPrincipal(f.acmeU), n, ai.ToolArgs{"target": "acme-core"})
				if iv.Outcome != ai.OutcomePolicyDenied || !strings.Contains(iv.Decision.Reason, tc.reason) {
					t.Fatalf("%s: outcome %s, reason %q", n, iv.Outcome, iv.Decision.Reason)
				}
			}
			if n := len(f.rec.sent()); n != 0 {
				t.Fatalf("a denied probe still sent %d packets", n)
			}
		})
	}

	// Every switch on: the gate opens for the workspace.
	f := activeProbeFixture(t)
	if g := f.s.aiNetProbeGate(f.acmeU); !g.Allow {
		t.Fatalf("all switches on, the gate stayed shut: %+v", g)
	}
}

// A model naming a probe in the agent loop is refused even with every switch
// on, and the refusal lands in the decision ledger.
func TestIrisActiveProbeModelNamedCallIsRefusedAndLedgered(t *testing.T) {
	f := activeProbeFixture(t)
	f.s.aiToolGateway = ai.NewToolGateway()
	o := f.s.newOrchestrator(httptest.NewRequest("POST", "/api/ai/ask", nil), f.acmeU)
	reg, pol := agentToolbox(o)
	rec, err := aidecision.NewRecorder("a@acme", aidecision.SurfaceCopilot)
	if err != nil {
		t.Fatal(err)
	}
	ctx := aidecision.WithRecorder(context.Background(), rec)
	rep, _ := f.s.executeAgentTool(ctx, f.acmeU, f.s.aiPrincipal(f.acmeU), reg, pol,
		ai.ToolCall{ID: "c", Name: "run_ping", Args: json.RawMessage(`{"target":"acme-core"}`)})
	if !rep.IsError || !strings.Contains(rep.Content, "a model cannot call it directly") {
		t.Fatalf("the model-named probe was not refused: %+v", rep)
	}
	found := false
	for _, e := range rec.Entries() {
		if e.Tool == "run_ping" && e.EventType == aidecision.PolicyEvaluated && e.Outcome == "deny" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the refused probe is not in the ledger: %+v", rec.Entries())
	}
	if n := len(f.rec.sent()); n != 0 {
		t.Fatalf("the model-named probe sent %d packets", n)
	}
	for _, spec := range (ai.Toolbox{Registry: reg, Policy: pol}).Manifest(f.s.aiPrincipal(f.acmeU)) {
		switch spec.Name {
		case "run_ping", "run_traceroute", "run_dns_test", "run_http_test":
			t.Fatalf("the agent manifest lists %s", spec.Name)
		}
	}
}

// A collector that cannot take the measurement says so; nothing is invented.
func TestIrisActiveProbeCollectorUnavailableIsHonest(t *testing.T) {
	f := activeProbeFixture(t)
	f.rec.unavailable = "this collector cannot send ICMP"
	rep, err := probeVia(t, f.s, f.acmeU, ai.ActiveProbeRequest{Kind: ai.ProbePing, Target: "acme-core"})
	if err != nil || len(rep.Results) != 1 || rep.Results[0].Unavailable == "" || rep.Results[0].Up {
		t.Fatalf("an unavailable collector: %+v %v", rep, err)
	}
	if text := renderedText(rep); !strings.Contains(text, "not measured") {
		t.Fatalf("the evidence must say nothing was measured: %s", text)
	}

	// A workspace that declares no web probe is told so, and nothing is sent.
	if _, err := f.s.aiTenantCfg.SetProbeTools(f.globex, true); err != nil {
		t.Fatal(err)
	}
	rep, err = probeVia(t, f.s, f.globU, ai.ActiveProbeRequest{Kind: ai.ProbeDNS})
	if err != nil || !strings.Contains(rep.Unavailable, "declares no DNS probe") {
		t.Fatalf("no declared DNS probe: %+v %v", rep, err)
	}
}
