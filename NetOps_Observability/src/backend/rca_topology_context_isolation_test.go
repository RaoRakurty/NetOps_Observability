// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_topology_context_isolation_test.go — CLAUDE.md §3a rule 5 for the RCA
// topology context (RCA document v2 §2/§7), on the org_isolation_test.go
// template: through the REAL router + auth middleware, two orgs each with one
// tenant, one operator user, devices, LLDP neighbours (through the real
// collector client) and a persisted graph. It asserts:
//
//   - own-only neighbours: a tenant's report draws its own adjacency, never the
//     other tenant's devices or links;
//   - a cross-tenant principal (the platform owner) reading tenant A's report
//     never receives tenant B's neighbours, though B is visible to it elsewhere;
//   - cross-tenant get → 404 (both the report and the path view);
//   - ?as_tenant into another org is ignored;
//   - an operator-restricted tenant's devices vanish from the owner's view of
//     the other tenant's report (the link that names them is dropped), its own
//     report is 404 to the owner, and the restriction never touches the
//     tenant's own users.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/rca"
	"netops/backend/models"
	"netops/backend/topology"
)

const (
	topoCorrA = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
	topoCorrB = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
)

// The persisted edges carry the reconciler's own id derivation, so the same
// link read live and from the graph is ONE edge (as in production).
var (
	topoEdgeAA = topoEdgeID(topoLink{Source: "a-core", LocalPort: "Gi2", Target: "a-edge", RemotePort: "Gi1"})
	topoEdgeBB = topoEdgeID(topoLink{Source: "b-core", LocalPort: "Gi2", Target: "b-edge", RemotePort: "Gi1"})
)

type topoCtxObj struct {
	owner string
	dev   string
}

// topoCtxFakeCH answers the slice reads for each object only when the
// request's tenant_scope reaches its owner and the SQL does not exclude it
// (the operator-visibility NOT IN clause) — the row policy + exclusion the
// real ClickHouse enforces.
func topoCtxFakeCH(t *testing.T, objs map[string]topoCtxObj) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		scope := r.URL.Query().Get("tenant_scope")
		w.Header().Set("Content-Type", "application/json")
		rows := func(rs []map[string]any) {
			out, _ := json.Marshal(rs)
			_, _ = w.Write([]byte(`{"meta":[],"data":` + string(out) + `,"rows":` + intToString(len(rs)) + `}`))
		}
		visible := func(owner string) bool {
			if scope != owner && scope != "__all__" {
				return false
			}
			if i := strings.Index(sql, "NOT IN ("); i >= 0 && strings.Contains(sql[i:], "'"+owner+"'") {
				return false
			}
			return true
		}
		for id, o := range objs {
			if !strings.Contains(sql, id) || !visible(o.owner) {
				continue
			}
			trig := "11111111-1111-4111-8111-" + id[24:]
			alarm := "22222222-2222-4222-8222-" + id[24:]
			switch {
			case strings.Contains(sql, "FROM netops.corr_objects"):
				rows([]map[string]any{{
					"version": "2", "tenant_id": o.owner, "state": "open", "merged_into": "",
					"window_start": "2026-11-12T04:50:00Z", "window_end": "2026-11-12T04:55:00Z",
					"trigger_signal": trig, "verdict_tier": "suspected", "top_hypothesis": "sig.ent.access.local-link-fault",
					"top_confidence": "0.5", "evidence_missing": "[]", "hypotheses": "{}",
					"affected":       `{"devices":["` + o.dev + `"],"interfaces":["` + o.dev + `:Gi1"]}`,
					"layer_coverage": "{}", "app_impact": "{}", "attribution": "{}",
				}})
			case strings.Contains(sql, "max(archived_version)"):
				rows([]map[string]any{{"av": "1"}})
			case strings.Contains(sql, "FROM netops.corr_signals_archive"):
				rows([]map[string]any{
					topoCtxSig(trig, "interface", o.dev+":Gi1", "if_metric_anomaly", "crit", o.dev),
					topoCtxSig(alarm, "device", o.dev, "device_alarm", "warn", o.dev),
				})
			case strings.Contains(sql, "FROM netops.corr_edges"):
				rows([]map[string]any{{
					"from_node": "interface:" + o.dev + ":Gi1:if_metric_anomaly", "to_node": "device:" + o.dev + ":device_alarm",
					"grounding_kind": "topo", "grounding_ref": "shared:" + o.dev, "weight": 0.9, "w_temporal": 1.0,
					"w_topo": 0.9, "w_reinforce": 1.0, "direction_conf": 0.8, "direction_basis": "onset_order+layer_prior",
				}})
			default:
				rows(nil)
			}
			return
		}
		rows(nil)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

func topoCtxSig(id, etype, eid, kind, sev, observer string) map[string]any {
	return map[string]any{
		"signal_id": id, "ts": "2026-11-12 04:51:00", "ingest_ts": "2026-11-12 04:51:00", "source": "metric", "kind": kind,
		"observer_type": "device", "observer_id": observer, "collection_path": "snmp_poll",
		"modality_class": "device_telemetry", "clock_quality": "",
		"entity_type": etype, "entity_id": eid, "entity_tokens": "[]",
		"severity": sev, "value": float64(0), "baseline": float64(0), "deviation": float64(0),
		"metric_name": "", "attrs": "{}", "onset_uncertainty_s": float64(0),
		"phase": "", "clear_ts": "", "probe_scope": "", "probe_authority": "", "classification_source": "",
	}
}

type topoCtxFixture struct {
	srv        *httptest.Server
	s          *server
	owner      string
	a, b       topoCtxPrincipal
	aOrg, bOrg string
	aTen, bTen string
}

type topoCtxPrincipal struct{ token, tenant string }

// newTopoCtxFixture builds two orgs/tenants/operators through the real API and
// seeds: tenant A — a-core (anchor) ─ a-edge, and a-core ─ b-core (a physical
// link A's own device reports to a device of tenant B); tenant B — b-core
// (anchor) ─ b-edge. The persisted graph holds each tenant's own link.
func newTopoCtxFixture(t *testing.T) *topoCtxFixture {
	t.Helper()
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:1")
	srv, s := newTestServerState(t)
	s.rcaPromotions = newRcaPromotionStore("")
	fixed := time.Date(2026, 11, 12, 5, 0, 0, 0, time.UTC)
	s.rcaClock = func() time.Time { return fixed }
	f := &topoCtxFixture{srv: srv, s: s, owner: login(t, srv, "admin", "Passw0rd!2345").Token}
	mk := func(name string) (org, tenant string, p topoCtxPrincipal) {
		st, body := do(t, srv, "POST", "/api/orgs", f.owner, map[string]any{"name": "Topo Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, body)
		}
		org = idOf(t, body)
		st, body = do(t, srv, "POST", "/api/tenants", f.owner, map[string]any{"name": "Topo Tenant " + name, "org_id": org})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, body)
		}
		tenant = idOf(t, body)
		user := "topo-user-" + name
		st, body = do(t, srv, "POST", "/api/users", f.owner, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenant,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, body)
		}
		return org, tenant, topoCtxPrincipal{token: login(t, srv, user, "Passw0rd!2345").Token, tenant: tenant}
	}
	f.aOrg, f.aTen, f.a = mk("A")
	f.bOrg, f.bTen, f.b = mk("B")

	for _, d := range []models.Device{
		{ID: "a-core", Name: "a-core", Address: "10.1.0.1", TenantID: f.aTen, Source: "snmp", LastSeen: fixed},
		{ID: "a-edge", Name: "a-edge", Address: "10.1.0.2", TenantID: f.aTen, Source: "snmp", LastSeen: fixed},
		{ID: "b-core", Name: "b-core", Address: "10.2.0.1", TenantID: f.bTen, Source: "snmp", LastSeen: fixed},
		{ID: "b-edge", Name: "b-edge", Address: "10.2.0.2", TenantID: f.bTen, Source: "snmp", LastSeen: fixed},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatalf("upsert %s: %v", d.ID, err)
		}
	}
	type nb struct {
		LocalDevice string `json:"local_device"`
		LocalPort   string `json:"local_port"`
		RemSysName  string `json:"rem_sysname"`
		RemChassis  string `json:"rem_chassis"`
		RemPort     string `json:"rem_port"`
		Proto       string `json:"proto"`
		TS          int64  `json:"ts"`
	}
	ts := time.Now().UnixMilli()
	payload, err := json.Marshal([]nb{
		{LocalDevice: "a-core", LocalPort: "Gi2", RemSysName: "a-edge", RemChassis: "10.1.0.2", RemPort: "Gi1", Proto: "lldp", TS: ts},
		{LocalDevice: "a-core", LocalPort: "Gi9", RemSysName: "b-core", RemChassis: "10.2.0.1", RemPort: "Gi9", Proto: "lldp", TS: ts},
		{LocalDevice: "b-core", LocalPort: "Gi2", RemSysName: "b-edge", RemChassis: "10.2.0.2", RemPort: "Gi1", Proto: "lldp", TS: ts},
	})
	if err != nil {
		t.Fatalf("marshal neighbours: %v", err)
	}
	fakeTopologyCollector(t, map[string]string{"netops:topology:lldp": string(payload)})

	store := topology.NewMemStore()
	if err := store.ReplaceAll(context.Background(), topology.GraphRecords{
		Nodes: []topology.NodeRecord{
			{TenantID: f.aTen, ID: "a-core", Label: "a-core", DeviceRole: "core_router", FirstSeen: fixed.Add(-48 * time.Hour), LastSeen: fixed},
			{TenantID: f.aTen, ID: "a-edge", Label: "a-edge", FirstSeen: fixed.Add(-48 * time.Hour), LastSeen: fixed},
			{TenantID: f.bTen, ID: "b-core", Label: "b-core", FirstSeen: fixed.Add(-48 * time.Hour), LastSeen: fixed},
			{TenantID: f.bTen, ID: "b-edge", Label: "b-edge", FirstSeen: fixed.Add(-48 * time.Hour), LastSeen: fixed},
		},
		Edges: []topology.EdgeRecord{
			{TenantID: f.aTen, ID: topoEdgeAA, Source: "a-core", Target: "a-edge", SourcePort: "Gi2", TargetPort: "Gi1",
				Protocol: "lldp", Resolved: true, FirstSeen: fixed.Add(-48 * time.Hour), LastSeen: fixed},
			{TenantID: f.bTen, ID: topoEdgeBB, Source: "b-core", Target: "b-edge", SourcePort: "Gi2", TargetPort: "Gi1",
				Protocol: "lldp", Resolved: true, FirstSeen: fixed.Add(-48 * time.Hour), LastSeen: fixed},
		},
	}); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	s.topology = store

	topoCtxFakeCH(t, map[string]topoCtxObj{
		topoCorrA: {owner: f.aTen, dev: "a-core"},
		topoCorrB: {owner: f.bTen, dev: "b-core"},
	})
	return f
}

// report GETs one subresource and returns its status and topology context.
func (f *topoCtxFixture) topo(t *testing.T, token, corr, sub, asTenant string) (int, rca.TopologyContext, string) {
	t.Helper()
	path := "/api/correlations/" + corr + "/" + sub
	if asTenant != "" {
		path += "?as_tenant=" + asTenant
	}
	st, body := do(t, f.srv, "GET", path, token, nil)
	var out struct {
		TopologyContext *rca.TopologyContext `json:"topology_context"`
	}
	if st == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode %s: %v (%s)", path, err, body)
		}
		if out.TopologyContext == nil {
			t.Fatalf("%s carries no topology_context: %s", path, body)
		}
		return st, *out.TopologyContext, string(body)
	}
	return st, rca.TopologyContext{}, string(body)
}

func topoIDs(tc rca.TopologyContext) map[string]bool {
	out := map[string]bool{}
	for _, n := range tc.Nodes {
		out[n.ID] = true
		out[n.Label] = true
	}
	for _, e := range tc.Edges {
		out[e.ID] = true
		out[e.A], out[e.B] = true, true
	}
	return out
}

func TestRCATopologyContextIsolation(t *testing.T) {
	f := newTopoCtxFixture(t)

	for _, sub := range []string{"rca-report", "rca-path-view"} {
		// 1) own-only: user A's report draws A's adjacency (a-edge from the live
		//    tables + the persisted graph, and the b-core A's own device hears),
		//    and nothing of tenant B's fabric.
		st, tc, raw := f.topo(t, f.a.token, topoCorrA, sub, "")
		if st != http.StatusOK {
			t.Fatalf("%s: user A GET own: %d %s", sub, st, raw)
		}
		ids := topoIDs(tc)
		if tc.State != rca.TopoStateTopologyOnly || !ids["a-edge"] || !ids[topoEdgeAA] {
			t.Fatalf("%s: user A must see its own neighbour a-edge (state %q): %+v", sub, tc.State, tc.Edges)
		}
		var aEdge rca.TopoCtxEdge
		for _, e := range tc.Edges {
			if e.ID == topoEdgeAA {
				aEdge = e
			}
		}
		if strings.Join(aEdge.Sources, ",") != "lldp,topology_graph" || aEdge.FirstSeen == "" {
			t.Fatalf("%s: the live link and the persisted edge must merge onto one edge: %+v", sub, aEdge)
		}
		if ids["b-edge"] || ids[topoEdgeBB] || strings.Contains(raw, "b-edge") {
			t.Fatalf("%s: TENANT LEAK — user A's report names tenant B's neighbour b-edge: %s", sub, raw)
		}

		// 2) the platform owner reading A's report: A's view, never B's neighbours.
		st, tc, raw = f.topo(t, f.owner, topoCorrA, sub, "")
		if st != http.StatusOK {
			t.Fatalf("%s: owner GET A: %d %s", sub, st, raw)
		}
		if !topoIDs(tc)["a-edge"] || strings.Contains(raw, "b-edge") || strings.Contains(raw, topoEdgeBB) {
			t.Fatalf("%s: CROSS-TENANT LEAK — the owner's view of A's report carries B's fabric: %s", sub, raw)
		}
		for _, n := range tc.Nodes {
			if n.ID == "b-core" && n.Managed {
				t.Fatalf("%s: b-core resolved to tenant B's inventory row inside A's report: %+v", sub, n)
			}
		}

		// 3) cross-tenant get → 404 (never reveal the id exists).
		if st, _, raw := f.topo(t, f.b.token, topoCorrA, sub, ""); st != http.StatusNotFound {
			t.Fatalf("%s: user B GET A's object: %d (%s), want 404", sub, st, raw)
		}
		if st, _, raw := f.topo(t, f.a.token, topoCorrB, sub, ""); st != http.StatusNotFound {
			t.Fatalf("%s: user A GET B's object: %d (%s), want 404", sub, st, raw)
		}

		// 4) as_tenant into another org is ignored: user A switching to B still
		//    gets A's own object and 404 for B's.
		st, tc, raw = f.topo(t, f.a.token, topoCorrA, sub, f.bTen)
		if st != http.StatusOK || !topoIDs(tc)["a-edge"] || strings.Contains(raw, "b-edge") {
			t.Fatalf("%s: user A ?as_tenant=B leaked or broke own read: %d %s", sub, st, raw)
		}
		if st, _, raw := f.topo(t, f.a.token, topoCorrB, sub, f.bTen); st != http.StatusNotFound {
			t.Fatalf("%s: user A ?as_tenant=B read B's object: %d %s", sub, st, raw)
		}
	}

	// baseline for half 5: before any restriction the owner's view of A's
	// report includes the a-core ─ b-core link A's device reports.
	_, tc, _ := f.topo(t, f.owner, topoCorrA, "rca-report", "")
	if !topoIDs(tc)["ext:b-core"] {
		t.Fatalf("fixture: the owner must see A's reported neighbour ext:b-core before the restriction: %+v", tc.Edges)
	}

	// 5) tenant B switches on the operator-visibility restriction.
	if _, err := f.s.tenants.SetOperatorRestricted(f.bTen, true); err != nil {
		t.Fatalf("restrict B: %v", err)
	}
	for _, sub := range []string{"rca-report", "rca-path-view"} {
		st, tc, raw := f.topo(t, f.owner, topoCorrA, sub, "")
		if st != http.StatusOK {
			t.Fatalf("%s: owner GET A after restricting B: %d %s", sub, st, raw)
		}
		if strings.Contains(raw, "b-core") || strings.Contains(raw, "b-edge") {
			t.Fatalf("%s: RESTRICTION LEAK — the owner's view of A's report still names B's device: %s", sub, raw)
		}
		if !topoIDs(tc)["a-edge"] {
			t.Fatalf("%s: the restriction must not take A's own neighbour away: %+v", sub, tc.Edges)
		}
		if st, _, raw := f.topo(t, f.owner, topoCorrB, sub, ""); st != http.StatusNotFound {
			t.Fatalf("%s: owner GET restricted B's object: %d %s, want 404", sub, st, raw)
		}
		if st, _, raw := f.topo(t, f.owner, topoCorrB, sub, f.bTen); st != http.StatusNotFound {
			t.Fatalf("%s: owner ?as_tenant=B (restricted) read B's object: %d %s, want 404", sub, st, raw)
		}
		// the restriction is about what the OPERATOR reads: B's own user and A's
		// own user are unaffected.
		st, tc, raw = f.topo(t, f.b.token, topoCorrB, sub, "")
		if st != http.StatusOK || !topoIDs(tc)["b-edge"] {
			t.Fatalf("%s: tenant B lost its own topology to its own restriction: %d %s", sub, st, raw)
		}
		st, tc, raw = f.topo(t, f.a.token, topoCorrA, sub, "")
		if st != http.StatusOK || !topoIDs(tc)["ext:b-core"] {
			t.Fatalf("%s: tenant A's own observation must not change with B's operator restriction: %d %s", sub, st, raw)
		}
	}
}

// TestRCATopologyContextReaderScopesByOwnerAndCaller drives the reader directly:
// a scoped principal asking for another tenant's object reads nothing (the
// defence in depth behind the 404), and a restricted owner is answered like
// an empty one.
func TestRCATopologyContextReaderScopesByOwnerAndCaller(t *testing.T) {
	f := newTopoCtxFixture(t)
	read := func(claims jwtClaims, owner string) rca.TopologyRead {
		t.Helper()
		r, err := serverTopologySource{s: f.s, claims: claims}.ReadTopology(context.Background(),
			rca.TopologyQuery{OwnerTenant: owner, Devices: []string{"a-core", "b-core"}, Now: time.Now()})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return r
	}
	userA := jwtClaims{Sub: "topo-user-A", Role: RoleOperator, Tenant: f.aTen}
	if r := read(userA, f.bTen); len(r.Inventory)+len(r.Links)+len(r.Reads) != 0 {
		t.Fatalf("a scoped principal must read nothing of another tenant's object: %+v", r)
	}
	r := read(userA, f.aTen)
	for _, d := range r.Inventory {
		if strings.HasPrefix(d.ID, "b-") {
			t.Fatalf("owner-A read returned tenant B's inventory row %q", d.ID)
		}
	}
	for _, l := range r.Links {
		if l.A == "b-core" || l.B == "b-edge" || l.A == "b-edge" {
			t.Fatalf("owner-A read returned tenant B's link %+v", l)
		}
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	if _, err := f.s.tenants.SetOperatorRestricted(f.aTen, true); err != nil {
		t.Fatalf("restrict A: %v", err)
	}
	if r := read(owner, f.aTen); len(r.Inventory)+len(r.Links)+len(r.Reads) != 0 {
		t.Fatalf("a restricted owner tenant must read as empty to the operator: %+v", r)
	}
	scopedIn := owner
	scopedIn.ActingTenant = f.aTen
	if r := read(scopedIn, f.aTen); len(r.Inventory)+len(r.Links)+len(r.Reads) != 0 {
		t.Fatalf("the operator scoped into a restricted tenant must read nothing: %+v", r)
	}
	_ = fmt.Sprint(f.aOrg, f.bOrg)
}
