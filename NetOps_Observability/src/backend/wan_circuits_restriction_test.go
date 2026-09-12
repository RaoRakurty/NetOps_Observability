// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// wan_circuits_restriction_test.go — the CLAUDE.md §3a rule-5 isolation tests for
// the operator-visibility restriction (Tenant.OperatorRestricted) on the WAN
// surfaces: GET /api/wan/endpoints, GET /api/wan/circuits, GET /api/wan/interfaces
// and GET /api/wan/policy.
//
// All four hang off ONE projection, wanProject, whose device predicate used to be
// `if !cross && deviceTenant(d) != tenant` — on the Global path it took every
// device in the registry. So the platform operator read a restricted tenant's WAN
// transport interfaces, their IP addresses, their declared site and the derived
// circuits over them.
//
// THE HALF A DEVICE FILTER DOES NOT OBVIOUSLY BUY YOU. The device slice is also
// the RESOLUTION UNIVERSE for the neighbour index, so removing a device can
// CONVERT a leak rather than close it — the way filtering the topology slice
// demoted an adjacency to `ext:acme-core` with the hidden device's name still on
// the edge. Here the same shape exists: an UNRESTRICTED tenant's interface that
// is LLDP-adjacent to a RESTRICTED tenant's router derives its measurement target
// from that router — the peer's interface IP as `target`, the peer's device and
// interface names as `remote_device`/`remote_if` and inside `target_label`. That
// row is globex's and must keep being served; what must vanish from it is every
// trace of acme. TestWanCircuitsHonour… asserts the CIRCUIT PAYLOAD, not only the
// endpoint list.
//
// The fixture is a real server over real stores, so the switch under test is the
// production one and the devices are keyed on the opaque tenant ids the store
// mints.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// ── fixture ──────────────────────────────────────────────────────────────────

type restrictedWanFixture struct {
	t      *testing.T
	s      *server
	acme   string
	globex string
}

func (f *restrictedWanFixture) owner() jwtClaims {
	return jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
}

func (f *restrictedWanFixture) acmeUser() jwtClaims {
	return jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: f.acme}
}

func (f *restrictedWanFixture) globexUser() jwtClaims {
	return jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: f.globex}
}

func (f *restrictedWanFixture) restrictAcme() {
	f.t.Helper()
	if _, err := f.s.tenants.SetOperatorRestricted("acme", true); err != nil {
		f.t.Fatalf("restrict acme: %v", err)
	}
}

// newRestrictedWanFixture seeds three owners' WAN estates:
//
//	acme     — acme-wan (WAN device, Ethernet1 + Ethernet9), acme-spine (pulled in
//	           by its link to acme-wan)                       ← gets restricted
//	globex   — globex-wan (WAN device, Ethernet1 + Ethernet2) ← must stay whole
//	platform — stack-gw (WAN device, Ethernet1, no tenant)    ← must survive
//
// The adjacency set deliberately includes a link that JOINS two tenants —
// globex-wan/Ethernet2 ⇄ acme-wan/Ethernet9 — because that is the row on which a
// device filter can convert the leak instead of closing it.
func newRestrictedWanFixture(t *testing.T) *restrictedWanFixture {
	t.Helper()
	dir := t.TempDir()
	// No VictoriaMetrics in a unit test: a closed port fails fast and honestly
	// (rows carry no utilisation) rather than spending the handler's budget on a
	// DNS timeout.
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:1")
	t.Setenv("METRICS_URL", "http://127.0.0.1:1")

	ts, err := newTenantStore(filepath.Join(dir, "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	roles, err := newRoleStore(filepath.Join(dir, "roles.json"))
	if err != nil {
		t.Fatalf("newRoleStore: %v", err)
	}
	sites, err := newSitesStore(filepath.Join(dir, "sites.json"))
	if err != nil {
		t.Fatalf("newSitesStore: %v", err)
	}
	ds, err := newDeviceSiteStore(filepath.Join(dir, "device_sites.json"))
	if err != nil {
		t.Fatalf("newDeviceSiteStore: %v", err)
	}
	wp, err := newWanPolicyStore(filepath.Join(dir, "wan_policy.json"))
	if err != nil {
		t.Fatalf("newWanPolicyStore: %v", err)
	}

	// device → interface IP → ifName, as the interface-IP collector publishes it.
	ifaddr := map[string]map[string]string{
		"acme-wan":    {"10.1.0.1": "Ethernet1", "10.1.9.1": "Ethernet9"},
		"acme-spine":  {"10.1.0.2": "Ethernet3"},
		"globex-wan":  {"10.2.0.1": "Ethernet1", "10.2.1.1": "Ethernet2"},
		"stack-gw":    {"10.9.0.1": "Ethernet1"},
		"globex-leaf": {"10.2.0.2": "Ethernet7"},
	}
	links := []collectors.LLDPNeighbor{
		// wholly inside the restricted tenant
		{LocalDevice: "acme-wan", LocalPort: "Ethernet1", RemSysName: "acme-spine", RemPort: "Ethernet3", Proto: "lldp"},
		{LocalDevice: "acme-spine", LocalPort: "Ethernet3", RemSysName: "acme-wan", RemPort: "Ethernet1", Proto: "lldp"},
		// the link that JOINS the two tenants — the conversion case
		{LocalDevice: "globex-wan", LocalPort: "Ethernet2", RemSysName: "acme-wan", RemPort: "Ethernet9", Proto: "lldp"},
		{LocalDevice: "acme-wan", LocalPort: "Ethernet9", RemSysName: "globex-wan", RemPort: "Ethernet2", Proto: "lldp"},
		// unrestricted tenant, wholly its own — must be unmoved
		{LocalDevice: "globex-wan", LocalPort: "Ethernet1", RemSysName: "globex-leaf", RemPort: "Ethernet7", Proto: "lldp"},
		{LocalDevice: "globex-leaf", LocalPort: "Ethernet7", RemSysName: "globex-wan", RemPort: "Ethernet1", Proto: "lldp"},
	}

	d := discovery.NewDiscoveryAggregator()
	for _, dev := range []models.Device{
		{ID: "acme-wan", Name: "acme-wan", Address: "10.1.0.254", TenantID: acme.ID},
		{ID: "acme-spine", Name: "acme-spine", Address: "10.1.0.253", TenantID: acme.ID},
		{ID: "globex-wan", Name: "globex-wan", Address: "10.2.0.254", TenantID: globex.ID},
		{ID: "globex-leaf", Name: "globex-leaf", Address: "10.2.0.253", TenantID: globex.ID},
		{ID: "stack-gw", Name: "stack-gw", Address: "10.9.0.254"}, // platform-owned
	} {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("upsert %s: %v", dev.ID, err)
		}
	}

	// A declared site on the restricted tenant's WAN router: the endpoint payload
	// carries it, so it is a second thing that must stop being served.
	if err := ds.Set(DeviceSiteBinding{TenantID: acme.ID, DeviceID: "acme-wan", Device: "acme-wan", Site: "nyc-dc1"}); err != nil {
		t.Fatalf("bind acme-wan site: %v", err)
	}
	if err := ds.Set(DeviceSiteBinding{TenantID: globex.ID, DeviceID: "globex-wan", Device: "globex-wan", Site: "lon-dc1"}); err != nil {
		t.Fatalf("bind globex-wan site: %v", err)
	}

	s := &server{
		discovery: d, tenants: ts, roles: roles, sites: sites, deviceSites: ds, wanPolicy: wp,
		wanIfAddr: func(context.Context) (map[string]map[string]string, error) {
			return ifaddr, nil
		},
		wanNeighbors: func(context.Context) ([]collectors.LLDPNeighbor, error) {
			return links, nil
		},
	}
	return &restrictedWanFixture{t: t, s: s, acme: acme.ID, globex: globex.ID}
}

// get runs one real GET through a handler and returns the decoded body plus the
// raw wire bytes — the raw bytes are what the "does a hidden name escape in ANY
// field" assertions are made against, so a leak in a field this test forgot to
// model still fails it.
func (f *restrictedWanFixture) get(h http.HandlerFunc, path string, claims jwtClaims, out any) string {
	f.t.Helper()
	w := httptest.NewRecorder()
	h(w, req(http.MethodGet, path, "", claims))
	if w.Code != http.StatusOK {
		f.t.Fatalf("GET %s = %d (%s)", path, w.Code, w.Body.String())
	}
	body := w.Body.String()
	if out != nil {
		if err := json.Unmarshal([]byte(body), out); err != nil {
			f.t.Fatalf("decode %s: %v (%s)", path, err, body)
		}
	}
	return body
}

// asTenant is the ?as_tenant= half. The switcher's override is applied by the
// auth middleware (withActingTenant) and arrives at a handler as ActingTenant on
// the claims, so a handler-level test carries it the same way the map/topology
// template does.
func (f *restrictedWanFixture) asTenant(h http.HandlerFunc, path, tenantID string, out any) string {
	f.t.Helper()
	return f.get(h, path, ownerActing(f.owner(), tenantID), out)
}

// ── decoded shapes ───────────────────────────────────────────────────────────

type wanEndpointsResp struct {
	Endpoints []struct {
		TenantID       string `json:"tenant_id"`
		Device         string `json:"device"`
		Interface      string `json:"interface"`
		Address        string `json:"address"`
		Site           string `json:"site"`
		Target         string `json:"target"`
		TargetKind     string `json:"target_kind"`
		TargetLabel    string `json:"target_label"`
		ConnectedToWAN bool   `json:"connected_to_wan"`
	} `json:"endpoints"`
}

// keys renders the endpoint set as "device/interface" — an assertion names the
// leaked interface rather than reporting a count that moved.
func (e wanEndpointsResp) keys() map[string]bool {
	out := map[string]bool{}
	for _, ep := range e.Endpoints {
		out[ep.Device+"/"+ep.Interface] = true
	}
	return out
}

type wanCircuitsResp struct {
	Circuits []struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		Kind     string `json:"kind"`
		Local    struct {
			Device    string `json:"device"`
			Interface string `json:"interface"`
			Address   string `json:"address"`
			Site      string `json:"site"`
		} `json:"local"`
		Remote struct {
			Device     string `json:"device"`
			Interface  string `json:"interface"`
			Address    string `json:"address"`
			Measurable string `json:"measurable_addr"`
		} `json:"remote"`
	} `json:"circuits"`
}

func (c wanCircuitsResp) locals() map[string]bool {
	out := map[string]bool{}
	for _, k := range c.Circuits {
		out[k.Local.Device+"/"+k.Local.Interface] = true
	}
	return out
}

type wanInterfacesResp struct {
	Interfaces []struct {
		Device       string `json:"device"`
		Interface    string `json:"interface"`
		Address      string `json:"address"`
		Site         string `json:"site"`
		Target       string `json:"target"`
		TargetLabel  string `json:"target_label"`
		RemoteDevice string `json:"remote_device"`
		RemoteIf     string `json:"remote_if"`
	} `json:"interfaces"`
}

func (i wanInterfacesResp) keys() map[string]bool {
	out := map[string]bool{}
	for _, r := range i.Interfaces {
		out[r.Device+"/"+r.Interface] = true
	}
	return out
}

// acmeTraces are every string that identifies the restricted tenant's estate on
// these surfaces: device names, interface IPs, its declared site. The wire body
// must contain none of them once acme is restricted — this is the check that
// catches a leak CONVERTED into a label rather than closed.
var acmeTraces = []string{"acme-wan", "acme-spine", "10.1.0.1", "10.1.9.1", "10.1.0.2", "nyc-dc1"}

func assertNoAcmeTrace(t *testing.T, what, body string) {
	t.Helper()
	for _, trace := range acmeTraces {
		if strings.Contains(body, trace) {
			t.Errorf("RESTRICTION LEAK: %s still carries the restricted tenant's %q.\n  body=%s", what, trace, body)
		}
	}
}

// ── /api/wan/endpoints + /api/wan/circuits ───────────────────────────────────

// TestWanEndpointsHonourTheOperatorVisibilityRestriction — the endpoint registry
// is the restricted tenant's WAN transport inventory: which routers face the
// outside world, on which interfaces, at which addresses, at which site.
func TestWanEndpointsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedWanFixture(t)

	// ── baseline. Without it every assertion below could pass on an empty set.
	var base wanEndpointsResp
	f.get(f.s.handleWanEndpoints, "/api/wan/endpoints", f.owner(), &base)
	got := base.keys()
	for _, want := range []string{"acme-wan/Ethernet1", "acme-wan/Ethernet9", "acme-spine/Ethernet3",
		"globex-wan/Ethernet1", "globex-wan/Ethernet2", "stack-gw/Ethernet1"} {
		if !got[want] {
			t.Fatalf("baseline Global endpoints = %v, want %s among them — the fixture does not reach the handler",
				sortedKeys(got), want)
		}
	}
	// acme's OWN view, captured BEFORE the switch.
	var acmeBefore wanEndpointsResp
	f.get(f.s.handleWanEndpoints, "/api/wan/endpoints", f.acmeUser(), &acmeBefore)
	if k := acmeBefore.keys(); !k["acme-wan/Ethernet1"] || !k["acme-spine/Ethernet3"] {
		t.Fatalf("acme's own endpoints = %v, want its own WAN + connected interfaces", sortedKeys(k))
	}

	f.restrictAcme()

	// ── half 1: the Global view drops acme's interfaces entirely.
	var global wanEndpointsResp
	body := f.get(f.s.handleWanEndpoints, "/api/wan/endpoints", f.owner(), &global)
	for _, ep := range global.Endpoints {
		if strings.HasPrefix(ep.Device, "acme-") {
			t.Errorf("RESTRICTION LEAK: the Global endpoint registry still lists the restricted tenant's %s/%s at %s (site %q)",
				ep.Device, ep.Interface, ep.Address, ep.Site)
		}
	}
	assertNoAcmeTrace(t, "GET /api/wan/endpoints in the Global view", body)
	if k := global.keys(); !k["globex-wan/Ethernet1"] || !k["globex-wan/Ethernet2"] || !k["stack-gw/Ethernet1"] {
		t.Errorf("the Global endpoint registry lost globex's or the platform's interfaces: %v — restricting acme must not empty it",
			sortedKeys(k))
	}

	// ── half 2: the owner walks in with as_tenant=acme. Nothing is served.
	var scoped wanEndpointsResp
	f.asTenant(f.s.handleWanEndpoints, "/api/wan/endpoints", f.acme, &scoped)
	if n := len(scoped.Endpoints); n != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme served %d WAN endpoint(s): %v", n, sortedKeys(scoped.keys()))
	}

	// ── the owner scoped into the UNRESTRICTED tenant still sees it whole.
	var gscoped wanEndpointsResp
	f.asTenant(f.s.handleWanEndpoints, "/api/wan/endpoints", f.globex, &gscoped)
	if k := gscoped.keys(); !k["globex-wan/Ethernet1"] || !k["globex-wan/Ethernet2"] {
		t.Errorf("as_tenant=globex endpoints = %v, want globex's WAN interfaces — restricting acme must not change globex",
			sortedKeys(k))
	}

	// ── acme's OWN view is undamaged: the switch hides a tenant from the
	//    PLATFORM, never from itself.
	var acmeAfter wanEndpointsResp
	f.get(f.s.handleWanEndpoints, "/api/wan/endpoints", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.keys(), acmeAfter.keys()) {
		t.Errorf("acme's own WAN endpoints changed when acme restricted itself: %v → %v",
			sortedKeys(acmeBefore.keys()), sortedKeys(acmeAfter.keys()))
	}
}

// TestWanCircuitsHonourTheOperatorVisibilityRestriction is the CONVERSION check.
// globex-wan/Ethernet2 is LLDP-adjacent to acme-wan/Ethernet9, so before the
// switch its circuit measures TO acme and names acme in four places: the target
// address, remote.device, remote.interface and the human target_label. That row
// belongs to globex and must keep being served — with every trace of acme gone
// from it, the target having fallen back to the reachability anchor.
func TestWanCircuitsHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedWanFixture(t)

	// ── baseline: the cross-tenant circuit really does name acme today.
	var base wanCircuitsResp
	f.get(f.s.handleWanCircuits, "/api/wan/circuits", f.owner(), &base)
	var crossLink, found = struct {
		id, target, remoteDev, remoteIf string
	}{}, false
	for _, c := range base.Circuits {
		if c.Local.Device == "globex-wan" && c.Local.Interface == "Ethernet2" {
			crossLink.id, crossLink.target = c.ID, c.Remote.Measurable
			crossLink.remoteDev, crossLink.remoteIf = c.Remote.Device, c.Remote.Interface
			found = true
		}
	}
	if !found {
		t.Fatalf("baseline Global circuits = %v, want globex-wan/Ethernet2 among them — the fixture does not reach the handler",
			sortedKeys(base.locals()))
	}
	if crossLink.remoteDev != "acme-wan" || crossLink.target != "10.1.9.1" {
		t.Fatalf("baseline: globex-wan/Ethernet2 should measure to acme-wan at 10.1.9.1, got remote=%s/%s target=%s — "+
			"without that the conversion half of this test proves nothing",
			crossLink.remoteDev, crossLink.remoteIf, crossLink.target)
	}
	if !base.locals()["acme-wan/Ethernet1"] {
		t.Fatalf("baseline Global circuits = %v, want acme's own circuits among them", sortedKeys(base.locals()))
	}
	var acmeBefore wanCircuitsResp
	f.get(f.s.handleWanCircuits, "/api/wan/circuits", f.acmeUser(), &acmeBefore)
	if len(acmeBefore.Circuits) == 0 {
		t.Fatal("acme's own circuit set is empty before the switch — the comparison below would prove nothing")
	}

	f.restrictAcme()

	// ── half 1: the Global view.
	var global wanCircuitsResp
	body := f.get(f.s.handleWanCircuits, "/api/wan/circuits", f.owner(), &global)
	for _, c := range global.Circuits {
		if strings.HasPrefix(c.Local.Device, "acme-") {
			t.Errorf("RESTRICTION LEAK: the Global circuit list still carries %s (%s/%s → %s)",
				c.ID, c.Local.Device, c.Local.Interface, c.Remote.Measurable)
		}
	}
	// THE CONVERSION: globex's row survives, and names nothing of acme's.
	var survivor bool
	for _, c := range global.Circuits {
		if c.Local.Device != "globex-wan" || c.Local.Interface != "Ethernet2" {
			continue
		}
		survivor = true
		if c.Remote.Device == "acme-wan" || c.Remote.Measurable == "10.1.9.1" || c.Remote.Interface == "Ethernet9" {
			t.Errorf("RESTRICTION LEAK (CONVERTED, not closed): globex-wan/Ethernet2's circuit %s still resolves to the "+
				"restricted tenant's router — remote=%s/%s measurable=%s. Filtering the device slice removed the NODE and "+
				"left the EDGE naming it.", c.ID, c.Remote.Device, c.Remote.Interface, c.Remote.Measurable)
		}
		if c.Kind != string(WanTargetAnchor) {
			t.Errorf("globex-wan/Ethernet2 should fall back to the reachability anchor once its peer is hidden, got kind %q", c.Kind)
		}
	}
	if !survivor {
		t.Error("globex-wan/Ethernet2 disappeared from the Global circuit list — restricting acme must not take globex's own interface away")
	}
	assertNoAcmeTrace(t, "GET /api/wan/circuits in the Global view", body)
	if !global.locals()["globex-wan/Ethernet1"] || !global.locals()["stack-gw/Ethernet1"] {
		t.Errorf("the Global circuit list lost globex's or the platform's circuits: %v", sortedKeys(global.locals()))
	}

	// ── half 2: as_tenant=acme serves nothing.
	var scoped wanCircuitsResp
	f.asTenant(f.s.handleWanCircuits, "/api/wan/circuits", f.acme, &scoped)
	if n := len(scoped.Circuits); n != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme served %d circuit(s): %v", n, sortedKeys(scoped.locals()))
	}

	// ── the unrestricted tenant is unmoved.
	var gscoped wanCircuitsResp
	f.asTenant(f.s.handleWanCircuits, "/api/wan/circuits", f.globex, &gscoped)
	if !gscoped.locals()["globex-wan/Ethernet1"] || !gscoped.locals()["globex-wan/Ethernet2"] {
		t.Errorf("as_tenant=globex circuits = %v, want globex's own interfaces", sortedKeys(gscoped.locals()))
	}

	// ── acme's own circuits are undamaged, peer resolution included.
	var acmeAfter wanCircuitsResp
	f.get(f.s.handleWanCircuits, "/api/wan/circuits", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.locals(), acmeAfter.locals()) {
		t.Errorf("acme's own circuits changed when acme restricted itself: %v → %v",
			sortedKeys(acmeBefore.locals()), sortedKeys(acmeAfter.locals()))
	}
	for _, c := range acmeAfter.Circuits {
		if c.Local.Device == "acme-wan" && c.Local.Interface == "Ethernet1" && c.Remote.Device != "acme-spine" {
			t.Errorf("acme lost its own peer resolution after restricting itself: acme-wan/Ethernet1 remote = %q, want acme-spine",
				c.Remote.Device)
		}
	}
}

// TestWanInterfacesHonourTheOperatorVisibilityRestriction — the table the WAN
// page actually renders. It reads the same projection, so it must move with it:
// the device name, its interface address, its site and its resolved peer.
func TestWanInterfacesHonourTheOperatorVisibilityRestriction(t *testing.T) {
	f := newRestrictedWanFixture(t)

	var base wanInterfacesResp
	f.get(f.s.handleWanInterfaces, "/api/wan/interfaces", f.owner(), &base)
	if k := base.keys(); !k["acme-wan/Ethernet1"] || !k["globex-wan/Ethernet1"] || !k["stack-gw/Ethernet1"] {
		t.Fatalf("baseline Global interface table = %v, want every tenant's rows — the fixture does not reach the handler",
			sortedKeys(k))
	}
	var acmeBefore wanInterfacesResp
	f.get(f.s.handleWanInterfaces, "/api/wan/interfaces", f.acmeUser(), &acmeBefore)
	if len(acmeBefore.Interfaces) == 0 {
		t.Fatal("acme's own interface table is empty before the switch")
	}

	f.restrictAcme()

	var global wanInterfacesResp
	body := f.get(f.s.handleWanInterfaces, "/api/wan/interfaces", f.owner(), &global)
	for _, r := range global.Interfaces {
		if strings.HasPrefix(r.Device, "acme-") || strings.HasPrefix(r.RemoteDevice, "acme-") {
			t.Errorf("RESTRICTION LEAK: the Global WAN interface table still carries %s/%s (%s, site %q) → %s/%s",
				r.Device, r.Interface, r.Address, r.Site, r.RemoteDevice, r.RemoteIf)
		}
	}
	assertNoAcmeTrace(t, "GET /api/wan/interfaces in the Global view", body)
	if k := global.keys(); !k["globex-wan/Ethernet1"] || !k["stack-gw/Ethernet1"] {
		t.Errorf("the Global WAN interface table lost globex's or the platform's rows: %v", sortedKeys(k))
	}

	var scoped wanInterfacesResp
	f.asTenant(f.s.handleWanInterfaces, "/api/wan/interfaces", f.acme, &scoped)
	if n := len(scoped.Interfaces); n != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme served %d WAN interface row(s): %v", n, sortedKeys(scoped.keys()))
	}

	var gscoped wanInterfacesResp
	f.asTenant(f.s.handleWanInterfaces, "/api/wan/interfaces", f.globex, &gscoped)
	if k := gscoped.keys(); !k["globex-wan/Ethernet1"] {
		t.Errorf("as_tenant=globex interface table = %v, want globex's rows", sortedKeys(k))
	}

	var acmeAfter wanInterfacesResp
	f.get(f.s.handleWanInterfaces, "/api/wan/interfaces", f.acmeUser(), &acmeAfter)
	if !sameSet(acmeBefore.keys(), acmeAfter.keys()) {
		t.Errorf("acme's own WAN interface table changed when acme restricted itself: %v → %v",
			sortedKeys(acmeBefore.keys()), sortedKeys(acmeAfter.keys()))
	}
}

// ── /api/wan/policy ──────────────────────────────────────────────────────────

// TestWanPolicyIsNeverReadAcrossTenants covers the fourth WAN surface, which
// carries operator INTENT rather than device data — and carries it in a shape
// that names devices: next_hops is keyed by "<device>/<ifName>" and valued with
// that tenant's ISP addresses.
//
// Every tenant's row lives under the SAME collection id ("policy"), so the
// cross-tenant read missed on the platform key and fell through to
// Collection.Get's "the id may live under any tenant" scan — handing the
// platform owner whichever tenant's row the map yielded first.
func TestWanPolicyIsNeverReadAcrossTenants(t *testing.T) {
	f := newRestrictedWanFixture(t)

	acmePolicy := WanMeasurementPolicy{
		TenantID:   f.acme,
		WanPattern: "acme-only-pattern",
		NextHops:   map[string]string{"acme-wan/Ethernet1": "203.0.113.7"},
	}
	if err := f.s.wanPolicy.Put(acmePolicy); err != nil {
		t.Fatalf("put acme policy: %v", err)
	}

	type policyResp struct {
		TenantID   string            `json:"tenant_id"`
		WanPattern string            `json:"wan_pattern"`
		NextHops   map[string]string `json:"next_hops"`
	}

	// ── the Global view reads the PLATFORM's own row (here: the baseline), never
	//    a tenant's. This half holds whether or not anything is restricted.
	var global policyResp
	body := f.get(f.s.handleWanPolicy, "/api/wan/policy", f.owner(), &global)
	if global.WanPattern == "acme-only-pattern" || len(global.NextHops) != 0 {
		t.Errorf("CROSS-TENANT LEAK: the Global WAN policy read returned acme's row — pattern=%q next_hops=%v.\n  body=%s",
			global.WanPattern, global.NextHops, body)
	}
	if strings.Contains(body, "203.0.113.7") || strings.Contains(body, "acme-wan") {
		t.Errorf("CROSS-TENANT LEAK: the Global WAN policy body names acme's device or its ISP next-hop: %s", body)
	}

	// ── acme's own read is the row it saved.
	var own policyResp
	f.get(f.s.handleWanPolicy, "/api/wan/policy", f.acmeUser(), &own)
	if own.WanPattern != "acme-only-pattern" || own.NextHops["acme-wan/Ethernet1"] != "203.0.113.7" {
		t.Fatalf("acme's own WAN policy = %+v, want the row it saved", own)
	}

	// ── globex reads its own baseline, never acme's.
	var g policyResp
	f.get(f.s.handleWanPolicy, "/api/wan/policy", f.globexUser(), &g)
	if g.WanPattern == "acme-only-pattern" || len(g.NextHops) != 0 {
		t.Errorf("CROSS-TENANT LEAK: globex read acme's WAN policy: %+v", g)
	}

	f.restrictAcme()

	// ── the restriction's deny half: as_tenant=acme gets the baseline, which
	//    discloses nothing — the same answer an unconfigured tenant gets.
	var scoped policyResp
	sbody := f.asTenant(f.s.handleWanPolicy, "/api/wan/policy", f.acme, &scoped)
	if scoped.WanPattern == "acme-only-pattern" || len(scoped.NextHops) != 0 {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme read the restricted tenant's WAN policy — pattern=%q next_hops=%v.\n  body=%s",
			scoped.WanPattern, scoped.NextHops, sbody)
	}
	if strings.Contains(sbody, "203.0.113.7") {
		t.Errorf("RESTRICTION LEAK: as_tenant=acme WAN policy body carries acme's ISP next-hop: %s", sbody)
	}

	// ── the unrestricted tenant is reachable exactly as before.
	var gscoped policyResp
	f.asTenant(f.s.handleWanPolicy, "/api/wan/policy", f.globex, &gscoped)
	if gscoped.WanPattern == "acme-only-pattern" {
		t.Errorf("as_tenant=globex read acme's WAN policy: %+v", gscoped)
	}

	// ── acme's own access is undamaged.
	var ownAfter policyResp
	f.get(f.s.handleWanPolicy, "/api/wan/policy", f.acmeUser(), &ownAfter)
	if ownAfter.WanPattern != "acme-only-pattern" || ownAfter.NextHops["acme-wan/Ethernet1"] != "203.0.113.7" {
		t.Errorf("acme lost its own WAN policy when it restricted itself: %+v", ownAfter)
	}
}

// ── the publisher is NOT an operator read ────────────────────────────────────

// TestWanEchoPublisherKeepsMeasuringARestrictedTenant pins the boundary of the
// rule. The wan-echo target publisher is platform INFRASTRUCTURE acting on every
// tenant's behalf: each target carries its tenant label and the measurements come
// back to that tenant's own users. Narrowing it with the operator-visibility
// restriction would take a restricted tenant's path metrics away from the tenant
// ITSELF — the restriction governs operator READS, never collection (the same
// boundary that keeps licence usage, metering and netops_devices_total counting a
// restricted tenant's devices).
func TestWanEchoPublisherKeepsMeasuringARestrictedTenant(t *testing.T) {
	f := newRestrictedWanFixture(t)
	f.restrictAcme()

	_, circuits := f.s.wanProject(context.Background(), platformInfraDeviceVisibility())
	var sawAcme bool
	for _, c := range circuits {
		if c.Local.Device == "acme-wan" {
			sawAcme = true
		}
	}
	if !sawAcme {
		t.Error("the wan-echo publisher stopped projecting the restricted tenant's circuits — " +
			"that removes the tenant's OWN path measurements, which the restriction must never do")
	}
	// And the operator's read of the same projection does not see them.
	var global wanCircuitsResp
	f.get(f.s.handleWanCircuits, "/api/wan/circuits", f.owner(), &global)
	if global.locals()["acme-wan/Ethernet1"] {
		t.Error("the operator's Global circuit read still carries the restricted tenant's circuit")
	}
}
