// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"netops/backend/models"
	"netops/backend/nms"
)

// inventory_facts_test.go — model, site and role from the NMS onto the registry
// (tracker 387 PR 13a).

// fakeControllerStore is an nms.EnabledLister that records how it was read.
type fakeControllerStore struct {
	ints  []nms.Integration
	devs  map[string][]nms.ControllerDevice // integration id → devices
	err   error
	calls []string // "tenant|cross|integration"
}

func (f *fakeControllerStore) ListEnabled(context.Context) ([]nms.Integration, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ints, nil
}

func (f *fakeControllerStore) Devices(_ context.Context, tenant string, cross bool, id string) ([]nms.ControllerDevice, error) {
	f.calls = append(f.calls, tenant+"|"+map[bool]string{true: "cross", false: "scoped"}[cross]+"|"+id)
	var out []nms.ControllerDevice
	for _, d := range f.devs[id] {
		if d.TenantID == tenant { // the real store's RLS
			out = append(out, d)
		}
	}
	return out, nil
}

// labControllerDevices is the lab vManage's device list as controller_devices
// holds it (read 2026-11-10), owned by the given integration owner.
func labControllerDevices(tenant string) []nms.ControllerDevice {
	row := func(sys, name, model, site, role string) nms.ControllerDevice {
		return nms.ControllerDevice{TenantID: tenant, IntegrationID: "nmsi-668f5b96d5ce7857", SourceSystem: "vmanage",
			KeyKind: nms.KeySystemIP, Key: sys, Name: name, MgmtAddr: sys, Model: model, SiteID: site, Role: role,
			Managed: role == nms.RoleEdge}
	}
	return []nms.ControllerDevice{
		row("10.255.255.1", "vManage", "vmanage", "250", nms.RoleManager),
		row("10.255.255.2", "vSmart", "vsmart", "250", nms.RoleController),
		row("10.255.255.3", "vBond", "vedge-cloud", "250", nms.RoleOrchestrator),
		row("10.255.255.40", "cEDGE-40", "vedge-CSR-1000v", "40", nms.RoleEdge),
		row("10.255.255.60", "cEDGE-60", "vedge-CSR-1000v", "60", nms.RoleEdge),
		row("10.255.255.80", "cEDGE-80", "vedge-CSR-1000v", "80", nms.RoleEdge),
		row("10.255.255.81", "cEDGE-81", "vedge-CSR-1000v", "81", nms.RoleEdge),
		row("10.255.255.100", "vEdge-100", "vedge-cloud", "100", nms.RoleEdge),
		row("10.255.255.20", "vEdge-20", "vedge-cloud", "20", nms.RoleEdge),
		row("10.255.255.51", "vEdge-51", "vedge-cloud", "50", nms.RoleEdge),
		row("10.255.255.52", "vEdge-52", "vedge-cloud", "50", nms.RoleEdge),
	}
}

// labSNMPEdges is the eight SNMP-scanned edges as the registry holds them
// today (vendor only), with the given owner, and — when merged — the
// controller twin's system_ip label discovery carries after the merge.
func labSNMPEdges(tenant string, merged bool) []models.Device {
	edges := [][3]string{
		{"vedge-51-0a0b4db5", "vEdge-51", "51"}, {"vedge-52-749b1687", "vEdge-52", "52"},
		{"vedge-100-c9b717ef", "vEdge-100", "100"}, {"vedge-20-1e95f00f", "vEdge-20", "20"},
		{"cedge-80-9beba319", "cEDGE-80", "80"}, {"cedge-81-11060ae2", "cEDGE-81", "81"},
		{"cedge-40-b99e47eb", "cEDGE-40", "40"}, {"cedge-60-2199eef8", "cEDGE-60", "60"},
	}
	addr := map[string]string{"vEdge-51": "101", "vEdge-52": "102", "vEdge-100": "103", "vEdge-20": "104",
		"cEDGE-80": "105", "cEDGE-81": "106", "cEDGE-40": "107", "cEDGE-60": "108"}
	var out []models.Device
	for _, e := range edges {
		d := models.Device{ID: e[0], Name: e[1], Address: "192.168.222." + addr[e[1]], Vendor: "cisco", TenantID: tenant, Source: "snmp"}
		if merged {
			d.Labels = map[string]string{"system_ip": "10.255.255." + e[2]}
		}
		out = append(out, d)
	}
	return out
}

func resolverOver(devs []models.Device) *nms.InventoryResolver {
	r := &nms.InventoryResolver{}
	r.Store(nms.BuildInventoryIndex(devs, nil, nil))
	return r
}

func rowsByIdentity(rows []enrichmentRow) map[string]enrichmentRow {
	out := map[string]enrichmentRow{}
	for _, r := range rows {
		out[r.Identity] = r
	}
	return out
}

func TestResolveDeviceFactsPrecedence(t *testing.T) {
	votes := func(model, site, role []string) *factVotes {
		v := newFactVotes()
		for _, m := range model {
			v.models[m] = true
		}
		for _, s := range site {
			v.sites[s] = true
		}
		for _, r := range role {
			v.roles[r] = true
		}
		return v
	}
	cases := []struct {
		name   string
		d      models.Device
		manual string
		v      *factVotes
		want   invDeviceFacts
	}{
		{"nothing states anything", models.Device{}, "", nil, invDeviceFacts{
			model: factOutcome{"", factSourceNone, factStateBlank}, site: factOutcome{"", factSourceNone, factStateBlank}, role: factOutcome{"", factSourceNone, factStateBlank}}},
		{"NMS fills all three", models.Device{}, "", votes([]string{"vedge-CSR-1000v"}, []string{"81"}, []string{"edge"}), invDeviceFacts{
			model: factOutcome{"vedge-CSR-1000v", factSourceNMS, factStateSet}, site: factOutcome{"81", factSourceNMS, factStateSet}, role: factOutcome{"edge", factSourceNMS, factStateSet}}},
		{"manual site and role win over the NMS", models.Device{Labels: map[string]string{"role": "hub"}}, "dc-east", votes(nil, []string{"81"}, []string{"edge"}), invDeviceFacts{
			model: factOutcome{"", factSourceNone, factStateBlank}, site: factOutcome{"dc-east", factSourceManual, factStateSet}, role: factOutcome{"hub", factSourceManual, factStateSet}}},
		{"inventory model agrees with the NMS", models.Device{Model: "vedge-CSR-1000v"}, "", votes([]string{"vedge-CSR-1000v"}, nil, nil), invDeviceFacts{
			model: factOutcome{"vedge-CSR-1000v", factSourceNMS, factStateSet}, site: factOutcome{"", factSourceNone, factStateBlank}, role: factOutcome{"", factSourceNone, factStateBlank}}},
		{"inventory model alone", models.Device{Model: "C8300", Type: "router"}, "", nil, invDeviceFacts{
			model: factOutcome{"C8300", factSourceInventory, factStateSet}, site: factOutcome{"", factSourceNone, factStateBlank}, role: factOutcome{"router", factSourceInventory, factStateSet}}},
		{"inventory and NMS disagree: blank", models.Device{Model: "CSR1000V"}, "", votes([]string{"vedge-CSR-1000v"}, nil, nil), invDeviceFacts{
			model: factOutcome{"", factSourceNMS, factStateConflict}, site: factOutcome{"", factSourceNone, factStateBlank}, role: factOutcome{"", factSourceNone, factStateBlank}}},
		{"two controllers disagree: blank, and no type fallback", models.Device{Type: "router"}, "", votes(nil, []string{"40", "41"}, []string{"edge", "controller"}), invDeviceFacts{
			model: factOutcome{"", factSourceNone, factStateBlank}, site: factOutcome{"", factSourceNMS, factStateConflict}, role: factOutcome{"", factSourceNMS, factStateConflict}}},
	}
	for _, c := range cases {
		if got := resolveDeviceFacts(c.d, c.manual, c.v); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

// The lab, once the controller and the SNMP twins have one owner (here the
// platform's own integration): every edge's model, site and role reach the
// registry, on every identity of the device.
func TestRegistryStampsTheLabsNMSFacts(t *testing.T) {
	devs := labSNMPEdges("", true)
	store := &fakeControllerStore{
		ints: []nms.Integration{{Tenant: "global", ID: "nmsi-668f5b96d5ce7857", Vendor: "vmanage", Enabled: true}},
		devs: map[string][]nms.ControllerDevice{"nmsi-668f5b96d5ce7857": labControllerDevices("global")},
	}
	f := newInventoryFacts()
	if err := f.refresh(context.Background(), store, resolverOver(devs).Peek); err != nil {
		t.Fatal(err)
	}
	if len(store.calls) != 1 || store.calls[0] != "global|scoped|nmsi-668f5b96d5ce7857" {
		t.Fatalf("the device list must be read tenant-scoped, as the integration's owner: %v", store.calls)
	}
	rows, stats := buildEnrichmentRowsFacts(devs, nil, f.current())
	got := rowsByIdentity(rows)
	want := map[string][3]string{ // identity → model, site, role
		"cedge-81-11060ae2":  {"vedge-CSR-1000v", "81", "edge"},
		"cEDGE-81":           {"vedge-CSR-1000v", "81", "edge"},
		"192.168.222.106":    {"vedge-CSR-1000v", "81", "edge"},
		"cedge-40-b99e47eb":  {"vedge-CSR-1000v", "40", "edge"},
		"cedge-60-2199eef8":  {"vedge-CSR-1000v", "60", "edge"},
		"cedge-80-9beba319":  {"vedge-CSR-1000v", "80", "edge"},
		"vedge-20-1e95f00f":  {"vedge-cloud", "20", "edge"},
		"vedge-51-0a0b4db5":  {"vedge-cloud", "50", "edge"},
		"vedge-52-749b1687":  {"vedge-cloud", "50", "edge"},
		"vedge-100-c9b717ef": {"vedge-cloud", "100", "edge"},
	}
	for id, w := range want {
		r := got[id]
		if r.Model != w[0] || r.Site != w[1] || r.Role != w[2] || r.Tenant != "" || r.Vendor != "cisco" {
			t.Errorf("%s: %+v, want model/site/role %v (tenant and vendor unchanged)", id, r, w)
		}
	}
	for _, k := range []factStatKey{{factModel, factSourceNMS, factStateSet}, {factSite, factSourceNMS, factStateSet}, {factRole, factSourceNMS, factStateSet}} {
		if stats[k] != 8 {
			t.Errorf("stats %v = %d, want 8", k, stats[k])
		}
	}
}

// The lab as it stands: the integration is RETAIL-WALMART's, the SNMP edges
// the platform's. RETAIL-WALMART's controller may name only its own devices, so
// the platform rows keep exactly what they had (§3a), and the model, site and
// role stay blank until the owners are aligned.
func TestRegistryFactsNeverCrossFromAnotherOwnersController(t *testing.T) {
	const retail = "t_c8afbc3445ca56b4fa54887d3e548c27"
	devs := labSNMPEdges("", true) // even with the system_ip label a merge would leave
	store := &fakeControllerStore{
		ints: []nms.Integration{{Tenant: retail, ID: "nmsi-668f5b96d5ce7857", Vendor: "vmanage", Enabled: true}},
		devs: map[string][]nms.ControllerDevice{"nmsi-668f5b96d5ce7857": labControllerDevices(retail)},
	}
	f := newInventoryFacts()
	if err := f.refresh(context.Background(), store, resolverOver(devs).Peek); err != nil {
		t.Fatal(err)
	}
	if len(f.current()) != 0 {
		t.Fatalf("another owner's controller voted on platform devices: %v", f.current())
	}
	before := rowsByIdentity(buildEnrichmentRows(devs))
	rows, stats := buildEnrichmentRowsFacts(devs, nil, f.current())
	for id, r := range rowsByIdentity(rows) {
		if r != before[id] {
			t.Errorf("%s changed: %+v → %+v", id, before[id], r)
		}
		if r.Model != "" || r.Site != "" || r.Role != "" {
			t.Errorf("%s gained a fact: %+v", id, r)
		}
	}
	if stats[factStatKey{factModel, factSourceNone, factStateBlank}] != 8 {
		t.Fatalf("stats %v", stats)
	}
}

func TestInventoryFactsRefreshFailureKeepsThePreviousFacts(t *testing.T) {
	devs := labSNMPEdges("", true)
	store := &fakeControllerStore{
		ints: []nms.Integration{{Tenant: "global", ID: "i1", Vendor: "vmanage", Enabled: true}},
		devs: map[string][]nms.ControllerDevice{"i1": labControllerDevices("global")},
	}
	f := newInventoryFacts()
	if err := f.refresh(context.Background(), store, resolverOver(devs).Peek); err != nil {
		t.Fatal(err)
	}
	n := len(f.current())
	store.err = errors.New("pg down")
	if err := f.refresh(context.Background(), store, resolverOver(devs).Peek); err == nil {
		t.Fatal("a failed read was not reported")
	}
	if len(f.current()) != n || n == 0 {
		t.Fatalf("a failed read changed the facts: %d → %d", n, len(f.current()))
	}
	var b bytes.Buffer
	f.setStats(map[factStatKey]int{{factModel, factSourceNMS, factStateSet}: 8})
	f.WriteMetrics(&b)
	out := b.String()
	for _, line := range []string{
		`netops_inventory_facts{fact="model",source="nms",state="set"} 8`,
		`netops_inventory_facts{fact="role",source="none",state="blank"} 0`,
		`netops_inventory_facts_read_failures_total 1`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing %q in\n%s", line, out)
		}
	}
	if strings.Count(out, "netops_inventory_facts{") != len(factStatKeys()) {
		t.Fatal("label set not closed / zero-filled")
	}
	for _, bad := range []string{"tenant", "device="} {
		if strings.Contains(out, bad) {
			t.Fatalf("label %q on a platform series", bad)
		}
	}
	// nil-safe
	var nf *inventoryFacts
	nf.WriteMetrics(&b)
	nf.setStats(nil)
	if nf.current() != nil {
		t.Fatal("nil current")
	}
}

// Without NMS facts the registry is byte-for-byte what PR 12 wrote.
func TestRegistryWithoutNMSFactsIsUnchanged(t *testing.T) {
	devs := isoDevices()
	a := buildEnrichmentRows(devs)
	b, _ := buildEnrichmentRowsFacts(devs, nil, map[factKey]*factVotes{})
	if len(a) != len(b) {
		t.Fatalf("rows %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("row %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}
