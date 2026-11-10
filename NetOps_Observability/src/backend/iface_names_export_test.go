// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

func ifaceFixtureDevices() []models.Device {
	return []models.Device{
		{ID: "acme-core", Address: "10.1.0.1", TenantID: "acme"},
		{ID: "globex-core", Address: "10.2.0.1:161", TenantID: "globex"},
		{ID: "vedge-20", Address: "10.70.245.104"}, // platform-owned
	}
}

func ifaceFixtureMap() map[string]map[string]string {
	return map[string]map[string]string{
		"acme-core":   {"4": "Gi4", "1": "Gi1"},
		"globex-core": {"4": "GLOBEX-Gi4"},
		"vedge-20":    {"1": "ge0/0", "2": "ge0/1", "4": "ge0/3", "5": "system"},
	}
}

// §3a: a row's tenant is its DEVICE's tenant from inventory. acme's device
// gives acme rows, globex's gives globex rows, the platform device gives ”.
func TestIfaceNamesExportStampsTenantFromInventory(t *testing.T) {
	rows, truncated := buildIfaceNameRows(ifaceFixtureDevices(), ifaceFixtureMap(), ifaceNamesMaxRows)
	if truncated != 0 {
		t.Fatalf("truncated %d, want 0", truncated)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.DeviceID+"|"+ifx32(r.IfIndex)] = r.TenantID + "|" + r.ExporterAddr + "|" + r.IfName
	}
	want := map[string]string{
		"acme-core|1":   "acme|10.1.0.1|Gi1",
		"acme-core|4":   "acme|10.1.0.1|Gi4",
		"globex-core|4": "globex|10.2.0.1|GLOBEX-Gi4", // host:port reduced to the IP flows carry
		"vedge-20|1":    "|10.70.245.104|ge0/0",
		"vedge-20|2":    "|10.70.245.104|ge0/1",
		"vedge-20|4":    "|10.70.245.104|ge0/3",
		"vedge-20|5":    "|10.70.245.104|system",
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("row %s = %q, want %q", k, got[k], v)
		}
	}

	// A device that moved tenant is re-stamped on the next build.
	devs := ifaceFixtureDevices()
	devs[0].TenantID = "initech"
	rows, _ = buildIfaceNameRows(devs, ifaceFixtureMap(), ifaceNamesMaxRows)
	for _, r := range rows {
		if r.DeviceID == "acme-core" && r.TenantID != "initech" {
			t.Errorf("moved device still stamped %q, want initech", r.TenantID)
		}
	}
}

// Never invent a name: sentinels, blank names and an address two devices of
// one tenant share produce no row. The same address in two tenants is two rows.
func TestIfaceNamesExportNeverInvents(t *testing.T) {
	devs := []models.Device{
		{ID: "a1", Address: "10.0.0.1", TenantID: "acme"},
		{ID: "a2", Address: "10.0.0.1", TenantID: "acme"}, // shares a1's address
		{ID: "g1", Address: "10.0.0.1", TenantID: "globex"},
		{ID: "x", Address: "not-an-ip"},
	}
	m := map[string]map[string]string{
		"a1": {"1": "Gi1"},
		"a2": {"1": "Gi1-other"},
		"g1": {"0": "zero", "4294967295": "none", "2": "  ", "3": "Gi3", "bad": "Gi9"},
		"x":  {"1": "eth0"},
	}
	rows, _ := buildIfaceNameRows(devs, m, ifaceNamesMaxRows)
	if len(rows) != 1 || rows[0].DeviceID != "g1" || rows[0].IfIndex != 3 || rows[0].TenantID != "globex" {
		t.Fatalf("rows = %+v, want only g1/3 in globex", rows)
	}
	long := strings.Repeat("x", 500)
	rows, _ = buildIfaceNameRows([]models.Device{{ID: "d", Address: "10.0.0.9"}}, map[string]map[string]string{"d": {"1": long}}, 10)
	if len([]rune(rows[0].IfName)) != ifaceNameMaxRunes {
		t.Errorf("device-reported name not bounded: %d runes", len([]rune(rows[0].IfName)))
	}
}

// The export is bounded, and a truncation is counted and exposed.
func TestIfaceNamesExportBounded(t *testing.T) {
	rows, truncated := buildIfaceNameRows(ifaceFixtureDevices(), ifaceFixtureMap(), 3)
	if len(rows) != 3 || truncated != 4 {
		t.Fatalf("rows=%d truncated=%d, want 3 and 4", len(rows), truncated)
	}
	e := newIfaceNameExporter()
	big := map[string]map[string]string{"d": {}}
	for i := 1; i <= ifaceNamesMaxRows+5; i++ {
		big["d"][ifx32(uint32(i))] = "p"
	}
	read := func(context.Context) (map[string]map[string]string, error) { return big, nil }
	var wrote int
	write := func(_ context.Context, b []map[string]any) error { wrote = len(b); return nil }
	if err := e.cycle(context.Background(), []models.Device{{ID: "d", Address: "10.0.0.1"}}, read, write, time.Now()); err != nil {
		t.Fatal(err)
	}
	if wrote != ifaceNamesMaxRows || e.truncated.Load() != 5 {
		t.Fatalf("wrote %d truncated %d, want %d and 5", wrote, e.truncated.Load(), ifaceNamesMaxRows)
	}
	var buf bytes.Buffer
	e.WriteMetrics(&buf)
	for _, want := range []string{
		"netops_iface_names_truncated_total 5\n",
		"netops_iface_names_rows{source=\"snmp\"} 200000\n",
		"netops_iface_names_exporters_uncovered -1\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, buf.String())
		}
	}
}

// A read failure keeps the last good names (an unread bridge is not "no
// names"); an unchanged set is not rewritten until the refresh is due; a write
// failure is counted.
func TestIfaceNamesCycleKeepsLastGoodAndRefreshes(t *testing.T) {
	e := newIfaceNameExporter()
	devs := ifaceFixtureDevices()
	ok := func(context.Context) (map[string]map[string]string, error) { return ifaceFixtureMap(), nil }
	writes := 0
	write := func(context.Context, []map[string]any) error { writes++; return nil }
	t0 := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if err := e.cycle(context.Background(), devs, ok, write, t0); err != nil {
		t.Fatal(err)
	}
	if n, hit := e.lookup("", "10.70.245.104", 4); !hit || n != "ge0/3" {
		t.Fatalf("lookup vedge-20/4 = %q,%v, want ge0/3", n, hit)
	}
	if err := e.cycle(context.Background(), devs, ok, write, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("unchanged set rewritten: %d writes, want 1", writes)
	}
	if err := e.cycle(context.Background(), devs, ok, write, t0.Add(ifaceNamesRefreshEvery+time.Minute)); err != nil {
		t.Fatal(err)
	}
	if writes != 2 {
		t.Fatalf("refresh not written inside the TTL: %d writes, want 2", writes)
	}
	bad := func(context.Context) (map[string]map[string]string, error) { return nil, errors.New("valkey down") }
	if err := e.cycle(context.Background(), devs, bad, write, t0.Add(2*ifaceNamesRefreshEvery)); err == nil {
		t.Fatal("an unread bridge must be an error")
	}
	if n, hit := e.lookup("", "10.70.245.104", 4); !hit || n != "ge0/3" || e.readFailures.Load() != 1 {
		t.Fatalf("read failure dropped the last good names (%q,%v) or was not counted (%d)", n, hit, e.readFailures.Load())
	}
	failing := func(context.Context, []map[string]any) error { return errors.New("ch down") }
	changed := func(context.Context) (map[string]map[string]string, error) {
		m := ifaceFixtureMap()
		m["vedge-20"]["4"] = "ge0/3-renamed"
		return m, nil
	}
	if err := e.cycle(context.Background(), devs, changed, failing, t0.Add(3*ifaceNamesRefreshEvery)); err == nil || e.writeFailures.Load() != 1 {
		t.Fatalf("write failure not reported (%v) or not counted (%d)", err, e.writeFailures.Load())
	}
}

// The in-memory lookup is keyed by the ROW's tenant: acme's name for an
// exporter never answers a globex row for the same exporter, and sentinels
// never name.
func TestIfaceNameLookupKeyedByRowTenant(t *testing.T) {
	e := newIfaceNameExporter()
	e.install([]ifaceNameRow{
		{TenantID: "acme", ExporterAddr: "10.0.0.1", IfIndex: 4, IfName: "ACME-Gi4"},
		{TenantID: "", ExporterAddr: "10.0.0.2", IfIndex: 4, IfName: "ge0/3"},
	})
	if _, hit := e.lookup("globex", "10.0.0.1", 4); hit {
		t.Fatal("TENANT LEAK: acme's interface name resolved on a globex row")
	}
	if _, hit := e.lookup("", "10.0.0.1", 4); hit {
		t.Fatal("TENANT LEAK: acme's interface name resolved on a platform row")
	}
	if n, hit := e.lookup("acme", "10.0.0.1", 4); !hit || n != "ACME-Gi4" {
		t.Fatalf("acme's own row: %q,%v", n, hit)
	}
	if _, hit := e.lookup("acme", "10.0.0.2", 4); hit {
		t.Fatal("a platform device's name must not answer a row another tenant owns")
	}
	for _, s := range []uint32{0, 4294967295} {
		if _, hit := e.lookup("", "10.0.0.2", s); hit {
			t.Errorf("sentinel %d named", s)
		}
	}
}

func ifx32(n uint32) string { return intToString(int(n)) }
