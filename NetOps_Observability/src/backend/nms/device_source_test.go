// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeLister records how the source reads, so the tests can prove every read
// is tenant-scoped.
type fakeLister struct {
	ints    []Integration
	devs    map[string][]ControllerDevice // integration id → rows
	listErr error
	devErr  error
	calls   []string // "tenant|cross|id"
}

func (f *fakeLister) ListEnabled(context.Context) ([]Integration, error) { return f.ints, f.listErr }
func (f *fakeLister) Devices(_ context.Context, tenant string, cross bool, id string) ([]ControllerDevice, error) {
	f.calls = append(f.calls, tenant+"|"+map[bool]string{true: "cross", false: "scoped"}[cross]+"|"+id)
	if f.devErr != nil {
		return nil, f.devErr
	}
	return f.devs[id], nil
}

func cdev(key, name string, managed bool) ControllerDevice {
	return ControllerDevice{KeyKind: KeySystemIP, Key: key, Name: name, MgmtAddr: key, SourceSystem: "vmanage",
		Vendor: "cisco", Model: "vedge-cloud", OSVersion: "20.6.1", SiteID: "20", Role: "edge", Managed: managed,
		Aliases: map[string]string{"uuid": "u-" + key}, LastSeen: time.Unix(1792296433, 0).UTC()}
}

func TestControllerDeviceSourceMapsManagedDevicesOfEnabledIntegrations(t *testing.T) {
	f := &fakeLister{
		ints: []Integration{{Tenant: "t_retail", ID: "int-r", Vendor: "vmanage"}, {Tenant: "global", ID: "int-p", Vendor: "vmanage"}},
		devs: map[string][]ControllerDevice{
			"int-r": {cdev("10.255.255.20", "vEdge-20", true), cdev("10.255.255.2", "vSmart", false)},
			"int-p": {cdev("10.255.255.20", "vEdge-20", true)},
		},
	}
	out, err := NewControllerDeviceSource(f, 0).Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("%d devices — want the managed edge of each integration, never the vSmart", len(out))
	}
	for _, c := range f.calls {
		if !strings.Contains(c, "|scoped|") {
			t.Fatalf("a store read was not tenant-scoped: %v", f.calls)
		}
	}
	byTenant := map[string]string{}
	for _, d := range out {
		byTenant[d.TenantID] = d.ID
		if d.Source != ControllerSourceName || d.PreferredProtocol != "" || d.Address != "10.255.255.20" || d.Type != "router" {
			t.Fatalf("mapping %+v", d)
		}
		if d.Labels["system_ip"] != "10.255.255.20" || d.Labels["controller_site_id"] != "20" || d.Labels["site"] != "" || d.Labels["controller_uuid"] == "" {
			t.Fatalf("labels %v — the controller's site id must never be filed as the operator's site", d.Labels)
		}
		if d.OSVersion != "20.6.1" || d.OSVersionSource != "api:vmanage" {
			t.Fatalf("version provenance %+v", d)
		}
	}
	// The platform-owned integration's device is the platform's (""); the
	// same system-ip in two owners is two devices with different ids.
	if _, ok := byTenant[""]; !ok {
		t.Fatalf("platform-owned integration must yield platform devices: %v", byTenant)
	}
	if byTenant[""] == byTenant["t_retail"] || !strings.HasPrefix(byTenant["t_retail"], "ctl-vmanage-") {
		t.Fatalf("ids %v", byTenant)
	}
}

func TestControllerDeviceSourceFailsClosed(t *testing.T) {
	if _, err := NewControllerDeviceSource(nil, 0).Poll(context.Background()); err == nil {
		t.Fatal("an unwired source must fail, not report an empty fleet (an empty poll PRUNES)")
	}
	f := &fakeLister{listErr: errors.New("pg down")}
	if _, err := NewControllerDeviceSource(f, 0).Poll(context.Background()); err == nil {
		t.Fatal("a failed integration list must be returned")
	}
	f = &fakeLister{ints: []Integration{{Tenant: "t", ID: "i"}}, devErr: errors.New("rls")}
	if out, err := NewControllerDeviceSource(f, 0).Poll(context.Background()); err == nil || out != nil {
		t.Fatalf("a failed device read must be returned, never a shorter list: %v %v", out, err)
	}
}

func TestControllerDeviceIDIsStableAndOwnerBound(t *testing.T) {
	a := ControllerDeviceID("t_retail", "vmanage", KeySystemIP, "10.255.255.20")
	if a != ControllerDeviceID("T_RETAIL ", "vmanage", KeySystemIP, "10.255.255.20") {
		t.Fatal("owner spelling must not change the id")
	}
	if a == ControllerDeviceID("t_acme", "vmanage", KeySystemIP, "10.255.255.20") {
		t.Fatal("the same key in two tenants must be two ids")
	}
	if ControllerDeviceID("", "vmanage", KeySystemIP, "x") != ControllerDeviceID("global", "vmanage", KeySystemIP, "x") {
		t.Fatal(`the platform's two spellings ("" and "global") are one owner`)
	}
}
