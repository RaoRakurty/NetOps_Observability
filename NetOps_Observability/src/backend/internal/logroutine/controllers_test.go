// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/nms"
)

// fakeStore is a tenant-partitioned NMS store. It records which tenant each
// read ran under, so the test can prove no read crossed a tenant.
type fakeStore struct {
	ints    []nms.Integration
	devs    map[string][]nms.ControllerDevice // tenant\x00integration → devices
	listErr error
	reads   []string
}

func (f *fakeStore) List(_ context.Context, tenant string, cross bool) ([]nms.Integration, error) {
	f.reads = append(f.reads, "list:"+tenant)
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []nms.Integration
	for _, ic := range f.ints {
		if cross || ic.Tenant == tenant {
			out = append(out, ic)
		}
	}
	return out, nil
}

func (f *fakeStore) Devices(_ context.Context, tenant string, cross bool, id string) ([]nms.ControllerDevice, error) {
	f.reads = append(f.reads, "devices:"+tenant+"/"+id)
	if cross {
		return nil, errors.New("test store: a cross-tenant device read is not expected")
	}
	return f.devs[tenant+"\x00"+id], nil
}

func twoTenantStore() *fakeStore {
	return &fakeStore{
		ints: []nms.Integration{
			{Tenant: "acme", ID: "vm1", Enabled: true, BaseURL: "https://10.70.245.200:8443"},
			{Tenant: "acme", ID: "off", Enabled: false, BaseURL: "https://10.9.9.9"},
			{Tenant: "globex", ID: "vm2", Enabled: true, BaseURL: "https://vmanage.globex.example"},
		},
		devs: map[string][]nms.ControllerDevice{
			"acme\x00vm1": {
				{KeyKind: nms.KeySystemIP, Key: "10.255.255.1", MgmtAddr: "10.255.255.1", Role: "controller", Managed: false},
				{KeyKind: nms.KeySystemIP, Key: "10.255.255.3", MgmtAddr: "", Role: "controller", Aliases: map[string]string{"system_ip": "10.255.255.3"}},
				{KeyKind: nms.KeySystemIP, Key: "10.255.255.51", MgmtAddr: "10.255.255.51", Role: "edge", Managed: true},
			},
			"acme\x00off":   {{KeyKind: nms.KeySystemIP, Key: "10.9.9.10", Managed: false}},
			"globex\x00vm2": {{KeyKind: nms.KeySystemIP, Key: "172.16.255.1", MgmtAddr: "172.16.255.1", Managed: false}},
		},
	}
}

// §3a: a tenant's controller addresses come only from its own integrations.
// An edge (Managed) is never a controller, a disabled integration contributes
// nothing, and the integration's own address counts when it is an IP.
func TestControllerAddrsAreTenantScoped(t *testing.T) {
	st := twoTenantStore()
	c := NewControllerAddrs(st, time.Minute, nil)
	got, err := c.Addrs(context.Background(), "acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "10.255.255.1,10.255.255.3,10.70.245.200" {
		t.Fatalf("acme controller addrs = %v", got)
	}
	for _, r := range st.reads {
		if strings.Contains(r, "globex") {
			t.Fatalf("TENANT LEAK: acme's resolution read %q", r)
		}
	}

	globex, err := c.Addrs(context.Background(), "globex", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(globex, ",") != "172.16.255.1" {
		t.Fatalf("globex controller addrs = %v (acme's must not appear)", globex)
	}

	// A cross-tenant principal reads every tenant, each under its OWNER.
	all, err := c.Addrs(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(all, ",") != "10.255.255.1,10.255.255.3,10.70.245.200,172.16.255.1" {
		t.Fatalf("cross addrs = %v", all)
	}
}

func TestControllerAddrsCacheAndErrors(t *testing.T) {
	st := twoTenantStore()
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	c := NewControllerAddrs(st, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	if _, err := c.Addrs(ctx, "acme", false); err != nil {
		t.Fatal(err)
	}
	n := len(st.reads)
	if _, err := c.Addrs(ctx, "acme", false); err != nil || len(st.reads) != n {
		t.Fatalf("a second read inside the TTL hit the store (%d → %d)", n, len(st.reads))
	}
	// A different scope is its own entry: own and cross never share one.
	if _, err := c.Addrs(ctx, "acme", true); err != nil || len(st.reads) == n {
		t.Fatal("the cross scope reused the tenant scope's entry")
	}
	now = now.Add(2 * time.Minute)
	n = len(st.reads)
	if _, err := c.Addrs(ctx, "acme", false); err != nil || len(st.reads) == n {
		t.Fatal("an expired entry was not re-read")
	}

	// A store error is returned with no addresses: fewer records hidden, never more.
	st.listErr = errors.New("pg down")
	now = now.Add(2 * time.Minute)
	got, err := c.Addrs(ctx, "acme", false)
	if err == nil || got != nil {
		t.Fatalf("store error: got %v, %v", got, err)
	}

	// No store (no controller integrations on this install): nothing, no error.
	var none *ControllerAddrs
	if got, err := none.Addrs(ctx, "acme", false); got != nil || err != nil {
		t.Fatalf("nil resolver = %v, %v", got, err)
	}
	if got, err := NewControllerAddrs(nil, 0, nil).Addrs(ctx, "acme", false); got != nil || err != nil {
		t.Fatalf("nil store = %v, %v", got, err)
	}
}
