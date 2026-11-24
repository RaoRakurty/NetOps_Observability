// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_tenant_isolation_test.go — §3a isolation for the cloud lane's tenant
// (tracker 392; template: org_isolation_test.go).
//
// The surface is the registry file Vector and the engine stamp cloud series
// from, and the platform owner's restricted Global view of those series:
//
//   - own-only: a cloud resource's key carries only the tenant whose inventory
//     lists it — never a tenant whose DEVICE shares the resource's name;
//   - cross-tenant: a resource two tenants list is a MISS (unattributable), and
//     no tenant can claim another's key by naming a device "cloud:<id>";
//   - restricted view: a restricted tenant's cloud series are hidden from the
//     Global view by resource id, and fail closed when its inventory is unread.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"netops/backend/cloud"
)

const (
	cloudIsoA = "t_alpha"
	cloudIsoB = "t_beta"
)

// cloudIsoServer: A's cloud resource i-a is NAMED web-1; B owns a device named
// web-1 and also lists the shared id arn:shared, which A lists too.
func cloudIsoServer(t *testing.T) *server {
	t.Helper()
	st := cloud.NewMemStore()
	ctx := context.Background()
	if err := st.ReplaceInventory(ctx, cloudIsoA, []cloud.CloudResource{
		{ResourceID: "i-a", ResourceName: "web-1"},
		{ResourceID: "arn:shared", ResourceName: "shared"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceInventory(ctx, cloudIsoB, []cloud.CloudResource{
		{ResourceID: "i-b", ResourceName: "api-1"},
		{ResourceID: "arn:shared", ResourceName: "shared"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	return &server{cloud: st}
}

type erroringCloudStore struct{ cloud.Store }

func (erroringCloudStore) ListResources(context.Context, string, bool) ([]cloud.CloudResource, error) {
	return nil, errors.New("pg: connection refused")
}

func TestCloudRegistryIsOwnOnlyAndNeverTakenFromADeviceName(t *testing.T) {
	s := cloudIsoServer(t)
	cloudRows, held := s.cloudRegistryRows()
	if held {
		t.Fatal("a readable inventory must not hold the export")
	}
	// B's device named like A's resource, and B trying to claim A's key outright.
	deviceRows := []enrichmentRow{
		{Identity: "web-1", Tenant: cloudIsoB},
		{Identity: "cloud:i-a", Tenant: cloudIsoB},
		{Identity: "Cloud:i-b", Tenant: cloudIsoA},
	}
	got := isoExport(t, mergeCloudRegistryRows(deviceRows, cloudRows))

	if got["cloud:i-a"]["tenant_id"] != cloudIsoA {
		t.Errorf("A's resource key = %q, want %q (own-only)", got["cloud:i-a"]["tenant_id"], cloudIsoA)
	}
	if got["cloud:i-b"]["tenant_id"] != cloudIsoB {
		t.Errorf("B's resource key = %q, want %q", got["cloud:i-b"]["tenant_id"], cloudIsoB)
	}
	if _, ok := got["cloud:arn:shared"]; ok {
		t.Error("a resource two tenants list must be a miss, not either tenant's")
	}
	if _, ok := got["Cloud:i-b"]; ok {
		t.Error("a device identity in the reserved namespace (any case) must be omitted")
	}
	if got["web-1"]["tenant_id"] != cloudIsoB {
		t.Errorf("B's own device row must be untouched, got %q", got["web-1"]["tenant_id"])
	}
	for id := range got {
		if strings.HasPrefix(strings.ToLower(id), "cloud:") && id != "cloud:i-a" && id != "cloud:i-b" {
			t.Errorf("unexpected cloud key %q in the registry", id)
		}
	}
}

func TestAnUnreadableCloudInventoryHoldsTheRegistry(t *testing.T) {
	s := &server{cloud: erroringCloudStore{}}
	if _, held := s.cloudRegistryRows(); !held {
		t.Fatal("an unread inventory must keep the previous file, not publish one without the cloud rows")
	}
	if rows, held := (&server{}).cloudRegistryRows(); held || len(rows) != 0 {
		t.Fatalf("no cloud store = no cloud rows and no hold, got %v held=%v", rows, held)
	}
}

func TestRestrictedGlobalViewHidesTheRestrictedTenantsCloudSeries(t *testing.T) {
	s := cloudIsoServer(t)
	ex := s.restrictedCloudExclusion([]string{cloudIsoA})
	if ex.all || len(ex.ids) != 2 {
		t.Fatalf("exclusion = %+v, want A's two resource ids", ex)
	}
	f := metricsExcludeFilters(nil, nil, []string{cloudIsoA}, ex)

	// A's cloud series, as VictoriaMetrics holds them: device = the resource
	// NAME, and a tenant_id that predates attribution ("" or a guessed tenant).
	for _, series := range []map[string]string{
		{"__name__": "cloud_cpu_utilization", "device": "web-1", "resource_id": "i-a", "tenant_id": ""},
		{"__name__": "cloud_cpu_utilization", "device": "web-1", "resource_id": "i-a", "tenant_id": cloudIsoB},
		{"__name__": "cloud_cpu_utilization", "device": "shared", "resource_id": "arn:shared", "tenant_id": ""},
	} {
		if admittedEx(f, series) {
			t.Errorf("a restricted tenant's cloud series reached the Global view: %v (filters %v)", series, f)
		}
	}
	// B's cloud series and an unrelated device series stay visible.
	if !admittedEx(f, map[string]string{"__name__": "cloud_cpu_utilization", "device": "api-1", "resource_id": "i-b", "tenant_id": cloudIsoB}) {
		t.Errorf("an unrestricted tenant's cloud series was over-excluded: %v", f)
	}
	if !admittedEx(f, map[string]string{"__name__": "device_cpu_percent", "device": "core-1"}) {
		t.Errorf("a device-lane series was excluded by the cloud clause: %v", f)
	}
}

func TestRestrictedGlobalViewFailsClosedWhenTheCloudInventoryIsUnread(t *testing.T) {
	s := &server{cloud: erroringCloudStore{}}
	ex := s.restrictedCloudExclusion([]string{cloudIsoA})
	if !ex.all {
		t.Fatalf("exclusion = %+v, want all (fail-closed)", ex)
	}
	f := metricsExcludeFilters(nil, nil, []string{cloudIsoA}, ex)
	if admittedEx(f, map[string]string{"__name__": "cloud_cpu_utilization", "device": "api-1", "resource_id": "i-b", "tenant_id": cloudIsoB}) {
		t.Errorf("with the inventory unread, NO cloud series may reach the Global view: %v", f)
	}
	if !admittedEx(f, map[string]string{"__name__": "device_cpu_percent", "device": "core-1"}) {
		t.Errorf("device-lane series must stay visible: %v", f)
	}
}

func TestRestrictedCloudExclusionFailsClosedPastTheQueryCap(t *testing.T) {
	st := cloud.NewMemStore()
	res := make([]cloud.CloudResource, 0, maxCloudExclusionIDs+1)
	for i := 0; i <= maxCloudExclusionIDs; i++ {
		res = append(res, cloud.CloudResource{ResourceID: "i-" + strconv.Itoa(i)})
	}
	if err := st.ReplaceInventory(context.Background(), cloudIsoA, res, nil); err != nil {
		t.Fatal(err)
	}
	if ex := (&server{cloud: st}).restrictedCloudExclusion([]string{cloudIsoA}); !ex.all {
		t.Fatalf("past the cap the view must fail closed, got %d ids", len(ex.ids))
	}
}

func TestNoRestrictionMeansNoCloudRead(t *testing.T) {
	s := &server{cloud: erroringCloudStore{}}
	if ex := s.restrictedCloudExclusion(nil); ex.all || len(ex.ids) != 0 {
		t.Fatalf("no restricted tenant = nothing to exclude, got %+v", ex)
	}
}
