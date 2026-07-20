package main

// stampSpineCloudIdentity (truthfulness epic / topology task): provider marks
// and human names come ONLY from declared inventory — cloud NIC/EIP bindings
// and the tenant's device records. Tenant-scoped; unclaimed addresses and
// already-named hops are untouched. Includes the §3a cross-tenant assertion.

import (
	"context"
	"testing"

	"netops/backend/cloud"
	"netops/backend/pathgraph"
)

func TestStampSpineCloudIdentity(t *testing.T) {
	ctx := context.Background()
	s := &server{cloud: newCloudStore()}
	_ = s.cloud.ReplaceInventory(ctx, "org-a", []cloud.CloudResource{
		{ResourceID: "i-app", Provider: cloud.AWS, ResourceName: "correlix-aws-app-host-01",
			PrivateIPs: []string{"10.60.10.10"}},
		{ResourceID: "vm-app", Provider: cloud.Azure, AppName: "booking",
			PrivateIPs: []string{"10.61.10.10"}, PublicIPs: []string{"20.9.199.16"}},
	}, nil)

	spine := &pathgraph.Spine{Spine: []pathgraph.SpineNode{
		{Index: 0, Label: "client-pc", Address: "192.168.1.10"},  // unclaimed → untouched
		{Index: 1, Label: "10.60.10.10", Address: "10.60.10.10"}, // cloud-claimed, IP-labelled → named + marked
		{Index: 2, Label: "edge-fw-01", Address: "10.61.10.10"},  // already named → mark only
		{Index: 3, Label: "", Address: "20.9.199.16"},            // public EIP → named + marked
	}}
	s.stampSpineCloudIdentity(ctx, "org-a", spine)

	if spine.Spine[0].Provider != "" || spine.Spine[0].Label != "client-pc" {
		t.Fatalf("unclaimed hop mutated: %+v", spine.Spine[0])
	}
	if spine.Spine[1].Provider != "aws" || spine.Spine[1].Label != "correlix-aws-app-host-01" {
		t.Fatalf("aws hop not identified: %+v", spine.Spine[1])
	}
	if spine.Spine[2].Provider != "azure" || spine.Spine[2].Label != "edge-fw-01" {
		t.Fatalf("named hop must keep its name, gain only the mark: %+v", spine.Spine[2])
	}
	if spine.Spine[3].Provider != "azure" || spine.Spine[3].Label != "booking" {
		t.Fatalf("public EIP not identified: %+v", spine.Spine[3])
	}

	// §3a — another tenant's inventory must not name/mark this tenant's spine.
	other := &pathgraph.Spine{Spine: []pathgraph.SpineNode{
		{Index: 0, Label: "10.60.10.10", Address: "10.60.10.10"},
	}}
	s.stampSpineCloudIdentity(ctx, "org-b", other)
	if other.Spine[0].Provider != "" || other.Spine[0].Label != "10.60.10.10" {
		t.Fatalf("cross-tenant identity leak: %+v", other.Spine[0])
	}
}
