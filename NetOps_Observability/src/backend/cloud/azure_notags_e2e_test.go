// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// azure_notags_e2e_test.go — end-to-end attribution of an Azure subscription the
// way the live one actually arrives: VMs with EMPTY tags (the monitoring service
// principal is read-only Reader + Monitoring Reader; it CANNOT write tags). The
// contract: Correlix still discovers and GROUPS the resources by the built-in
// service inference the poller wrote into azure.json — no tag required, no write
// needed. A second subscription with PARTIAL tags proves a present tag still wins
// and its value is used, while its untagged siblings fall back to inference.

import (
	"context"
	"testing"
)

// A poller-written azure.json for a fully UNTAGGED subscription — every VM has
// tags:{} but carries the inferred_service the built-in mapping derived from the
// resource-group name + shared-subnet structure (service_infer.py).
const azureNoTagsFixture = `{
  "provider": "azure", "account_id": "sub-untagged",
  "collection": {"mode": "live_poller", "collected_at": "2026-07-15T08:00:00Z"},
  "resources": [
    {"resource_id": "/subscriptions/s/resourceGroups/rg-payments-prod/providers/Microsoft.Compute/virtualMachines/web01",
     "resource_name": "web01", "resource_type": "compute:virtualMachine", "private_ips": ["10.1.0.11"], "tags": {},
     "inferred_service": "payments", "inferred_service_confidence": "strong",
     "inferred_service_basis": "resource-group name 'rg-payments-prod'; 2 resources share subnet 'app-tier'"},
    {"resource_id": "/subscriptions/s/resourceGroups/rg-payments-prod/providers/Microsoft.Compute/virtualMachines/web02",
     "resource_name": "web02", "resource_type": "compute:virtualMachine", "private_ips": ["10.1.0.12"], "tags": {},
     "inferred_service": "payments", "inferred_service_confidence": "strong",
     "inferred_service_basis": "resource-group name 'rg-payments-prod'; 2 resources share subnet 'app-tier'"},
    {"resource_id": "/subscriptions/s/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01",
     "resource_name": "vm-01", "resource_type": "compute:virtualMachine", "private_ips": ["10.1.9.9"], "tags": {}}
  ]
}`

func TestAzure_NoTags_StillDiscoversAndGroups(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "azure.json", azureNoTagsFixture)
	p := NewFixtureProvider(dir)

	res, err := p.ListResources(context.Background(), "t_acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("empty tags must NOT drop resources: want 3, got %d", len(res))
	}
	byID := map[string]CloudResource{}
	for _, r := range res {
		byID[r.ResourceName] = r
	}
	// The two payments VMs group under the inferred service, honestly labeled.
	for _, name := range []string{"web01", "web02"} {
		r := byID[name]
		if r.AppID != "payments" || r.Source != SrcInferredService || r.Confidence != Strong {
			t.Fatalf("%s: untagged VM must attribute via inference to payments, got %+v", name, r)
		}
	}
	// The lone generic VM has no usable signal → stays honestly unknown, not
	// force-named. (Its inventory row still exists — it's discovered, just not
	// attributed.)
	if r := byID["vm-01"]; r.AppID != "" || r.Confidence == Confirmed {
		t.Fatalf("vm-01 must stay unattributed (no signal), got %+v", r)
	}
	// Identity mappings still emit for the untagged fleet, so flow/alerts
	// surfaces can name the inferred service on every private IP.
	maps, err := p.ListIdentityMappings(context.Background(), "t_acme", "")
	if err != nil {
		t.Fatal(err)
	}
	var payMapped int
	for _, m := range maps {
		if m.AppID == "payments" && m.MatchKeyType == MatchPrivateIP {
			payMapped++
		}
	}
	if payMapped != 2 {
		t.Fatalf("both payments IPs must map to the inferred service, got %d", payMapped)
	}
}

// A subscription where SOME resources are tagged: the tag is used verbatim (and
// beats inference), untagged siblings fall back to inference.
const azurePartialTagsFixture = `{
  "provider": "azure", "account_id": "sub-partial",
  "collection": {"mode": "live_poller", "collected_at": "2026-07-15T08:00:00Z"},
  "resources": [
    {"resource_id": "/subscriptions/s/resourceGroups/rg-orders/providers/Microsoft.Compute/virtualMachines/api01",
     "resource_name": "api01", "resource_type": "compute:virtualMachine", "private_ips": ["10.2.0.1"],
     "tags": {"app": "checkout", "env": "prod"},
     "inferred_service": "orders", "inferred_service_confidence": "strong"},
    {"resource_id": "/subscriptions/s/resourceGroups/rg-orders/providers/Microsoft.Compute/virtualMachines/api02",
     "resource_name": "api02", "resource_type": "compute:virtualMachine", "private_ips": ["10.2.0.2"], "tags": {},
     "inferred_service": "orders", "inferred_service_confidence": "strong"}
  ]
}`

func TestAzure_PartialTags_TagWinsSiblingInferred(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "azure.json", azurePartialTagsFixture)
	p := NewFixtureProvider(dir)
	res, err := p.ListResources(context.Background(), "t_acme", "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]CloudResource{}
	for _, r := range res {
		byID[r.ResourceName] = r
	}
	// Present tag: used verbatim, marked Confirmed, and beats the inference.
	if r := byID["api01"]; r.AppID != "checkout" || r.Source != SrcCloudTag || r.Confidence != Confirmed {
		t.Fatalf("tagged VM must use the tag value (checkout), got %+v", r)
	}
	if r := byID["api01"]; r.Env != "prod" {
		t.Fatalf("present tag value should populate env, got %q", r.Env)
	}
	// Untagged sibling: inference fills the gap.
	if r := byID["api02"]; r.AppID != "orders" || r.Source != SrcInferredService {
		t.Fatalf("untagged sibling must fall back to inference (orders), got %+v", r)
	}
}
