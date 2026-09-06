// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// layered_test.go — the static-fixture / live-runtime split (P0 hygiene):
// a runtime file shadows the same-named tracked fixture; a missing runtime
// layer degrades to the fixtures; the new component fields (vpc_id, status,
// key metric, seam attachments) round-trip losslessly with the caller's
// tenant stamped — never one from the file.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLayeredProvider_RuntimeShadowsFixture(t *testing.T) {
	fixtures := t.TempDir()
	runtime := t.TempDir()
	writeFile(t, fixtures, "aws.json", `{"provider":"aws","account_id":"111",
		"resources":[{"resource_id":"i-fixture"}]}`)
	writeFile(t, fixtures, "azure.json", `{"provider":"azure","account_id":"222",
		"resources":[{"resource_id":"vm-fixture"}]}`)
	// The live poller rewrote aws.json in the runtime layer — it must win.
	writeFile(t, runtime, "aws.json", `{"provider":"aws","account_id":"111",
		"collection":{"mode":"live_poller","collected_at":"2026-07-16T08:00:00Z"},
		"resources":[{"resource_id":"i-live"},{"resource_id":"i-live2"}]}`)

	prov := NewLayeredFixtureProvider(fixtures, runtime)
	res, err := prov.ListResources(context.Background(), "tenant-a", "")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range res {
		ids[r.ResourceID] = true
		if r.TenantID != "tenant-a" {
			t.Fatalf("tenant must be stamped from the caller, got %q", r.TenantID)
		}
	}
	if ids["i-fixture"] {
		t.Fatal("runtime aws.json must shadow the fixture aws.json")
	}
	if !ids["i-live"] || !ids["i-live2"] || !ids["vm-fixture"] {
		t.Fatalf("expected live aws + fixture azure resources, got %v", ids)
	}

	// Provenance follows the winning layer: aws reads live, azure fixture.
	conns, err := prov.Connectors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kind := map[Provider]string{}
	for _, c := range conns {
		kind[c.Provider] = c.Kind
	}
	if kind[AWS] != ConnectorKindLive || kind[Azure] != ConnectorKindFixture {
		t.Fatalf("provenance wrong: %v", kind)
	}
}

func TestLayeredProvider_MissingRuntimeDegradesToFixtures(t *testing.T) {
	fixtures := t.TempDir()
	writeFile(t, fixtures, "gcp.json", `{"provider":"gcp","account_id":"p1",
		"resources":[{"resource_id":"vm-1"}]}`)
	prov := NewLayeredFixtureProvider(fixtures, filepath.Join(fixtures, "does-not-exist"))
	res, err := prov.ListResources(context.Background(), "t", "")
	if err != nil || len(res) != 1 {
		t.Fatalf("fresh install (no runtime dir) must still serve fixtures: res=%d err=%v", len(res), err)
	}
}

func TestComponentFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "aws.json", `{"provider":"aws","account_id":"111","resources":[
		{"resource_id":"arn:aws:elasticloadbalancing:us-west-2:1:loadbalancer/app/web/x",
		 "resource_type":"elbv2:loadbalancer","resource_name":"web","region":"us-west-2",
		 "vpc_id":"vpc-1","subnet_ids":["subnet-a","subnet-b"],
		 "status":"degraded","status_reason":"targets 1/3 healthy",
		 "key_metric_name":"healthy_targets","key_metric_value":1,"key_metric_unit":"targets",
		 "attrs":{"lb_type":"application"}},
		{"resource_id":"vpn-1","resource_type":"ec2:vpnconnection","region":"us-west-2",
		 "status":"down","status_reason":"all 2 tunnels down",
		 "attached_vpc_ids":["vpc-1","vpc-9"],"attached_regions":["us-west-2"]},
		{"resource_id":"acl-1","resource_type":"wafv2:webacl","region":"global",
		 "status":"not_measured","status_reason":"WAF exposes no health signal"}]}`)

	res, err := NewFixtureProvider(dir).ListResources(context.Background(), "t1", "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]CloudResource{}
	for _, r := range res {
		byID[r.ResourceID] = r
	}
	lb := byID["arn:aws:elasticloadbalancing:us-west-2:1:loadbalancer/app/web/x"]
	if lb.VpcID != "vpc-1" || len(lb.SubnetIDs) != 2 {
		t.Fatalf("VPC/subnet context lost: %+v", lb)
	}
	if lb.Status != StatusDegraded || lb.StatusReason == "" {
		t.Fatalf("status lost: %+v", lb)
	}
	if lb.KeyMetricName != "healthy_targets" || lb.KeyMetricValue == nil || *lb.KeyMetricValue != 1 {
		t.Fatalf("key metric lost: %+v", lb)
	}
	if lb.Attrs["lb_type"] != "application" {
		t.Fatalf("attrs lost: %+v", lb.Attrs)
	}
	seam := byID["vpn-1"]
	if len(seam.AttachedVpcIDs) != 2 || seam.AttachedVpcIDs[1] != "vpc-9" {
		t.Fatalf("seam attachment tagging lost: %+v", seam)
	}
	if ComponentFamily(seam.ResourceType) != FamilySeam {
		t.Fatalf("vpn connection must map to the seam family")
	}
	waf := byID["acl-1"]
	// Honesty: an unmeasured component must carry (or normalize to) not_measured.
	if NormalizeComponentStatus(waf.Status) != StatusNotMeasured {
		t.Fatalf("WAF must stay not_measured, got %q", waf.Status)
	}
	// A component with NO status field normalizes to not_measured, never healthy.
	if NormalizeComponentStatus(byID["missing"].Status) != StatusNotMeasured {
		t.Fatal("absent status must normalize to not_measured")
	}
}

func TestLoadTopologiesLayered_RuntimeShadows(t *testing.T) {
	fixtures := t.TempDir()
	runtime := t.TempDir()
	writeFile(t, fixtures, "aws-topology.json", `{"provider":"aws","account_id":"111",
		"region":"us-west-2","vpcs":[{"id":"vpc-fixture","cidr":"10.0.0.0/16"}]}`)
	writeFile(t, runtime, "aws-topology.json", `{"provider":"aws","account_id":"111",
		"region":"us-west-2","vpcs":[{"id":"vpc-live","cidr":"10.9.0.0/16"}]}`)
	topos, err := LoadTopologiesLayered(fixtures, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if len(topos) != 1 || topos[0].VPCs[0].ID != "vpc-live" {
		t.Fatalf("runtime topology must shadow the fixture: %+v", topos)
	}
	// Fixture-only (fresh install) still loads.
	topos, err = LoadTopologiesLayered(fixtures, filepath.Join(runtime, "missing"))
	if err != nil || len(topos) != 1 || topos[0].VPCs[0].ID != "vpc-fixture" {
		t.Fatalf("fixture fallback broken: %+v err=%v", topos, err)
	}
}
