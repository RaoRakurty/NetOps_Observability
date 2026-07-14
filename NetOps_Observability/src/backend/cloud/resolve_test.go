package cloud

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAttributeResource_TagConfirmed(t *testing.T) {
	r := CloudResource{ResourceName: "billing-alb", ResourceType: "AWS::ELB", Tags: map[string]string{"App": "billing", "Owner": "payments", "Environment": "prod"}}
	AttributeResource(&r)
	if r.AppID != "billing" || r.Source != SrcCloudTag || r.Confidence != Confirmed {
		t.Fatalf("tag should confirm billing, got %+v", r)
	}
	if r.Owner != "payments" || r.Env != "prod" {
		t.Fatalf("owner/env not picked up: %+v", r)
	}
}

// A resource's own NAME is a GUESS at an application, never attribution. It must
// stay unattributed (AppID empty) so the coverage funnel counts it as a gap and
// the operator is prompted to tag it — the old "name → Strong resource-graph"
// path made the funnel report ~100% coverage on a 0%-attributed account
// (audit 2026-07-13, P0-1).
func TestAttributeResource_NameOnlyIsSuspectedNotAttributed(t *testing.T) {
	r := CloudResource{ResourceName: "legacy-reports-worker", ResourceType: "AWS::EC2::Instance"}
	AttributeResource(&r)
	if r.Source != SrcSuspectedName || r.Confidence != Suspected {
		t.Fatalf("name-only must be SUSPECTED, got %+v", r)
	}
	if r.AppID != "" {
		t.Fatalf("name-only must NOT claim an app identity, got app_id=%q", r.AppID)
	}
}

// The tag the lab's own account actually uses must be read (it was omitted).
func TestAttributeResource_AppIDTagIsConfirmed(t *testing.T) {
	r := CloudResource{ResourceName: "host-1", Tags: map[string]string{"app_id": "checkout"}}
	AttributeResource(&r)
	if r.Source != SrcCloudTag || r.Confidence != Confirmed || r.AppID != "checkout" {
		t.Fatalf("app_id tag must be authoritative, got %+v", r)
	}
}

func TestAttributeResource_Unknown(t *testing.T) {
	r := CloudResource{ResourceType: "AWS::EC2::Instance"} // no tag, no name
	AttributeResource(&r)
	if r.Confidence != Unknown || r.AppID != "" || r.Source != SrcUnknown {
		t.Fatalf("untagged/unnamed must be unknown, got %+v", r)
	}
}

func TestResolve_Precedence_TagBeatsGraphBeatsIPCatalog(t *testing.T) {
	// Same dst, three candidate attributions of decreasing trust. Tag must win, and
	// an IP-catalog guess must NEVER override the cloud tag.
	cands := []CloudIdentityMapping{
		{MatchKey: "10.0.1.10", AppID: "guessed-saas", Source: SrcIPCatalog, Confidence: Weak},
		{MatchKey: "10.0.1.10", AppID: "billing", Source: SrcCloudTag, Confidence: Confirmed},
		{MatchKey: "10.0.1.10", AppID: "billing-svc", Source: SrcCloudGraph, Confidence: Strong},
	}
	best, ok := Resolve(cands)
	if !ok || best.AppID != "billing" || best.Source != SrcCloudTag {
		t.Fatalf("tag must win, got %+v", best)
	}
	// IP-catalog alone never beats graph
	best, _ = Resolve([]CloudIdentityMapping{
		{AppID: "guessed", Source: SrcIPCatalog, Confidence: Weak},
		{AppID: "real", Source: SrcCloudGraph, Confidence: Strong},
	})
	if best.AppID != "real" {
		t.Fatalf("graph must beat ip-catalog, got %+v", best)
	}
}

func TestIdentityMappings_ExpandKeys(t *testing.T) {
	r := CloudResource{
		TenantID: "org-a", ResourceID: "billing-db",
		ResourceURI: "arn:aws:rds:...:db:billing-db", ResourceType: "AWS::RDS::DBInstance",
		ResourceName: "billing-db", PrivateIPs: []string{"10.0.4.50"},
		NetworkInterfaceIDs: []string{"eni-db1"}, Tags: map[string]string{"app": "billing"},
	}
	AttributeResource(&r)
	ms := IdentityMappings(r)
	// 1 private_ip + 1 eni + 1 resource_id + 1 arn = 4 mappings, all confirmed billing
	if len(ms) != 4 {
		t.Fatalf("want 4 mappings, got %d: %+v", len(ms), ms)
	}
	kinds := map[MatchKeyType]bool{}
	for _, m := range ms {
		kinds[m.MatchKeyType] = true
		if m.AppID != "billing" || m.Confidence != Confirmed || m.TenantID != "org-a" {
			t.Fatalf("mapping wrong: %+v", m)
		}
	}
	for _, want := range []MatchKeyType{MatchPrivateIP, MatchENI, MatchResourceID, MatchARN} {
		if !kinds[want] {
			t.Fatalf("missing key kind %s", want)
		}
	}
}

// Acceptance: a fixture AWS app behind ALB + ECS + RDS is attributed to one app_id.
func TestFixtureProvider_AWSBillingBehindALBECSRDS(t *testing.T) {
	p := NewFixtureProvider("testdata")
	res, err := p.ListResources(context.Background(), "org-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 5 {
		t.Fatalf("want 5 resources, got %d", len(res))
	}
	var billing, strong, unknown int
	for _, r := range res {
		if r.TenantID != "org-a" {
			t.Fatalf("tenant not stamped from caller: %+v", r)
		}
		switch {
		case r.AppID == "billing" && r.Confidence == Confirmed:
			billing++ // ALB + ECS + RDS, all tagged app=billing
		case r.Source == SrcSuspectedName && r.Confidence == Suspected:
			strong++ // legacy-reports-worker — a NAME guess, not attribution
		case r.Confidence == Unknown:
			unknown++ // untagged EC2
		}
	}
	// The name-only resource is SUSPECTED (a guess), never Strong.
	if billing != 3 || strong != 1 || unknown != 1 {
		t.Fatalf("attribution mix wrong: billing=%d suspected-name=%d unknown=%d", billing, strong, unknown)
	}

	// the ALB's two private IPs resolve to billing via the identity map
	ms, _ := p.ListIdentityMappings(context.Background(), "org-a", "")
	got := map[string]string{}
	for _, m := range ms {
		if m.MatchKeyType == MatchPrivateIP {
			got[m.MatchKey] = m.AppID
		}
	}
	if got["10.0.1.10"] != "billing" || got["10.0.4.50"] != "billing" {
		t.Fatalf("ALB/RDS IPs should map to billing: %+v", got)
	}
	if got["10.0.6.6"] != "" { // untagged EC2 IP → unknown (empty app), still mapped
		t.Fatalf("untagged IP should map to unknown app, got %q", got["10.0.6.6"])
	}
}

func TestFixtureProvider_UnsupportedProviderGraceful(t *testing.T) {
	dir := t.TempDir()
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "bad.json"),
		[]byte(`{"provider":"oracle","account_id":"x","resources":[{"resource_id":"r1","private_ips":["1.1.1.1"]}]}`), 0o600))
	must(os.WriteFile(filepath.Join(dir, "good.json"),
		[]byte(`{"provider":"gcp","account_id":"proj","resources":[{"resource_id":"vm1","resource_name":"web","private_ips":["10.0.0.9"]}]}`), 0o600))
	res, err := NewFixtureProvider(dir).ListResources(context.Background(), "org-a", "")
	if err != nil {
		t.Fatalf("unsupported provider must not error: %v", err)
	}
	if len(res) != 1 || res[0].Provider != GCP { // oracle skipped, gcp kept
		t.Fatalf("unsupported provider should be skipped, got %+v", res)
	}
}

func TestFixtureProvider_MalformedDoesNotCrash(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "broken.json"), []byte(`{not json`), 0o600)
	if _, err := NewFixtureProvider(dir).ListResources(context.Background(), "org-a", ""); err == nil {
		t.Fatal("malformed fixture should return an error, not crash")
	}
}
