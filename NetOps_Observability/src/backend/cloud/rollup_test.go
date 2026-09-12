// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// rollup_test.go — table-driven tests for the P1 roll-up engine: the worst-of
// precedence matrix (unknown ≠ green), named-reason propagation, seam-not-in-VPC
// attribution, issue localization, performance honesty and truncation disclosure.

import (
	"strings"
	"testing"
	"time"
)

var rollupNow = time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

// comp builds one inventory row with the fields the engine reads.
func comp(provider Provider, region, vpc, id, rtype, status, reason string) CloudResource {
	return CloudResource{
		Provider:     provider,
		Region:       region,
		VpcID:        vpc,
		ResourceID:   id,
		ResourceName: id,
		ResourceType: rtype,
		Status:       status,
		StatusReason: reason,
		LastSeenAt:   rollupNow.Add(-5 * time.Minute),
	}
}

func f64(v float64) *float64 { return &v }

// vpcByID finds a VPC in the built overview (test helper; fails the test when absent).
func vpcByID(t *testing.T, ov NetworkOverview, provider, region, vpcID string) VPCOverview {
	t.Helper()
	for _, p := range ov.Providers {
		if p.Provider != provider {
			continue
		}
		for _, r := range p.Regions {
			if r.Region != region {
				continue
			}
			for _, v := range r.VPCs {
				if v.VpcID == vpcID {
					return v
				}
			}
		}
	}
	t.Fatalf("vpc %s/%s/%s not in overview", provider, region, vpcID)
	return VPCOverview{}
}

// TestRollupWorstOfPrecedence is the precedence matrix: down > degraded >
// healthy among MEASURED children; zero measured children → not_measured (never
// healthy); healthy + unmeasured stays healthy but the ratio says so.
func TestRollupWorstOfPrecedence(t *testing.T) {
	cases := []struct {
		name         string
		statuses     []string // component statuses inside one VPC
		wantStatus   string
		wantMeasured int
		wantTotal    int
	}{
		{"all healthy", []string{"healthy", "healthy"}, StatusHealthy, 2, 2},
		{"down beats degraded", []string{"degraded", "down", "healthy"}, StatusDown, 3, 3},
		{"degraded beats healthy", []string{"healthy", "degraded"}, StatusDegraded, 2, 2},
		{"all unmeasured is not_measured, never healthy", []string{"", ""}, StatusNotMeasured, 0, 2},
		{"unrecognised status reads not_measured", []string{"weird", "junk"}, StatusNotMeasured, 0, 2},
		{"healthy plus unmeasured reads healthy with ratio", []string{"healthy", "", ""}, StatusHealthy, 1, 3},
		{"down beats a sea of unmeasured", []string{"", "down", ""}, StatusDown, 1, 3},
		{"degraded plus unmeasured", []string{"", "degraded"}, StatusDegraded, 1, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var res []CloudResource
			for i, st := range c.statuses {
				res = append(res, comp(AWS, "us-west-2", "vpc-1", "r-"+string(rune('a'+i)), "ec2:instance", st, ""))
			}
			ov := BuildNetworkOverview(res, nil, OverviewLimits{}, rollupNow)
			v := vpcByID(t, ov, "aws", "us-west-2", "vpc-1")
			if v.Status != c.wantStatus {
				t.Fatalf("vpc status = %q, want %q (reason %q)", v.Status, c.wantStatus, v.StatusReason)
			}
			if v.MeasuredRatio.Measured != c.wantMeasured || v.MeasuredRatio.Total != c.wantTotal {
				t.Fatalf("measured_ratio = %d/%d, want %d/%d",
					v.MeasuredRatio.Measured, v.MeasuredRatio.Total, c.wantMeasured, c.wantTotal)
			}
			if v.StatusReason == "" {
				t.Fatal("every roll-up must carry a status_reason")
			}
			// The same precedence must hold at region and provider level.
			if got := ov.Providers[0].Regions[0].Status; got != c.wantStatus {
				t.Fatalf("region status = %q, want %q", got, c.wantStatus)
			}
			if got := ov.Providers[0].Status; got != c.wantStatus {
				t.Fatalf("provider status = %q, want %q", got, c.wantStatus)
			}
		})
	}
}

// TestRollupNamedReasonPropagation: the VPC, region AND provider reasons all
// name the worst contributor — never a bare count.
func TestRollupNamedReasonPropagation(t *testing.T) {
	res := []CloudResource{
		comp(AWS, "us-west-2", "vpc-1", "correlix-edge-alb", "elbv2:loadbalancer", "degraded", "targets 2/3 healthy"),
		comp(AWS, "us-west-2", "vpc-1", "web-1", "ec2:instance", "healthy", "running"),
		comp(AWS, "us-west-2", "vpc-2", "web-2", "ec2:instance", "healthy", "running"),
	}
	ov := BuildNetworkOverview(res, nil, OverviewLimits{}, rollupNow)
	want := "degraded — targets 2/3 healthy (correlix-edge-alb)"
	v := vpcByID(t, ov, "aws", "us-west-2", "vpc-1")
	if v.StatusReason != want {
		t.Fatalf("vpc reason = %q, want %q", v.StatusReason, want)
	}
	if got := ov.Providers[0].Regions[0].StatusReason; got != want {
		t.Fatalf("region reason = %q, want %q", got, want)
	}
	if got := ov.Providers[0].StatusReason; got != want {
		t.Fatalf("provider reason = %q, want %q", got, want)
	}
	// A worst contributor WITHOUT a stored reason still gets named.
	res2 := []CloudResource{comp(Azure, "westus2", "vnet-1", "fw-1", "network:networksecuritygroup", "down", "")}
	ov2 := BuildNetworkOverview(res2, nil, OverviewLimits{}, rollupNow)
	v2 := vpcByID(t, ov2, "azure", "westus2", "vnet-1")
	if !strings.Contains(v2.StatusReason, "fw-1") {
		t.Fatalf("reason must name the contributor even without a stored reason, got %q", v2.StatusReason)
	}
	// Healthy roll-ups spell out partial coverage.
	res3 := []CloudResource{
		comp(GCP, "us-west1", "net-1", "ok-1", "compute:instance", "healthy", ""),
		comp(GCP, "us-west1", "net-1", "quiet-1", "compute:instance", "", ""),
		comp(GCP, "us-west1", "net-1", "quiet-2", "compute:instance", "", ""),
	}
	ov3 := BuildNetworkOverview(res3, nil, OverviewLimits{}, rollupNow)
	v3 := vpcByID(t, ov3, "gcp", "us-west1", "net-1")
	if !strings.Contains(v3.StatusReason, "1 of 3 measured") {
		t.Fatalf("partial-coverage healthy must disclose the ratio, got %q", v3.StatusReason)
	}
}

// TestSeamNotInVPCAttribution (§4a): a seam-family resource lives ONLY in
// seams[]; its status and its incidents never roll into the VPC or region.
func TestSeamNotInVPCAttribution(t *testing.T) {
	vpn := comp(AWS, "us-west-2", "vpc-1", "vpn-conn-1", "ec2:vpnconnection", "down", "0/2 tunnels up")
	vpn.AttachedVpcIDs = []string{"vpc-1"}
	vpn.AttachedRegions = []string{"us-west-2", "eu-central-1"}
	res := []CloudResource{
		vpn,
		comp(AWS, "us-west-2", "vpc-1", "web-1", "ec2:instance", "healthy", "running"),
	}
	issues := []OverviewIssue{{
		ID:      "corr-1",
		Title:   "IPsec tunnel down — cloud private path",
		Handles: []string{"vpn-conn-1"},
		Kinds:   []string{"ipsec_tunnel_status"},
	}}
	ov := BuildNetworkOverview(res, issues, OverviewLimits{}, rollupNow)

	// The VPC roll-up must NOT be dragged down by the seam device...
	v := vpcByID(t, ov, "aws", "us-west-2", "vpc-1")
	if v.Status != StatusHealthy {
		t.Fatalf("vpc status = %q — the seam device leaked into the VPC roll-up", v.Status)
	}
	if v.ComponentCount != 1 {
		t.Fatalf("vpc component count = %d, want 1 (seam devices are not VPC components)", v.ComponentCount)
	}
	// ...and the seam issue must sit on the seam, not the VPC/region/provider.
	if v.OpenIssues.Count != 0 {
		t.Fatalf("seam issue leaked into the VPC (count %d)", v.OpenIssues.Count)
	}
	if got := ov.Providers[0].Regions[0].OpenIssues.Count; got != 0 {
		t.Fatalf("seam issue leaked into the region (count %d)", got)
	}
	if len(ov.Seams) != 1 {
		t.Fatalf("want 1 seam, got %d", len(ov.Seams))
	}
	s := ov.Seams[0]
	if s.Status != StatusDown {
		t.Fatalf("seam status = %q, want down", s.Status)
	}
	if !strings.Contains(s.StatusReason, "0/2 tunnels up") || !strings.Contains(s.StatusReason, "vpn-conn-1") {
		t.Fatalf("seam reason must name the device and its signal, got %q", s.StatusReason)
	}
	if s.OpenIssues.Count != 1 || s.OpenIssues.TopIssue != "IPsec tunnel down — cloud private path" {
		t.Fatalf("seam open_issues = %+v, want the tunnel investigation", s.OpenIssues)
	}
	// Endpoints carry both sides of the lateral link.
	regions := map[string]bool{}
	for _, e := range s.Endpoints {
		if e.Region != "" {
			regions[e.Region] = true
		}
	}
	if !regions["us-west-2"] || !regions["eu-central-1"] {
		t.Fatalf("seam endpoints missing a side: %+v", s.Endpoints)
	}
	if len(s.Devices) != 1 || s.Devices[0].ResourceID != "vpn-conn-1" {
		t.Fatalf("seam devices = %+v, want the traversed VPN connection", s.Devices)
	}
	// An unmeasured seam reads not_measured, never green.
	quiet := comp(AWS, "us-west-2", "", "tgw-1", "ec2:transitgateway", "", "")
	ov2 := BuildNetworkOverview([]CloudResource{quiet}, nil, OverviewLimits{}, rollupNow)
	if len(ov2.Seams) != 1 || ov2.Seams[0].Status != StatusNotMeasured {
		t.Fatalf("unmeasured seam must be not_measured, got %+v", ov2.Seams)
	}
}

// TestIssueLocalization: issues attach once per node, roll up to region and
// provider, resolve by secondary handles (ENI/IP), and an unresolvable issue is
// counted as unlocalized — never dropped.
func TestIssueLocalization(t *testing.T) {
	web := comp(AWS, "us-west-2", "vpc-1", "i-0abc", "ec2:instance", "healthy", "running")
	web.NetworkInterfaceIDs = []string{"eni-123"}
	web.PrivateIPs = []string{"10.60.10.10"}
	res := []CloudResource{
		web,
		comp(AWS, "us-west-2", "vpc-2", "i-0def", "ec2:instance", "healthy", "running"),
		comp(AWS, "eu-central-1", "", "zone-1", "route53:hostedzone", "healthy", "56 records"),
	}
	issues := []OverviewIssue{
		// newest first: both handles of this issue resolve into vpc-1 → ONE count.
		{ID: "c1", Title: "Traffic rejected by a security rule", Handles: []string{"eni-123", "10.60.10.10"}},
		{ID: "c2", Title: "Instance impaired", Handles: []string{"i-0abc"}},
		// touches a non-VPC (global-ish) resource → counts at its region only.
		{ID: "c3", Title: "DNS zone problem", Handles: []string{"zone-1"}},
		// resolves to nothing the tenant declared.
		{ID: "c4", Title: "Mystery", Handles: []string{"i-unknown"}},
	}
	ov := BuildNetworkOverview(res, issues, OverviewLimits{}, rollupNow)

	v1 := vpcByID(t, ov, "aws", "us-west-2", "vpc-1")
	if v1.OpenIssues.Count != 2 {
		t.Fatalf("vpc-1 open issues = %d, want 2 (one per investigation, dedup across handles)", v1.OpenIssues.Count)
	}
	if v1.OpenIssues.TopIssue != "Traffic rejected by a security rule" {
		t.Fatalf("top issue = %q, want the newest", v1.OpenIssues.TopIssue)
	}
	if v2 := vpcByID(t, ov, "aws", "us-west-2", "vpc-2"); v2.OpenIssues.Count != 0 {
		t.Fatalf("vpc-2 must have no issues, got %d", v2.OpenIssues.Count)
	}
	p := ov.Providers[0]
	if p.OpenIssues.Count != 3 {
		t.Fatalf("provider open issues = %d, want 3 (distinct localized investigations)", p.OpenIssues.Count)
	}
	var usw, euc RegionOverview
	for _, r := range p.Regions {
		switch r.Region {
		case "us-west-2":
			usw = r
		case "eu-central-1":
			euc = r
		}
	}
	if usw.OpenIssues.Count != 2 {
		t.Fatalf("us-west-2 open issues = %d, want 2", usw.OpenIssues.Count)
	}
	if euc.OpenIssues.Count != 1 || euc.OpenIssues.TopIssue != "DNS zone problem" {
		t.Fatalf("eu-central-1 open issues = %+v, want the DNS investigation", euc.OpenIssues)
	}
	if ov.OpenIssuesLocalized != 3 || ov.OpenIssuesUnlocalized != 1 {
		t.Fatalf("localized/unlocalized = %d/%d, want 3/1", ov.OpenIssuesLocalized, ov.OpenIssuesUnlocalized)
	}
}

// TestPerformanceRollupHonesty: only really-measured key metrics appear; counts
// sum, rates take the worst value, single values pass through undecorated.
func TestPerformanceRollupHonesty(t *testing.T) {
	lb1 := comp(AWS, "us-west-2", "vpc-1", "alb-1", "elbv2:loadbalancer", "healthy", "")
	lb1.KeyMetricName, lb1.KeyMetricValue, lb1.KeyMetricUnit = "healthy targets", f64(3), "targets"
	lb2 := comp(AWS, "us-west-2", "vpc-1", "alb-2", "elbv2:loadbalancer", "healthy", "")
	lb2.KeyMetricName, lb2.KeyMetricValue, lb2.KeyMetricUnit = "healthy targets", f64(2), "targets"
	dns := comp(AWS, "us-west-2", "vpc-1", "zone-a", "route53:hostedzone", "healthy", "")
	dns.KeyMetricName, dns.KeyMetricValue, dns.KeyMetricUnit = "error rate", f64(1.5), "%"
	dns2 := comp(AWS, "us-west-2", "vpc-1", "zone-b", "route53:hostedzone", "healthy", "")
	dns2.KeyMetricName, dns2.KeyMetricValue, dns2.KeyMetricUnit = "error rate", f64(4.5), "%"
	quiet := comp(AWS, "us-west-2", "vpc-1", "sg-1", "ec2:securitygroup", "", "") // no metric at all

	ov := BuildNetworkOverview([]CloudResource{lb1, lb2, dns, dns2, quiet}, nil, OverviewLimits{}, rollupNow)
	v := vpcByID(t, ov, "aws", "us-west-2", "vpc-1")
	if len(v.Performance) != 2 {
		t.Fatalf("performance entries = %d, want 2 (absent metrics stay absent)", len(v.Performance))
	}
	byMetric := map[string]PerformanceMetric{}
	for _, m := range v.Performance {
		byMetric[m.Metric] = m
	}
	lb := byMetric["healthy targets"]
	if lb.Value != 5 || lb.Aggregation != "sum" || lb.Components != 2 {
		t.Fatalf("count-like metric must SUM: %+v", lb)
	}
	er := byMetric["error rate"]
	if er.Value != 4.5 || er.Aggregation != "max" || er.Components != 2 {
		t.Fatalf("rate metric must take the WORST: %+v", er)
	}
	// A VPC with no measured metrics has an EMPTY performance strip — never zeros.
	ovQuiet := BuildNetworkOverview([]CloudResource{quiet}, nil, OverviewLimits{}, rollupNow)
	if got := vpcByID(t, ovQuiet, "aws", "us-west-2", "vpc-1").Performance; len(got) != 0 {
		t.Fatalf("unmeasured VPC must have no performance entries, got %+v", got)
	}
}

// TestOverviewTruncationDisclosure: caps cut the LISTS worst-first but the true
// counts and a truncated marker survive.
func TestOverviewTruncationDisclosure(t *testing.T) {
	var res []CloudResource
	// 4 VPCs; vpc-broken is down and must survive a cap of 2.
	for _, id := range []string{"vpc-a", "vpc-b", "vpc-broken", "vpc-c"} {
		st, reason := "healthy", "running"
		if id == "vpc-broken" {
			st, reason = "down", "gateway offline"
		}
		res = append(res, comp(AWS, "us-west-2", id, "i-"+id, "ec2:instance", st, reason))
	}
	lim := OverviewLimits{MaxVPCsPerRegion: 2}
	ov := BuildNetworkOverview(res, nil, lim, rollupNow)
	r := ov.Providers[0].Regions[0]
	if !r.VPCsTruncated {
		t.Fatal("vpcs_truncated must disclose the cap")
	}
	if r.VPCCount != 4 {
		t.Fatalf("vpc_count must stay the TRUE total, got %d", r.VPCCount)
	}
	if len(r.VPCs) != 2 {
		t.Fatalf("vpc list = %d, want capped 2", len(r.VPCs))
	}
	if r.VPCs[0].VpcID != "vpc-broken" {
		t.Fatalf("worst-first ordering must keep the broken VPC visible, got %q first", r.VPCs[0].VpcID)
	}
	// Seam cap discloses too.
	var seamRes []CloudResource
	for i := 0; i < 3; i++ {
		s := comp(AWS, "us-west-2", "", "vpn-"+string(rune('a'+i)), "ec2:vpnconnection", "healthy", "2/2 tunnels up")
		seamRes = append(seamRes, s)
	}
	ov2 := BuildNetworkOverview(seamRes, nil, OverviewLimits{MaxSeams: 2}, rollupNow)
	if !ov2.SeamsTruncated || len(ov2.Seams) != 2 {
		t.Fatalf("seam truncation not disclosed: truncated=%v len=%d", ov2.SeamsTruncated, len(ov2.Seams))
	}
	// Subnet cap discloses on the VPC.
	multi := comp(AWS, "us-west-2", "vpc-s", "lb-1", "elbv2:loadbalancer", "healthy", "")
	multi.SubnetIDs = []string{"subnet-1", "subnet-2", "subnet-3"}
	ov3 := BuildNetworkOverview([]CloudResource{multi}, nil, OverviewLimits{MaxSubnetsPerVPC: 2}, rollupNow)
	v := vpcByID(t, ov3, "aws", "us-west-2", "vpc-s")
	if !v.SubnetsTruncated || len(v.Subnets) != 2 {
		t.Fatalf("subnet truncation not disclosed: truncated=%v len=%d", v.SubnetsTruncated, len(v.Subnets))
	}
}

// TestRollupStructure: families, regional (non-VPC) components, the global
// region bucket, and last_measured freshness.
func TestRollupStructure(t *testing.T) {
	inst := comp(AWS, "us-west-2", "vpc-1", "i-1", "ec2:instance", "healthy", "running")
	inst.LastSeenAt = rollupNow.Add(-1 * time.Minute)
	lb := comp(AWS, "us-west-2", "vpc-1", "alb-1", "elbv2:loadbalancer", "degraded", "targets 1/2 healthy")
	lb.LastSeenAt = rollupNow.Add(-10 * time.Minute)
	zone := comp(AWS, "", "", "zone-1", "route53:hostedzone", "healthy", "56 records") // regionless → global
	res := []CloudResource{inst, lb, zone}

	ov := BuildNetworkOverview(res, nil, OverviewLimits{}, rollupNow)
	if len(ov.Providers) != 1 || ov.Providers[0].Provider != "aws" {
		t.Fatalf("providers = %+v", ov.Providers)
	}
	p := ov.Providers[0]
	if p.RegionCount != 2 || p.ComponentCount != 3 {
		t.Fatalf("provider counts = %d regions / %d components, want 2/3", p.RegionCount, p.ComponentCount)
	}
	var global, usw RegionOverview
	for _, r := range p.Regions {
		switch r.Region {
		case "global":
			global = r
		case "us-west-2":
			usw = r
		}
	}
	if global.Region == "" {
		t.Fatal("regionless components must land in the customer-facing 'global' region")
	}
	if len(global.RegionalComponents) != 1 || global.RegionalComponents[0].Family != FamilyDNS {
		t.Fatalf("global regional_components = %+v, want one dns family", global.RegionalComponents)
	}
	v := vpcByID(t, ov, "aws", "us-west-2", "vpc-1")
	if len(v.Families) != 2 {
		t.Fatalf("families = %+v, want lb + instance", v.Families)
	}
	if v.Families[0].Family != FamilyLB { // stable render order: entry points first
		t.Fatalf("family order = %+v, want lb first", v.Families)
	}
	if v.Families[0].Status != StatusDegraded || !strings.Contains(v.Families[0].StatusReason, "alb-1") {
		t.Fatalf("lb family dot = %+v, want degraded with named reason", v.Families[0])
	}
	if v.LastMeasured != rollupNow.Add(-1*time.Minute).Format(time.RFC3339) {
		t.Fatalf("last_measured = %q, want the freshest child", v.LastMeasured)
	}
	if usw.LastMeasured != v.LastMeasured {
		t.Fatalf("region last_measured = %q, want %q", usw.LastMeasured, v.LastMeasured)
	}
	// Empty inventory → an empty, honest overview.
	empty := BuildNetworkOverview(nil, nil, OverviewLimits{}, rollupNow)
	if len(empty.Providers) != 0 || len(empty.Seams) != 0 {
		t.Fatalf("empty inventory must yield an empty overview, got %+v", empty)
	}
}
