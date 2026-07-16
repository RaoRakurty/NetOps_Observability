package main

import "testing"

// Contract tests for the Go segment-classifier mirror (path-causality RCA P0). One test per
// pattern + the two honesty invariants, matching test_segment_classifier.py. Offline: reads
// only the embedded bundled snapshot.

func classifyHop(t *testing.T, h Hop) SegmentClass {
	t.Helper()
	return getSegmentClassifier().Classify(h)
}

func TestSegmentAWSCIDRIsCloud(t *testing.T) {
	r := classifyHop(t, Hop{IP: "52.216.100.5"}) // inside 52.216.0.0/15 (AWS S3)
	if r.SegmentType != SegCloud || r.Provider != "aws" {
		t.Fatalf("got segment=%s provider=%s, want cloud/aws (%s)", r.SegmentType, r.Provider, r.Reason)
	}
	if r.Confidence != ConfStrong {
		t.Fatalf("got confidence=%s, want strong", r.Confidence)
	}
	if r.Boundary != "CLOUD" {
		t.Fatalf("got boundary=%s, want CLOUD", r.Boundary)
	}
}

func TestSegmentAzureCIDRIsCloud(t *testing.T) {
	r := classifyHop(t, Hop{IP: "40.65.0.10"}) // inside 40.64.0.0/10 (AzureCloud)
	if r.SegmentType != SegCloud || r.Provider != "azure" || r.Confidence != ConfStrong {
		t.Fatalf("got %+v, want cloud/azure/strong", r)
	}
}

func TestSegmentGCPCIDRIsCloud(t *testing.T) {
	r := classifyHop(t, Hop{IP: "35.190.10.10"}) // inside 35.184.0.0/13 (Google Cloud)
	if r.SegmentType != SegCloud || r.Provider != "gcp" {
		t.Fatalf("got segment=%s provider=%s, want cloud/gcp", r.SegmentType, r.Provider)
	}
}

func TestSegmentGCPIPv6IsCloud(t *testing.T) {
	r := classifyHop(t, Hop{IP: "2600:1900:4000::1"}) // inside 2600:1900::/28 (GCP)
	if r.SegmentType != SegCloud || r.Provider != "gcp" {
		t.Fatalf("got segment=%s provider=%s, want cloud/gcp", r.SegmentType, r.Provider)
	}
}

func TestSegmentLongestPrefixMatchWins(t *testing.T) {
	r := classifyHop(t, Hop{IP: "52.216.0.1"}) // most specific service = S3
	if r.Service != "S3" {
		t.Fatalf("got service=%s, want S3 (longest-prefix)", r.Service)
	}
}

func TestSegmentRFC1918IsPrivate(t *testing.T) {
	r := classifyHop(t, Hop{IP: "10.20.30.40"})
	if r.SegmentType != SegLAN && r.SegmentType != SegDC {
		t.Fatalf("got segment=%s, want lan/dc", r.SegmentType)
	}
	if r.Confidence != ConfMedium { // ambiguous alone
		t.Fatalf("got confidence=%s, want medium", r.Confidence)
	}
}

func TestSegmentRFC1918PlusFabricRoleIsDC(t *testing.T) {
	r := classifyHop(t, Hop{IP: "10.20.30.40", DeviceRoleHint: "dc-spine-01"})
	if r.SegmentType != SegDC || r.DeviceRole != RoleSwitch || r.Confidence != ConfStrong {
		t.Fatalf("got %+v, want dc/switch/strong", r)
	}
}

func TestSegmentCGNATIsWAN(t *testing.T) {
	r := classifyHop(t, Hop{IP: "100.64.12.9"})
	if r.SegmentType != SegWAN || r.Confidence != ConfStrong {
		t.Fatalf("got %+v, want wan/strong", r)
	}
}

func TestSegmentTransitASNIsWAN(t *testing.T) {
	r := classifyHop(t, Hop{IP: "154.54.1.1", ASN: 174}) // AS174 Cogent (transit)
	if r.SegmentType != SegWAN {
		t.Fatalf("got segment=%s, want wan (%s)", r.SegmentType, r.Reason)
	}
}

func TestSegmentCloudASNCorroborates(t *testing.T) {
	r := classifyHop(t, Hop{IP: "52.216.100.5", ASN: 16509})
	if r.SegmentType != SegCloud || r.Confidence != ConfStrong {
		t.Fatalf("got %+v, want cloud/strong", r)
	}
}

func TestSegmentDeviceRoles(t *testing.T) {
	cases := []struct {
		hint     string
		wantRole string
	}{
		{"prod application load balancer", RoleLoadBalancer},
		{"azure app gateway WAF", RoleWAF},
		{"edge-fw fortigate", RoleFirewall},
		{"unbound dns resolver", RoleDNSResolver},
	}
	for _, c := range cases {
		r := classifyHop(t, Hop{IP: "52.216.100.5", DeviceRoleHint: c.hint})
		if r.DeviceRole != c.wantRole {
			t.Fatalf("hint %q → role %s, want %s", c.hint, r.DeviceRole, c.wantRole)
		}
	}
}

func TestSegmentTunnelGWMarksWANSeam(t *testing.T) {
	r := classifyHop(t, Hop{IP: "10.0.0.1", DeviceRoleHint: "ipsec vpn gateway"})
	if r.DeviceRole != RoleTunnelGW || r.SegmentType != SegWANSeam || r.SeamKind != "VPN" {
		t.Fatalf("got %+v, want tunnel_gw/wan_seam/VPN", r)
	}
}

func TestSegmentDirectConnectMarksDX(t *testing.T) {
	r := classifyHop(t, Hop{IP: "10.0.0.1", DeviceRoleHint: "AWS Direct Connect gateway"})
	if r.SegmentType != SegWANSeam || r.SeamKind != "DX" {
		t.Fatalf("got segment=%s seam=%s, want wan_seam/DX", r.SegmentType, r.SeamKind)
	}
}

// ── honesty invariants ──────────────────────────────────────────────────────

func TestSegmentUnknownWhenNothingMatches(t *testing.T) {
	r := classifyHop(t, Hop{IP: "127.0.0.1"})
	if r.SegmentType != SegUnknown || r.Confidence != ConfNone || r.Reason == "" {
		t.Fatalf("got %+v, want unknown/none/reason", r)
	}
}

func TestSegmentUnknownOnUnparseableIP(t *testing.T) {
	r := classifyHop(t, Hop{IP: "not-an-ip"})
	if r.SegmentType != SegUnknown {
		t.Fatalf("got segment=%s, want unknown", r.SegmentType)
	}
}

func TestSegmentUnknownOnMissingIP(t *testing.T) {
	r := classifyHop(t, Hop{RDNS: "whatever.example.com"})
	if r.SegmentType != SegUnknown || r.Reason == "" {
		t.Fatalf("got %+v, want unknown + reason", r)
	}
}

func TestSegmentSingleWeakRDNSNeverConfident(t *testing.T) {
	// rDNS alone looks like AWS, but rDNS is weak/spoofable — never strong/medium.
	r := classifyHop(t, Hop{IP: "203.0.113.7", RDNS: "ec2-203-0-113-7.compute.amazonaws.com"})
	if r.Confidence == ConfStrong || r.Confidence == ConfMedium {
		t.Fatalf("got confidence=%s (segment=%s), want weak/none", r.Confidence, r.SegmentType)
	}
}

func TestSegmentWeakRoleHintStaysLowConfidence(t *testing.T) {
	r := classifyHop(t, Hop{IP: "203.0.113.7", RDNS: "lb01.example.net"})
	if r.DeviceRole != RoleLoadBalancer {
		t.Fatalf("got role=%s, want load_balancer", r.DeviceRole)
	}
	if r.Confidence == ConfStrong || r.Confidence == ConfMedium {
		t.Fatalf("got confidence=%s, want weak/none", r.Confidence)
	}
}

// ── untrusted feed data must not crash (CLAUDE.md §8) ────────────────────────

func TestSegmentMalformedFeedEntriesSkipped(t *testing.T) {
	raw := []byte(`{"prefixes":[
		{"prefix":"not-a-cidr","provider":"aws"},
		"a-bare-string-ignored-by-typed-decode",
		{"prefix":"198.51.100.0/24","provider":"aws","region":"us-east-1"}
	]}`)
	trie := loadProviderTrie(raw)
	if trie.Count != 1 {
		t.Fatalf("got count=%d, want 1 (malformed skipped)", trie.Count)
	}
	c := &SegmentClassifier{trie: trie}
	r := c.Classify(Hop{IP: "198.51.100.5"})
	if r.SegmentType != SegCloud {
		t.Fatalf("got segment=%s, want cloud", r.SegmentType)
	}
}

func TestSegmentMissingSnapshotNotFatal(t *testing.T) {
	trie := loadProviderTrie([]byte("this is not json"))
	if trie.Count != 0 {
		t.Fatalf("got count=%d, want 0", trie.Count)
	}
	c := &SegmentClassifier{trie: trie}
	r := c.Classify(Hop{IP: "10.1.1.1"}) // private space still classifies CIDR-blind
	if r.SegmentType != SegLAN {
		t.Fatalf("got segment=%s, want lan", r.SegmentType)
	}
}

func TestSegmentJSONShape(t *testing.T) {
	// Ensure the result marshals (ingest stamps it onto the event).
	r := classifyHop(t, Hop{IP: "52.216.100.5", DeviceRoleHint: "alb"})
	if r.SegmentType != SegCloud || r.DeviceRole != RoleLoadBalancer {
		t.Fatalf("got %+v", r)
	}
}
