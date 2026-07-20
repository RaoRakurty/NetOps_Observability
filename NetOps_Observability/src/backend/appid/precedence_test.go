package appid

import (
	"reflect"
	"testing"
)

func TestNormalizePrecedence(t *testing.T) {
	// The default order round-trips (with case/space normalization).
	got, err := NormalizePrecedence([]string{" Operator ", "CLOUD_TAG", "firewall_appid", "cloud_graph", "domain", "ip_catalog"})
	if err != nil || !reflect.DeepEqual(got, PrecedenceClasses()) {
		t.Fatalf("normalize = (%v, %v)", got, err)
	}
	bad := [][]string{
		nil,          // empty
		{"operator"}, // incomplete
		{"operator", "cloud_tag", "firewall_appid", "cloud_graph", "domain", "asn"},       // unknown class
		{"operator", "operator", "firewall_appid", "cloud_graph", "domain", "ip_catalog"}, // duplicate
	}
	for _, b := range bad {
		if _, err := NormalizePrecedence(b); err == nil {
			t.Errorf("NormalizePrecedence(%v) must fail — permutation required", b)
		}
	}
}

func TestIsDefaultPrecedence(t *testing.T) {
	if !IsDefaultPrecedence(PrecedenceClasses()) {
		t.Fatal("default order must read as default")
	}
	rev := []string{ClassIPCatalog, ClassDomain, ClassCloudGraph, ClassFirewallAppID, ClassCloudTag, ClassOperator}
	if IsDefaultPrecedence(rev) {
		t.Fatal("reversed order must not read as default")
	}
}

// supportsApp returns the app whose signals were assigned Role=Supports — the
// WINNER of candidate selection, visible even when a contradicted verdict
// honestly reads "unknown" (competing classed claims demote below the floor).
func supportsApp(t *testing.T, v Verdict) string {
	t.Helper()
	for _, s := range v.Signals {
		if s.Role == Supports {
			return s.App
		}
	}
	return ""
}

func TestFuseWithPrecedenceReordersWinner(t *testing.T) {
	signals := []Signal{
		{Source: SrcCloudTag, App: "billing"},
		{Source: SrcNGFWAppID, App: "payments"},
	}
	// No override → identical to Fuse (winner and verdict alike).
	got, want := FuseWithPrecedence(signals, nil), Fuse(signals)
	if got.App != want.App || supportsApp(t, got) != supportsApp(t, want) {
		t.Fatalf("nil order fused %+v, Fuse fused %+v — must be identical", got, want)
	}
	// firewall_appid raised above cloud_tag → the NGFW claim is the primary
	// (Role=Supports) candidate; the tag claim contradicts it.
	order := []string{ClassFirewallAppID, ClassOperator, ClassCloudTag, ClassCloudGraph, ClassDomain, ClassIPCatalog}
	v := FuseWithPrecedence(signals, order)
	if supportsApp(t, v) != "payments" {
		t.Fatalf("reordered winner = %q (verdict %+v), want payments", supportsApp(t, v), v)
	}
	// Two authoritative sources disagreeing is a real contradiction — the
	// verdict itself must stay honest regardless of order.
	if !v.Contradicted {
		t.Fatalf("competing authoritative claims must contradict, got %+v", v)
	}
}

func TestFuseWithPrecedenceKeepsTrustSemantics(t *testing.T) {
	// A tenant ranks ip_catalog FIRST: an uncontested catalog match now wins
	// candidate selection — but it stays medium trust: Suspected, never
	// Confirmed. Reordering precedence must not inflate certainty.
	order := []string{ClassIPCatalog, ClassOperator, ClassCloudTag, ClassFirewallAppID, ClassCloudGraph, ClassDomain}
	if _, err := NormalizePrecedence(order); err != nil {
		t.Fatal(err)
	}
	v := FuseWithPrecedence([]Signal{{Source: SrcIPCatalog, App: "aws-s3"}}, order)
	if v.App != "aws-s3" || v.Tier != Suspected {
		t.Fatalf("catalog-first uncontested = %+v, want suspected aws-s3", v)
	}
	// Classless sources (asn/port) always rank below every class: the catalog
	// claim wins even though asn appears first and asn is not a contradiction.
	v = FuseWithPrecedence([]Signal{
		{Source: SrcASN, App: "asn-org"},
		{Source: SrcIPCatalog, App: "aws-s3"},
	}, order)
	if v.App != "aws-s3" || v.Contradicted {
		t.Fatalf("ASN must stay below every class and not contradict, got %+v", v)
	}
}

// The refactored Fuse (fuseRanked with intrinsic strength) is behaviorally
// unchanged. (verdict_test.go covers the full matrix; this is the seam check.)
func TestFuseUnchangedAfterRankRefactor(t *testing.T) {
	// Agreement across bands: authoritative + strong on the same app → Confirmed.
	v := Fuse([]Signal{
		{Source: SrcCloudTag, App: "billing"},
		{Source: SrcDNS, App: "billing"},
	})
	if v.App != "billing" || v.Tier != Confirmed {
		t.Fatalf("corroborated authoritative = %+v, want confirmed billing", v)
	}
	// Disagreement: the authoritative claim is primary, the verdict honestly
	// demotes to unknown (contradiction below the floor) — as before.
	v = Fuse([]Signal{
		{Source: SrcIPCatalog, App: "aws-s3"},
		{Source: SrcCloudTag, App: "billing"},
	})
	if supportsApp(t, v) != "billing" || !v.Contradicted {
		t.Fatalf("tag must outrank catalog as primary, got %+v", v)
	}
	if v := Fuse(nil); v.App != "unknown" || v.Tier != Undetermined {
		t.Fatalf("no signals must stay first-class unknown, got %+v", v)
	}
}
