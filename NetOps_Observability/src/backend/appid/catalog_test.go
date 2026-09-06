// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import (
	"net/netip"
	"testing"
)

func TestTrie_LongestPrefixMatch(t *testing.T) {
	tr := newPrefixTrie()
	tr.insert(netip.MustParsePrefix("10.0.0.0/8"), ipCatalogEntry("10.0.0.0/8", "Wide", "x"))
	tr.insert(netip.MustParsePrefix("10.1.2.0/24"), ipCatalogEntry("10.1.2.0/24", "Narrow", "x"))

	// most specific wins
	got := tr.lookup(netip.MustParseAddr("10.1.2.3"))
	if len(got) != 1 || got[0].App != "Narrow" {
		t.Fatalf("LPM should pick the /24, got %+v", got)
	}
	// falls back to the wider prefix elsewhere in /8
	got = tr.lookup(netip.MustParseAddr("10.9.9.9"))
	if len(got) != 1 || got[0].App != "Wide" {
		t.Fatalf("should fall back to /8, got %+v", got)
	}
	// outside any prefix → no match
	if got = tr.lookup(netip.MustParseAddr("8.8.8.8")); got != nil {
		t.Fatalf("expected no match, got %+v", got)
	}
}

func TestTrie_IPv6(t *testing.T) {
	tr := newPrefixTrie()
	tr.insert(netip.MustParsePrefix("2620:1ec::/36"), ipCatalogEntry("2620:1ec::/36", "M365", "m365"))
	if got := tr.lookup(netip.MustParseAddr("2620:1ec:8:9::1")); len(got) != 1 || got[0].App != "M365" {
		t.Fatalf("v6 LPM failed, got %+v", got)
	}
	if got := tr.lookup(netip.MustParseAddr("2001:db8::1")); got != nil {
		t.Fatalf("v6 should not match, got %+v", got)
	}
}

func TestParseAWS(t *testing.T) {
	raw := []byte(`{"prefixes":[{"ip_prefix":"52.94.0.0/22","service":"S3"},{"ip_prefix":"bad","service":"EC2"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/40","service":"DYNAMODB"}]}`)
	es, err := ParseAWS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 { // the "bad" prefix is dropped
		t.Fatalf("want 2 valid entries, got %d: %+v", len(es), es)
	}
	if es[0].App != "AWS S3" || es[0].Source != SrcIPCatalog {
		t.Fatalf("unexpected entry %+v", es[0])
	}
}

func TestParseAWS_GenericAmazonTag(t *testing.T) {
	// the catch-all "AMAZON" aggregate renders as plain "AWS", not "AWS AMAZON".
	es, err := ParseAWS([]byte(`{"prefixes":[{"ip_prefix":"52.94.0.0/22","service":"AMAZON"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].App != "AWS" {
		t.Fatalf("AMAZON aggregate should be 'AWS', got %+v", es)
	}
}

func TestParseAzure(t *testing.T) {
	raw := []byte(`{"values":[{"name":"Storage.WestUS","properties":{"systemService":"AzureStorage","addressPrefixes":["20.150.0.0/16","2603:1030::/44"]}}]}`)
	es, err := ParseAzure(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].App != "Azure AzureStorage" {
		t.Fatalf("unexpected %+v", es)
	}
}

func TestParseGCP(t *testing.T) {
	raw := []byte(`{"prefixes":[{"ipv4Prefix":"34.80.0.0/15","service":"Google Cloud"},{"ipv6Prefix":"2600:1900::/35","service":""}]}`)
	es, err := ParseGCP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[1].App != "Google Cloud" {
		t.Fatalf("unexpected %+v", es)
	}
}

func TestParseM365(t *testing.T) {
	raw := []byte(`[{"serviceArea":"Exchange","ips":["13.107.6.152/31","40.92.0.0/15"],"urls":["outlook.office.com"]}]`)
	es, err := ParseM365(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 2 || es[0].App != "Microsoft 365 Exchange" {
		t.Fatalf("unexpected %+v", es)
	}
}

func TestCatalog_ResolveAndFuse(t *testing.T) {
	es, _ := ParseM365([]byte(`[{"serviceArea":"Exchange","ips":["13.107.6.152/31"]}]`))
	c := NewCatalog(es)
	if c.Size() != 1 {
		t.Fatalf("size = %d", c.Size())
	}

	// IP-catalog hit alone → suspected M365 Exchange
	v := c.ResolveStr("13.107.6.153")
	if v.App != "Microsoft 365 Exchange" || v.Tier != Suspected {
		t.Fatalf("catalog-only should be suspected, got %+v", v)
	}

	// add a corroborating DNS signal → strong + agreement → confirmed
	v = c.ResolveStr("13.107.6.153", Signal{Source: SrcDNS, App: "Microsoft 365 Exchange"})
	if v.Tier != Confirmed {
		t.Fatalf("catalog+dns agreement should confirm, got %+v", v)
	}

	// miss → first-class unknown
	if v = c.ResolveStr("8.8.8.8"); v.App != "unknown" {
		t.Fatalf("a miss must be unknown, got %+v", v)
	}
}

func TestNilCatalogResolvesUnknown(t *testing.T) {
	var c *Catalog
	if v := c.ResolveStr("1.2.3.4"); v.App != "unknown" {
		t.Fatalf("nil catalog must be safe + unknown, got %+v", v)
	}
}
