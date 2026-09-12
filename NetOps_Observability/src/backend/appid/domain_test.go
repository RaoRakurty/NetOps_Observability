// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import "testing"

func TestDomainIndex_ExactAndSuffix(t *testing.T) {
	d := NewDomainIndex()
	d.Add("*.outlook.com", "Microsoft 365 Exchange", SrcDNS, 0)
	d.Add("teams.microsoft.com", "Microsoft 365 Teams", SrcDNS, 0) // exact, more specific
	d.Add(".zoom.us", "Zoom", SrcDNS, 0)

	// suffix match
	if s := d.SignalsFor("mail-aaa.outlook.com"); len(s) != 1 || s[0].App != "Microsoft 365 Exchange" {
		t.Fatalf("suffix match failed: %+v", s)
	}
	// exact beats nothing-else
	if s := d.SignalsFor("teams.microsoft.com"); len(s) != 1 || s[0].App != "Microsoft 365 Teams" {
		t.Fatalf("exact match failed: %+v", s)
	}
	// .zoom.us suffix
	if s := d.SignalsFor("us02web.zoom.us"); len(s) != 1 || s[0].App != "Zoom" {
		t.Fatalf("zoom suffix failed: %+v", s)
	}
	// trailing dot + case normalized
	if s := d.SignalsFor("US02WEB.ZOOM.US."); len(s) != 1 || s[0].App != "Zoom" {
		t.Fatalf("normalization failed: %+v", s)
	}
	// no match
	if s := d.SignalsFor("example.org"); s != nil {
		t.Fatalf("unexpected match: %+v", s)
	}
	// the domain signal is strong (SrcDNS)
	if s := d.SignalsFor("x.zoom.us"); s[0].Source != SrcDNS {
		t.Fatalf("domain signal should be SrcDNS, got %v", s[0].Source)
	}
}

func TestDomainIndex_MostSpecificSuffixWins(t *testing.T) {
	d := NewDomainIndex()
	d.Add("*.cloudapp.net", "Azure", SrcDNS, 0)
	d.Add("*.blob.core.windows.net", "Azure Storage", SrcDNS, 0)
	if s := d.SignalsFor("acct.blob.core.windows.net"); len(s) != 1 || s[0].App != "Azure Storage" {
		t.Fatalf("most-specific suffix should win, got %+v", s)
	}
}

func TestM365Domains(t *testing.T) {
	raw := []byte(`[{"serviceArea":"Exchange","ips":["13.107.6.152/31"],"urls":["outlook.office.com","*.outlook.com"]},{"serviceArea":"SharePoint","urls":["*.sharepoint.com"]}]`)
	es, err := M365Domains(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 3 || es[0].App != "Microsoft 365 Exchange" || es[0].Pattern != "outlook.office.com" {
		t.Fatalf("unexpected domains: %+v", es)
	}
}

func TestDomainOperatorAuthoritative(t *testing.T) {
	d := NewDomainIndex()
	d.Add("wiki.corp", "Corp Wiki", SrcOperator, 0)
	s := d.SignalsFor("wiki.corp")
	if len(s) != 1 || s[0].Source != SrcOperator {
		t.Fatalf("operator domain should be authoritative, got %+v", s)
	}
	// fused alone → confirmed (authoritative)
	if got := Fuse(s); got.Tier != Confirmed || got.App != "Corp Wiki" {
		t.Fatalf("operator domain should confirm, got %+v", got)
	}
}
