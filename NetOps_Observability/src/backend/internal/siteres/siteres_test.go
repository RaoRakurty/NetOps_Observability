// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package siteres

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	all := Input{
		Tenant: "acme", BindingSlug: "nyc", BindingName: "New York",
		Label: "label-site", ControllerSiteID: "50", ControllerSystem: "vmanage",
	}
	cases := []struct {
		name   string
		in     Input
		key    string
		label  string
		source Source
	}{
		{"manual binding wins over everything", all, "nyc", "New York", SourceManual},
		{"a binding with no site name reads as its slug", Input{BindingSlug: "nyc"}, "nyc", "nyc", SourceManual},
		{"then the discovery site label", Input{Label: "dc-east", ControllerSiteID: "50", ControllerSystem: "vmanage"}, "dc-east", "dc-east", SourceLabel},
		{"then the controller's site id, with provenance", Input{Tenant: "acme", ControllerSiteID: "50", ControllerSystem: "vmanage"},
			"discovered:acme:sdwan:50", "Site 50 · from vManage", SourceDiscovered},
		{"the controller's site name names the site", Input{Tenant: "acme", ControllerSiteID: "50", ControllerSiteName: "Branch Boston", ControllerSystem: "vmanage"},
			"discovered:acme:sdwan:50", "Branch Boston · from vManage", SourceDiscovered},
		{"the device's own MIB answer beats the controller's", Input{Tenant: "acme", DeviceSiteID: "51", ControllerSiteID: "50", ControllerSiteName: "Boston", ControllerSystem: "vmanage"},
			"discovered:acme:sdwan:51", "Site 51 · from device", SourceDiscovered},
		{"peers are the last resort", Input{Tenant: "acme", PeerSiteID: "60"}, "discovered:acme:sdwan:60", "Site 60 · from SD-WAN peers", SourceDiscovered},
		{"a controller with no system name", Input{Tenant: "acme", ControllerSiteID: "7"}, "discovered:acme:controller:7", "Site 7 · from controller", SourceDiscovered},
		{"controller site 250 groups like any other", Input{Tenant: "acme", ControllerSiteID: "250", ControllerSystem: "vmanage"},
			"discovered:acme:sdwan:250", "Site 250 · from vManage", SourceDiscovered},
		{"nothing known", Input{Tenant: "acme"}, "", "", ""},
	}
	for _, c := range cases {
		got := Resolve(c.in)
		if got.Key != c.key || got.Label != c.label || got.Source != c.source {
			t.Errorf("%s: got (%q,%q,%q) want (%q,%q,%q)", c.name, got.Key, got.Label, got.Source, c.key, c.label, c.source)
		}
	}
}

func TestResolveKeepsTheReportedIDWhateverWins(t *testing.T) {
	got := Resolve(Input{BindingSlug: "nyc", ControllerSiteID: "50", ControllerSystem: "vmanage"})
	if got.Reported != "50" || got.ReportedOrigin != "vmanage" {
		t.Fatalf("reported = (%q,%q)", got.Reported, got.ReportedOrigin)
	}
	if got.SiteID != "" || got.Origin != "" {
		t.Fatalf("a manual site must not carry discovered provenance: %+v", got)
	}
}

// §3a: the same site id in two tenants is two sites; and two namespaces never
// merge, while the SD-WAN sources (MIB, peers, vManage) do.
func TestDiscoveredKeysAreTenantAndNamespaceQualified(t *testing.T) {
	a := Resolve(Input{Tenant: "acme", ControllerSiteID: "50", ControllerSystem: "vmanage"})
	b := Resolve(Input{Tenant: "globex", ControllerSiteID: "50", ControllerSystem: "vmanage"})
	if a.Key == b.Key {
		t.Fatalf("two tenants' site 50 share a key %q", a.Key)
	}
	m := Resolve(Input{Tenant: "acme", ControllerSiteID: "50", ControllerSystem: "meraki"})
	if m.Key == a.Key {
		t.Fatalf("a Meraki id merged with an SD-WAN site: %q", m.Key)
	}
	mib := Resolve(Input{Tenant: "acme", DeviceSiteID: "50"})
	peer := Resolve(Input{Tenant: "ACME ", PeerSiteID: "50"})
	if mib.Key != a.Key || peer.Key != a.Key {
		t.Fatalf("SD-WAN sources split one branch: %q %q %q", a.Key, mib.Key, peer.Key)
	}
}

func TestDisagreementNote(t *testing.T) {
	cases := []struct {
		in   Input
		note bool
	}{
		{Input{BindingSlug: "nyc", BindingName: "New York", ControllerSiteID: "50", ControllerSystem: "vmanage"}, true},
		{Input{BindingSlug: "site-50", BindingName: "Boston", ControllerSiteID: "50"}, false},
		{Input{BindingSlug: "bos", BindingName: "Branch 50", DeviceSiteID: "50"}, false},
		{Input{BindingSlug: "site-500", ControllerSiteID: "50"}, true}, // a whole token, not a substring
		{Input{BindingSlug: "nyc"}, false},                             // nothing reported
		{Input{Label: "nyc", ControllerSiteID: "50"}, false},           // only a manual site can disagree
	}
	for i, c := range cases {
		got := Resolve(c.in)
		if (got.Note != "") != c.note {
			t.Errorf("case %d: note = %q, want note=%v", i, got.Note, c.note)
		}
	}
	got := Resolve(cases[0].in)
	if !strings.Contains(got.Note, "50") || !strings.Contains(got.Note, "vManage") {
		t.Errorf("note does not say what was reported: %q", got.Note)
	}
}

func TestHarmonizePicksOneLabelPerSite(t *testing.T) {
	sites := []Site{
		Resolve(Input{Tenant: "t", PeerSiteID: "50"}),
		Resolve(Input{Tenant: "t", DeviceSiteID: "50"}),
		Resolve(Input{Tenant: "t", ControllerSiteID: "50", ControllerSiteName: "Boston", ControllerSystem: "vmanage"}),
		Resolve(Input{Tenant: "t", BindingSlug: "nyc"}),
	}
	Harmonize(sites)
	for _, s := range sites[:3] {
		if s.Label != "Boston · from vManage" || s.Name != "Boston" {
			t.Fatalf("member label = %q / %q", s.Label, s.Name)
		}
	}
	if sites[3].Label != "nyc" {
		t.Fatalf("a manual site was relabelled: %q", sites[3].Label)
	}
	// Without a controller name the device's own answer beats its peers'.
	two := []Site{Resolve(Input{Tenant: "t", PeerSiteID: "9"}), Resolve(Input{Tenant: "t", DeviceSiteID: "9"})}
	Harmonize(two)
	if two[0].Label != "Site 9 · from device" {
		t.Fatalf("label = %q", two[0].Label)
	}
}

func TestFieldsAreBounded(t *testing.T) {
	long := strings.Repeat("é", 500)
	got := Resolve(Input{Tenant: "t", ControllerSiteID: "1", ControllerSiteName: long, ControllerSystem: "vmanage"})
	if n := len([]rune(got.Name)); n != maxField {
		t.Fatalf("name runes = %d", n)
	}
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func dev(id, tenant string, in Input) Device {
	in.Tenant = tenant
	return Device{ID: id, Name: id, Tenant: tenant, Site: Resolve(in)}
}

func TestPlanAdoption(t *testing.T) {
	vm := func(site string) Input { return Input{ControllerSiteID: site, ControllerSystem: "vmanage"} }
	manual := vm("50")
	manual.BindingSlug, manual.BindingName = "boston", "Boston"
	labelled := vm("60")
	labelled.Label = "dc-west"
	devs := []Device{
		dev("ve51", "acme", vm("50")),
		dev("ve52", "acme", vm("50")),
		dev("ve53", "acme", manual), // reports 50, manually placed → skip
		dev("vsmart", "acme", vm("250")),
		dev("vbond", "acme", vm("250")),
		dev("ce60", "acme", labelled), // only a labelled device → no site offered
		dev("sw1", "acme", Input{}),   // reports nothing
	}
	sites := make([]Site, len(devs))
	for i := range devs {
		sites[i] = devs[i].Site
	}
	Harmonize(sites)
	for i := range devs {
		devs[i].Site = sites[i]
	}
	existing := map[string]bool{"site-250": true}
	plan := PlanAdoption(devs, slug, func(s string) bool { return existing[s] })

	if len(plan.Sites) != 2 {
		t.Fatalf("sites = %+v", plan.Sites)
	}
	s250, s50 := plan.Sites[0], plan.Sites[1] // sorted by key: …:250 < …:50
	if s50.Slug != "site-50" || s50.Action != ActionCreate || s50.Name != "Site 50" || s50.Label != "Site 50 · from vManage" {
		t.Fatalf("site 50 = %+v", s50)
	}
	if s250.Slug != "site-250" || s250.Action != ActionReuse {
		t.Fatalf("site 250 = %+v", s250)
	}
	var skipped AdoptDevice
	binds := 0
	for _, d := range s50.Devices {
		switch d.Action {
		case ActionBind:
			binds++
		case ActionSkip:
			skipped = d
		}
	}
	if binds != 2 || skipped.DeviceID != "ve53" || !strings.Contains(skipped.Detail, "operator") {
		t.Fatalf("site 50 rows = %+v", s50.Devices)
	}
	want := map[string]int{ActionCreate: 1, ActionReuse: 1, ActionBind: 4, ActionSkip: 1, ActionRefused: 0, ActionError: 0}
	if !reflect.DeepEqual(plan.Summary, want) {
		t.Fatalf("summary = %v want %v", plan.Summary, want)
	}

	// Determinism: the same input plans the same output (preview == apply).
	again := PlanAdoption(devs, slug, func(s string) bool { return existing[s] })
	if !reflect.DeepEqual(plan, again) {
		t.Fatal("two plans of one input differ")
	}

	// Idempotence: once every discovered device is bound, nothing is offered.
	var bound []Device
	for _, d := range devs {
		in := Input{ControllerSiteID: d.Site.Reported, ControllerSystem: d.Site.ReportedOrigin}
		if d.Site.Source == SourceDiscovered {
			in.BindingSlug = "site-" + d.Site.SiteID
		} else if d.Site.Source == SourceManual {
			in.BindingSlug = d.Site.Key
		} else if d.Site.Source == SourceLabel {
			in.Label = d.Site.Key
		}
		bound = append(bound, dev(d.ID, d.Tenant, in))
	}
	if p := PlanAdoption(bound, slug, func(string) bool { return true }); len(p.Sites) != 0 {
		t.Fatalf("second plan offered %+v", p.Sites)
	}
}

func TestPlanAdoptionQualifiesASlugCollision(t *testing.T) {
	devs := []Device{
		dev("a", "t", Input{ControllerSiteID: "50", ControllerSystem: "vmanage"}),
		dev("b", "t", Input{ControllerSiteID: "x1", ControllerSiteName: "Site 50", ControllerSystem: "meraki"}),
	}
	plan := PlanAdoption(devs, slug, func(string) bool { return false })
	if len(plan.Sites) != 2 || plan.Sites[0].Slug == plan.Sites[1].Slug {
		t.Fatalf("slugs collided: %+v", plan.Sites)
	}
}
