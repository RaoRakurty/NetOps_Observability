// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package noclabel

// labels_parity_test.go — the Go half of the noclabel ↔ labels.ts parity
// contract (RCA v2 §3.2/§7). src/contracts/noc_label_parity.json pins, for every
// explicit signature title and one probe id per cascade rung, the title an
// operator must see. This side is the definition: the test fails when a title
// here changes or a new explicit entry is not in the fixture, and the frontend
// test (labels.parity.test.ts, owned by the frontend workstream) fails when
// signatureNocTitle disagrees with the same file. Regenerate deliberately with
// NOCLABEL_UPDATE_PARITY=1 and mirror the change in labels.ts.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const parityFixture = "../../../contracts/noc_label_parity.json"

type parityHypCase struct {
	ID           string `json:"id"`
	CatalogTitle string `json:"catalog_title"`
	Want         string `json:"want"`
}

type parityFile struct {
	Comment         string            `json:"_comment"`
	SignatureTitles map[string]string `json:"signature_titles"`
	CascadeProbes   map[string]string `json:"cascade_probes"`
	HypothesisTitle []parityHypCase   `json:"hypothesis_titles"`
}

// cascadeProbeIDs — one id per SignatureTitle cascade rung (plus the dropped
// `access` token and the honest last resort), none of them in the explicit map.
var cascadeProbeIDs = []string{
	"sig.ent.app.checkout-latency",
	"sig.ent.k8s.pod-egress",
	"sig.ent.edge.cert-rotation",
	"sig.ent.cloud.vpc-peering",
	"sig.ent.middle-mile.jitter",
	"sig.ent.sdwan.overlay-loss",
	"sig.ent.lan.dns-forwarder",
	"sig.sp.core.l3vpn-leak",
	"sig.ent.internet.provider-loss",
	"sig.ent.core.isis-route-churn",
	"sig.ent.lan.uplink-errors",
	"sig.ent.access.port-link-errors",
	"sig.ent.access.new-template",
	"sig.ent.edge.nat-pool",
	"sig.ent.lan.cpu-spike",
	"sig.ent.lan.unclassified",
}

var parityHypCases = []parityHypCase{
	// explicit map wins over the catalog title
	{ID: "sig.ent.access.mac-flap", CatalogTitle: "MAC flapping / move storm"},
	{ID: "sig.ent.security.exposure-story", CatalogTitle: "Exposed device is also failing (exposure + network fault on one node)"},
	// catalog title wins over the cascade
	{ID: "sig.ent.lan.some-new-template", CatalogTitle: "Some new template"},
	// no catalog title → cascade
	{ID: "sig.ent.lan.uplink-errors", CatalogTitle: ""},
}

func buildParity() parityFile {
	p := parityFile{
		Comment: "Go/TS parity contract for NOC signature titles (RCA v2 §3.2). Generated from " +
			"src/backend/internal/noclabel (the definition) with NOCLABEL_UPDATE_PARITY=1; " +
			"src/frontend/src/components/rca/labels.ts must produce the same titles.",
		SignatureTitles: map[string]string{},
		CascadeProbes:   map[string]string{},
	}
	for id := range sigTitle {
		p.SignatureTitles[id] = SignatureTitle(id)
	}
	for _, id := range cascadeProbeIDs {
		p.CascadeProbes[id] = SignatureTitle(id)
	}
	for _, c := range parityHypCases {
		c.Want = HypothesisTitle(c.ID, c.CatalogTitle)
		p.HypothesisTitle = append(p.HypothesisTitle, c)
	}
	return p
}

func TestLabelParityFixtureMatchesGo(t *testing.T) {
	want := buildParity()
	got, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	path := filepath.Clean(parityFixture)
	if os.Getenv("NOCLABEL_UPDATE_PARITY") == "1" {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		t.Logf("parity fixture regenerated: %s — mirror the change in labels.ts", path)
		return
	}
	disk, err := os.ReadFile(path) // #nosec G304 -- fixed repo-relative fixture path
	if err != nil {
		t.Fatalf("read parity fixture: %v (regenerate with NOCLABEL_UPDATE_PARITY=1)", err)
	}
	if bytes.Equal(disk, got) {
		return
	}
	var onDisk parityFile
	if err := json.Unmarshal(disk, &onDisk); err != nil {
		t.Fatalf("parity fixture is not valid JSON: %v", err)
	}
	var diffs []string
	for id, title := range want.SignatureTitles {
		if onDisk.SignatureTitles[id] != title {
			diffs = append(diffs, id+": go="+title+" fixture="+onDisk.SignatureTitles[id])
		}
	}
	for id := range onDisk.SignatureTitles {
		if _, ok := want.SignatureTitles[id]; !ok {
			diffs = append(diffs, id+": in the fixture but no longer an explicit Go title")
		}
	}
	for id, title := range want.CascadeProbes {
		if onDisk.CascadeProbes[id] != title {
			diffs = append(diffs, id+" (cascade): go="+title+" fixture="+onDisk.CascadeProbes[id])
		}
	}
	sort.Strings(diffs)
	t.Fatalf("Go titles drifted from %s (regenerate with NOCLABEL_UPDATE_PARITY=1 AND mirror labels.ts):\n%v", path, diffs)
}

// The two §3.2 cases the fixture exists for, asserted directly so a careless
// regeneration cannot quietly bless a regression.
func TestAccessTemplatesHaveDistinctTitles(t *testing.T) {
	llf := SignatureTitle("sig.ent.access.local-link-fault")
	mac := SignatureTitle("sig.ent.access.mac-flap")
	ospf := SignatureTitle("sig.ent.access.ospf-adjacency-flap")
	dns := SignatureTitle("sig.ent.access.dns-local-resolver-failure")
	seen := map[string]string{}
	for id, title := range map[string]string{"local-link-fault": llf, "mac-flap": mac, "ospf": ospf, "dns": dns} {
		if title == "Link state change" {
			t.Errorf("%s is still titled with the link-event cascade phrase", id)
		}
		if other, dup := seen[title]; dup {
			t.Errorf("%s and %s share the title %q", id, other, title)
		}
		seen[title] = id
	}
	if mac != "MAC address flapping" {
		t.Errorf("mac-flap = %q", mac)
	}
	// `access` is no longer a cascade token: an unmapped access template is not
	// a link event unless its id actually says link.
	if got := SignatureTitle("sig.ent.access.new-template"); got == "Link state change" {
		t.Errorf("unmapped access template fell into the link rung: %q", got)
	}
	if got := SignatureTitle("sig.ent.access.port-link-errors"); got != "Link state change" {
		t.Errorf("an id that says link must still read as a link event, got %q", got)
	}
}

func TestHypothesisTitlePrecedence(t *testing.T) {
	if got := HypothesisTitle("sig.ent.access.local-link-fault", "Local link fault"); got != "Local link fault" {
		t.Errorf("local-link-fault = %q", got)
	}
	if got := HypothesisTitle("sig.ent.security.exposure-story", "Exposed device is also failing (exposure + network fault on one node)"); got != "Known security exposure on this device" {
		t.Errorf("explicit map must beat a raw catalog title: %q", got)
	}
	if got := HypothesisTitle("sig.ent.lan.new-thing", "New thing"); got != "New thing" {
		t.Errorf("catalog title must beat the cascade: %q", got)
	}
	if got := HypothesisTitle("sig.ent.lan.new-thing", "sig.ent.lan.new-thing"); got == "sig.ent.lan.new-thing" {
		t.Errorf("a catalog title equal to the id must not leak the raw id")
	}
}

func TestLocalisationSentence(t *testing.T) {
	cases := []struct {
		subject   string
		localised bool
		want      string
	}{
		{"cedge-60-07ae8615", false, "Evidence concentrates on cedge-60-07ae8615; not independently localised."},
		{"cedge-60-07ae8615", true, "Fault localised to cedge-60-07ae8615 by independent evidence."},
		{"", false, "The evidence does not concentrate on a single object; not localised."},
	}
	for _, c := range cases {
		if got := LocalisationSentence(c.subject, c.localised); got != c.want {
			t.Errorf("LocalisationSentence(%q,%v) = %q, want %q", c.subject, c.localised, got, c.want)
		}
	}
}
