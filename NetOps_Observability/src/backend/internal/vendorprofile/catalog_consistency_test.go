// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package vendorprofile

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// catalog_consistency_test.go — the ONE VOCABULARY guard.
//
// The registry's profiles are Go-embedded JSON; the parser/collection catalog
// under telemetry-catalog/ is Python-read YAML. They are two files, so nothing
// but a test stops them drifting into two parallel vendor vocabularies. This
// test is that stop: every vendor and (vendor, platform) identifier the catalog
// names must resolve in the registry, and vice versa for the vendors the
// catalog claims to parse.

const catalogDir = "../../../../telemetry-catalog/"

var (
	reCatalogVendor   = regexp.MustCompile(`^\s*-?\s*vendor:\s*([A-Za-z0-9_.-]+)\s*$`)
	reCatalogPlatform = regexp.MustCompile(`^\s*platform:\s*([A-Za-z0-9_.-]+)\s*$`)
	reEventVendors    = regexp.MustCompile(`^\s*vendors:\s*\[([^\]]*)\]\s*$`)
)

// pseudoVendors are the NON-vendor tokens telemetry-catalog/events.yaml uses to
// mark grammars that are not vendor-anchored. "generic" is a real registry
// document (it carries the vendor-neutral dialect synonyms); "standard" and
// "any" are catalog-only markers meaning "an IETF/IEEE standard grammar" and
// "every vendor" — neither describes a device, so neither gets a profile.
var pseudoVendors = map[string]struct{}{"standard": {}, "any": {}}

// readCatalog returns the catalog file's lines, skipping the test when the
// catalog is not present (a backend-only checkout).
func readCatalog(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(catalogDir + name)
	if err != nil {
		t.Skipf("telemetry-catalog/%s not readable from this checkout: %v", name, err)
	}
	return strings.Split(string(b), "\n")
}

// TestCollectionCatalogPairsResolve — every (vendor, platform) row in
// telemetry-catalog/collection.yaml must resolve to a profile, by canonical id
// or by a declared platform alias.
func TestCollectionCatalogPairsResolve(t *testing.T) {
	reg := Default()
	lines := readCatalog(t, "collection.yaml")
	seen := map[string]struct{}{}
	vendor := ""
	for _, ln := range lines {
		if m := reCatalogVendor.FindStringSubmatch(ln); m != nil {
			vendor = m[1]
			continue
		}
		if m := reCatalogPlatform.FindStringSubmatch(ln); m != nil && vendor != "" {
			seen[vendor+"/"+m[1]] = struct{}{}
		}
	}
	if len(seen) == 0 {
		t.Fatal("parsed no (vendor, platform) pairs out of collection.yaml — the scan broke")
	}
	pairs := make([]string, 0, len(seen))
	for k := range seen {
		pairs = append(pairs, k)
	}
	sort.Strings(pairs)
	for _, pair := range pairs {
		if _, ok := reg.Lookup(pair); !ok {
			t.Errorf("collection.yaml names %q but no vendor profile claims it — "+
				"the registry and the telemetry catalog must share ONE vendor/platform vocabulary", pair)
		}
	}
	t.Logf("catalog (vendor, platform) pairs resolved: %v", pairs)
}

// TestEventCatalogVendorsAreKnown — every vendor token in
// telemetry-catalog/events.yaml's `vendors:` lists must be a registry vendor id
// or a documented pseudo-vendor. A token that is neither is a NEW vocabulary
// appearing on one side only.
func TestEventCatalogVendorsAreKnown(t *testing.T) {
	reg := Default()
	known := map[string]struct{}{}
	for _, v := range reg.VendorIDs() {
		known[v] = struct{}{}
	}
	lines := readCatalog(t, "events.yaml")
	tokens := map[string]struct{}{}
	for _, ln := range lines {
		m := reEventVendors.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		for _, raw := range strings.Split(m[1], ",") {
			if tok := strings.TrimSpace(raw); tok != "" {
				tokens[tok] = struct{}{}
			}
		}
	}
	if len(tokens) == 0 {
		t.Fatal("parsed no vendor tokens out of events.yaml — the scan broke")
	}
	got := make([]string, 0, len(tokens))
	for tok := range tokens {
		got = append(got, tok)
	}
	sort.Strings(got)
	for _, tok := range got {
		if _, ok := known[tok]; ok {
			continue
		}
		if _, ok := pseudoVendors[tok]; ok {
			continue
		}
		t.Errorf("events.yaml uses vendor token %q, which is neither a vendor profile nor a documented pseudo-vendor", tok)
	}
	t.Logf("event-catalog vendor tokens: %v", got)
}

// TestFidelityVocabularyMatchesTheCatalogLadder — the profile `fidelity` field
// must use the SAME words collection.yaml's fidelity_status column uses, so a
// coverage claim means the same thing on both sides.
func TestFidelityVocabularyMatchesTheCatalogLadder(t *testing.T) {
	lines := readCatalog(t, "collection.yaml")
	re := regexp.MustCompile(`^\s*fidelity_status:\s*([a-z_]+)\s*$`)
	found := 0
	for _, ln := range lines {
		m := re.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		found++
		if _, ok := validFidelity[m[1]]; !ok {
			t.Errorf("collection.yaml uses fidelity_status %q, which the profile schema does not accept", m[1])
		}
	}
	if found == 0 {
		t.Fatal("parsed no fidelity_status values out of collection.yaml — the scan broke")
	}
	// Every profile's own claim must be on the ladder too (the loader enforces
	// this; asserted here so the two checks live together).
	for _, p := range Default().Profiles() {
		if _, ok := validFidelity[p.Fidelity]; !ok {
			t.Errorf("profile %s claims fidelity %q, off the ladder", p.ID, p.Fidelity)
		}
	}
}

// TestProfilePlatformIDsAreCPEProductStrings — the platform segment of a profile
// id is the CPE product token the vulnerability feed matches on, which is also
// what collectors.ParseOS emits. Keeping them identical is what lets an advisory
// query be built straight off a detected profile.
func TestProfilePlatformIDsAreCPEProductStrings(t *testing.T) {
	for _, p := range Default().Profiles() {
		if p.Detection.OSParse == nil {
			continue
		}
		if p.Detection.OSParse.Product != p.Platform {
			t.Errorf("profile %s: os_parse.product %q != platform %q — the profile id must BE the CPE product token",
				p.ID, p.Detection.OSParse.Product, p.Platform)
		}
		for _, id := range p.Advisory.ProductIDs {
			if id != p.Platform {
				t.Errorf("profile %s: advisory product id %q is not the platform token", p.ID, id)
			}
		}
	}
}
