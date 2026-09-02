package secapi

// rules_test.go — the catalog's contract with the registries it is assembled
// from, and with the bus vocabulary the Exposure Story query filters on.

import (
	"encoding/json"
	"regexp"
	"testing"

	"netops/backend/internal/advisory"
	"netops/backend/internal/hardening"
	"netops/backend/internal/secbus"
	"netops/backend/internal/threatlane"
)

// TestCatalogCoversEveryShippedRule is the anti-drift guard: the page lists what
// ships. A hand-maintained list would let a detection fire while being invisible
// (or be listed while not existing) — both of which make the enable toggle a
// lie about what is running.
func TestCatalogCoversEveryShippedRule(t *testing.T) {
	cat := Catalog()
	ids := CatalogIDs()

	hc := hardening.DefaultCatalog()
	tc := threatlane.DefaultCatalog()
	want := hc.Len() + tc.Len() + 2 // +2 advisory providers
	if len(cat) != want {
		t.Fatalf("catalog holds %d entries, the registries ship %d", len(cat), want)
	}
	for _, r := range hc.Rules() {
		if !ids[r.ID] {
			t.Errorf("hardening rule %q is not in the catalog", r.ID)
		}
	}
	for _, p := range hc.Probes() {
		if !ids[p.ID] {
			t.Errorf("exposure probe %q is not in the catalog", p.ID)
		}
	}
	for _, r := range tc.LogRules() {
		if !ids[r.ID] {
			t.Errorf("threatlane log rule %q is not in the catalog", r.ID)
		}
	}
	for _, r := range tc.PairRules() {
		if !ids[r.ID] {
			t.Errorf("threatlane pair rule %q is not in the catalog", r.ID)
		}
	}
	for _, r := range tc.SourceRules() {
		if !ids[r.ID] {
			t.Errorf("threatlane source rule %q is not in the catalog", r.ID)
		}
	}
	for _, src := range []string{advisory.SourceOfflineFeed, advisory.SourceCiscoOpenVuln} {
		if !ids[src] {
			t.Errorf("advisory provider %q is not in the catalog", src)
		}
	}
}

// TestCatalogFieldsAreHonest pins the three derived fields. Fidelity and
// seam-awareness are read off the registries rather than hand-assigned, so a
// new behavioral rule cannot ship claiming high fidelity.
func TestCatalogFieldsAreHonest(t *testing.T) {
	seamAware, mitred, behavioral := 0, 0, 0
	for _, r := range Catalog() {
		switch r.Family {
		case FamilyHardening, FamilyExposure, FamilyThreat, FamilyAdvisory:
		default:
			t.Errorf("rule %s has unknown family %q", r.RuleID, r.Family)
		}
		if r.Fidelity != FidelityHigh && r.Fidelity != FidelityMedium {
			t.Errorf("rule %s has unknown fidelity %q", r.RuleID, r.Fidelity)
		}
		if r.SeamAware {
			seamAware++
			if r.Family != FamilyExposure {
				t.Errorf("rule %s claims seam awareness outside the exposure family", r.RuleID)
			}
		}
		if len(r.MITRE) > 0 {
			mitred++
			if r.Family != FamilyThreat {
				t.Errorf("rule %s carries a MITRE technique outside the threat family", r.RuleID)
			}
		}
		if r.Fidelity == FidelityMedium {
			behavioral++
		}
		if !r.Enabled {
			t.Errorf("the shipped catalog must default every rule ENABLED; %s is off", r.RuleID)
		}
	}
	if seamAware == 0 {
		t.Error("no seam-aware entries — the §5e exposure probes are missing from the catalog")
	}
	if mitred == 0 {
		t.Error("no MITRE-tagged entries — the threatlane detections are missing from the catalog")
	}
	if behavioral == 0 {
		t.Error("no medium-fidelity entries — the behavioral detections are being advertised as deterministic")
	}
}

// TestSecuritySignalKindsMatchTheBus pins the string literals in rules.go equal
// to the secbus vocabulary. secbus is a leaf producer nothing in the core
// imports, so the production code cannot import it — but a TEST can, and this
// is the only thing standing between a renamed kind and an Exposure Story page
// that is silently, permanently empty.
func TestSecuritySignalKindsMatchTheBus(t *testing.T) {
	want := []string{secbus.KindPosture, secbus.KindExposure, secbus.KindSignal}
	if len(SecuritySignalKinds) != len(want) {
		t.Fatalf("SecuritySignalKinds has %d entries, secbus defines %d", len(SecuritySignalKinds), len(want))
	}
	for i, k := range want {
		if SecuritySignalKinds[i] != k {
			t.Errorf("SecuritySignalKinds[%d] = %q, secbus says %q", i, SecuritySignalKinds[i], k)
		}
	}
}

func TestApplyIgnoresUnknownRuleIDs(t *testing.T) {
	cat := Catalog()
	got := Apply(cat, map[string]bool{"a-rule-that-was-retired": false})
	if len(got) != len(cat) {
		t.Fatalf("Apply changed the catalog size: %d → %d", len(cat), len(got))
	}
	for _, r := range got {
		if !r.Enabled {
			t.Fatalf("an unknown override disabled %s", r.RuleID)
		}
	}
}

// techniqueID is the ATT&CK id grammar the wire carries: a technique (T1071) or
// a sub-technique (T1562.001). Anything else is a malformed tag.
var techniqueID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// TestRulesJSONMitreIsAlwaysAnArray is the REGRESSION for the Detection Rules
// white-screen: the field was serialized as a bare string ("T1071") while every
// consumer treats it as a list, so the page's `r.mitre.map(...)` threw and took
// the whole section down. The type is the contract — pin the SERIALIZED shape,
// not just the Go field, because only the serialized shape is what the browser
// sees.
func TestRulesJSONMitreIsAlwaysAnArray(t *testing.T) {
	raw, err := json.Marshal(Apply(Catalog(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the catalog serialized to an empty list")
	}
	tagged := 0
	for _, row := range rows {
		id := string(row["rule_id"])
		m, ok := row["mitre"]
		if !ok {
			continue // omitempty: an untagged rule carries no field at all
		}
		if len(m) == 0 || m[0] != '[' {
			t.Fatalf("rule %s serialized mitre as %s — the contract is an ARRAY of technique ids", id, m)
		}
		var techs []string
		if err := json.Unmarshal(m, &techs); err != nil {
			t.Fatalf("rule %s: mitre does not decode as []string: %v", id, err)
		}
		if len(techs) == 0 {
			t.Errorf("rule %s emitted an EMPTY mitre array; omitempty must drop the field instead", id)
		}
		for _, tech := range techs {
			if !techniqueID.MatchString(tech) {
				t.Errorf("rule %s carries malformed technique %q (want T#### or T####.###)", id, tech)
			}
		}
		if string(row["family"]) != `"`+FamilyThreat+`"` {
			t.Errorf("rule %s carries mitre outside the threat family", id)
		}
		tagged++
	}
	if tagged == 0 {
		t.Fatal("no rule serialized a mitre array — the threat lane is missing from the wire catalog")
	}
}

// TestRulesJSONGoldenShape pins the exact key set and value types the Detection
// Rules page decodes, one representative per family. A field renamed, dropped or
// re-typed here is a UI break, and the frontend cannot fail this build — so the
// backend fails it instead.
func TestRulesJSONGoldenShape(t *testing.T) {
	raw, err := json.Marshal(Apply(Catalog(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Every row: the five always-present keys, plus mitre only on threat rules.
	base := map[string]string{
		"rule_id": "string", "family": "string", "enabled": "bool",
		"fidelity": "string", "seam_aware": "bool",
	}
	seenFamily := map[string]bool{}
	for _, row := range rows {
		for k, want := range base {
			v, ok := row[k]
			if !ok {
				t.Fatalf("row %v is missing required key %q", row["rule_id"], k)
			}
			switch want {
			case "string":
				if _, ok := v.(string); !ok {
					t.Errorf("row %v: %s = %T, want string", row["rule_id"], k, v)
				}
			case "bool":
				if _, ok := v.(bool); !ok {
					t.Errorf("row %v: %s = %T, want bool", row["rule_id"], k, v)
				}
			}
		}
		for k := range row {
			if _, ok := base[k]; !ok && k != "mitre" {
				t.Errorf("row %v carries unexpected key %q — the page decodes a closed shape", row["rule_id"], k)
			}
		}
		if m, ok := row["mitre"]; ok {
			if _, ok := m.([]any); !ok {
				t.Errorf("row %v: mitre = %T, want []any", row["rule_id"], m)
			}
		}
		seenFamily[row["family"].(string)] = true
	}
	for _, f := range []string{FamilyHardening, FamilyExposure, FamilyThreat, FamilyAdvisory} {
		if !seenFamily[f] {
			t.Errorf("the serialized catalog carries no %s rule", f)
		}
	}

	// The exact byte shape of one threat row and one hardening row — the two
	// bodies the production page was observed to receive.
	one := func(id string) string {
		for _, r := range Apply(Catalog(), nil) {
			if r.RuleID == id {
				b, err := json.Marshal(r)
				if err != nil {
					t.Fatalf("marshal %s: %v", id, err)
				}
				return string(b)
			}
		}
		t.Fatalf("rule %s is not in the catalog", id)
		return ""
	}
	for id, want := range map[string]string{
		"flow-beaconing": `{"rule_id":"flow-beaconing","family":"threat","enabled":true,"fidelity":"medium","mitre":["T1071"],"seam_aware":false}`,
		"bootp-server":   `{"rule_id":"bootp-server","family":"hardening","enabled":true,"fidelity":"high","seam_aware":false}`,
	} {
		if got := one(id); got != want {
			t.Errorf("golden shape drift for %s:\n got %s\nwant %s", id, got, want)
		}
	}
}

// TestMitreTechniquesNormalization covers the splitter directly: one id, a
// comma/space list, a sub-technique (the dot is part of the id and must survive)
// and an empty tag (no field at all, never [""]).
func TestMitreTechniquesNormalization(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"T1071", []string{"T1071"}},
		{"T1562.001", []string{"T1562.001"}},
		{"T1071, T1571", []string{"T1071", "T1571"}},
		{"T1071 T1571", []string{"T1071", "T1571"}},
		{"T1071;T1571", []string{"T1071", "T1571"}},
		{" T1071 ,, T1071 ", []string{"T1071"}}, // deduped, order preserved
	}
	for _, c := range cases {
		got := mitreTechniques(c.in)
		if len(got) != len(c.want) {
			t.Errorf("mitreTechniques(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("mitreTechniques(%q) = %v, want %v", c.in, got, c.want)
				break
			}
		}
	}
}
