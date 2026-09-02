package vendorprofile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// TestEmbeddedProfilesLoad is the gate that makes Default()'s panic-on-error
// contract safe: the SHIPPED profile set must load and validate in CI.
func TestEmbeddedProfilesLoad(t *testing.T) {
	reg := Default()
	if len(reg.VendorIDs()) == 0 {
		t.Fatal("registry loaded no vendors")
	}
	if len(reg.IDs()) == 0 {
		t.Fatal("registry loaded no profiles")
	}
	for _, p := range reg.Profiles() {
		if p.ID != p.Vendor+"/"+p.Platform {
			t.Errorf("profile id %q is not <vendor>/<platform> (%s/%s)", p.ID, p.Vendor, p.Platform)
		}
		if _, ok := reg.Vendor(p.Vendor); !ok {
			t.Errorf("profile %q references unknown vendor %q", p.ID, p.Vendor)
		}
	}
}

// TestLoadDeterminism — two independent loads of the same filesystem must
// produce identical registries (ordering, indexes and all). The profile set is
// reference data; a map-iteration-ordered load would make every downstream
// verdict irreproducible.
func TestLoadDeterminism(t *testing.T) {
	a, err := Load(profilesFS, "profiles")
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := Load(profilesFS, "profiles")
	if err != nil {
		t.Fatalf("load b: %v", err)
	}
	if !reflect.DeepEqual(a.IDs(), b.IDs()) {
		t.Fatalf("profile order differs between loads:\n%v\n%v", a.IDs(), b.IDs())
	}
	if !reflect.DeepEqual(a.VendorIDs(), b.VendorIDs()) {
		t.Fatalf("vendor order differs between loads")
	}
	if !reflect.DeepEqual(a.Profiles(), b.Profiles()) {
		t.Fatal("profile contents differ between loads")
	}
	// Ranked tables must be sorted ascending — the first-match-wins semantics
	// of sysDescr and platform resolution depend on it.
	for i := 1; i < len(a.descrRules); i++ {
		if a.descrRules[i-1].rank >= a.descrRules[i].rank {
			t.Fatalf("descrRules not strictly ascending at %d", i)
		}
	}
	for i := 1; i < len(a.platRules); i++ {
		if a.platRules[i-1].rank >= a.platRules[i].rank {
			t.Fatalf("platRules not strictly ascending at %d", i)
		}
	}
}

// goodDoc is a minimal, valid vendor document used as the base for the negative
// schema cases below.
func goodDoc() map[string]any {
	return map[string]any{
		"schema_version": SchemaVersion,
		"vendor":         "acme",
		"display_name":   "Acme",
		"detection": map[string]any{
			"sysobjectid_prefixes": []string{"1.3.6.1.4.1.99999"},
			"sysdescr_contains":    []string{"acmeos"},
			"sysdescr_rank":        1,
			"os_version_pattern":   `(?i)\bAcmeOS[ :]+([0-9.]+)`,
		},
		"dialect": map[string]any{"vrf_term": "VRF", "vrf_term_keys": []string{"acme"}},
		"profiles": []any{map[string]any{
			"platform":     "acmeos",
			"display_name": "Acme AcmeOS",
			"device_class": []string{"switch"},
			"fidelity":     FidelityDocClaimed,
			"detection":    map[string]any{"os_parse": map[string]any{"product": "acmeos", "sysdescr_contains_any": []string{}, "rank": 1}},
			"capture":      map[string]any{},
			"advisory":     map[string]any{"provider": "offline-feed", "product_ids": []string{"acmeos"}},
			"hardening":    map[string]any{},
			"threat":       map[string]any{},
		}},
	}
}

func loadDoc(t *testing.T, doc map[string]any) (*Registry, error) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	name := "p/" + doc["vendor"].(string) + ".json"
	return Load(fstest.MapFS{name: &fstest.MapFile{Data: b}}, "p")
}

func TestLoaderAcceptsAValidDocument(t *testing.T) {
	reg, err := loadDoc(t, goodDoc())
	if err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if _, ok := reg.Lookup("acme/acmeos"); !ok {
		t.Fatal("acme/acmeos not indexed")
	}
}

// TestLoaderRejectsUnknownKeys — strict schema validation. A typo'd or invented
// key must FAIL the load, not be silently dropped (a dropped `hardening` block
// would silently disable a vendor's rules).
func TestLoaderRejectsUnknownKeys(t *testing.T) {
	t.Run("top level", func(t *testing.T) {
		d := goodDoc()
		d["hardning"] = "typo"
		if _, err := loadDoc(t, d); err == nil {
			t.Fatal("unknown top-level key accepted")
		}
	})
	t.Run("nested detection", func(t *testing.T) {
		d := goodDoc()
		d["detection"].(map[string]any)["sysdescr_countains"] = []string{"x"}
		if _, err := loadDoc(t, d); err == nil {
			t.Fatal("unknown detection key accepted")
		}
	})
	t.Run("nested profile", func(t *testing.T) {
		d := goodDoc()
		d["profiles"].([]any)[0].(map[string]any)["capure"] = map[string]any{}
		if _, err := loadDoc(t, d); err == nil {
			t.Fatal("unknown profile key accepted")
		}
	})
}

// TestLoaderRejectsInvalidDocuments covers every required-field and invariant
// check, one mutation per case.
func TestLoaderRejectsInvalidDocuments(t *testing.T) {
	cases := map[string]func(d map[string]any){
		"wrong schema version": func(d map[string]any) { d["schema_version"] = 99 },
		"missing vendor":       func(d map[string]any) { d["vendor"] = "" },
		"upper-case vendor":    func(d map[string]any) { d["vendor"] = "Acme" },
		"missing display name": func(d map[string]any) { d["display_name"] = "" },
		"bad sysobjectid prefix": func(d map[string]any) {
			d["detection"].(map[string]any)["sysobjectid_prefixes"] = []string{"1.3.6.1.2.1.1"}
		},
		"deep sysobjectid prefix": func(d map[string]any) {
			d["detection"].(map[string]any)["sysobjectid_prefixes"] = []string{"1.3.6.1.4.1.9.1.1"}
		},
		"upper-case sysdescr":      func(d map[string]any) { d["detection"].(map[string]any)["sysdescr_contains"] = []string{"AcmeOS"} },
		"sysdescr without rank":    func(d map[string]any) { delete(d["detection"].(map[string]any), "sysdescr_rank") },
		"rank without sysdescr":    func(d map[string]any) { delete(d["detection"].(map[string]any), "sysdescr_contains") },
		"bad version regexp":       func(d map[string]any) { d["detection"].(map[string]any)["os_version_pattern"] = "([" },
		"vendor-level profile key": func(d map[string]any) { d["detection"].(map[string]any)["platform_rank"] = 3 },
		"dialect keys no term": func(d map[string]any) {
			d["dialect"] = map[string]any{"vrf_synonyms": []string{"vrf"}}
		},
		"dialect term no keys": func(d map[string]any) { d["dialect"] = map[string]any{"vrf_term": "VRF"} },
		"missing platform": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["platform"] = ""
		},
		"platform with slash": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["platform"] = "acme/os"
		},
		"missing device class": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["device_class"] = []string{}
		},
		"unknown device class": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["device_class"] = []string{"toaster"}
		},
		"unknown fidelity": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["fidelity"] = "probably-fine"
		},
		"profile-level vendor key": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["detection"].(map[string]any)["sysdescr_rank"] = 2
		},
		"os_parse without product": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["detection"].(map[string]any)["os_parse"] = map[string]any{"rank": 1}
		},
		"platform_contains without rank": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["detection"].(map[string]any)["platform_contains"] = []string{"acme"}
		},
		"bad prompt regexp": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["capture"] = map[string]any{"prompt_regex": "(["}
		},
		"hardening binding without display": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["hardening"] = map[string]any{"binding": "acme"}
		},
		"advisory products without provider": func(d map[string]any) {
			d["profiles"].([]any)[0].(map[string]any)["advisory"] = map[string]any{"product_ids": []string{"acmeos"}}
		},
		"file name does not match vendor": func(d map[string]any) {
			// vendor renamed after the file name is derived → mismatch
			d["vendor"] = "acme2"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := goodDoc()
			fname := "p/acme.json"
			mutate(d)
			b, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Load(fstest.MapFS{fname: &fstest.MapFile{Data: b}}, "p"); err == nil {
				t.Fatalf("invalid document accepted (%s)", name)
			}
		})
	}
}

// TestLoaderRejectsCrossDocumentConflicts covers the invariants that only show
// up once two documents are indexed together.
func TestLoaderRejectsCrossDocumentConflicts(t *testing.T) {
	mk := func(t *testing.T, vendor string, mutate func(map[string]any)) *fstest.MapFile {
		t.Helper()
		d := goodDoc()
		d["vendor"] = vendor
		if mutate != nil {
			mutate(d)
		}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return &fstest.MapFile{Data: b}
	}
	t.Run("duplicate enterprise number", func(t *testing.T) {
		a := mk(t, "acme", nil)
		b := mk(t, "beta", func(d map[string]any) {
			d["detection"].(map[string]any)["sysdescr_rank"] = 2
		})
		if _, err := Load(fstest.MapFS{"p/acme.json": a, "p/beta.json": b}, "p"); err == nil ||
			!strings.Contains(err.Error(), "enterprise") {
			t.Fatalf("duplicate enterprise not rejected: %v", err)
		}
	})
	t.Run("duplicate sysdescr rank", func(t *testing.T) {
		a := mk(t, "acme", nil)
		b := mk(t, "beta", func(d map[string]any) {
			d["detection"].(map[string]any)["sysobjectid_prefixes"] = []string{"1.3.6.1.4.1.99998"}
		})
		if _, err := Load(fstest.MapFS{"p/acme.json": a, "p/beta.json": b}, "p"); err == nil ||
			!strings.Contains(err.Error(), "sysdescr_rank") {
			t.Fatalf("duplicate sysdescr_rank not rejected: %v", err)
		}
	})
	t.Run("two unconditional os_parse defaults for one vendor", func(t *testing.T) {
		d := goodDoc()
		second := map[string]any{
			"platform": "acmeos2", "display_name": "Acme AcmeOS 2",
			"device_class": []string{"switch"}, "fidelity": FidelityDocClaimed,
			"detection": map[string]any{"os_parse": map[string]any{"product": "acmeos2", "sysdescr_contains_any": []string{}, "rank": 2}},
			"capture":   map[string]any{}, "advisory": map[string]any{}, "hardening": map[string]any{}, "threat": map[string]any{},
		}
		d["profiles"] = append(d["profiles"].([]any), second)
		if _, err := loadDoc(t, d); err == nil || !strings.Contains(err.Error(), "unconditional") {
			t.Fatalf("two unconditional defaults not rejected: %v", err)
		}
	})
	t.Run("unconditional default must rank last", func(t *testing.T) {
		d := goodDoc()
		second := map[string]any{
			"platform": "acmeos2", "display_name": "Acme AcmeOS 2",
			"device_class": []string{"switch"}, "fidelity": FidelityDocClaimed,
			"detection": map[string]any{"os_parse": map[string]any{"product": "acmeos2", "sysdescr_contains_any": []string{"acme2"}, "rank": 2}},
			"capture":   map[string]any{}, "advisory": map[string]any{}, "hardening": map[string]any{}, "threat": map[string]any{},
		}
		d["profiles"] = append(d["profiles"].([]any), second)
		if _, err := loadDoc(t, d); err == nil || !strings.Contains(err.Error(), "highest rank") {
			t.Fatalf("mis-ranked unconditional default not rejected: %v", err)
		}
	})
	t.Run("empty directory", func(t *testing.T) {
		if _, err := Load(fstest.MapFS{}, "p"); err == nil {
			t.Fatal("an empty profile directory must be an error, not an empty registry")
		}
	})
}
