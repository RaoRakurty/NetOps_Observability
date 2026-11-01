// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package oslog

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The tests in this file judge TenantFilter by WHO SEES WHAT, not by the shape
// of the JSON it builds: matches() evaluates the generated clause against a
// document the way OpenSearch would, for the subset of the query DSL the filter
// uses. A shape test passed throughout the 2026-11-01 regression — the clause
// looked right and matched no flow at all.

// matches evaluates an OpenSearch query clause against one document.
func matches(t *testing.T, clause map[string]any, doc map[string]any) bool {
	t.Helper()
	if len(clause) != 1 {
		t.Fatalf("clause must have exactly one key, got %v", clause)
	}
	for kind, body := range clause {
		switch kind {
		case "match_none":
			return false
		case "match_all":
			return true
		case "term":
			for f, want := range body.(map[string]any) {
				return fieldEquals(doc, f, want)
			}
		case "terms":
			for f, vals := range body.(map[string]any) {
				for _, v := range toAnySlice(t, vals) {
					if fieldEquals(doc, f, v) {
						return true
					}
				}
				return false
			}
		case "exists":
			f := body.(map[string]any)["field"].(string)
			_, ok := doc[f]
			return ok
		case "bool":
			b := body.(map[string]any)
			for _, c := range toAnySlice(t, b["must"]) {
				if !matches(t, c.(map[string]any), doc) {
					return false
				}
			}
			for _, c := range toAnySlice(t, b["must_not"]) {
				if matches(t, c.(map[string]any), doc) {
					return false
				}
			}
			should := toAnySlice(t, b["should"])
			if len(should) == 0 {
				return true
			}
			min := 0
			if m, ok := b["minimum_should_match"].(int); ok {
				min = m
			}
			if min == 0 && (b["must"] != nil || b["must_not"] != nil) {
				return true // OpenSearch: should is optional beside must/filter
			}
			if min == 0 {
				min = 1
			}
			n := 0
			for _, c := range should {
				if matches(t, c.(map[string]any), doc) {
					n++
				}
			}
			return n >= min
		default:
			t.Fatalf("evaluator does not understand %q — extend it before the filter uses it", kind)
		}
	}
	return false
}

func toAnySlice(t *testing.T, v any) []any {
	t.Helper()
	switch s := v.(type) {
	case nil:
		return nil
	case []any:
		return s
	case []string:
		out := make([]any, len(s))
		for i := range s {
			out[i] = s[i]
		}
		return out
	default:
		t.Fatalf("expected a list, got %T", v)
		return nil
	}
}

// fieldEquals compares like OpenSearch: ip-mapped fields by address, keyword
// fields exactly.
func fieldEquals(doc map[string]any, field string, want any) bool {
	got, ok := doc[field]
	if !ok {
		return false
	}
	gs, ws := got.(string), want.(string)
	if field == "sampler_address" {
		ga, gerr := netip.ParseAddr(gs)
		wa, werr := netip.ParseAddr(ws)
		return gerr == nil && werr == nil && ga.Unmap() == wa.Unmap()
	}
	return gs == ws
}

// The documents are the lab's, from the 2026-11-01 incident.
var (
	flowFromProviderEdge = map[string]any{"tenant_id": "", "sampler_address": "192.168.222.104"}
	flowNoTenantField    = map[string]any{"sampler_address": "192.168.222.101"}
	trapFromUnknownHost  = map[string]any{"tenant_id": "", "host": "192.168.200.33", "hostname": "192.168.200.33"}
	syslogProviderTagged = map[string]any{"tenant_id": "global", "host": "cEDGE-40"}
	retailTagged         = map[string]any{"tenant_id": "t_retail", "host": "branch-7"}
	otherTenantSameName  = map[string]any{"tenant_id": "t_other", "host": "branch-7", "source_ip": "10.9.9.9"}
	untaggedFromRetailIP = map[string]any{"tenant_id": "", "source_ip": "10.9.9.9"}
	untaggedRetailFlow   = map[string]any{"tenant_id": "", "sampler_address": "::ffff:10.9.9.9"}
	untaggedRetailHost   = map[string]any{"host": "branch-7"}
)

func TestTenantFilterVisibility(t *testing.T) {
	retailKeys := []string{"branch-7", "ctl-vmanage-1"}
	// Addresses as the inventory may hold them: a zone and a non-address must
	// never reach the ip-mapped sampler_address (one bad value fails the search).
	retailAddrs := []string{"10.9.9.9", "fe80::1%eth0", "not-an-ip", "10.9.9.9"}

	docs := map[string]map[string]any{
		"flowFromProviderEdge": flowFromProviderEdge,
		"flowNoTenantField":    flowNoTenantField,
		"trapFromUnknownHost":  trapFromUnknownHost,
		"syslogProviderTagged": syslogProviderTagged,
		"retailTagged":         retailTagged,
		"otherTenantSameName":  otherTenantSameName,
		"untaggedFromRetailIP": untaggedFromRetailIP,
		"untaggedRetailFlow":   untaggedRetailFlow,
		"untaggedRetailHost":   untaggedRetailHost,
	}
	untagged := []string{"flowFromProviderEdge", "flowNoTenantField", "trapFromUnknownHost",
		"untaggedFromRetailIP", "untaggedRetailFlow", "untaggedRetailHost"}

	cases := []struct {
		name    string
		tenant  string
		keys    []string
		addrs   []string
		visible []string
	}{
		{
			// The regression: Provider must read every untagged document —
			// platform-owned by the one owner rule — and its own stamped ones,
			// and nothing a tenant owns.
			name: "provider", tenant: "global",
			visible: append([]string{"syslogProviderTagged"}, untagged...),
		},
		{
			name: "provider spelled loosely", tenant: "  GLOBAL ",
			visible: append([]string{"syslogProviderTagged"}, untagged...),
		},
		{
			// Device identities given to the Provider change nothing: untagged
			// is its own, and a tenant's stamped rows stay the tenant's.
			name: "provider ignores device identities", tenant: "global", keys: retailKeys, addrs: retailAddrs,
			visible: append([]string{"syslogProviderTagged"}, untagged...),
		},
		{
			// A tenant reads its stamped rows and the untagged rows its own
			// devices emitted — by host, by source_ip and, for flows, by the
			// exporter address — and never another tenant's stamped row even
			// when the host name collides.
			name: "tenant with devices", tenant: "t_retail", keys: retailKeys, addrs: retailAddrs,
			visible: []string{"retailTagged", "untaggedFromRetailIP", "untaggedRetailFlow", "untaggedRetailHost"},
		},
		{
			name: "tenant without devices", tenant: "t_retail",
			visible: []string{"retailTagged"},
		},
		{
			// An unbound caller is never widened into the platform realm.
			name: "unbound scope", tenant: "", keys: retailKeys, addrs: retailAddrs,
			visible: nil,
		},
		{
			name: "unbound scope spelled as blanks", tenant: "   ",
			visible: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := TenantFilter(tc.tenant, false, tc.keys, tc.addrs)
			if f == nil {
				t.Fatal("a non-cross caller must always get a filter")
			}
			want := map[string]bool{}
			for _, n := range tc.visible {
				want[n] = true
			}
			for name, doc := range docs {
				if got := matches(t, f, doc); got != want[name] {
					t.Errorf("%s: visible=%v, want %v", name, got, want[name])
				}
			}
			assertIPFieldsCarryOnlyAddresses(t, f)
		})
	}
}

func TestTenantFilterCrossIsUnrestricted(t *testing.T) {
	for _, tenant := range []string{"", "global", "t_retail"} {
		if f := TenantFilter(tenant, true, []string{"x"}, []string{"10.0.0.1"}); f != nil {
			t.Errorf("cross caller (tenant %q) must get no filter, got %v", tenant, f)
		}
	}
}

func TestIsProviderScope(t *testing.T) {
	for in, want := range map[string]bool{"global": true, " Global ": true, "": false, " ": false, "t_retail": false, "globalx": false, "all": false} {
		if got := IsProviderScope(in); got != want {
			t.Errorf("IsProviderScope(%q) = %v, want %v", in, got, want)
		}
	}
}

// assertIPFieldsCarryOnlyAddresses walks a clause and fails if any ip-kind
// identity field is handed a value OpenSearch would reject.
func assertIPFieldsCarryOnlyAddresses(t *testing.T, clause any) {
	t.Helper()
	ipFields := map[string]bool{}
	for _, f := range DeviceIdentityFields() {
		if f.Kind == IdentityIP {
			ipFields[f.Name] = true
		}
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if terms, ok := x["terms"].(map[string]any); ok {
				for field, vals := range terms {
					if !ipFields[field] {
						continue
					}
					for _, val := range toAnySlice(t, vals) {
						a, err := netip.ParseAddr(val.(string))
						if err != nil || a.Zone() != "" {
							t.Errorf("ip field %s carries %q, which fails the whole search", field, val)
						}
					}
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(clause)
}

// TestScopedLogFamiliesSatisfyIdentityContract is the guard that would have
// caught the flows gap the day flows shipped. For every log family a scoped
// caller reads, in EVERY shipped copy of the index templates, the mapping must
// carry tenant_id as keyword and at least one device-identity field, each with
// the type its kind requires. With `dynamic: false` an unmapped field cannot be
// queried at all, so "the producer writes it" is not enough — it must be mapped.
func TestScopedLogFamiliesSatisfyIdentityContract(t *testing.T) {
	copies := []string{
		filepath.Join("..", "..", "..", "..", "deployment", "docker", "opensearch", "index-templates.json"),
		filepath.Join("..", "..", "..", "..", "deployment", "helm", "correlix", "files", "opensearch", "index-templates.json"),
	}
	wantType := map[IdentityKind]string{IdentityKey: "keyword", IdentityAddr: "keyword", IdentityIP: "ip"}
	var shapes []map[string]map[string]string
	for _, path := range copies {
		props := templateProperties(t, path)
		shape := map[string]map[string]string{}
		for _, family := range ScopedLogFamilies() {
			p, ok := props[family]
			if !ok {
				t.Errorf("%s: no template for scoped log family %s", path, family)
				continue
			}
			shape[family] = p
			if p["tenant_id"] != "keyword" {
				t.Errorf("%s: %s maps tenant_id as %q, want keyword", path, family, p["tenant_id"])
			}
			n := 0
			for _, f := range DeviceIdentityFields() {
				typ, mapped := p[f.Name]
				if !mapped {
					continue
				}
				n++
				if typ != wantType[f.Kind] {
					t.Errorf("%s: %s maps identity field %s as %q, want %q", path, family, f.Name, typ, wantType[f.Kind])
				}
			}
			if n == 0 {
				t.Errorf("%s: %s maps none of the device-identity fields %v — no tenant scope could ever tie an untagged document to its device",
					path, family, identityNames())
			}
		}
		shapes = append(shapes, shape)
	}
	if len(shapes) == 2 && !reflect.DeepEqual(shapes[0], shapes[1]) {
		t.Errorf("the docker and helm templates disagree on the scoped families' fields:\n docker %v\n helm   %v", shapes[0], shapes[1])
	}
}

func identityNames() []string {
	var out []string
	for _, f := range DeviceIdentityFields() {
		out = append(out, f.Name)
	}
	return out
}

// templateProperties reads an index-templates.json and returns, per family
// (index pattern without the trailing "-*"), its top-level field → type.
func templateProperties(t *testing.T, path string) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Templates map[string]json.RawMessage `json:"templates"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]map[string]string{}
	for name, rawTpl := range doc.Templates {
		var tpl struct {
			IndexPatterns []string `json:"index_patterns"`
			Template      struct {
				Mappings struct {
					Properties map[string]struct {
						Type string `json:"type"`
					} `json:"properties"`
				} `json:"mappings"`
			} `json:"template"`
		}
		if err := json.Unmarshal(rawTpl, &tpl); err != nil {
			t.Fatalf("%s: template %s: %v", path, name, err)
		}
		fields := map[string]string{}
		for f, m := range tpl.Template.Mappings.Properties {
			fields[f] = m.Type
		}
		for _, pat := range tpl.IndexPatterns {
			out[strings.TrimSuffix(pat, "-*")] = fields
		}
	}
	return out
}
