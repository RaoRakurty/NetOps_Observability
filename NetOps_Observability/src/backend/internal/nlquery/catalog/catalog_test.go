// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.Version(), "v1-") || len(c.Version()) != len("v1-")+12 {
		t.Fatalf("version = %q", c.Version())
	}
	for _, want := range []string{"site", "device", "interface", "circuit", "bgp_peer", "provider", "application", "incident", "change", "probe_target"} {
		if _, ok := c.Entity(want); !ok {
			t.Errorf("entity %q missing", want)
		}
	}
	if m, ok := c.Metric("circuit_loss_pct"); !ok || m.Scope != "gated:N-B5" || m.Unit != "percent" {
		t.Fatalf("circuit_loss_pct = %+v", m)
	}
}

// mutate decodes the embedded catalog to a generic map, applies f, and parses
// the result — so each rejection test changes exactly one thing.
func mutate(t *testing.T, f func(m map[string]any)) error {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(embeddedV1, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(raw)
	return err
}

func first(m map[string]any, key string) map[string]any { return m[key].([]any)[0].(map[string]any) }

func TestParseRejects(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"unknown top-level field": func(m map[string]any) { m["tenant"] = "t-a" },
		"unknown metric field":    func(m map[string]any) { first(m, "metrics")["sql"] = "SELECT 1" },
		"schema version":          func(m map[string]any) { m["schema_version"] = 2 },
		"duplicate metric": func(m map[string]any) {
			ms := m["metrics"].([]any)
			m["metrics"] = append(ms, ms[0])
		},
		"resolver outside set":     func(m map[string]any) { first(m, "entities")["resolver"] = "raw_sql" },
		"backend outside set":      func(m map[string]any) { first(m, "metrics")["backend"] = "mysql" },
		"scope outside set":        func(m map[string]any) { first(m, "metrics")["scope"] = "tenant_blind" },
		"unknown entity on metric": func(m map[string]any) { first(m, "metrics")["entity_types"] = []any{"planet"} },
		"operator outside set":     func(m map[string]any) { first(m, "metrics")["operators"] = []any{"regex"} },
		"default agg not allowed":  func(m map[string]any) { first(m, "metrics")["default_agg"] = "sum" },
		"no emitters":              func(m map[string]any) { first(m, "metrics")["emitters"] = []any{} },
		"bad id pattern":           func(m map[string]any) { first(m, "entities")["id_pattern"] = "([" },
		"restricted filterable": func(m map[string]any) {
			for _, d := range m["dimensions"].([]any) {
				if d.(map[string]any)["name"] == "before" {
					d.(map[string]any)["filterable"] = true
				}
			}
		},
		"relationship to nowhere": func(m map[string]any) {
			m["relationships"] = append(m["relationships"].([]any), map[string]any{"from": "site", "to": "moon", "via": "label", "cardinality": "1:n"})
		},
		"alias collides two metrics on one entity": func(m map[string]any) {
			for _, x := range m["metrics"].([]any) {
				mm := x.(map[string]any)
				if mm["name"] == "if_in_bps" {
					mm["aliases"] = append(mm["aliases"].([]any), "utilization")
				}
			}
		},
		"alias collides two entity types": func(m map[string]any) {
			first(m, "entities")["aliases"] = append(first(m, "entities")["aliases"].([]any), "router")
		},
	}
	for name, f := range cases {
		if err := mutate(t, f); err == nil {
			t.Errorf("%s: Parse accepted it", name)
		}
	}
	if _, err := Parse(append(append([]byte{}, embeddedV1...), []byte(` {}`)...)); err == nil {
		t.Error("trailing data must be rejected")
	}
}

func TestLookupSharedAliasSplitsByEntityType(t *testing.T) {
	c := MustLoad()
	hits := c.Lookup("Packet-Loss")
	var names []string
	for _, h := range hits {
		if h.Kind == "metric" {
			names = append(names, h.Name+"@"+h.For)
		}
	}
	if strings.Join(names, " ") != "circuit_loss_pct@circuit probe_loss_pct@probe_target" {
		t.Fatalf("\"packet loss\" hits = %v", names)
	}
	if hits := c.Lookup("utilization"); len(hits) != 1 || hits[0].Name != "if_util_max_pct" {
		t.Fatalf("\"utilization\" = %+v", hits)
	}
	if hits := c.Lookup("wan"); len(hits) == 0 {
		t.Fatal("\"wan\" must resolve (change class / incident seam class)")
	}
}

func TestReachableWithinTwoHops(t *testing.T) {
	c := MustLoad()
	for _, p := range [][2]string{{"site", "device"}, {"site", "interface"}, {"provider", "device"}, {"incident", "site"}, {"change", "device"}, {"device", "device"}} {
		if !c.Reachable(p[0], p[1]) {
			t.Errorf("%s→%s must be reachable", p[0], p[1])
		}
	}
	if c.Reachable("probe_target", "change") {
		t.Error("probe_target→change has no relationship path")
	}
}

func TestNormalizeAlias(t *testing.T) {
	for in, want := range map[string]string{"  Packet_Loss ": "packet loss", "SD-WAN": "sd wan", "BGP   flaps": "bgp flaps"} {
		if got := NormalizeAlias(in); got != want {
			t.Errorf("NormalizeAlias(%q) = %q, want %q", in, got, want)
		}
	}
}
