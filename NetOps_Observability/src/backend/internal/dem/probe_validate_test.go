// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

import (
	"strings"
	"testing"
)

// Paths P3, layer 1 of 3: with path tracing or STAMP ticked, an address that
// is NEVER probed is refused at save, whoever asks; without them the same
// target is an ordinary synthetic check. A name is left to the publish layer.
func TestValidateRefusesNeverProbedTraceTargets(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.5", "0.0.0.0"} {
		tg := Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: host, TracePath: true}
		if err := tg.Validate(); err == nil || !strings.Contains(err.Error(), "never probed") {
			t.Fatalf("trace_path to %s: %v, want a never-probed refusal", host, err)
		}
		st := Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: host, StampProbe: true}
		if err := st.Validate(); err == nil {
			t.Fatalf("stamp_probe to %s must be refused", host)
		}
	}
	for _, tg := range []Target{
		{TenantID: "acme", Name: "edge", Kind: KindICMP, Host: "10.40.0.1", TracePath: true},
		{TenantID: "acme", Name: "edge", Kind: KindICMP, Host: "edge.branch40.example", TracePath: true},
		{TenantID: "acme", Name: "web", Kind: KindHTTP, Host: "https://203.0.113.9/health", TracePath: true, StampProbe: true},
		{TenantID: "acme", Name: "plain", Kind: KindICMP, Host: "127.0.0.1"}, // not traced: P3 adds no rule
	} {
		if err := tg.Validate(); err != nil {
			t.Fatalf("%+v: %v", tg, err)
		}
	}
	if h := (Target{Kind: KindHTTP, Host: "https://203.0.113.9:8443/x"}).ProbeHost(); h != "203.0.113.9" {
		t.Fatalf("http ProbeHost = %q", h)
	}
	if h := (Target{Kind: KindDNS, Host: "corp.example."}).ProbeHost(); h != "corp.example" {
		t.Fatalf("dns ProbeHost = %q", h)
	}
}

// The create body and the patch both carry the two switches; a patch can turn
// path tracing off without touching anything else.
func TestPatchCarriesTheMeasurementSwitches(t *testing.T) {
	on, off := true, false
	got := Patch{TracePath: &on, StampProbe: &off}.apply(Target{StampProbe: true, Name: "keep"})
	if !got.TracePath || got.StampProbe || got.Name != "keep" {
		t.Fatalf("patched = %+v", got)
	}
}
