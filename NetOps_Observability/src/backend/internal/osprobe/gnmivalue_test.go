// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package osprobe

// gnmivalue_test.go — leaf extraction, which is where a gNMI rung either finds
// the version or quietly does not. Every shape here is one a real client can
// hand back for the SAME read.

import "testing"

func TestLeafOf(t *testing.T) {
	cases := map[string]string{
		"/platform/control[slot=A]/software-version":                 "software-version",
		"/system/state/software-version":                             "software-version",
		"/components/component[name=Chassis]/state/software-version": "software-version",
		"/system/information/version":                                "version",
		"/openconfig-system:system/state/software-version":           "software-version",
		"software-version":                                           "software-version",
		"":                                                           "",
	}
	for path, want := range cases {
		if got := LeafOf(path); got != want {
			t.Errorf("LeafOf(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestExtractLeaf(t *testing.T) {
	const leaf = "software-version"
	cases := []struct {
		name, raw, want string
	}{
		{"a bare scalar", "v26.3.2-426-g2b38957bbca", "v26.3.2-426-g2b38957bbca"},
		{"a JSON scalar", `"4.32.0F"`, "4.32.0F"},
		{"a json_ietf leaf object", `{"software-version":"4.32.0F"}`, "4.32.0F"},
		{"a module-qualified leaf", `{"srl_nokia-platform:software-version":"v26.3.2-426-g2b38957bbca"}`, "v26.3.2-426-g2b38957bbca"},
		{"the parent container", `{"state":{"software-version":"4.32.0F","oper-status":"UP"}}`, "4.32.0F"},
		{"a nested OpenConfig container", `{"openconfig-system:system":{"state":{"software-version":"17.09.04a"}}}`, "17.09.04a"},
		{"whitespace around the value", "  v26.3.2  ", "v26.3.2"},
		{"a leaf that is not there", `{"oper-status":"UP"}`, ""},
		{"an empty leaf value", `{"software-version":""}`, ""},
		{"a leaf whose value is an object", `{"software-version":{"major":26}}`, ""},
		{"an array payload", `["4.32.0F"]`, ""},
		{"nothing at all", "", ""},
		{"only whitespace", "   \n ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractLeaf(tc.raw, leaf); got != tc.want {
				t.Errorf("ExtractLeaf(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestExtractLeafPrefersTheShallowestMatch — a container that repeats the leaf
// name deeper down must not shadow the one the path addressed.
func TestExtractLeafPrefersTheShallowestMatch(t *testing.T) {
	raw := `{"software-version":"4.32.0F","subcomponent":{"software-version":"1.0.0-bootloader"}}`
	if got := ExtractLeaf(raw, "software-version"); got != "4.32.0F" {
		t.Errorf("ExtractLeaf = %q, want the top-level leaf", got)
	}
}

// TestExtractLeafIsBounded — §9. A target that answers with a megabyte is not
// answering with a leaf, and the probe must not decode it.
func TestExtractLeafIsBounded(t *testing.T) {
	big := `{"software-version":"` + repeat("A", maxGNMIValueBytes) + `"}`
	if got := ExtractLeaf(big, "software-version"); got != "" {
		t.Errorf("an over-sized payload was decoded (%d bytes of value)", len(got))
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for len(out) < n {
		out = append(out, s...)
	}
	return string(out)
}
