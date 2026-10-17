// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import "testing"

func TestParseExporterAppID(t *testing.T) {
	for in, want := range map[string]ExporterAppID{
		"13:453":         {Engine: 13, Selector: 453, Kind: ExporterKindApp},
		"20:12356:41394": {Engine: 20, PEN: 12356, Selector: 41394, Kind: ExporterKindApp},
		"3:443":          {Engine: 3, Selector: 443, Kind: ExporterKindServiceClass},
		"1:6":            {Engine: 1, Selector: 6, Kind: ExporterKindServiceClass},
		"13:0":           {Engine: 13, Selector: 0, Kind: ExporterKindUnclassified},
		"99:5":           {Engine: 99, Selector: 5, Kind: ExporterKindUnknown},
	} {
		got, ok := ParseExporterAppID(in)
		if !ok || got != want {
			t.Errorf("%q → %+v,%v want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "13", "0:5", "256:1", "20:5", "13:-1", "13:x", "20:99999999999:1", "13:4:5", "a:b"} {
		if _, ok := ParseExporterAppID(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExporterAppNameIgnoresNonNames(t *testing.T) {
	for in, want := range map[string]string{
		"ms-office-365": "ms-office-365", " webex ": "webex", "unknown": "", "Unclassified": "", "": "",
	} {
		if got := ExporterAppName(in); got != want {
			t.Errorf("%q → %q want %q", in, got, want)
		}
	}
}
