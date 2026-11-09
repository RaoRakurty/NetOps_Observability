// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logsecrets

import (
	"encoding/json"
	"strings"
	"testing"
)

const fabricatedValue = "fabricated-community-7f3a"

func TestStripSourceRemovesTheFieldAndKeepsTheRest(t *testing.T) {
	in := json.RawMessage(`{"message":"a<b","snmp_community":"` + fabricatedValue + `","snmp_community_present":true,"n":12345678901234567890}`)
	out, err := StripSource(in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, fabricatedValue) || strings.Contains(s, `"snmp_community":`) {
		t.Fatalf("field survived: %s", s)
	}
	for _, want := range []string{`"message":"a<b"`, `"snmp_community_present":true`, `"n":12345678901234567890`} {
		if !strings.Contains(s, want) {
			t.Errorf("lost %s: %s", want, s)
		}
	}
}

func TestStripSourceTreatsEveryValueTheSame(t *testing.T) {
	for _, value := range []string{"public", "private", "", fabricatedValue} {
		out, err := StripSource(json.RawMessage(`{"snmp_community":"` + value + `","a":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != `{"a":1}` {
			t.Errorf("value %q: got %s", value, out)
		}
	}
}

func TestStripSourceCatchesAKeySpelledWithAnEscape(t *testing.T) {
	out, err := StripSource(json.RawMessage(`{"snmp_community":"` + fabricatedValue + `","a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), fabricatedValue) {
		t.Fatalf("escaped key survived: %s", out)
	}
}

func TestStripSourceLeavesOtherDocumentsByteIdentical(t *testing.T) {
	for _, doc := range []string{
		`{ "z":1,  "a":"<b>" }`,
		`{"note":"café"}`, // escape takes the slow path, no field, still unchanged
		`null`,
	} {
		out, err := StripSource(json.RawMessage(doc))
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != doc {
			t.Errorf("got %s want %s", out, doc)
		}
	}
}

// Default-closed: a body that may hold the field but cannot be checked is an
// error the caller must refuse, never something passed along.
func TestStripRefusesWhatItCannotCheck(t *testing.T) {
	if _, err := StripSource(json.RawMessage(`{"snmp_community":"` + fabricatedValue)); err == nil {
		t.Error("truncated _source must be refused")
	}
	if _, err := StripSource(json.RawMessage(`["snmp_community"]`)); err == nil {
		t.Error("non-object _source must be refused")
	}
	for name, body := range map[string]string{
		"truncated":     `{"hits":{"hits":[{"_source":{"snmp_community":"` + fabricatedValue,
		"hits scalar":   `{"hits":"snmp_community"}`,
		"list scalar":   `{"hits":{"hits":"snmp_community"}}`,
		"source scalar": `{"hits":{"hits":[{"_source":"snmp_community"}]}}`,
	} {
		if _, err := StripSearchResponse([]byte(body)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func TestStripSearchResponseCleansEveryHit(t *testing.T) {
	body := `{"took":3,"hits":{"total":{"value":2},"hits":[` +
		`{"_index":"netops-snmptrap-acme-2026.11.09","_id":"1","_source":{"message":"m1","snmp_community":"` + fabricatedValue + `"}},` +
		`{"_index":"netops-syslog-acme-2026.11.09","_id":"2","_source":{"message":"m2","time_received_ns":1762657500123456789}}]}}`
	out, err := StripSearchResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, fabricatedValue) || strings.Contains(s, `"snmp_community"`) {
		t.Fatalf("field survived: %s", s)
	}
	for _, want := range []string{`"took":3`, `"value":2`, `"m1"`, `"m2"`, `1762657500123456789`, `netops-snmptrap-acme-2026.11.09`} {
		if !strings.Contains(s, want) {
			t.Errorf("lost %s: %s", want, s)
		}
	}
}

func TestStripSearchResponseWithoutTheFieldIsByteIdentical(t *testing.T) {
	body := `{"took":3,  "hits":{"hits":[{"_source":{"message":"x"}}]}}`
	out, err := StripSearchResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != body {
		t.Fatalf("rewrote a clean body: %s", out)
	}
}

func TestStripSearchResponseAMessageNamingTheFieldIsKept(t *testing.T) {
	body := `{"hits":{"hits":[{"_source":{"message":"operator asked about snmp_community"}}]}}`
	out, err := StripSearchResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "operator asked about snmp_community") {
		t.Fatalf("message text was altered: %s", out)
	}
}

func TestStripFields(t *testing.T) {
	doc := map[string]any{"snmp_community": fabricatedValue, "a": 1.0}
	StripFields(doc)
	if _, ok := doc["snmp_community"]; ok || doc["a"] != 1.0 {
		t.Fatalf("got %v", doc)
	}
	StripFields(nil) // a hit with no _source must not panic
}

func TestScrubText(t *testing.T) {
	for name, in := range map[string]string{
		"whole":    `{"a":1,"snmp_community":"` + fabricatedValue + `","b":2}`,
		"spaced":   `{"snmp_community" : "` + fabricatedValue + `"}`,
		"cut":      `{"a":1,"snmp_community":"` + fabricatedValue,
		"escaped":  `{"snmp_community":"x\"` + fabricatedValue + `"}`,
		"cutEsc":   `{"snmp_community":"` + fabricatedValue + `\`,
		"repeated": `{"snmp_community":"` + fabricatedValue + `"} {"snmp_community":"` + fabricatedValue + `"}`,
	} {
		if got := ScrubText(in); strings.Contains(got, fabricatedValue) {
			t.Errorf("%s: value survived: %s", name, got)
		}
	}
	if got := ScrubText(`{"a":1,"snmp_community":"x","b":2}`); got != `{"a":1,"snmp_community":"[REDACTED]","b":2}` {
		t.Errorf("surrounding bytes changed: %s", got)
	}
	clean := `{"snmp_community_present":true,"message":"snmp_community"}`
	if got := ScrubText(clean); got != clean {
		t.Errorf("clean text changed: %s", got)
	}
}
