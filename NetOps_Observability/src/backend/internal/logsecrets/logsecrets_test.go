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
	out, err := StripSource(in, nil)
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
		out, err := StripSource(json.RawMessage(`{"snmp_community":"`+value+`","a":1}`), nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != `{"a":1}` {
			t.Errorf("value %q: got %s", value, out)
		}
	}
}

func TestStripSourceCatchesAKeySpelledWithAnEscape(t *testing.T) {
	out, err := StripSource(json.RawMessage(`{"snmp_community":"`+fabricatedValue+`","a":1}`), nil)
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
		out, err := StripSource(json.RawMessage(doc), nil)
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
	if _, err := StripSource(json.RawMessage(`{"snmp_community":"`+fabricatedValue), nil); err == nil {
		t.Error("truncated _source must be refused")
	}
	if _, err := StripSource(json.RawMessage(`["snmp_community"]`), nil); err == nil {
		t.Error("non-object _source must be refused")
	}
	for name, body := range map[string]string{
		"truncated":     `{"hits":{"hits":[{"_source":{"snmp_community":"` + fabricatedValue,
		"hits scalar":   `{"hits":"snmp_community"}`,
		"list scalar":   `{"hits":{"hits":"snmp_community"}}`,
		"source scalar": `{"hits":{"hits":[{"_source":"snmp_community"}]}}`,
	} {
		if _, err := StripSearchResponse([]byte(body), nil); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}

func TestStripSearchResponseCleansEveryHit(t *testing.T) {
	body := `{"took":3,"hits":{"total":{"value":2},"hits":[` +
		`{"_index":"netops-snmptrap-acme-2026.11.09","_id":"1","_source":{"message":"m1","snmp_community":"` + fabricatedValue + `"}},` +
		`{"_index":"netops-syslog-acme-2026.11.09","_id":"2","_source":{"message":"m2","time_received_ns":1762657500123456789}}]}}`
	out, err := StripSearchResponse([]byte(body), nil)
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
	out, err := StripSearchResponse([]byte(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != body {
		t.Fatalf("rewrote a clean body: %s", out)
	}
}

func TestStripSearchResponseAMessageNamingTheFieldIsKept(t *testing.T) {
	body := `{"hits":{"hits":[{"_source":{"message":"operator asked about snmp_community"}}]}}`
	out, err := StripSearchResponse([]byte(body), nil)
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

// A credential a device wrote into a line's text is masked wherever the text is
// stored, on every door that serves _source. Tracker 387 PR 10 stores it twice more.
func TestStripSourceMasksCredentialsInTextFields(t *testing.T) {
	raw := json.RawMessage(`{"hostname":"r1","ts":1234567890123456789,` +
		`"message":"snmp-server community hunter2 RO",` +
		`"message_original":"<189>Nov  9 09:00:01 r1 app: snmp-server community hunter2 RO",` +
		`"structured_data":"[a@1 password=\"hunter2\"]","summary":"password=hunter2"}`)
	out, err := StripSource(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2") {
		t.Fatalf("the credential left in the text: %s", out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("the masked document is not JSON: %v", err)
	}
	if doc["hostname"] != "r1" {
		t.Fatalf("a field it should not touch moved: %s", out)
	}
	if !strings.Contains(string(out), "1234567890123456789") {
		t.Fatalf("a number lost its precision: %s", out)
	}
}

// A username is not a credential here: it stays for security attribution (owner D7).
func TestStripSourceKeepsUsernames(t *testing.T) {
	raw := json.RawMessage(`{"message_original":"<189>r1 app: User 'svc-user' authenticated with token auth"}`)
	out, err := StripSource(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "svc-user") {
		t.Fatalf("the username must stay in the record: %s", out)
	}
}

// The fast path: an ordinary document is not parsed or re-encoded, even with a key
// order or number form a re-encode would change.
func TestStripSourcePassesAnOrdinaryDocumentByteForByte(t *testing.T) {
	raw := json.RawMessage(`{"z":1.0,"a":2,"message":"Interface Gi1, changed state to down","message_original":"<187>x"}`)
	out, err := StripSource(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(raw) {
		t.Fatalf("an ordinary document was rewritten: %s", out)
	}
}

// A search answer goes through the same masking, hit by hit.
func TestStripSearchResponseMasksTextFields(t *testing.T) {
	raw := []byte(`{"took":1,"hits":{"total":{"value":1},"hits":[{"_id":"a","_source":{"message_original":"password=hunter2"}}]}}`)
	out, err := StripSearchResponse(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2") {
		t.Fatalf("the credential reached the search answer: %s", out)
	}
}

// The quarantine restore puts a document back in the pipeline: the store keeps the text.
func TestStripFieldsLeavesTheTextForTheStore(t *testing.T) {
	doc := map[string]any{TrapCommunityField: "public", "message_original": "password=hunter2"}
	StripFields(doc)
	if _, present := doc[TrapCommunityField]; present {
		t.Fatal("the community survived")
	}
	if doc["message_original"] != "password=hunter2" {
		t.Fatalf("the original must reach the store unchanged: %v", doc)
	}
}
