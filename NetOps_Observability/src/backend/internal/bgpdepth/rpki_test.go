// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

import (
	"context"
	"errors"
	"testing"
)

// The payload below is the REAL shape returned by RIPEstat's rpki-validation
// data call for AS3333 / 193.0.0.0/21 (captured 2026-09-02).
const realRPKIValid = `{"resource":"3333","prefix":"193.0.0.0/21","validating_roas":[{"origin":"3333","prefix":"193.0.0.0/21","validity":"valid","max_length":21}],"status":"valid","validator":"routinator"}`

func TestNormalizeRPKIStateCoversEveryUpstreamSpelling(t *testing.T) {
	cases := []struct {
		in     string
		state  RPKIState
		reason string
	}{
		{"valid", RPKIValid, ""},
		{"VALID", RPKIValid, ""},
		{"invalid", RPKIInvalid, ""},
		{"invalid_asn", RPKIInvalid, "origin_as"},
		{"invalid-asn", RPKIInvalid, "origin_as"},
		{"invalid_length", RPKIInvalid, "max_length"},
		{"unknown", RPKIUnknown, ""},
		{"not-found", RPKIUnknown, ""},
		{"notfound", RPKIUnknown, ""},
		{"", RPKIUnavailable, ""},
		{"something-new", RPKIUnavailable, ""},
	}
	for _, c := range cases {
		st, reason := NormalizeRPKIState(c.in)
		if st != c.state || reason != c.reason {
			t.Errorf("Normalize(%q) = (%s,%q), want (%s,%q)", c.in, st, reason, c.state, c.reason)
		}
	}
	// The safety property: nothing unrecognized may become "valid".
	for _, s := range []string{"vali", "VALID_ISH", "true", "1", "ok"} {
		if st, _ := NormalizeRPKIState(s); st == RPKIValid {
			t.Errorf("Normalize(%q) became VALID — an unrecognized status must never read as valid", s)
		}
	}
}

func TestValidateRPKIParsesTheRealPayload(t *testing.T) {
	f := newFake()
	f.put("rpki-validation", "AS3333", realRPKIValid)
	got := ValidateRPKI(context.Background(), f, fixedNow(), nil, "193.0.0.0/21", "AS3333")
	if got.State != RPKIValid {
		t.Fatalf("state = %s, want valid (%+v)", got.State, got)
	}
	if got.Origin != "AS3333" || got.Validator != "routinator" || len(got.ROAs) != 1 {
		t.Fatalf("parsed result is wrong: %+v", got)
	}
	if got.ROAs[0].MaxLength != 21 || got.ROAs[0].Validity != "valid" {
		t.Fatalf("ROA = %+v", got.ROAs[0])
	}
	if !f.sawExtra("prefix=193.0.0.0%2F21") {
		t.Fatal("the prefix must be sent ESCAPED as the extra parameter")
	}
}

func TestValidateRPKIUsesTheANNOUNCEDOriginNotACallerHint(t *testing.T) {
	f := newFake()
	f.put("rpki-validation", "AS64500", `{"status":"invalid","validating_roas":[]}`)
	resolved := false
	resolve := func(context.Context, string) string { resolved = true; return "64500" }
	got := ValidateRPKI(context.Background(), f, fixedNow(), resolve, "203.0.113.0/24", "")
	if !resolved {
		t.Fatal("the resolver was not consulted — the verdict would judge a hypothetical origin")
	}
	if got.State != RPKIInvalid || got.Origin != "AS64500" {
		t.Fatalf("got %+v", got)
	}
}

func TestValidateRPKIUnresolvableOriginIsHonest(t *testing.T) {
	f := newFake()
	got := ValidateRPKI(context.Background(), f, fixedNow(), func(context.Context, string) string { return "" }, "203.0.113.0/24", "")
	if got.State != RPKIUnavailable || got.Error == "" {
		t.Fatalf("an unresolvable origin must be unavailable + explained, got %+v", got)
	}
	if f.calls.Load() != 0 {
		t.Fatal("no origin means no upstream call")
	}
}

func TestValidateRPKIUpstreamFailureIsNotAVerdict(t *testing.T) {
	f := newFake()
	f.putErr("rpki-validation", "AS3333", errors.New("upstream 503"))
	got := ValidateRPKI(context.Background(), f, fixedNow(), nil, "193.0.0.0/21", "AS3333")
	if got.State == RPKIValid || got.State == RPKIInvalid || got.Error == "" {
		t.Fatalf("a failed lookup must never render as a verdict: %+v", got)
	}
}

func TestValidateRPKISetIsBoundedOrderedAndSorted(t *testing.T) {
	f := newFake()
	var prefixes []string
	for i := 0; i < RPKIMaxPrefixes+7; i++ {
		p := prefixFor(i)
		prefixes = append(prefixes, p)
		f.put("rpki-validation", "AS1", `{"status":"valid"}`)
	}
	res, truncated, err := ValidateRPKISet(context.Background(), f, fixedNow(),
		func(context.Context, string) string { return "1" }, prefixes)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("a watchlist past the cap must be DECLARED truncated")
	}
	if len(res) != RPKIMaxPrefixes {
		t.Fatalf("returned %d results, cap is %d", len(res), RPKIMaxPrefixes)
	}
	// Input order is preserved before sorting (each slot holds ITS prefix).
	for i, r := range res {
		if r.Prefix != prefixes[i] {
			t.Fatalf("slot %d holds %q, want %q — concurrent writes crossed slots", i, r.Prefix, prefixes[i])
		}
	}
}

func TestSortRPKIWorstFirst(t *testing.T) {
	in := []RPKIResult{
		{Prefix: "a", State: RPKIValid},
		{Prefix: "b", State: RPKIUnknown},
		{Prefix: "c", State: RPKIInvalid},
		{Prefix: "d", State: RPKIUnavailable},
		{Prefix: "e", State: RPKIInvalid},
	}
	SortRPKIWorstFirst(in)
	want := []string{"c", "e", "d", "b", "a"}
	for i, w := range want {
		if in[i].Prefix != w {
			t.Fatalf("order = %v, want %v", names(in), want)
		}
	}
}

func names(rs []RPKIResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Prefix
	}
	return out
}

func prefixFor(i int) string {
	return "203.0." + itoa(i) + ".0/24"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
