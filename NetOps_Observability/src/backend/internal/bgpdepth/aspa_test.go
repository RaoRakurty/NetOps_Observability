// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The HONESTY test. If someone ever wires a fabricated ASPA answer in, this
// fails: with nothing configured the default provider must ERROR, never return
// an empty-but-successful record (which reads as "this AS authorizes nobody").
func TestNoASPAProviderNeverFabricatesAVerdict(t *testing.T) {
	res, err := NoASPAProvider{}.ASPA(context.Background(), "3333")
	if !errors.Is(err, ErrNoASPASource) {
		t.Fatalf("err = %v, want ErrNoASPASource", err)
	}
	if res.Found {
		t.Fatal("the no-source provider claimed a finding")
	}
}

func TestNotConfiguredStatusExplainsItselfAndNamesTheKnob(t *testing.T) {
	st := NotConfiguredStatus()
	if st.Configured {
		t.Fatal("configured=true with no provider")
	}
	if !strings.Contains(st.HowTo, EnvASPAProviderURL) {
		t.Fatalf("the operator is not told which env var to set: %q", st.HowTo)
	}
	if !strings.Contains(strings.ToLower(st.Reason), "no aspa data source") {
		t.Fatalf("reason does not state the gap plainly: %q", st.Reason)
	}
}

func TestNewASPAProviderFallsBackToHonestOnBadConfig(t *testing.T) {
	f := newFake()
	for _, bad := range []string{"", "   ", "http://plain.example/aspa", "https://127.0.0.1/aspa", "https://x:9000/aspa"} {
		p := NewASPAProvider(bad, f, fixedNow())
		if _, ok := p.(NoASPAProvider); !ok {
			t.Errorf("NewASPAProvider(%q) built a live provider from an unsafe/absent URL", bad)
		}
	}
	if _, ok := NewASPAProvider("https://validator.example/aspa", nil, fixedNow()).(NoASPAProvider); !ok {
		t.Error("a nil fetcher must yield the honest provider")
	}
	if _, ok := NewASPAProvider("https://validator.example/aspa", f, fixedNow()).(HTTPProvider); !ok {
		t.Error("a safe URL + fetcher must build the HTTP provider")
	}
}

func TestHTTPProviderParsesAndBoundsARealShape(t *testing.T) {
	f := newFake()
	f.putGet("https://validator.example/aspa?asn=64500",
		`{"customer_asn":64500,"providers":[{"asn":3333,"afi":"ipv4"},{"asn":1299,"afi":"nonsense"},{"asn":0},{"asn":"nope"}],"source":"routinator-0.14"}`)
	p := NewASPAProvider("https://validator.example/aspa", f, fixedNow())
	res, err := p.ASPA(context.Background(), "AS64500")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.CustomerASN != 64500 || res.Source != "routinator-0.14" {
		t.Fatalf("res = %+v", res)
	}
	if len(res.Providers) != 2 {
		t.Fatalf("providers = %+v — invalid rows must be DROPPED, not repaired", res.Providers)
	}
	// {"asn":"nope"} is a row the source wrote in a form we cannot read — a
	// FAULT that must be counted. {"asn":0} is a well-formed "no AS" (RFC 7607)
	// and is not a fault: a shorter list must never be the only evidence that
	// the upstream is emitting garbage (§10).
	if res.ProvidersUnreadable != 1 {
		t.Fatalf("providers_unreadable = %d, want 1 — the unreadable row was dropped SILENTLY", res.ProvidersUnreadable)
	}
	if res.Providers[0].AFI != "ipv4" || res.Providers[1].AFI != "" {
		t.Fatalf("AFI normalization wrong: %+v", res.Providers)
	}
}

// A provider answering about a DIFFERENT AS is an error, never a verdict shown
// against the AS we asked about (§3: never trust an upstream's framing).
func TestHTTPProviderRefusesAnAnswerAboutAnotherAS(t *testing.T) {
	f := newFake()
	f.putGet("https://validator.example/aspa?asn=64500", `{"customer_asn":1299,"providers":[{"asn":3333}]}`)
	_, err := NewASPAProvider("https://validator.example/aspa", f, fixedNow()).ASPA(context.Background(), "AS64500")
	if err == nil {
		t.Fatal("a mismatched customer_asn was accepted")
	}
}

func TestHTTPProviderRejectsGarbage(t *testing.T) {
	f := newFake()
	p := NewASPAProvider("https://validator.example/aspa", f, fixedNow())
	for _, asn := range []string{"", "AS0", "notanasn", "AS99999999999", "-1"} {
		if _, err := p.ASPA(context.Background(), asn); err == nil {
			t.Errorf("ASPA(%q) was accepted", asn)
		}
	}
	f.putGet("https://validator.example/aspa?asn=1", `not json`)
	if _, err := p.ASPA(context.Background(), "AS1"); err == nil {
		t.Error("an unparsable provider payload must be an error")
	}
	f.putGet("https://validator.example/aspa?asn=2", `{"providers":[]}`)
	if _, err := p.ASPA(context.Background(), "AS2"); err == nil {
		t.Error("a payload with no customer_asn must be an error, not an empty verdict")
	}
}

// The configured status must never echo the provider URL, which may carry a
// token (§8 — no secrets in responses or logs).

func TestConfiguredStatusHidesTheURL(t *testing.T) {
	st := ConfiguredStatus("https://validator.example/aspa?token=SUPERSECRET")
	if st.Host != "validator.example" {
		t.Fatalf("host = %q", st.Host)
	}
	blob := st.Host + st.Reason + st.HowTo
	if strings.Contains(blob, "SUPERSECRET") || strings.Contains(blob, "token=") {
		t.Fatalf("the provider URL/token leaked into the status: %+v", st)
	}
}

// A source that answers with NOTHING WE CAN READ has made no statement about
// who this AS authorizes. It must surface as a FAILED provider, never as an
// empty-but-successful verdict — which reads as "this AS authorizes nobody".
func TestHTTPProviderFailsWhenEveryProviderRowIsUnreadable(t *testing.T) {
	f := newFake()
	f.putGet("https://validator.example/aspa?asn=64500",
		`{"customer_asn":64500,"providers":[{"asn":"nope"},{"asn":"also-nope"}],"source":"routinator-0.14"}`)
	res, err := NewASPAProvider("https://validator.example/aspa", f, fixedNow()).ASPA(context.Background(), "AS64500")
	if err == nil {
		t.Fatalf("an all-garbage provider list was accepted as a verdict: %+v", res)
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("the error does not say WHAT failed: %v", err)
	}
	if res.Found {
		t.Errorf("a failed answer was marked Found: %+v", res)
	}
	// Contrast: a source that genuinely says "no providers" is NOT an error.
	f.putGet("https://validator.example/aspa?asn=64501", `{"customer_asn":64501,"providers":[],"source":"routinator-0.14"}`)
	ok, err := NewASPAProvider("https://validator.example/aspa", f, fixedNow()).ASPA(context.Background(), "AS64501")
	if err != nil {
		t.Fatalf("an honest empty ASPA was reported as a failure: %v", err)
	}
	if !ok.Found || len(ok.Providers) != 0 || ok.ProvidersUnreadable != 0 {
		t.Fatalf("empty-but-answered verdict = %+v", ok)
	}
}

// An ASN we cannot read and the reserved AS0 are different facts, and the
// operator reading the status card must be able to tell them apart.
func TestASPARejectsUnreadableAndReservedASNsDistinctly(t *testing.T) {
	f := newFake()
	p := NewASPAProvider("https://validator.example/aspa", f, fixedNow())
	_, unreadable := p.ASPA(context.Background(), "notanasn")
	_, reserved := p.ASPA(context.Background(), "AS0")
	if unreadable == nil || reserved == nil {
		t.Fatalf("both must be refused: unreadable=%v reserved=%v", unreadable, reserved)
	}
	if !strings.Contains(unreadable.Error(), "unreadable") {
		t.Errorf("an unparsable ASN is not named as such: %v", unreadable)
	}
	if !strings.Contains(reserved.Error(), "AS0 is reserved") {
		t.Errorf("AS0 is not named as reserved: %v", reserved)
	}
	if unreadable.Error() == reserved.Error() {
		t.Error("the two failures are indistinguishable to the operator")
	}
}

// The three-state core: a fault, a benign absence, and a value.
func TestParseASNValueSeparatesUnreadableFromReserved(t *testing.T) {
	cases := []struct {
		raw  string
		want asnParse
		asn  uint32
	}{
		{`3333`, asnOK, 3333},
		{`"AS3333"`, asnOK, 3333},
		{`"nope"`, asnUnreadable, 0},
		{`{}`, asnUnreadable, 0},
		{`0`, asnReserved, 0},
		{`""`, asnReserved, 0},
		{`"AS99999999999"`, asnUnreadable, 0},
	}
	for _, c := range cases {
		v, got := parseASNValue(json.RawMessage(c.raw))
		if got != c.want || v != c.asn {
			t.Errorf("parseASNValue(%s) = (%d,%v), want (%d,%v)", c.raw, v, got, c.asn, c.want)
		}
		// The boolean shim must stay consistent with the three-state core.
		if bv, ok := ParseASNValue(json.RawMessage(c.raw)); ok != (c.want == asnOK) || bv != c.asn {
			t.Errorf("ParseASNValue(%s) = (%d,%v), inconsistent with the core", c.raw, bv, ok)
		}
	}
}

// A provider that does not ANSWER must produce an error the status card can
// render, never an empty ASPAResult (which claims "authorizes nobody").
func TestFailingASPAFetcherIsAnErrorNotAnEmptyVerdict(t *testing.T) {
	f := newFake() // nothing scripted: the fake refuses the GET
	res, err := NewASPAProvider("https://validator.example/aspa", f, fixedNow()).ASPA(context.Background(), "AS64500")
	if err == nil {
		t.Fatalf("a failed fetch produced a verdict: %+v", res)
	}
	if !strings.Contains(err.Error(), "aspa provider") {
		t.Errorf("the failure is not attributed to the provider: %v", err)
	}
	if res.Found || len(res.Providers) != 0 {
		t.Fatalf("a failed fetch returned partial data: %+v", res)
	}
	if errors.Is(err, ErrNoASPASource) {
		t.Error("a BROKEN provider was reported as 'no source configured' — two different facts")
	}
}
