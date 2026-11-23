// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devname

import "testing"

func lab() *Replacer {
	return NewReplacer(map[string]string{
		"cedge-81-dde8d64d": "cEDGE-81",
		"vedge-51-79fbba30": "vEdge-51",
		"10.0.0.9":          "core-9", // an address id: never replaced in prose
	})
}

func TestTextNamesTheDeviceAndKeepsTheInterfaceForm(t *testing.T) {
	r := lab()
	cases := map[string]string{
		"Confirmed link down on cedge-81-dde8d64d:Gi2":     "Confirmed link down on cEDGE-81:Gi2",
		"cedge-81-dde8d64d lost BGP to vedge-51-79fbba30.": "cEDGE-81 lost BGP to vEdge-51.",
		"(cedge-81-dde8d64d)":                              "(cEDGE-81)",
		"path vedge-51-79fbba30->cedge-81-dde8d64d":        "path vEdge-51->cEDGE-81",
		"device:cedge-81-dde8d64d":                         "device:cEDGE-81",
		"cedge-81-dde8d64d":                                "cEDGE-81",
		"no device named here":                             "no device named here",
		"":                                                 "",
	}
	for in, want := range cases {
		if got := r.Text(in); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTextLeavesLinksLongerTokensAndAddressesAlone(t *testing.T) {
	r := lab()
	for _, in := range []string{
		"https://correlix.example/#/devices/cedge-81-dde8d64d",
		"/api/metrics?device=cedge-81-dde8d64d",
		"cedge-81-dde8d64d-old",         // a longer token is a different thing
		"xcedge-81-dde8d64d",            // so is a prefixed one
		"cedge-81-dde8d64d.example.net", // an FQDN is not the id
		"neighbor 10.0.0.9 went down",   // an address in prose stays an address
	} {
		if got := r.Text(in); got != in {
			t.Errorf("Text(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestNilAndEmptyReplacersChangeNothing(t *testing.T) {
	var r *Replacer
	if r.Text("cedge-81-dde8d64d") != "cedge-81-dde8d64d" || string(r.HTML([]byte("<b>x</b>"))) != "<b>x</b>" {
		t.Fatal("a nil Replacer must be a no-op")
	}
	if NewReplacer(nil) != nil || NewReplacer(map[string]string{"a": "a", "10.1.1.1": "x"}) != nil {
		t.Fatal("a map with nothing replaceable must give a nil Replacer")
	}
	if got := r.All([]string{"cedge-81-dde8d64d"}); got[0] != "cedge-81-dde8d64d" {
		t.Fatal("nil All must pass through")
	}
	if got := lab().All(nil); got != nil {
		t.Fatal("All(nil) must stay nil")
	}
}

func TestHTMLRewritesOnlyTheTextAPersonReads(t *testing.T) {
	r := lab()
	in := `<html><head><title>RCA cedge-81-dde8d64d</title><style>.cedge-81-dde8d64d{color:red}</style></head>` +
		`<body data-dev="cedge-81-dde8d64d"><!-- cedge-81-dde8d64d --><a href="#/devices/cedge-81-dde8d64d">cedge-81-dde8d64d:Gi2</a>` +
		`<svg><text id="n-cedge-81-dde8d64d">vedge-51-79fbba30</text></svg><p>a &amp; b cedge-81-dde8d64d.</p></body></html>`
	want := `<html><head><title>RCA cEDGE-81</title><style>.cedge-81-dde8d64d{color:red}</style></head>` +
		`<body data-dev="cedge-81-dde8d64d"><!-- cedge-81-dde8d64d --><a href="#/devices/cedge-81-dde8d64d">cEDGE-81:Gi2</a>` +
		`<svg><text id="n-cedge-81-dde8d64d">vEdge-51</text></svg><p>a &amp; b cEDGE-81.</p></body></html>`
	if got := string(r.HTML([]byte(in))); got != want {
		t.Fatalf("HTML:\n got %s\nwant %s", got, want)
	}
}

func TestHTMLRawTextBodiesAreFoundOnTheOriginalBytes(t *testing.T) {
	r := lab()
	// Mixed-case tags and non-ASCII text whose lower-casing changes length
	// ("İ" lower-cases to two runes): the style body must still end exactly at
	// its own closing tag, and the text after it must still be named.
	in := `<STYLE>/* İİİİ */ .cedge-81-dde8d64d{}</Style><p>İ cedge-81-dde8d64d</p>`
	want := `<STYLE>/* İİİİ */ .cedge-81-dde8d64d{}</Style><p>İ cEDGE-81</p>`
	if got := string(r.HTML([]byte(in))); got != want {
		t.Fatalf("HTML:\n got %s\nwant %s", got, want)
	}
	if indexFoldASCII("ab</ScRiPt>", "</script") != 2 || indexFoldASCII("abc", "</style") != -1 {
		t.Fatal("indexFoldASCII")
	}
}

func TestHTMLIsSafeOnTruncatedMarkup(t *testing.T) {
	r := lab()
	for _, in := range []string{"<p>cedge-81-dde8d64d", "<style>cedge-81-dde8d64d", "<!-- cedge-81-dde8d64d", "x <a href=\"cedge-81-dde8d64d"} {
		_ = r.HTML([]byte(in)) // must not panic
	}
	if got := string(r.HTML([]byte("<p>cedge-81-dde8d64d"))); got != "<p>cEDGE-81" {
		t.Fatalf("got %q", got)
	}
	if got := string(r.HTML([]byte("<style>cedge-81-dde8d64d"))); got != "<style>cedge-81-dde8d64d" {
		t.Fatalf("an unterminated style body must pass through, got %q", got)
	}
}
