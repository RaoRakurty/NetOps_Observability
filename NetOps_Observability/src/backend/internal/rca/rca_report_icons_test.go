// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// The embedded cloud glyphs are ORIGINAL Correlix artwork (licence audit D5,
// 2026-09-04). These tests are the guard that keeps them that way: one shared
// silhouette, a plain letter tag as the only difference, and not one provider
// brand colour or trademark artefact anywhere in the bytes we ship.

// Every hex the removed provider marks used, plus the Azure gradient stops and
// the AWS icon tile. Lower-case; the assertions lower-case the document too.
var providerBrandHexes = []string{
	"#ff9900",                                  // AWS orange
	"#0078d4",                                  // Azure blue
	"#4285f4",                                  // Google blue
	"#ea4335",                                  // Google red
	"#34a853",                                  // Google green
	"#fbbc05",                                  // Google yellow
	"#114a8b", "#0669bc", "#3ccbf4", "#2892df", // Azure gradient stops
	"#242f3e", // AWS icon tile
}

// Words that would mean a vendor mark or its provenance came back.
var providerBrandWords = []string{
	"lineargradient", "gradient",
	"icon-architecture-group", "aws-cloud-logo",
	"icon-service-azure", "google cloud", "amazon",
}

var wantTags = map[string]string{"aws": "AWS", "azure": "AZ", "gcp": "GCP"}

func readCloudIcon(t *testing.T, provider string) string {
	t.Helper()
	b, err := cloudIconFiles.ReadFile("cloudicons/" + provider + ".svg")
	if err != nil {
		t.Fatalf("go:embed must still resolve cloudicons/%s.svg: %v", provider, err)
	}
	return string(b)
}

func TestCloudIconDataURIReturnsGlyphForEachProvider(t *testing.T) {
	for _, p := range cloudIconProviders {
		uri := CloudIconDataURI(p)
		if !strings.HasPrefix(uri, "data:image/svg+xml;base64,") {
			t.Fatalf("%s: want a base64 svg data URI, got %q", p, uri)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "data:image/svg+xml;base64,"))
		if err != nil {
			t.Fatalf("%s: data URI payload is not valid base64: %v", p, err)
		}
		if !strings.HasPrefix(strings.TrimSpace(string(raw)), "<svg") {
			t.Fatalf("%s: decoded payload is not an SVG document", p)
		}
	}
	// case / whitespace tolerant, like every other provider lookup
	if CloudIconDataURI("  AWS ") != CloudIconDataURI("aws") {
		t.Fatal("provider lookup must normalise case and whitespace")
	}
}

func TestCloudIconDataURIHonestFallbackForUnknownProvider(t *testing.T) {
	// An unknown provider gets "" so rca_report_html.go renders its NAME as
	// text. It must never be handed another provider's glyph.
	for _, p := range []string{"", "   ", "nifcloud", "oracle", "ibm", "unknown"} {
		if got := CloudIconDataURI(p); got != "" {
			t.Fatalf("provider %q must have no glyph, got %q", p, got)
		}
	}
}

func TestCloudIconsShareOneSilhouetteAndDifferOnlyByTag(t *testing.T) {
	pathRe := regexp.MustCompile(`<path d="([^"]+)"`)
	textRe := regexp.MustCompile(`<text[^>]*>([^<]+)</text>`)

	var silhouette string
	for _, p := range cloudIconProviders {
		doc := readCloudIcon(t, p)

		pm := pathRe.FindStringSubmatch(doc)
		if pm == nil {
			t.Fatalf("%s: no silhouette path found", p)
		}
		if silhouette == "" {
			silhouette = pm[1]
		} else if pm[1] != silhouette {
			t.Fatalf("%s: silhouette differs from the family:\n got %q\nwant %q", p, pm[1], silhouette)
		}

		tm := textRe.FindStringSubmatch(doc)
		if tm == nil {
			t.Fatalf("%s: no letter tag found", p)
		}
		if tm[1] != wantTags[p] {
			t.Fatalf("%s: tag = %q, want %q", p, tm[1], wantTags[p])
		}

		// Product icon style: one shared viewBox, currentColor stroke, and the
		// icon set's 1.6 weight with round joins.
		for _, want := range []string{`viewBox="0 0 24 24"`, `stroke="currentColor"`, `stroke-width="1.6"`, `stroke-linejoin="round"`} {
			if !strings.Contains(doc, want) {
				t.Fatalf("%s: glyph must keep the product icon style (%s)", p, want)
			}
		}
	}
	if silhouette == "" {
		t.Fatal("no glyphs were checked")
	}
}

func TestCloudIconsCarryNoProviderTrademark(t *testing.T) {
	for _, p := range cloudIconProviders {
		doc := strings.ToLower(readCloudIcon(t, p))
		for _, hex := range providerBrandHexes {
			if strings.Contains(doc, hex) {
				t.Fatalf("%s.svg reintroduced a provider brand colour (%s)", p, hex)
			}
		}
		for _, word := range providerBrandWords {
			if strings.Contains(doc, word) {
				t.Fatalf("%s.svg reintroduced provider trademark content (%q)", p, word)
			}
		}
		// Colour comes from the theme, never from a literal fill/stroke hex.
		if regexp.MustCompile(`(fill|stroke|stop-color)="#`).MatchString(strings.ReplaceAll(doc, `color="#475569"`, "")) {
			t.Fatalf("%s.svg paints with a literal hex; the glyph must use currentColor", p)
		}
	}
}

// The report still renders the same structure: an <image> carrying the glyph
// plus the provider NAME beside it for a known provider, and the name alone for
// an unknown one.
func TestPathCausalitySVGUsesGlyphForKnownProviderAndTextForUnknown(t *testing.T) {
	known := string(rcaPathGraphSVG(TopologyView{Available: true, Hops: []SpineHopView{
		{Index: 0, Label: "vpc-nat", Address: "10.0.0.1", Kind: "cloud", State: "responding", Boundary: "provider", Provider: "aws"},
	}}))
	if !strings.Contains(known, "<image href=\"data:image/svg+xml;base64,") {
		t.Fatalf("known provider hop must embed the glyph as an <image> data URI:\n%s", known)
	}
	if !strings.Contains(known, ">AWS<") {
		t.Fatalf("known provider hop must still name the provider beside the glyph:\n%s", known)
	}

	unknown := string(rcaPathGraphSVG(TopologyView{Available: true, Hops: []SpineHopView{
		{Index: 0, Label: "vpc-nat", Address: "10.0.0.1", Kind: "cloud", State: "responding", Boundary: "provider", Provider: "nifcloud"},
	}}))
	if strings.Contains(unknown, "<image href=") {
		t.Fatalf("unknown provider must not borrow a glyph:\n%s", unknown)
	}
	if !strings.Contains(unknown, ">NIFCLOUD<") {
		t.Fatalf("unknown provider must fall back to its name as text:\n%s", unknown)
	}
}
