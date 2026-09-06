// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// realWhois104 is the shape RIPEstat's whois data call actually returns for
// 104.28.0.0/16 (captured 2026-09-02) — the geofeed lives in a "Comment"
// record, NOT in a dedicated attribute, which is exactly why discovery scans
// values and not just keys.
const realWhois104 = `{"records":[[{"key":"NetRange","value":"104.16.0.0 - 104.31.255.255"},{"key":"Organization","value":"Cloudflare, Inc."},{"key":"Comment","value":"Geofeed: https://api.cloudflare.com/local-ip-ranges.csv"}]],"irr_records":[]}`

// realGeofeedCSV rows are verbatim from Cloudflare's published feed.
const realGeofeedCSV = `103.22.200.0/24,SG,,Singapore,
103.22.201.0/24,JP,,Tokyo,
104.28.1.0/24,IN,,Chandigarh,
104.28.2.0/24,US,US-GA,Atlanta,30301
`

func TestDiscoverGeofeedURLFindsBothRFC9092Forms(t *testing.T) {
	if u, ok := DiscoverGeofeedURL(json.RawMessage(realWhois104)); !ok || u != "https://api.cloudflare.com/local-ip-ranges.csv" {
		t.Fatalf("remark form: got (%q,%v)", u, ok)
	}
	attr := `{"records":[[{"key":"geofeed","value":"https://example.com/geo.csv"}]]}`
	if u, ok := DiscoverGeofeedURL(json.RawMessage(attr)); !ok || u != "https://example.com/geo.csv" {
		t.Fatalf("attribute form: got (%q,%v)", u, ok)
	}
	irr := `{"records":[],"irr_records":[[{"key":"remarks","value":"geofeed https://example.com/g.csv please"}]]}`
	if u, ok := DiscoverGeofeedURL(json.RawMessage(irr)); !ok || u != "https://example.com/g.csv" {
		t.Fatalf("irr remark: got (%q,%v)", u, ok)
	}
}

// The geofeed URL is written by a THIRD PARTY into a whois object. Discovery
// must refuse an SSRF payload outright rather than hand it to the fetcher.
func TestDiscoverGeofeedURLRefusesSSRFPayloads(t *testing.T) {
	for _, v := range []string{
		"Geofeed: http://169.254.169.254/latest/meta-data/",
		"Geofeed: https://127.0.0.1/geo.csv",
		"Geofeed: https://10.0.0.1:8080/geo.csv",
		"Geofeed: file:///etc/passwd",
		"geofeed: https://user:pw@internal.example/geo.csv",
	} {
		doc := `{"records":[[{"key":"Comment","value":` + mustJSON(v) + `}]]}`
		if u, ok := DiscoverGeofeedURL(json.RawMessage(doc)); ok {
			t.Errorf("discovery accepted an unsafe geofeed URL from %q → %q", v, u)
		}
	}
	if _, ok := DiscoverGeofeedURL(json.RawMessage(`{"records":[[{"key":"descr","value":"nothing here"}]]}`)); ok {
		t.Error("discovery invented a URL where none was published")
	}
	if _, ok := DiscoverGeofeedURL(json.RawMessage(`not json`)); ok {
		t.Error("unparsable whois yielded a URL")
	}
}

func TestParseGeofeedCSVIsConservativeAndScoped(t *testing.T) {
	scope := []netip.Prefix{netip.MustParsePrefix("104.28.0.0/16")}
	got, scanned, dropped, truncated := ParseGeofeedCSV(strings.NewReader(realGeofeedCSV), scope, 0)
	if truncated {
		t.Fatal("a 4-row feed was reported truncated")
	}
	if scanned != 4 {
		t.Fatalf("scanned = %d, want 4", scanned)
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
	if len(got) != 2 {
		t.Fatalf("kept %d rows, want the 2 inside 104.28.0.0/16: %+v", len(got), got)
	}
	if got[1].Country != "US" || got[1].Region != "US-GA" || got[1].City != "Atlanta" || got[1].Postal != "30301" {
		t.Fatalf("row = %+v", got[1])
	}
}

func TestParseGeofeedCSVDropsMalformedRowsNeverRepairsThem(t *testing.T) {
	in := strings.Join([]string{
		"# a comment",
		"",
		"203.0.113.0/24,US,,Springfield,",
		"not-a-prefix,US,,X,",       // bad prefix → dropped
		"203.0.113.0/24,UNITED,,X,", // country is not alpha-2 → dropped
		"203.0.113.4/24,GB,,Y,",     // host bits set → canonicalized, kept
		"203.0.113.0/24,de,XX,Z,",   // lowercase country upcased; bad region cleared
		"203.0.113.0/24",            // prefix only → kept, no geo
	}, "\n")
	got, scanned, dropped, _ := ParseGeofeedCSV(strings.NewReader(in), nil, 0)
	if scanned != 6 {
		t.Fatalf("scanned = %d, want 6 (comments and blanks are not rows)", scanned)
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	if len(got) != 4 {
		t.Fatalf("kept %d, want 4: %+v", len(got), got)
	}
	for _, e := range got {
		if e.Prefix != "203.0.113.0/24" {
			t.Fatalf("prefix not canonicalized: %+v", e)
		}
		if e.Country != "" && e.Country != strings.ToUpper(e.Country) {
			t.Fatalf("country not upcased: %+v", e)
		}
		if e.Region != "" && e.Region != "US-GA" && !strings.Contains(e.Region, "-") {
			t.Fatalf("a non-ISO region survived: %+v", e)
		}
	}
}

func TestParseGeofeedCSVCapsRowsAndDeclaresIt(t *testing.T) {
	var b strings.Builder
	for i := 0; i < GeofeedMaxRows+50; i++ {
		b.WriteString("203.0." + itoa(i%250) + ".0/24,US,,City,\n")
	}
	got, _, _, truncated := ParseGeofeedCSV(strings.NewReader(b.String()), nil, 0)
	if len(got) != GeofeedMaxRows {
		t.Fatalf("kept %d rows, cap is %d", len(got), GeofeedMaxRows)
	}
	if !truncated {
		t.Fatal("the cap BIT and was not declared — a silently truncated feed is a lie")
	}
}

func TestParseGeofeedCSVStripsControlCharacters(t *testing.T) {
	got, _, _, _ := ParseGeofeedCSV(strings.NewReader("203.0.113.0/24,US,,At\x00lan\x1bta,\n"), nil, 0)
	if len(got) != 1 {
		t.Fatal("row dropped")
	}
	if strings.ContainsAny(got[0].City, "\x00\x1b") {
		t.Fatalf("control characters survived: %q", got[0].City)
	}
}

func TestGeofeedEndToEndForAPrefix(t *testing.T) {
	f := newFake()
	f.put("whois", "104.28.0.0/16", realWhois104)
	f.putGet("https://api.cloudflare.com/local-ip-ranges.csv", realGeofeedCSV)
	res := Geofeed(context.Background(), f, fixedNow(), "104.28.0.0/16", "prefix")
	if !res.Published || res.Error != "" {
		t.Fatalf("res = %+v", res)
	}
	if res.SourceURL != "https://api.cloudflare.com/local-ip-ranges.csv" {
		t.Fatalf("source = %q", res.SourceURL)
	}
	if res.RowsKept != 2 || len(res.Entries) != 2 {
		t.Fatalf("kept %d rows: %+v", res.RowsKept, res.Entries)
	}
}

// No geofeed published is a FACT, not an error, and must not be dressed up as
// either a failure or an empty success with a source URL.
func TestGeofeedNotPublishedIsHonest(t *testing.T) {
	f := newFake()
	f.put("whois", "203.0.113.0/24", `{"records":[[{"key":"descr","value":"nothing"}]]}`)
	res := Geofeed(context.Background(), f, fixedNow(), "203.0.113.0/24", "prefix")
	if res.Published || res.Error != "" || res.SourceURL != "" {
		t.Fatalf("res = %+v", res)
	}
	if res.Entries == nil {
		t.Fatal("Entries must be an empty array, never null (the UI maps over it)")
	}
	if f.getCalls.Load() != 0 {
		t.Fatal("no discovery means no fetch")
	}
}

func TestGeofeedForAnASNFansOutBoundedly(t *testing.T) {
	f := newFake()
	var prefixes []string
	for i := 0; i < 20; i++ {
		p := "203.0." + itoa(i) + ".0/24"
		prefixes = append(prefixes, `{"prefix":"`+p+`"}`)
		f.put("whois", p, `{"records":[[{"key":"descr","value":"none"}]]}`)
	}
	f.put("announced-prefixes", "AS64500", `{"prefixes":[`+strings.Join(prefixes, ",")+`]}`)
	res := Geofeed(context.Background(), f, fixedNow(), "AS64500", "asn")
	if res.Published {
		t.Fatal("no geofeed exists yet published=true")
	}
	// 1 announced-prefixes + at most geofeedMaxASNPrefixes whois lookups.
	if got := f.calls.Load(); got > int64(1+geofeedMaxASNPrefixes) {
		t.Fatalf("ASN fan-out made %d upstream calls, cap is %d", got, 1+geofeedMaxASNPrefixes)
	}
	if !strings.Contains(res.Note, "announced prefixes") {
		t.Fatalf("the fan-out bound is not declared to the operator: %q", res.Note)
	}
}

func TestGeofeedUpstreamFailureIsNamedNotSwallowed(t *testing.T) {
	f := newFake()
	res := Geofeed(context.Background(), f, fixedNow(), "203.0.113.0/24", "prefix")
	if res.Error == "" {
		t.Fatal("a failed registry lookup must be named")
	}
	res = Geofeed(context.Background(), f, fixedNow(), "AS1", "bogus-kind")
	if res.Error == "" {
		t.Fatal("an unknown kind must be refused")
	}
}

func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
