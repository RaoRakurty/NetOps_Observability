// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"strings"
	"testing"
)

// docs_fold_test.go — the plural/suffix folding table (kb.go foldTerm), the
// release-notes down-weight and the per-page diversity cap (docs_index.go).

// TestFoldTermTable pins every rule of foldTerm, and — just as important — the
// words it must leave alone. A fold that is too eager merges unrelated terms;
// one that is too timid leaves "seams" unable to find "seam".
func TestFoldTermTable(t *testing.T) {
	cases := []struct{ in, want string }{
		// Plurals.
		{"seams", "seam"},
		{"verdicts", "verdict"},
		{"commands", "command"},
		{"routers", "router"},
		{"policies", "policy"},
		{"queries", "query"},
		{"classes", "class"},
		{"addresses", "address"},
		{"switches", "switch"},
		{"patches", "patch"},
		{"meshes", "mesh"},
		{"boxes", "box"},
		{"keys", "key"},
		{"vrfs", "vrf"},
		{"logs", "log"},
		// -ed / -ing / -ied, and the silent e they meet on.
		{"configure", "configur"},
		{"configures", "configur"},
		{"configured", "configur"},
		{"configuring", "configur"},
		{"onboarding", "onboard"},
		{"onboarded", "onboard"},
		{"monitoring", "monitor"},
		{"troubleshooting", "troubleshoot"},
		{"enabled", "enabl"},
		{"enable", "enabl"},
		{"devices", "devic"},
		{"device", "devic"},
		{"applied", "apply"},
		{"verified", "verify"},
		{"shipped", "ship"},
		{"dropped", "drop"},
		{"installed", "install"}, // l stays doubled
		{"embedded", "embed"},
		// Irregular table.
		{"aliases", "alias"},
		{"statuses", "status"},
		{"analyses", "analysis"},
		{"indices", "index"},
		{"indexes", "index"},
		{"caches", "cache"},
		{"apis", "api"},
		{"kpis", "kpi"},

		// MUST NOT fold.
		{"access", "access"},     // -ss
		{"status", "status"},     // -us
		{"analysis", "analysis"}, // -is
		{"redis", "redis"},       // -is
		{"series", "series"},     // keep list: not a plural of "sery"
		{"alias", "alias"},       // keep list
		{"canvas", "canvas"},     // keep list
		{"news", "news"},         // keep list
		{"https", "https"},       // keep list
		{"during", "during"},     // keep list: not a verb form
		{"setting", "setting"},   // stem "sett" is too short: never "set"
		{"routing", "routing"},   // stem "rout" is too short
		{"warning", "warning"},   // stem "warn" is too short
		{"string", "string"},     // stem too short
		{"speed", "speed"},       // -eed is not -ed
		{"exceed", "exceed"},     // -eed is not -ed
		{"plane", "plane"},       // five letters keep the e: never "plan"
		{"route", "route"},       // five letters keep the e
		{"bgp", "bgp"},           // shorter than 4
		{"dns", "dns"},           // shorter than 4
		{"ipv4", "ipv4"},         // digits never fold
		{"802.1x", "802.1x"},     // not a plain word
		{"ports2", "ports2"},     // digits never fold
	}
	for _, c := range cases {
		if got := foldTerm(c.in); got != c.want {
			t.Errorf("foldTerm(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFoldTermIsIdempotent — folding a folded term must not move it again, or
// a document term and a query term could land on different stems depending on
// how many times each passed through the tokenizer.
func TestFoldTermIsIdempotent(t *testing.T) {
	for _, w := range []string{
		"seams", "policies", "configuring", "devices", "switches", "shipped",
		"installed", "applied", "monitoring", "aliases", "series", "setting",
	} {
		once := foldTerm(w)
		if twice := foldTerm(once); twice != once {
			t.Errorf("foldTerm not idempotent for %q: %q → %q", w, once, twice)
		}
	}
}

// TestFoldAppliedOnBothSides — a query and a document that differ only by
// inflection produce the same terms. This is the property the whole fold
// exists for; testing foldTerm alone would not catch a side that forgot to
// call it.
func TestFoldAppliedOnBothSides(t *testing.T) {
	q := docsQueryTerms("configured seams and verdicts on the routers")
	d := docTerms("configure seam verdict router")
	if strings.Join(q, " ") != strings.Join(d, " ") {
		t.Fatalf("query terms %v != document terms %v", q, d)
	}
	// A fold that lands on a stopword is dropped, as the stopword would be.
	if got := docsQueryTerms("it needs shows"); len(got) != 0 {
		t.Fatalf("folded stopwords must be dropped, got %v", got)
	}
}

// TestFoldFindsSingularFromPlural — end to end on a tiny index: a page that
// only ever uses the singular is found by a plural question, and the curated
// tier (which has no portal slug) takes part the same way.
func TestFoldFindsSingularFromPlural(t *testing.T) {
	ix := &DocsIndex{df: map[string]int{}}
	for _, c := range chunkMarkdownDoc("---\ntitle: Seam ownership\n---\n\nA seam is where ownership of the packet changes hands. The verdict names the seam.\n", "", "probe/seam", DocTierPortal) {
		ix.add(c)
	}
	for _, c := range chunkMarkdownDoc("---\ntitle: Weather\n---\n\nRain and sunshine forecasts for tomorrow.\n", "", "probe/weather", DocTierPortal) {
		ix.add(c)
	}
	ix.finish()
	hits := ix.Search("what are seams and verdicts", 3)
	if len(hits) == 0 || hits[0].Chunk.Slug != "probe/seam" {
		t.Fatalf("plural question must find the singular page, got %+v", hits)
	}
}

// TestReleaseNotesLoseCloseCalls — the release-notes page is given the
// STRONGER text (it repeats the question's words), so without the down-weight
// it would rank first. The feature page must win, and the release notes must
// still be retrievable (down-weighted, never dropped).
func TestReleaseNotesLoseCloseCalls(t *testing.T) {
	page := "The verdict ladder grades each seam from the independent evidence sources."
	notes := page + " New: the verdict ladder and seam attribution."
	ix := &DocsIndex{df: map[string]int{}}
	for _, d := range []struct{ slug, body string }{
		{"release-notes/2026-08", notes}, {"investigate/verdicts", page},
	} {
		for _, c := range chunkMarkdownDoc("---\ntitle: Verdict ladder\n---\n\n"+d.body+"\n", "", d.slug, DocTierPortal) {
			ix.add(c)
		}
	}
	ix.finish()
	hits := ix.Search("verdict ladder seam", 3)
	if len(hits) != 2 {
		t.Fatalf("both pages must be retrievable, got %d hits: %+v", len(hits), hits)
	}
	if hits[0].Chunk.Slug != "investigate/verdicts" {
		t.Fatalf("the feature page must outrank release notes, got %s first", hits[0].Chunk.Slug)
	}
	for _, s := range []string{"release-notes", "release-notes/2026-08", "release-notes/whats-new"} {
		if !isReleaseNotes(s) {
			t.Errorf("isReleaseNotes(%q) = false", s)
		}
	}
	for _, s := range []string{"", "reference/release-process", "release-notesx/a", "deploy/upgrade"} {
		if isReleaseNotes(s) {
			t.Errorf("isReleaseNotes(%q) = true", s)
		}
	}
}

// TestDiversifyByPage — at most N sections of one page, order preserved, and
// the curated tier (no slug) grouped by its citation id.
func TestDiversifyByPage(t *testing.T) {
	mk := func(id string) DocsHit { return DocsHit{Chunk: DocChunk{ID: id}} }
	in := []DocsHit{
		mk("doc:bgp/bmp"), mk("doc:bgp/bmp#a"), mk("doc:bgp/bmp#b"),
		mk("doc:send-data/syslog"), mk("doc:kb/correlix#x"), mk("doc:kb/correlix#y"),
		mk("doc:kb/correlix#z"), mk("doc:bgp/bmp#c"),
	}
	got := diversifyByPage(in, 2)
	var ids []string
	for _, h := range got {
		ids = append(ids, h.Chunk.ID)
	}
	want := "doc:bgp/bmp doc:bgp/bmp#a doc:send-data/syslog doc:kb/correlix#x doc:kb/correlix#y"
	if strings.Join(ids, " ") != want {
		t.Fatalf("diversifyByPage = %v, want %s", ids, want)
	}
	if n := len(diversifyByPage([]DocsHit{mk("a"), mk("a#1")}, 0)); n != 2 {
		t.Fatalf("perPage <= 0 must disable the cap, kept %d", n)
	}
}

// TestSyslogQuestionIsNotFloodedByTitleMatch — the regression that motivated
// the cap, on the real corpus: "point my routers' syslog" used to come back as
// eleven sections of the BMP page (title "Point a router at the BMP receiver").
func TestSyslogQuestionIsNotFloodedByTitleMatch(t *testing.T) {
	ix := goldenIndex()
	if ix.Len() == 0 {
		t.Skip("no documentation corpus embedded in this build")
	}
	hits := ix.Search("How do I point my routers' syslog at the platform?", 3)
	found := false
	for _, h := range hits {
		if h.Chunk.Slug == "send-data/syslog" || h.Chunk.Slug == "getting-started/quickstart" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a syslog page must be in the top 3, got %+v", hits)
	}
}
