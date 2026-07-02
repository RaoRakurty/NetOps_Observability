package ai

import (
	"strings"
	"testing"
)

// docs_index_test.go — the documentation retriever's definition of done:
// real portal pages are found by the questions operators actually ask, the
// honesty floor returns NOTHING for uncovered topics (never a weak paraphrase
// source), citations resolve to real /docs/ URLs, and the corpus is structurally
// tenant-free.

func TestDocsIndexLoadsPortalCorpus(t *testing.T) {
	ix := LoadDocsIndex()
	if ix.Len() < 200 {
		t.Fatalf("expected the 66-page portal to yield hundreds of chunks, got %d", ix.Len())
	}
	slugs := map[string]bool{}
	for _, c := range ix.All() {
		slugs[c.Slug] = true
		if c.ID == "" || !strings.HasPrefix(c.ID, "doc:") {
			t.Fatalf("chunk without a doc: citation id: %+v", c)
		}
		if c.Href != "" && !strings.HasPrefix(c.Href, "/docs/") {
			t.Fatalf("portal chunk href must be a /docs/ link, got %q", c.Href)
		}
		if strings.Contains(c.Body, "import Link from") {
			t.Fatalf("MDX import leaked into chunk body: %s", c.ID)
		}
	}
	for _, want := range []string{"onboard-devices/snmp-discovery", "getting-started/quickstart", "dashboards-reports/reports", "send-data/traps"} {
		if !slugs[want] {
			t.Fatalf("expected portal page %q in the index", want)
		}
	}
	// intro.md carries `slug: /` — it must land at the site root, not /docs/intro.
	if !slugs[""] {
		t.Fatal("intro.md (slug: /) missing from the index")
	}
}

// The retrieval cases the owner's P1 validation script uses: for questions
// answered by portal content, the right page must be among the retrieved hits
// (a curated concept section may legitimately take the top slot — the answer
// card then shows its text PLUS the portal page as a clickable citation).
func TestDocsIndexFindsTheRightPage(t *testing.T) {
	ix := LoadDocsIndex()
	cases := []struct {
		q        string
		wantSlug string
	}{
		{"how do I set up SNMP subnet discovery scan scope", "onboard-devices/snmp-discovery"},
		{"how do I schedule a report", "dashboards-reports/reports"},
		{"how do I configure SNMP traps", "send-data/traps"},
		{"how do I send syslog to correlix", "send-data/syslog"},
		{"how do I create a monitor threshold", "monitoring/create-a-monitor"},
		{"how do I connect servicenow ticketing", "incident-response/"},
		{"gnmi streaming telemetry setup", "onboard-devices/streaming-gnmi"},
		{"what are the connectivity requirements ports", "reference/connectivity-requirements"},
	}
	for _, tc := range cases {
		hits := ix.Search(tc.q, 4)
		if len(hits) == 0 {
			t.Errorf("%q: no hits, want %s", tc.q, tc.wantSlug)
			continue
		}
		found := false
		for _, h := range hits {
			if strings.HasPrefix(h.Chunk.Slug, tc.wantSlug) {
				found = true
				break
			}
		}
		if !found {
			var got []string
			for _, h := range hits {
				got = append(got, h.Chunk.ID)
			}
			t.Errorf("%q: portal page %s not in hits %v", tc.q, tc.wantSlug, got)
		}
	}
}

func TestDocsIndexHonestyFloor(t *testing.T) {
	ix := LoadDocsIndex()
	// Topics the docs genuinely don't cover must return NOTHING (the honest
	// "not in the docs" path) — not a weak incidental match.
	for _, q := range []string{
		"kubernetes helm chart autoscaling",
		"quarterly payroll journal entries",
		"zzqx qwerty plugh",
	} {
		if hits := ix.Search(q, 3); len(hits) != 0 {
			t.Errorf("%q: expected no hits (honesty floor), got %s (%.2f)", q, hits[0].Chunk.ID, hits[0].Score)
		}
	}
	if hits := ix.Search("", 3); hits != nil {
		t.Error("empty query must return nil")
	}
}

func TestDocsIndexCuratedTierJoins(t *testing.T) {
	ix := LoadDocsIndex(ExtraDoc{Name: "kb/test-concepts", Tier: DocTierCurated, Markdown: "---\ntitle: Test Concepts\n---\n\n## What is a frobnicator verdict\n\nA frobnicator verdict is a curated concept used only by this test."})
	hits := ix.Search("what is a frobnicator verdict", 3)
	if len(hits) == 0 || hits[0].Chunk.Tier != DocTierCurated {
		t.Fatalf("curated chunk must win its own concept question, got %+v", hits)
	}
	if hits[0].Chunk.Href != "" {
		t.Errorf("curated chunks are not portal pages — href must be empty, got %q", hits[0].Chunk.Href)
	}
	if hits[0].Chunk.ID != "doc:kb/test-concepts#what-is-a-frobnicator-verdict" {
		t.Errorf("curated citation id: %s", hits[0].Chunk.ID)
	}
}

func TestChunkMarkdownDoc(t *testing.T) {
	md := "---\ntitle: Discover devices (SNMP)\ndescription: x\n---\n\nimport Link from '@docusaurus/Link';\n\n# Discover devices (SNMP)\n\nIntro paragraph.\n\n## Step 1 — Enable SNMP on the devices\n\nBody one with `snmp-server community` config.\n\n```text\n<not-a-tag> stays literal\n```\n\n### Verify from the console\n\nSub body.\n"
	chunks := chunkMarkdownDoc(md, "", "onboard-devices/snmp-discovery", DocTierPortal)
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks (intro + h2 + h3), got %d: %+v", len(chunks), chunks)
	}
	// The intro chunk carries the frontmatter description + the pre-heading prose.
	if chunks[0].Anchor != "" || !strings.Contains(chunks[0].Body, "Intro paragraph.") || !strings.HasPrefix(chunks[0].Body, "x") {
		t.Errorf("intro chunk wrong: %+v", chunks[0])
	}
	h2 := chunks[1]
	if h2.Anchor != "step-1--enable-snmp-on-the-devices" {
		t.Errorf("anchor slug: %q", h2.Anchor)
	}
	if h2.Href != "/docs/onboard-devices/snmp-discovery#step-1--enable-snmp-on-the-devices" {
		t.Errorf("href: %q", h2.Href)
	}
	if !strings.Contains(h2.Body, "<not-a-tag> stays literal") {
		t.Errorf("code fence content must survive MDX stripping: %q", h2.Body)
	}
	h3 := chunks[2]
	if h3.Breadcrumb != "Discover devices (SNMP) › Step 1 — Enable SNMP on the devices › Verify from the console" {
		t.Errorf("h3 breadcrumb: %q", h3.Breadcrumb)
	}
}

func TestAnchorSlug(t *testing.T) {
	cases := map[string]string{
		"Step 1 — Enable SNMP on the devices": "step-1--enable-snmp-on-the-devices",
		"What is Correlix?":                   "what-is-correlix",
		"IPv4 & IPv6":                         "ipv4--ipv6",
		"already-kebab_case":                  "already-kebab_case",
	}
	for in, want := range cases {
		if got := anchorSlug(in); got != want {
			t.Errorf("anchorSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPromptBlockBoundedAndLabeled(t *testing.T) {
	ix := LoadDocsIndex()
	hits := ix.Search("how do I set up SNMP discovery", 3)
	if len(hits) == 0 {
		t.Fatal("expected hits")
	}
	block := PromptBlock(hits, 1500, 6000)
	if len(block) > 7000 {
		t.Fatalf("prompt block unbounded: %d bytes", len(block))
	}
	for _, want := range []string{"DOCUMENTATION EXCERPTS", "reference DATA", "[" + hits[0].Chunk.ID + "]"} {
		if !strings.Contains(block, want) {
			t.Errorf("prompt block missing %q", want)
		}
	}
	if PromptBlock(nil, 100, 100) != "" {
		t.Error("no hits → empty block")
	}
}

// The grounded brain's product answers must cite real portal pages when the
// docs index is wired, and decline honestly when the docs don't cover it.
func TestAnswerProductFromDocs(t *testing.T) {
	o := &Orchestrator{Docs: LoadDocsIndex()}
	plan := Plan{Intent: "product_question", Modules: []string{"product_navigation"}, Mode: ModeProductAnswer}

	a := o.answerProduct("how do I set up SNMP subnet discovery?", plan, nil)
	if a.Mode != ModeProductAnswer || a.Text == "" {
		t.Fatalf("expected a docs-grounded product answer, got %+v", a)
	}
	foundDoc := false
	for _, c := range a.Citations {
		if c.Kind == "doc" && strings.HasPrefix(c.Href, "/docs/") && strings.HasPrefix(c.ID, "doc:") {
			foundDoc = true
		}
	}
	if !foundDoc {
		t.Fatalf("expected at least one /docs citation, got %+v", a.Citations)
	}

	// Uncovered topic → the explicit honest decline, zero citations.
	d := o.answerProduct("how does correlix integrate with kubernetes helm autoscaling?", plan, nil)
	if len(d.Citations) != 0 || !strings.Contains(d.Text, "documentation doesn't cover") {
		t.Fatalf("expected the honest not-in-the-docs answer, got %+v", d)
	}
}
