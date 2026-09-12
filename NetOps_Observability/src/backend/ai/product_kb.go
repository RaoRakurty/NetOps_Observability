// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"embed"
	"regexp"
	"sort"
	"strings"
)

//go:embed product_knowledge/*.md
var productKnowledgeFS embed.FS

// product_kb.go — the Product Knowledge Retriever (HLD §9). It answers questions
// ABOUT Correlix ("what does 'suspected' mean?", "how do I set up SNMP
// discovery?", "what is a seam?") from the curated product knowledge
// (copilot_knowledge.md), retrieved deterministically. This makes the grounded,
// key-free assistant accurate on product/how-to questions — which previously fell
// through to a generic clarification — and gives the LLM the same sections as
// grounding when a provider key IS present. Retrieval is keyword-scored over the
// doc's `##` sections, bounded, and honest (no match → no answer).

// ProductSection is one retrievable chunk of the product knowledge (a `##` block).
type ProductSection struct {
	Title    string   `json:"title"`
	Body     string   `json:"body"`
	Keywords []string `json:"-"`
	Route    string   `json:"route,omitempty"` // a UI deep link, when the section maps to one
}

// ProductKB is the parsed, indexed product knowledge.
type ProductKB struct {
	sections []ProductSection
}

var reMdHeading = regexp.MustCompile(`(?m)^#{1,3}\s+(.+?)\s*$`)

// productRoutes maps a section title (lowercased substring) to a UI deep link, so
// a "how do I …" answer can offer the exact page.
//
// EVERY VALUE MUST BE A ROUTE THE SHELL RESOLVES. A deep link that lands on a
// section's first page instead of the page the answer is about is worse than no
// link: the reader believes they are where they were sent. The routes below are
// CANONICAL "#/<section>/<leaf>" ids taken from src/frontend/src/nav.tsx, and
// product_kb_links_test.go resolves every one of them through the same nav
// tables the SPA router uses — a leaf id that is renamed or moved fails the
// build here rather than in an answer. Legacy hashes still work in the browser
// (LEGACY_ROUTE_ALIAS rewrites them), but the assistant hands out the address
// the page actually has.
//
// Two entries were stale until 2026-09-05 and are the reason for the test:
// "#/admin/security" was never a route at all, and "#/monitoring/reports" fell
// back to the Operations section's first page.
var productRoutes = map[string]string{
	"correlation": "#/investigate/rca",
	"rca":         "#/investigate/rca",
	"verdict":     "#/investigate/rca",
	"seam":        "#/investigate/rca",
	"evidence":    "#/investigate/rca",
	"incident":    "#/operations/incidents",
	// The guided device-troubleshooting workspace, not the RCA board.
	"troubleshooting": "#/investigate/troubleshooting",
	"discovery":       "#/infrastructure/discovery",
	// SNMP credentials/profiles live in Administration → Data sources.
	"snmp": "#/admin/snmp",
	// Authentication is PROVIDER-only plumbing and moved to the Platform
	// section in the 2026-09-05 IA (docs/design/ADMIN_IA_2026-09-05.md §2).
	"sso":            "#/platform/auth",
	"authentication": "#/platform/auth",
	"report":         "#/analytics/reports",
	"itsm":           "#/admin/integrations",
	"notification":   "#/admin/notifications",
	// Tenants are a view inside Identity & Access.
	"tenant":        "#/admin/identity",
	"configuration": "#/admin/settings",
	"ui sections":   "#/overview/home",
	"architecture":  "#/investigate/topology",
}

// LoadProductKB builds the product knowledge base: the CURATED, concept-focused
// concepts doc (embedded ai/product_knowledge/*.md — the primary, well-titled
// answers) plus any `extra` markdown (e.g. the setup-focused copilot_knowledge.md
// for runbooks/architecture). Curated sections rank better for concept questions
// because they're concise and their titles carry the concept. Robust to empty input.
func LoadProductKB(extra ...string) *ProductKB {
	kb := &ProductKB{}
	// Curated concepts first.
	if entries, err := productKnowledgeFS.ReadDir("product_knowledge"); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
				continue
			}
			if raw, err := productKnowledgeFS.ReadFile("product_knowledge/" + e.Name()); err == nil {
				kb.addSections(string(raw))
			}
		}
	}
	// Then any extra docs (runbooks/architecture prose).
	for _, md := range extra {
		kb.addSections(md)
	}
	return kb
}

// addSections parses a markdown doc's `##` blocks into retrievable sections.
func (k *ProductKB) addSections(markdown string) {
	markdown = strings.ReplaceAll(markdown, "\r\n", "\n")
	locs := reMdHeading.FindAllStringSubmatchIndex(markdown, -1)
	for i, loc := range locs {
		title := strings.TrimSpace(markdown[loc[2]:loc[3]])
		bodyStart := loc[1]
		bodyEnd := len(markdown)
		if i+1 < len(locs) {
			bodyEnd = locs[i+1][0]
		}
		body := strings.TrimSpace(markdown[bodyStart:bodyEnd])
		if title == "" || body == "" {
			continue
		}
		sec := ProductSection{Title: title, Body: body, Keywords: productKeywords(title, body)}
		lt := strings.ToLower(title)
		for kw, route := range productRoutes {
			if strings.Contains(lt, kw) {
				sec.Route = route
				break
			}
		}
		k.sections = append(k.sections, sec)
	}
}

// All returns every parsed section (for tests / a "what can you tell me" listing).
func (k *ProductKB) All() []ProductSection { return k.sections }

// ProductHit is a scored retrieval result.
type ProductHit struct {
	Section ProductSection
	Score   int
}

// Search scores sections against the question and returns the top matches. Title
// terms weigh more than body terms; a min-score floor keeps an off-topic question
// from surfacing a weak section.
func (k *ProductKB) Search(query string, limit int) []ProductHit {
	terms := tokenize(query)
	if len(terms) == 0 {
		return nil
	}
	hits := make([]ProductHit, 0, len(k.sections))
	for _, s := range k.sections {
		title := strings.ToLower(s.Title)
		kw := strings.ToLower(strings.Join(s.Keywords, " "))
		body := strings.ToLower(s.Body)
		score := 0
		for _, t := range terms {
			if strings.Contains(title, t) {
				score += 4
			}
			if strings.Contains(kw, t) {
				score += 2
			}
			if strings.Contains(body, t) {
				score++
			}
		}
		if score >= 3 {
			hits = append(hits, ProductHit{Section: s, Score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		// Tie → prefer the more FOCUSED section (shorter title), then alphabetical,
		// so "What is Correlix" beats "What Iris AI can do" for "what is correlix".
		if len(hits[i].Section.Title) != len(hits[j].Section.Title) {
			return len(hits[i].Section.Title) < len(hits[j].Section.Title)
		}
		return hits[i].Section.Title < hits[j].Section.Title
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

// productKeywords derives salient terms from a section's title + body: the title
// words plus notable product nouns found in the body, minus stopwords.
func productKeywords(title, body string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		for _, t := range tokenize(s) {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	add(title)
	// Pull a handful of distinctive product terms from the body so a section is
	// findable by concept, not just its heading.
	for _, term := range productTerms {
		if strings.Contains(strings.ToLower(body), term) {
			if !seen[term] {
				seen[term] = true
				out = append(out, term)
			}
		}
	}
	return out
}

// productTerms are Correlix concept words worth indexing wherever they appear.
var productTerms = []string{
	"correlix", "platform", "observability", "dashboard",
	"correlation", "rca", "root cause", "seam", "verdict", "confirmed", "suspected",
	"undetermined", "evidence", "tenant", "org", "snmp", "gnmi", "netconf", "syslog",
	"flow", "netflow", "sflow", "ipfix", "telemetry", "topology", "incident", "alert",
	"report", "servicenow", "jira", "slack", "pagerduty", "sso", "oidc", "ldap",
	"tacacs", "mfa", "discovery", "device", "interface", "wan", "circuit", "stamp",
	"probe", "vulnerability", "compliance", "netbox", "provenance", "signature",
}
