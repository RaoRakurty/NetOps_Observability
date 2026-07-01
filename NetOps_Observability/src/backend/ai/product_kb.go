package ai

import (
	"regexp"
	"sort"
	"strings"
)

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
var productRoutes = map[string]string{
	"discovery":       "#/infrastructure/devices",
	"authentication":  "#/admin/security",
	"configuration":   "#/admin",
	"ui sections":     "#/dashboards/home",
	"setup runbooks":  "#/admin",
	"troubleshooting": "#/monitoring/correlations",
	"architecture":    "#/infrastructure/topology-canvas",
}

// LoadProductKB parses a markdown doc into retrievable `##` sections. Robust to an
// empty doc (returns an empty KB). Keywords are derived from the title + body.
func LoadProductKB(markdown string) *ProductKB {
	kb := &ProductKB{}
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
		for k, route := range productRoutes {
			if strings.Contains(lt, k) {
				sec.Route = route
				break
			}
		}
		kb.sections = append(kb.sections, sec)
	}
	return kb
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
