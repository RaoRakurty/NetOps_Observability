package ai

import (
	"embed"
	"sort"
	"strings"
)

// kb.go — the Network Expert Knowledge Base (HLD §8). A curated, vendor-neutral
// set of CCIE-grade troubleshooting playbooks, embedded into the binary so the
// copilot can reason like a senior NOC engineer WITHOUT shipping copyrighted
// material or making a network call. Retrieval is keyword/fault-domain scored and
// bounded — the model receives a few relevant snippets as SUPPORTING context, not
// the whole library, and never as system truth: live Correlix evidence always
// wins over a generic playbook. This is the "Network Expert Knowledge Retriever"
// box in the architecture, kept deterministic and offline.

//go:embed network_expert/*.md
var networkExpertFS embed.FS

// Playbook is one parsed troubleshooting guide.
type Playbook struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Owner        string   `json:"owner"`
	FaultDomains []string `json:"fault_domains"`
	Signals      []string `json:"signals"`
	Keywords     []string `json:"keywords"`
	NextActions  []string `json:"next_actions"`
	body         string   // full markdown body (after frontmatter)
}

// Snippet returns a bounded excerpt for prompting: the Symptoms + Recommended
// owner + Next actions sections, so the model gets actionable guidance without
// the whole file flooding the context window.
func (p Playbook) Snippet() string {
	var b strings.Builder
	b.WriteString(p.Title)
	if p.Owner != "" {
		b.WriteString(" (owner: " + p.Owner + ")")
	}
	b.WriteString("\n")
	if s := sectionOf(p.body, "Symptoms"); s != "" {
		b.WriteString("Symptoms: " + oneLine(s) + "\n")
	}
	if len(p.NextActions) > 0 {
		b.WriteString("Next actions: " + strings.Join(p.NextActions, " ") + "\n")
	}
	return strings.TrimSpace(b.String())
}

// KBHit is a scored retrieval result.
type KBHit struct {
	Playbook Playbook `json:"playbook"`
	Score    int      `json:"score"`
}

// KB is the loaded, indexed playbook set.
type KB struct {
	playbooks []Playbook
}

// LoadKB parses the embedded playbooks once. Safe to call at startup; never
// fails the server — a malformed/empty KB simply yields no supporting knowledge.
func LoadKB() *KB {
	kb := &KB{}
	entries, err := networkExpertFS.ReadDir("network_expert")
	if err != nil {
		return kb
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		raw, err := networkExpertFS.ReadFile("network_expert/" + e.Name())
		if err != nil {
			continue
		}
		if pb, ok := parsePlaybook(string(raw)); ok {
			kb.playbooks = append(kb.playbooks, pb)
		}
	}
	sort.Slice(kb.playbooks, func(i, j int) bool { return kb.playbooks[i].ID < kb.playbooks[j].ID })
	return kb
}

// All returns every loaded playbook (for the KB tool's "list" path + tests).
func (k *KB) All() []Playbook { return k.playbooks }

// Get returns a playbook by id.
func (k *KB) Get(id string) (Playbook, bool) {
	for _, p := range k.playbooks {
		if p.ID == id {
			return p, true
		}
	}
	return Playbook{}, false
}

// KBHints lets the caller bias retrieval toward a known fault domain / signal set
// (e.g. from the RCA object's owner_domain + missing-evidence) on top of the
// free-text query. All optional.
type KBHints struct {
	FaultDomains []string
	Signals      []string
}

// Search scores playbooks against the query + hints and returns the top matches.
// Scoring weights: keyword/term match in keywords (3), fault domain (2), signal
// (2), title (2), body (1); hint overlaps add (2) each. Zero-score items are
// dropped so an off-topic question gets NO playbook rather than a bad one.
func (k *KB) Search(query string, hints KBHints, limit int) []KBHit {
	terms := tokenize(query)
	hits := make([]KBHit, 0, len(k.playbooks))
	for _, p := range k.playbooks {
		score := 0
		kw := strings.ToLower(strings.Join(p.Keywords, " "))
		fd := strings.ToLower(strings.Join(p.FaultDomains, " "))
		sg := strings.ToLower(strings.Join(p.Signals, " "))
		title := strings.ToLower(p.Title)
		body := strings.ToLower(p.body)
		for _, t := range terms {
			if t == "" {
				continue
			}
			if strings.Contains(kw, t) {
				score += 3
			}
			if strings.Contains(fd, t) {
				score += 2
			}
			if strings.Contains(sg, t) {
				score += 2
			}
			if strings.Contains(title, t) {
				score += 2
			}
			if strings.Contains(body, t) {
				score++
			}
		}
		for _, h := range hints.FaultDomains {
			if h != "" && strings.Contains(fd, strings.ToLower(h)) {
				score += 2
			}
		}
		for _, h := range hints.Signals {
			if h != "" && strings.Contains(sg, strings.ToLower(h)) {
				score += 2
			}
		}
		// Floor of 3 = at least one keyword hit (or two domain/signal/title hits).
		// A lone body-word match (score 1) is too weak to surface a playbook, so an
		// off-topic question gets NO guidance rather than a spurious one.
		if score >= 3 {
			hits = append(hits, KBHit{Playbook: p, Score: score})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Playbook.ID < hits[j].Playbook.ID
	})
	if limit > 0 && len(hits) > limit {
		hits = hits[:limit]
	}
	return hits
}

// ---- parsing (stdlib only — minimal frontmatter, no YAML dependency) ----

// parsePlaybook splits "---\n<frontmatter>\n---\n<body>" and extracts the typed
// fields. A file without frontmatter is skipped (ok=false).
func parsePlaybook(raw string) (Playbook, bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if !strings.HasPrefix(raw, "---\n") {
		return Playbook{}, false
	}
	rest := raw[len("---\n"):]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return Playbook{}, false
	}
	front := rest[:end]
	body := strings.TrimLeft(rest[end+len("\n---"):], "\n")
	pb := Playbook{body: body}
	for _, line := range strings.Split(front, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.ToLower(k))
		v = strings.TrimSpace(v)
		switch k {
		case "id":
			pb.ID = v
		case "title":
			pb.Title = v
		case "owner":
			pb.Owner = v
		case "fault_domains":
			pb.FaultDomains = splitList(v)
		case "signals":
			pb.Signals = splitList(v)
		case "keywords":
			pb.Keywords = splitList(v)
		}
	}
	if pb.ID == "" || pb.Title == "" {
		return Playbook{}, false
	}
	pb.NextActions = numberedItems(sectionOf(body, "Next actions"))
	return pb, true
}

// splitList parses "a, b, c" into ["a","b","c"].
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sectionOf returns the text under a "## <name>" heading up to the next "## ".
func sectionOf(body, name string) string {
	marker := "## " + name
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// numberedItems pulls "1. foo" lines from a section into a clean slice.
func numberedItems(section string) []string {
	var out []string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		// strip a leading "N." enumerator
		if i := strings.IndexByte(line, '.'); i > 0 && i <= 3 && isAllDigits(line[:i]) {
			item := strings.TrimSpace(line[i+1:])
			if item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// oneLine collapses a multi-line section into a single bounded line.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "- ", "")
	fields := strings.Fields(s)
	out := strings.Join(fields, " ")
	if len(out) > 280 {
		out = out[:280] + "…"
	}
	return out
}

// kbStopwords are common English/question words filtered from queries so they
// don't match playbook BODY prose ("what", "today", …) and surface noise.
var kbStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "what": true, "why": true,
	"how": true, "when": true, "where": true, "who": true, "this": true, "that": true,
	"these": true, "those": true, "your": true, "you": true, "are": true, "was": true,
	"has": true, "have": true, "can": true, "does": true, "did": true, "will": true,
	"should": true, "would": true, "could": true, "there": true, "here": true, "about": true,
	"into": true, "over": true, "from": true, "then": true, "than": true, "them": true,
	"they": true, "today": true, "now": true, "any": true, "all": true, "get": true,
	"got": true, "see": true, "out": true, "off": true, "but": true, "not": true,
	"its": true, "our": true, "their": true, "some": true, "more": true, "much": true,
	"need": true, "want": true, "show": true, "tell": true, "give": true, "please": true,
}

// tokenize lowercases and splits a query into dedup'd word tokens (len ≥ 3, no
// stopwords) so retrieval keys on the meaningful terms only.
func tokenize(q string) []string {
	q = strings.ToLower(q)
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(q, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(f) >= 3 && !seen[f] && !kbStopwords[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}
