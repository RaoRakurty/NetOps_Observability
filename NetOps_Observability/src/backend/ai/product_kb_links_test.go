package ai

// product_kb_links_test.go — every UI deep link the assistant can hand out must
// resolve to a page that exists.
//
// WHY THIS TEST EXISTS. A wrong deep link is worse than no deep link. The SPA
// router never reports "not found": an unknown section falls back to the first
// section and an unknown leaf to that section's first page, so a stale link
// silently lands the reader on Home — or, worse, on a plausible-looking wrong
// page — while the answer above it says "open X". Two of the routes in
// product_kb.go had rotted exactly that way by 2026-09-05: "#/admin/security"
// was never a route in any IA, and "#/monitoring/reports" quietly resolved to
// the Operations section's first page.
//
// HOW IT WORKS. The nav tree is the frontend's, so this test READS it —
// src/frontend/src/nav.tsx — rather than restating it. A small stdlib extractor
// walks the NAV literal for section ids, leaf ids and sub-item ids, and lifts
// the two legacy alias tables; resolveNavHash then applies the SAME rules
// aliasSegs/resolveRoute apply in the browser (three-segment alias first, then
// the two-segment key, then the section rename, then the bare key). A link is
// good when it lands on a real section, and on a real leaf of it when it names
// one. A legacy hash that an alias table still rewrites is accepted — those
// work for a reader — but the KB is expected to carry the canonical address.
//
// Nothing here imports the frontend or runs node: it is stdlib text handling,
// and if the extractor ever stops finding the tree the sanity test fails loudly
// rather than passing vacuously.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// The nav index, extracted from src/frontend/src/nav.tsx
// ─────────────────────────────────────────────────────────────────────────────

type navIndex struct {
	sections     map[string]bool
	leaves       map[string]map[string]bool // section id → leaf ids
	subs         map[string]map[string]bool // "section/leaf" → sub-item ids
	routeAlias   map[string]string
	sectionAlias map[string]string
}

const navSourcePath = "../../frontend/src/nav.tsx"
const productKBSourcePath = "product_kb.go"
const copilotKnowledgePath = "../copilot_knowledge.md"

// stripTSComments blanks // and /* */ comments without touching string or
// template literals, so a bracket or an "id:" inside prose cannot be read as
// structure. Characters are replaced by spaces rather than deleted, which keeps
// every offset (and therefore every error message) honest.
func stripTSComments(src string) string {
	out := []byte(src)
	inStr := byte(0)
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inStr != 0 {
			switch c {
			case '\\':
				i++ // skip the escaped character
			case inStr:
				inStr = 0
			}
			continue
		}
		switch {
		case c == '"' || c == '\'' || c == '`':
			inStr = c
		case c == '/' && i+1 < len(out) && out[i+1] == '/':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			for i < len(out) && !(out[i] == '*' && i+1 < len(out) && out[i+1] == '/') {
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
			if i+1 < len(out) {
				out[i], out[i+1] = ' ', ' '
				i++
			}
		}
	}
	return string(out)
}

// Keys in these tables are quoted when they carry a "/" and bare identifiers
// when they do not (`"admin/auth": "platform/auth"` vs `explain: "admin"`), so
// both spellings are lifted.
var reAliasPair = regexp.MustCompile(`(?:"([^"]+)"|([A-Za-z_$][\w$]*))\s*:\s*"([^"]+)"`)

// aliasTable lifts one `const <name> ... = { "k": "v", … };` map.
func aliasTable(src, name string) map[string]string {
	out := map[string]string{}
	start := strings.Index(src, "const "+name)
	if start < 0 {
		return out
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		return out
	}
	body := src[start+open:]
	depth := 0
	end := len(body)
	for i, c := range body {
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	for _, m := range reAliasPair.FindAllStringSubmatch(body[:end], -1) {
		key := m[1]
		if key == "" {
			key = m[2]
		}
		out[key] = m[3]
	}
	return out
}

// parseNav walks the NAV literal and records the id at each nesting level. The
// enclosing ARRAY decides what an id means: the NAV array itself holds sections,
// a `children:` array holds leaves, a `subItems:` array holds sub-items.
func parseNav(t *testing.T, src string) *navIndex {
	t.Helper()
	idx := &navIndex{
		sections: map[string]bool{},
		leaves:   map[string]map[string]bool{},
		subs:     map[string]map[string]bool{},
	}
	anchor := strings.Index(src, "export const NAV")
	if anchor < 0 {
		t.Fatalf("%s: no `export const NAV` — the extractor is aimed at the wrong file", navSourcePath)
	}
	open := strings.Index(src[anchor:], "= [")
	if open < 0 {
		t.Fatalf("%s: `export const NAV` is not followed by an array literal", navSourcePath)
	}
	body := src[anchor+open+2:]

	var stack []string // enclosing array kinds, innermost last
	lastKey := ""
	curSection, curLeaf := "", ""

	readString := func(i int) (string, int) {
		quote := body[i]
		var sb strings.Builder
		for j := i + 1; j < len(body); j++ {
			switch body[j] {
			case '\\':
				j++
				if j < len(body) {
					sb.WriteByte(body[j])
				}
			case quote:
				return sb.String(), j
			default:
				sb.WriteByte(body[j])
			}
		}
		return sb.String(), len(body) - 1
	}

	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '"' || c == '\'' || c == '`':
			val, next := readString(i)
			i = next
			if lastKey == "id" {
				switch top(stack) {
				case "nav":
					curSection, curLeaf = val, ""
					idx.sections[val] = true
				case "children":
					curLeaf = val
					if curSection != "" {
						if idx.leaves[curSection] == nil {
							idx.leaves[curSection] = map[string]bool{}
						}
						idx.leaves[curSection][val] = true
					}
				case "subItems":
					if curSection != "" && curLeaf != "" {
						key := curSection + "/" + curLeaf
						if idx.subs[key] == nil {
							idx.subs[key] = map[string]bool{}
						}
						idx.subs[key][val] = true
					}
				}
			}
			lastKey = ""
		case c == '[':
			kind := lastKey
			if len(stack) == 0 {
				kind = "nav"
			}
			stack = append(stack, kind)
			lastKey = ""
		case c == ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if len(stack) == 0 {
				// The NAV literal is closed; everything after it is other code.
				return idx
			}
			lastKey = ""
		case isIdentByte(c):
			j := i
			for j < len(body) && isIdentByte(body[j]) {
				j++
			}
			word := body[i:j]
			k := j
			for k < len(body) && (body[k] == ' ' || body[k] == '\n' || body[k] == '\t') {
				k++
			}
			if k < len(body) && body[k] == ':' {
				lastKey = word
			}
			i = j - 1
		}
	}
	return idx
}

func top(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func loadNavIndex(t *testing.T) *navIndex {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(navSourcePath))
	if err != nil {
		t.Fatalf("read %s: %v", navSourcePath, err)
	}
	src := stripTSComments(string(raw))
	idx := parseNav(t, src)
	idx.routeAlias = aliasTable(src, "LEGACY_ROUTE_ALIAS")
	idx.sectionAlias = aliasTable(src, "LEGACY_SECTION_ALIAS")
	return idx
}

// aliasSegs mirrors nav.tsx aliasSegs exactly, including the order the three
// tables are consulted in. Order is the behaviour: a three-segment key wins
// over a two-segment one, and a section rename only applies when no exact
// route alias matched.
func (n *navIndex) aliasSegs(segs []string) []string {
	if len(segs) >= 3 {
		if v, ok := n.routeAlias[segs[0]+"/"+segs[1]+"/"+segs[2]]; ok {
			return append(strings.Split(v, "/"), segs[3:]...)
		}
	}
	key := segs[0]
	if len(segs) >= 2 {
		key = segs[0] + "/" + segs[1]
	}
	if v, ok := n.routeAlias[key]; ok {
		return append(strings.Split(v, "/"), segs[2:]...)
	}
	if v, ok := n.sectionAlias[segs[0]]; ok {
		return append([]string{v}, segs[1:]...)
	}
	if v, ok := n.routeAlias[segs[0]]; ok {
		return append(strings.Split(v, "/"), segs[1:]...)
	}
	return nil
}

// resolveNavHash reports why a hash does not resolve, "" when it does, and
// whether it needed an alias to get there.
func (n *navIndex) resolveNavHash(hash string) (problem string, aliased bool) {
	path := strings.TrimPrefix(hash, "#")
	path = strings.TrimPrefix(path, "/")
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return "empty route", false
	}
	segs := strings.Split(path, "/")
	if next := n.aliasSegs(segs); next != nil {
		segs, aliased = next, true
	}
	if !n.sections[segs[0]] {
		return "no section " + segs[0] + " in the nav tree (and no alias rewrites it)", aliased
	}
	if len(segs) == 1 {
		return "", aliased
	}
	if !n.leaves[segs[0]][segs[1]] {
		return "section " + segs[0] + " has no leaf " + segs[1] +
			" — the reader would land on that section's FIRST page instead", aliased
	}
	if len(segs) >= 3 {
		// A third segment is a sub-item only where the leaf declares them; other
		// pages read their own tab from it, so an undeclared one is not a fault.
		if subs, declared := n.subs[segs[0]+"/"+segs[1]]; declared && !subs[segs[2]] {
			return "leaf " + segs[0] + "/" + segs[1] + " declares sub-items but not " + segs[2], aliased
		}
	}
	return "", aliased
}

// ─────────────────────────────────────────────────────────────────────────────
// The links themselves
// ─────────────────────────────────────────────────────────────────────────────

// reDeepLink finds "#/..." anywhere in a source or a markdown doc. It stops at
// whatever ends a route in either: a quote, whitespace, a closing bracket, or
// markdown punctuation.
var reDeepLink = regexp.MustCompile(`#/[A-Za-z0-9_\-/]*[A-Za-z0-9_\-]`)

// deepLinksIn returns the distinct "#/…" routes a reader could actually be
// handed from path. For a Go source the comments are blanked first: a comment
// that NAMES a broken route (this file's own history does) is documentation,
// not something the assistant emits, and a guard that cannot tell the two apart
// would forbid writing the history down.
func deepLinksIn(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(raw)
	if strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".tsx") || strings.HasSuffix(path, ".ts") {
		text = stripTSComments(text)
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range reDeepLink.FindAllString(text, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// TestNavIndexExtractorSanity keeps this file from passing vacuously. An
// extractor that silently found nothing would make every link "valid".
func TestNavIndexExtractorSanity(t *testing.T) {
	idx := loadNavIndex(t)
	if len(idx.sections) < 8 {
		t.Fatalf("parsed only %d nav sections (%v) — the extractor is not reading the tree", len(idx.sections), keysOf(idx.sections))
	}
	// Anchors from docs/design/ADMIN_IA_2026-09-05.md: the two governance
	// sections and one leaf of each, plus a leaf that MOVED in that change.
	for _, want := range [][2]string{
		{"admin", "identity"}, {"admin", "snmp"}, {"platform", "licence"}, {"platform", "auth"},
		{"investigate", "rca"}, {"analytics", "reports"}, {"overview", "home"},
	} {
		if !idx.leaves[want[0]][want[1]] {
			t.Errorf("nav leaf %s/%s not found by the extractor", want[0], want[1])
		}
	}
	if len(idx.routeAlias) < 20 || len(idx.sectionAlias) < 5 {
		t.Fatalf("alias tables look unparsed: %d route aliases, %d section aliases",
			len(idx.routeAlias), len(idx.sectionAlias))
	}
	// The alias tables must agree with the tree they point INTO — a rewrite to a
	// page that no longer exists is the same silent fallback this file guards.
	for from, to := range idx.routeAlias {
		if problem, _ := idx.resolveNavHash("#/" + to); problem != "" {
			t.Errorf("LEGACY_ROUTE_ALIAS %q → %q does not resolve: %s", from, to, problem)
		}
	}
}

// TestProductKBDeepLinksResolve — every route the Product Knowledge Retriever
// can offer must be a real page, and (since these are ours to keep current) the
// CANONICAL address rather than one that survives only through an alias.
func TestProductKBDeepLinksResolve(t *testing.T) {
	idx := loadNavIndex(t)
	links := deepLinksIn(t, productKBSourcePath)
	if len(links) == 0 {
		t.Fatal("no deep links found in product_kb.go — the extractor or the file moved")
	}
	for _, link := range links {
		problem, aliased := idx.resolveNavHash(link)
		if problem != "" {
			t.Errorf("%s: %s — fix it against src/frontend/src/nav.tsx (the router never says \"not found\"; the reader would land somewhere else believing it was the page)", link, problem)
			continue
		}
		if aliased {
			t.Errorf("%s resolves only through a legacy alias — use the canonical #/<section>/<leaf> from nav.tsx so the assistant hands out the address the page actually has", link)
		}
	}
	// The two that were wrong, named so a revert is caught by name.
	for _, gone := range []string{"#/admin/security", "#/monitoring/reports"} {
		for _, link := range links {
			if link == gone {
				t.Errorf("%s is back: it was never a route (admin/security) or resolves to the wrong page (monitoring/reports)", gone)
			}
		}
	}
}

// TestCopilotKnowledgeDeepLinksResolve — the same rule for the curated product
// knowledge the assistant is grounded in. It carries UI paths as prose today
// and may carry hashes tomorrow; either way a link in it is an instruction to a
// reader and must land where it says.
func TestCopilotKnowledgeDeepLinksResolve(t *testing.T) {
	idx := loadNavIndex(t)
	for _, link := range deepLinksIn(t, copilotKnowledgePath) {
		if problem, _ := idx.resolveNavHash(link); problem != "" {
			t.Errorf("copilot_knowledge.md: %s: %s", link, problem)
		}
	}
}

// TestCopilotKnowledgeSectionNames — the doc's UI paths are PROSE, so no hash
// test can check them. What can be checked is that it never names a section the
// product no longer has: the 2026-08 redesign and the 2026-09-05 governance
// split renamed or dissolved five of them, and an answer that says
// "Automation → Source of Truth" sends a reader to a rail entry that is not
// there.
func TestCopilotKnowledgeSectionNames(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(copilotKnowledgePath))
	if err != nil {
		t.Fatalf("read %s: %v", copilotKnowledgePath, err)
	}
	doc := string(raw)
	for _, bad := range []struct{ path, instead string }{
		{"Automation → Source of Truth", "Infrastructure → Source of Truth"},
		{"Administration → Authentication", "Platform → Security → Authentication (it is provider-only since the 2026-09-05 IA)"},
		{"Alerts → Rules", "Operations → Monitor Rules"},
		{"Alerts → Active", "Operations → Active Alerts"},
		{"Infrastructure → SNMP Profiles", "Administration → Data sources → SNMP Profiles"},
		{"Administration → Platform Security", "Platform → Security"},
	} {
		if strings.Contains(doc, bad.path) {
			t.Errorf("copilot_knowledge.md still says %q — the rail has no such path; use %q (docs/design/ADMIN_IA_2026-09-05.md)", bad.path, bad.instead)
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
