// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// forbidden.go — the OUTPUT-ONLY COMMAND POLICY, loaded from data.
//
// Owner decision, 2026-09-05: a command that changes configuration, that
// restarts or reboots, or that touches a daemon must not merely be refused — it
// must not be KNOWN to Correlix at all. ai/tac/forbidden.yaml is that
// vocabulary written down; this file reads it and answers one question:
//
//	Match(dialect, command) → which family does this command belong to, if any?
//
// It is used at three moments, and none of the three is redundant:
//
//	1. INGESTION (scripts/tac-merge-research.py, through the sibling Python
//	   matcher): a forbidden record is refused at the door and never written
//	   anywhere. Only the count survives.
//	2. LOAD (loadPlan, below in load.go): a plan file that carries a forbidden
//	   command fails the load — the api does not boot with one.
//	3. GATE (gate.go): the policy is re-applied to the rendered string at the
//	   moment it would go on a wire, so a TAMPERED plan file still cannot reach
//	   a device. That is the layer that makes this structural rather than
//	   procedural.
//
// Matching is on TOKENS, never on substrings: a rule's tokens must be the
// command's LEADING tokens. `reload` therefore refuses `reload in 5` and leaves
// `show reload cause` alone, which is the distinction the whole policy rests on.

import (
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// Forbidden families. The owner named three; there is no fourth, and adding one
// is an owner decision, not a data change.
const (
	FamilyConfig  = "config"
	FamilyRestart = "restart"
	FamilyDaemon  = "daemon"
)

// forbiddenFamilies is the closed family set, in report order.
var forbiddenFamilies = []string{FamilyConfig, FamilyRestart, FamilyDaemon}

// PolicyFamily is one family's description, carried so the UI and the docs can
// state the rule in the policy's own words rather than re-typing it.
type PolicyFamily struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Rule  string `json:"rule"`
}

// ForbiddenRule is one entry of the vocabulary Correlix refuses to learn.
type ForbiddenRule struct {
	// Family is one of the three constants above.
	Family string `json:"family"`
	// Dialect is the dialect this rule is scoped to, or "" for a common rule.
	Dialect string `json:"dialect,omitempty"`
	// Tokens is the leading token sequence that triggers the rule.
	Tokens []string `json:"tokens"`
	// Why is the one-line reason, shown wherever the refusal is reported.
	Why string `json:"why"`
	// Except are token prefixes exempt from THIS rule — the documented
	// output-only leaves of an otherwise action-shaped branch.
	Except [][]string `json:"except,omitempty"`
}

// String renders the rule's tokens, for an error message.
func (r ForbiddenRule) String() string { return strings.Join(r.Tokens, " ") }

// SessionScope is a setter that narrows what a READ prints and dies with the
// CLI session. It changes no configuration and clears nothing, so the owner's
// rule does not bite — on the condition the loader enforces: the binding carries
// the matching teardown, and the collector runs it right after the read.
type SessionScope struct {
	Dialect  string   `json:"dialect"`
	Tokens   []string `json:"tokens"`
	Teardown string   `json:"teardown"`
	Why      string   `json:"why"`
	Sources  []Source `json:"sources,omitempty"`
}

// Census is what the policy excluded from the corpus, BY COUNT ONLY. The count
// is known; the command is not. scripts/tac-purge-forbidden.py regenerates it.
type Census struct {
	Generated string           `json:"generated"`
	Total     int              `json:"total"`
	ByFamily  map[string]int   `json:"by_family"`
	ByDialect []DialectExclude `json:"by_dialect"`
}

// DialectExclude is one dialect's exclusion counts.
type DialectExclude struct {
	Dialect string `json:"dialect"`
	Config  int    `json:"config"`
	Restart int    `json:"restart"`
	Daemon  int    `json:"daemon"`
	Total   int    `json:"total"`
}

// Policy is the compiled forbidden vocabulary. It is built once at load and
// never mutated, so it is safe to share across goroutines.
type Policy struct {
	Version  string
	Families []PolicyFamily
	Census   Census

	common    []ForbiddenRule
	byDialect map[string][]ForbiddenRule
	scopes    map[string][]SessionScope
}

// LoadPolicy reads and validates ai/tac/forbidden.yaml from fsys.
func LoadPolicy(fsys fs.FS) (*Policy, error) {
	raw, err := fs.ReadFile(fsys, "forbidden.yaml")
	if err != nil {
		return nil, fmt.Errorf("tac: forbidden.yaml: %w", err)
	}
	p, err := loadPolicy(string(raw))
	if err != nil {
		return nil, fmt.Errorf("tac: forbidden.yaml: %w", err)
	}
	return p, nil
}

func loadPolicy(src string) (*Policy, error) {
	doc, err := parseYAML(src)
	if err != nil {
		return nil, err
	}
	if !doc.isMap() {
		return nil, fmt.Errorf("document must be a mapping")
	}
	if err := yonly(doc, "the command policy", "schema_version", "version",
		"families", "sources", "common", "dialects", "session_scoped", "census"); err != nil {
		return nil, err
	}
	if err := requireSchemaVersion(doc); err != nil {
		return nil, err
	}
	version, err := ystr(doc, "version")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("`version` is required")
	}
	p := &Policy{
		Version:   version,
		byDialect: map[string][]ForbiddenRule{},
		scopes:    map[string][]SessionScope{},
	}

	fams, err := ylist(doc, "families")
	if err != nil {
		return nil, err
	}
	declared := map[string]bool{}
	for _, fn := range fams {
		if err := yonly(fn, "a family", "id", "title", "rule"); err != nil {
			return nil, err
		}
		f := PolicyFamily{}
		if f.ID, err = ystr(fn, "id"); err != nil {
			return nil, err
		}
		if f.Title, err = ystr(fn, "title"); err != nil {
			return nil, err
		}
		if f.Rule, err = ystr(fn, "rule"); err != nil {
			return nil, err
		}
		if !isForbiddenFamily(f.ID) {
			return nil, fmt.Errorf("family %q is outside the closed set (%s)",
				f.ID, strings.Join(forbiddenFamilies, ", "))
		}
		if declared[f.ID] {
			return nil, fmt.Errorf("family %q is declared twice", f.ID)
		}
		declared[f.ID] = true
		p.Families = append(p.Families, f)
	}
	for _, want := range forbiddenFamilies {
		if !declared[want] {
			return nil, fmt.Errorf("family %q is not declared — the three families are the owner's rule and all three must be stated", want)
		}
	}

	if p.common, err = loadForbiddenRules(doc, "common", ""); err != nil {
		return nil, err
	}
	if len(p.common) == 0 {
		return nil, fmt.Errorf("`common` is required — a policy with no cross-vendor rules is not a policy")
	}

	dialects, err := ylist(doc, "dialects")
	if err != nil {
		return nil, err
	}
	for _, dn := range dialects {
		if err := yonly(dn, "a dialect policy", "dialect", "sources", "rules"); err != nil {
			return nil, err
		}
		slug, serr := ystr(dn, "dialect")
		if serr != nil {
			return nil, serr
		}
		if !slugRE.MatchString(slug) {
			return nil, fmt.Errorf("dialect %q is not a slug", slug)
		}
		if _, dup := p.byDialect[slug]; dup {
			return nil, fmt.Errorf("dialect %q appears twice", slug)
		}
		rules, rerr := loadForbiddenRules(dn, "rules", slug)
		if rerr != nil {
			return nil, rerr
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("dialect %q carries no rules — omit the block instead of shipping an empty one", slug)
		}
		// A per-dialect rule set must cite the vendor reference it came from:
		// the policy is reviewed data, exactly like a plan.
		srcs, cerr := loadSources(dn)
		if cerr != nil {
			return nil, cerr
		}
		if len(srcs) == 0 {
			return nil, fmt.Errorf("dialect %q names no `sources` — a per-vendor rule must cite the vendor's own reference", slug)
		}
		p.byDialect[slug] = rules
	}

	scopes, err := ylist(doc, "session_scoped")
	if err != nil {
		return nil, err
	}
	for _, sn := range scopes {
		if err := yonly(sn, "a session-scoped setter", "dialect", "tokens", "teardown", "why", "sources"); err != nil {
			return nil, err
		}
		s := SessionScope{}
		if s.Dialect, err = ystr(sn, "dialect"); err != nil {
			return nil, err
		}
		toks, terr := ystr(sn, "tokens")
		if terr != nil {
			return nil, terr
		}
		s.Tokens = strings.Fields(strings.ToLower(toks))
		if len(s.Tokens) == 0 {
			return nil, fmt.Errorf("a session-scoped setter on %q names no tokens", s.Dialect)
		}
		if s.Teardown, err = ystr(sn, "teardown"); err != nil {
			return nil, err
		}
		s.Teardown = strings.Join(strings.Fields(s.Teardown), " ")
		if s.Teardown == "" {
			return nil, fmt.Errorf("session-scoped setter %q carries no teardown — the whole reason it is allowed is that Correlix undoes it", strings.Join(s.Tokens, " "))
		}
		// The teardown must be the setter's own branch plus a terminating verb:
		// it undoes THIS setter and cannot be some other command smuggled in.
		td := strings.Fields(strings.ToLower(s.Teardown))
		if len(td) != len(s.Tokens)+1 || !hasPrefixTokens(td, s.Tokens) {
			return nil, fmt.Errorf("teardown %q is not %q plus one terminating verb", s.Teardown, strings.Join(s.Tokens, " "))
		}
		switch td[len(td)-1] {
		case "clear", "reset", "flush", "none":
		default:
			return nil, fmt.Errorf("teardown %q must end in clear/reset/flush/none", s.Teardown)
		}
		if s.Why, err = ystr(sn, "why"); err != nil {
			return nil, err
		}
		if strings.TrimSpace(s.Why) == "" {
			return nil, fmt.Errorf("session-scoped setter %q says nothing about why it is exempt", strings.Join(s.Tokens, " "))
		}
		if s.Sources, err = loadSources(sn); err != nil {
			return nil, err
		}
		if len(s.Sources) == 0 {
			return nil, fmt.Errorf("session-scoped setter %q carries no `sources` — an exemption from the owner's rule must cite the page that establishes it", strings.Join(s.Tokens, " "))
		}
		p.scopes[s.Dialect] = append(p.scopes[s.Dialect], s)
	}

	if p.Census, err = loadCensus(doc); err != nil {
		return nil, err
	}
	return p, nil
}

// loadForbiddenRules reads one `common:` / `rules:` block.
func loadForbiddenRules(n *ynode, key, dialect string) ([]ForbiddenRule, error) {
	list, err := ylist(n, key)
	if err != nil {
		return nil, err
	}
	out := make([]ForbiddenRule, 0, len(list))
	seen := map[string]bool{}
	for _, rn := range list {
		if err := yonly(rn, "a policy rule", "family", "tokens", "why", "except"); err != nil {
			return nil, err
		}
		r := ForbiddenRule{Dialect: dialect}
		if r.Family, err = ystr(rn, "family"); err != nil {
			return nil, err
		}
		if !isForbiddenFamily(r.Family) {
			return nil, fmt.Errorf("rule family %q is outside the closed set (%s)",
				r.Family, strings.Join(forbiddenFamilies, ", "))
		}
		toks, terr := ystr(rn, "tokens")
		if terr != nil {
			return nil, terr
		}
		r.Tokens = strings.Fields(strings.ToLower(toks))
		if len(r.Tokens) == 0 {
			return nil, fmt.Errorf("a %s rule names no tokens", key)
		}
		// A rule that begins with a read verb would refuse reads, which is the
		// one thing this policy must never do.
		if isReadLead(r.Tokens[0]) {
			return nil, fmt.Errorf("rule %q begins with a read verb; the policy may never refuse an output command", r)
		}
		if r.Why, err = ystr(rn, "why"); err != nil {
			return nil, err
		}
		if strings.TrimSpace(r.Why) == "" {
			return nil, fmt.Errorf("rule %q says nothing about why", r)
		}
		exc, eerr := ystrs(rn, "except")
		if eerr != nil {
			return nil, eerr
		}
		for _, e := range exc {
			et := strings.Fields(strings.ToLower(e))
			if len(et) <= len(r.Tokens) || !hasPrefixTokens(et, r.Tokens) {
				return nil, fmt.Errorf("rule %q lists exception %q, which is not a longer form of the rule itself", r, e)
			}
			r.Except = append(r.Except, et)
		}
		key := r.Family + "\x00" + strings.Join(r.Tokens, " ")
		if seen[key] {
			return nil, fmt.Errorf("rule %q is declared twice", r)
		}
		seen[key] = true
		out = append(out, r)
	}
	return out, nil
}

func loadCensus(doc *ynode) (Census, error) {
	c := Census{ByFamily: map[string]int{}, ByDialect: []DialectExclude{}}
	n, err := ymap(doc, "census")
	if err != nil {
		return c, err
	}
	if n == nil {
		return c, fmt.Errorf("`census` is required — the count is the only thing that survives the purge, so it is stated")
	}
	if err := yonly(n, "the census", "generated", "total", "by_family", "by_dialect"); err != nil {
		return c, err
	}
	if c.Generated, err = ystr(n, "generated"); err != nil {
		return c, err
	}
	if c.Total, err = ynum(n, "total"); err != nil {
		return c, err
	}
	fam, err := ymap(n, "by_family")
	if err != nil {
		return c, err
	}
	if fam == nil {
		return c, fmt.Errorf("`census.by_family` is required")
	}
	if err := yonly(fam, "the census families", forbiddenFamilies...); err != nil {
		return c, err
	}
	for _, f := range forbiddenFamilies {
		v, verr := ynum(fam, f)
		if verr != nil {
			return c, verr
		}
		c.ByFamily[f] = v
	}
	rows, err := ylist(n, "by_dialect")
	if err != nil {
		return c, err
	}
	for _, rn := range rows {
		if err := yonly(rn, "a census row", "dialect", "config", "restart", "daemon", "total"); err != nil {
			return c, err
		}
		row := DialectExclude{}
		if row.Dialect, err = ystr(rn, "dialect"); err != nil {
			return c, err
		}
		for _, spec := range []struct {
			key string
			dst *int
		}{{"config", &row.Config}, {"restart", &row.Restart}, {"daemon", &row.Daemon}, {"total", &row.Total}} {
			v, verr := ynum(rn, spec.key)
			if verr != nil {
				return c, verr
			}
			*spec.dst = v
		}
		if row.Config+row.Restart+row.Daemon != row.Total {
			return c, fmt.Errorf("census row %q does not add up (%d + %d + %d != %d)",
				row.Dialect, row.Config, row.Restart, row.Daemon, row.Total)
		}
		c.ByDialect = append(c.ByDialect, row)
	}
	sum := 0
	for _, f := range forbiddenFamilies {
		sum += c.ByFamily[f]
	}
	if sum != c.Total {
		return c, fmt.Errorf("census by_family does not add up to total (%d != %d)", sum, c.Total)
	}
	return c, nil
}

// ── matching ────────────────────────────────────────────────────────────────

// Match reports the rule a command hits, if any. Longest rule wins; a DIALECT
// rule beats a common rule of the same length, so a vendor may name the family
// its own spelling belongs to. A dialect Correlix does not recognise still gets
// the common rules — the policy is never narrower for an unknown platform.
func (p *Policy) Match(dialect, command string) (ForbiddenRule, bool) {
	if p == nil {
		return ForbiddenRule{}, false
	}
	cmd := strings.Fields(strings.ToLower(command))
	if len(cmd) == 0 {
		return ForbiddenRule{}, false
	}
	best, found := ForbiddenRule{}, false
	consider := func(r ForbiddenRule) {
		if !hasPrefixTokens(cmd, r.Tokens) {
			return
		}
		for _, e := range r.Except {
			if hasPrefixTokens(cmd, e) {
				return
			}
		}
		if !found || len(r.Tokens) > len(best.Tokens) {
			best, found = r, true
		}
	}
	// Dialect rules first: at equal length the one already recorded wins, so
	// evaluating them ahead of the common set is what gives them precedence.
	for _, r := range p.byDialect[dialect] {
		consider(r)
	}
	for _, r := range p.common {
		consider(r)
	}
	return best, found
}

// SessionScope reports whether command is a documented session-scoped setter on
// this dialect, and the teardown it must be paired with.
func (p *Policy) SessionScope(dialect, command string) (SessionScope, bool) {
	if p == nil {
		return SessionScope{}, false
	}
	cmd := strings.Fields(strings.ToLower(command))
	for _, s := range p.scopes[dialect] {
		if hasPrefixTokens(cmd, s.Tokens) {
			return s, true
		}
	}
	return SessionScope{}, false
}

// SessionScopes returns every session-scoped setter, for the docs and the tests.
func (p *Policy) SessionScopes() []SessionScope {
	if p == nil {
		return nil
	}
	out := []SessionScope{}
	for _, d := range sortedKeys(p.scopes) {
		out = append(out, p.scopes[d]...)
	}
	return out
}

// Rules returns every rule — common first, then each dialect's — for the tests
// and for the docs generator.
func (p *Policy) Rules() []ForbiddenRule {
	if p == nil {
		return nil
	}
	out := append([]ForbiddenRule(nil), p.common...)
	for _, d := range sortedKeys(p.byDialect) {
		out = append(out, p.byDialect[d]...)
	}
	return out
}

// hasPrefixTokens reports whether toks begins with the whole of prefix.
func hasPrefixTokens(toks, prefix []string) bool {
	if len(prefix) == 0 || len(toks) < len(prefix) {
		return false
	}
	for i, w := range prefix {
		if toks[i] != w {
			return false
		}
	}
	return true
}

func isForbiddenFamily(s string) bool {
	for _, f := range forbiddenFamilies {
		if s == f {
			return true
		}
	}
	return false
}

// isReadLead reports the four verbs the read-only grammar admits. A policy rule
// may never begin with one: `show reload cause` is an output and stays allowed.
func isReadLead(tok string) bool {
	switch tok {
	case "show", "display", "get", "info":
		return true
	}
	return false
}

// ynum reads a non-negative integer scalar. A missing key is an error, not a
// zero: a census that silently reads zero would report "nothing was excluded".
func ynum(n *ynode, key string) (int, error) {
	raw, err := ystr(n, key)
	if err != nil {
		return 0, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("%q is required and must be a non-negative integer", key)
	}
	v, perr := strconv.Atoi(raw)
	if perr != nil || v < 0 {
		return 0, fmt.Errorf("%q must be a non-negative integer (got %q)", key, raw)
	}
	return v, nil
}

// sortedKeys is a deterministic key order for the two policy maps.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
