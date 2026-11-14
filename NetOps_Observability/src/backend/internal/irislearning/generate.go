// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irislearning

// generate.go — the generators. Pure functions over ONE tenant's inputs:
// the same inputs always give the same proposals, in the same order, so a
// refresh is reproducible and a test can pin it. They read only what the
// caller passes in; the caller reads it all from the principal's own tenant.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"netops/backend/internal/entityalias"
	"netops/backend/internal/incidentfp"
	"netops/backend/internal/irisquerylog"
	"netops/backend/internal/iristriage"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/rcaresolution"
)

// Thresholds. A pattern needs this much support before anyone is asked about
// it: one incident is an anecdote, three fixed the same way is a habit.
const (
	MinResolutions     = 3
	MinAliasPeople     = 2
	MinMisses          = 5
	ResolutionLookback = 90 * 24 * time.Hour
)

// Inputs is everything a refresh reads — all from one tenant.
type Inputs struct {
	Now          time.Time
	Resolutions  []rcaresolution.Resolution
	Fingerprints map[string]incidentfp.Fingerprint // by correlation id
	Queries      []irisquerylog.Record
	Aliases      []entityalias.Alias // the tenant's existing aliases
}

// Generate returns every proposal the inputs support, sorted by
// (generator, subject). It never returns more than MaxOpenPerTenant.
func Generate(in Inputs) []Proposal {
	var out []Proposal
	out = append(out, resolutionPatterns(in)...)
	out = append(out, entityCorrections(in)...)
	out = append(out, missClusters(in)...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Generator != out[j].Generator {
			return out[i].Generator < out[j].Generator
		}
		return out[i].Subject < out[j].Subject
	})
	if len(out) > MaxOpenPerTenant {
		out = out[:MaxOpenPerTenant]
	}
	return out
}

// deviceName is the shape a device name must have to be written into a draft:
// a plain hostname-like token. Anything else (an address, free text) is left
// out rather than copied into text that would reach a prompt.
var deviceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,62}$`)

var ipLike = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$|:.*:`)

func usableDevice(s string) bool {
	return deviceName.MatchString(s) && !ipLike.MatchString(s)
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// ── resolution patterns → Network context ─────────────────────────────────

type resolutionGroup struct {
	device string
	kind   rcaresolution.Kind
	rows   []rcaresolution.Resolution
}

func resolutionPatterns(in Inputs) []Proposal {
	since := in.Now.Add(-ResolutionLookback)
	groups := map[string]*resolutionGroup{}
	for _, r := range in.Resolutions {
		if r.CreatedAt.Before(since) || !rcaresolution.Valid(r.Kind) || r.Kind == rcaresolution.KindOther {
			continue // "other" has no meaning a template can state
		}
		fp, ok := in.Fingerprints[r.CorrelationID]
		if !ok {
			continue
		}
		seen := map[string]bool{}
		for _, d := range fp.Devices {
			if !usableDevice(d) || seen[d] {
				continue
			}
			seen[d] = true
			k := strings.ToLower(d) + "|" + string(r.Kind)
			g := groups[k]
			if g == nil {
				g = &resolutionGroup{device: d, kind: r.Kind}
				groups[k] = g
			}
			g.rows = append(g.rows, r)
		}
	}
	var out []Proposal
	for k, g := range groups {
		cases := map[string]rcaresolution.Resolution{} // one per case: its newest
		for _, r := range g.rows {
			if cur, ok := cases[r.CorrelationID]; !ok || r.CreatedAt.After(cur.CreatedAt) {
				cases[r.CorrelationID] = r
			}
		}
		if len(cases) < MinResolutions {
			continue
		}
		rows := make([]rcaresolution.Resolution, 0, len(cases))
		for _, r := range cases {
			rows = append(rows, r)
		}
		sort.Slice(rows, func(i, j int) bool {
			if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
				return rows[i].CreatedAt.After(rows[j].CreatedAt)
			}
			return rows[i].CorrelationID < rows[j].CorrelationID
		})
		if p, ok := resolutionProposal(k, g, rows); ok {
			out = append(out, p)
		}
	}
	return out
}

func resolutionProposal(subject string, g *resolutionGroup, rows []rcaresolution.Resolution) (Proposal, bool) {
	n := len(rows)
	first, last := rows[n-1].CreatedAt, rows[0].CreatedAt
	label := rcaresolution.Label(g.kind)
	span := fmt.Sprintf("between %s and %s", day(first), day(last))
	var d ContextDraft
	switch g.kind {
	case rcaresolution.KindProviderTicket:
		d = ContextDraft{Kind: orgcontext.KindCarrierRelationship, Key: g.device + " provider",
			Body: fmt.Sprintf("%s: %d incidents %s were fixed by a ticket with the provider. "+
				"The circuit is %s, run by %s; open a ticket with them through %s.",
				g.device, n, span, Placeholder+"circuit id}}", Placeholder+"carrier}}", Placeholder+"how to reach their NOC}}")}
	case rcaresolution.KindNoActionTransient:
		d = ContextDraft{Kind: orgcontext.KindKnownFalsePositive, Key: g.device + " transient alerts",
			Body: fmt.Sprintf("%s: %d incidents %s cleared on their own with no action. "+
				"Treat a repeat as low priority unless it lasts longer than %s.",
				g.device, n, span, Placeholder+"how long}}")}
	default:
		d = ContextDraft{Kind: orgcontext.KindTopologyNote, Key: g.device + " history",
			Body: fmt.Sprintf("%s: %d incidents %s were fixed by %s. %s",
				g.device, n, span, label, Placeholder+"what an operator should know about this device}}")}
	}
	d.Scope = orgcontext.ScopeTenant
	if orgcontext.CheckKey(d.Key) != nil {
		return Proposal{}, false
	}
	ev := make([]Evidence, 0, min(n, MaxEvidence))
	for i, r := range rows {
		if i == MaxEvidence {
			break
		}
		lbl := fmt.Sprintf("Case fixed by %s (recorded %s)", label, day(r.CreatedAt))
		if r.ChangeID != "" {
			lbl += ", change " + r.ChangeID
		}
		ev = append(ev, Evidence{Kind: "resolution", Ref: r.CorrelationID, At: r.CreatedAt, Label: lbl,
			Quote: clipRunes(strings.TrimSpace(r.Note), MaxQuoteRunes)})
	}
	return Proposal{
		Target: TargetContext, Generator: GenResolutionPattern, Subject: "resolution|" + subject,
		Title: fmt.Sprintf("%s: %d incidents fixed by %s", g.device, n, label),
		Why: fmt.Sprintf("Operators recorded the same fix for %d incidents on %s %s. "+
			"A note in Network context lets Iris say this up front next time.", n, g.device, span),
		Context: &d, Evidence: ev, EvidenceCount: n,
	}, true
}

// ── entity corrections → alias ─────────────────────────────────────────────

var stopwords = map[string]bool{
	"a": true, "an": true, "the": true, "is": true, "are": true, "was": true, "were": true, "be": true,
	"of": true, "on": true, "in": true, "at": true, "to": true, "for": true, "from": true, "by": true,
	"with": true, "and": true, "or": true, "not": true, "no": true, "it": true, "its": true, "this": true,
	"that": true, "these": true, "those": true, "my": true, "our": true, "me": true, "we": true, "i": true,
	"what": true, "why": true, "how": true, "when": true, "where": true, "which": true, "who": true,
	"show": true, "list": true, "give": true, "tell": true, "find": true, "get": true, "did": true,
	"does": true, "do": true, "has": true, "have": true, "had": true, "any": true, "all": true,
	"last": true, "today": true, "yesterday": true, "now": true, "hour": true, "hours": true,
	"day": true, "days": true, "week": true, "minutes": true, "down": true, "up": true, "about": true,
	"please": true, "can": true, "you": true, "there": true, "than": true, "over": true, "into": true,
	"traffic": true, "errors": true, "error": true, "loss": true, "latency": true, "status": true,
}

// words splits a question into lower-case letter/digit tokens.
func words(q string) []string {
	return strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-'
	})
}

// phrases returns the question's 1–3-word runs that carry meaning: no
// stopword at either end, not a bare number.
func phrases(q string) map[string]bool {
	ws := words(q)
	out := map[string]bool{}
	for i := range ws {
		for n := 1; n <= 3 && i+n <= len(ws); n++ {
			run := ws[i : i+n]
			if stopwords[run[0]] || stopwords[run[n-1]] {
				continue
			}
			p := strings.Join(run, " ")
			if strings.Trim(p, "0123456789- ") == "" || len([]rune(p)) > entityalias.MaxAliasLen {
				continue
			}
			out[p] = true
		}
	}
	return out
}

type correctionTarget struct {
	ref    string // type|id
	typ    string
	id     string
	people map[string]map[string]bool // principal → phrases they used
	ev     []Evidence
}

func entityCorrections(in Inputs) []Proposal {
	taken := map[string]bool{} // normalized alias texts already in use, any type
	for _, a := range in.Aliases {
		taken[a.Norm] = true
	}
	targets := map[string]*correctionTarget{}
	for _, rec := range in.Queries {
		had := map[string]bool{}
		for _, e := range rec.Entities {
			had[e.Type+"|"+e.ID] = true
		}
		for _, c := range rec.Corrections {
			if c.Kind != irisquerylog.KindWrongEntity || c.CorrectedAST == nil {
				continue
			}
			for _, ref := range c.CorrectedAST.Refs {
				key := ref.Type + "|" + ref.ID
				if had[key] || ref.Type == "" || ref.ID == "" {
					continue // not a change of entity
				}
				t := targets[key]
				if t == nil {
					t = &correctionTarget{ref: key, typ: ref.Type, id: ref.ID, people: map[string]map[string]bool{}}
					targets[key] = t
				}
				who := c.By
				if who == "" {
					who = rec.Principal
				}
				if t.people[who] == nil {
					t.people[who] = map[string]bool{}
				}
				for p := range phrases(rec.Question) {
					t.people[who][p] = true
				}
				t.ev = append(t.ev, Evidence{Kind: "correction", Ref: rec.ID, At: c.At,
					Label: fmt.Sprintf("An operator said an answer should have been about %s %s", ref.Type, ref.ID)})
			}
		}
	}
	var out []Proposal
	for _, t := range targets {
		if len(t.people) < MinAliasPeople {
			continue
		}
		phrase, people := bestPhrase(t, taken)
		if phrase == "" {
			continue
		}
		sort.Slice(t.ev, func(i, j int) bool {
			if !t.ev[i].At.Equal(t.ev[j].At) {
				return t.ev[i].At.After(t.ev[j].At)
			}
			return t.ev[i].Ref < t.ev[j].Ref
		})
		ev := t.ev
		if len(ev) > MaxEvidence {
			ev = ev[:MaxEvidence]
		}
		out = append(out, Proposal{
			Target: TargetAlias, Generator: GenEntityCorrection, Subject: "alias|" + t.ref + "|" + catalog.NormalizeAlias(phrase),
			Title: fmt.Sprintf("Let \"%s\" mean %s %s", phrase, t.typ, t.id),
			Why: fmt.Sprintf("%d different operators corrected answers to mean %s %s, and each of them used the words \"%s\". "+
				"An alias lets Iris understand those words the first time.", people, t.typ, t.id, phrase),
			Alias: &AliasDraft{EntityType: t.typ, EntityID: t.id, Alias: phrase}, Evidence: ev, EvidenceCount: len(t.ev),
		})
	}
	return out
}

// bestPhrase picks the phrase most people used (at least MinAliasPeople),
// preferring the longer phrase, then the alphabetically first — deterministic.
// A phrase already in use as an alias, or that is the entity id itself, is
// skipped.
func bestPhrase(t *correctionTarget, taken map[string]bool) (string, int) {
	count := map[string]int{}
	for _, ps := range t.people {
		for p := range ps {
			count[p]++
		}
	}
	local := strings.ToLower(t.id)
	if i := strings.LastIndex(local, ":"); i >= 0 {
		local = local[i+1:]
	}
	best, bestN := "", 0
	for p, n := range count {
		norm := catalog.NormalizeAlias(p)
		if n < MinAliasPeople || norm == "" || taken[norm] || norm == catalog.NormalizeAlias(local) {
			continue
		}
		lw, bw := len(strings.Fields(p)), len(strings.Fields(best))
		if n > bestN || (n == bestN && (lw > bw || (lw == bw && p < best))) {
			best, bestN = p, n
		}
	}
	return best, bestN
}

// ── miss clusters → a runbook draft ────────────────────────────────────────

var routeSlug = regexp.MustCompile(`[^a-z0-9]+`)

func missClusters(in Inputs) []Proposal {
	type cluster struct {
		class, route string
		ev           []Evidence
	}
	groups := map[string]*cluster{}
	for _, rec := range in.Queries {
		if rec.Outcome != irisquerylog.OutcomeMiss {
			continue
		}
		if rec.MissClass != iristriage.NoTool && rec.MissClass != iristriage.NoData {
			continue // wording and routing misses are Iris's to fix, not the team's
		}
		route := strings.Trim(routeSlug.ReplaceAllString(strings.ToLower(rec.Intent), "-"), "-")
		if route == "" {
			continue
		}
		k := rec.MissClass + "|" + route
		g := groups[k]
		if g == nil {
			g = &cluster{class: rec.MissClass, route: route}
			groups[k] = g
		}
		// No question text: colleagues' wording is never copied into a proposal.
		g.ev = append(g.ev, Evidence{Kind: "miss", Ref: rec.ID, At: rec.At,
			Label: fmt.Sprintf("Iris could not answer a %s question (%s)", route, missLabel(rec.MissClass))})
	}
	var out []Proposal
	for k, g := range groups {
		if len(g.ev) < MinMisses {
			continue
		}
		name := clipRunes("iris-gap-"+g.route, 48)
		name = strings.TrimRight(name, "-")
		md := gapSkill(name, g.route, g.class, len(g.ev))
		sort.Slice(g.ev, func(i, j int) bool {
			if !g.ev[i].At.Equal(g.ev[j].At) {
				return g.ev[i].At.After(g.ev[j].At)
			}
			return g.ev[i].Ref < g.ev[j].Ref
		})
		ev := g.ev
		if len(ev) > MaxEvidence {
			ev = ev[:MaxEvidence]
		}
		out = append(out, Proposal{
			Target: TargetRunbook, Generator: GenMissCluster, Subject: "miss|" + k,
			Title: fmt.Sprintf("Write down how your team answers %s questions", g.route),
			Why: fmt.Sprintf("Iris could not answer %d %s questions in the last 30 days (%s). "+
				"A procedure written by your team gives the next operator the steps, even where Iris has no tool for it.",
				len(g.ev), g.route, missLabel(g.class)),
			Runbook: &RunbookDraft{Name: name, SkillMD: md}, Evidence: ev, EvidenceCount: len(g.ev),
		})
	}
	return out
}

func missLabel(class string) string {
	switch class {
	case iristriage.NoTool:
		return "no tool reads that"
	case iristriage.NoData:
		return "the data was not there"
	}
	return class
}

// gapSkill is a procedure draft the team finishes. It parses as a MOP (Iris
// shows it, never runs it); the steps are placeholders to replace.
func gapSkill(name, route, class string, n int) string {
	words := strings.ReplaceAll(route, "-", " ")
	return "---\n" +
		"name: " + name + "\n" +
		"layer: analysis\n" +
		"version: 1\n" +
		"kind: mop\n" +
		"when_to_use: " + words + " question, " + words + " check\n" +
		"symptom_kinds: " + route + "\n" +
		"tools: get_rca_verdict\n" +
		"gather:\n" +
		"  - get_rca_verdict(correlation_id)\n" +
		"look_for:\n" +
		"  - " + Placeholder + "what the operator should look at first}}\n" +
		"decisions:\n" +
		"  - verdict=state which step was reached\n" +
		"steps:\n" +
		"  - " + Placeholder + "first step}}\n" +
		"  - " + Placeholder + "second step}}\n" +
		"---\n" +
		fmt.Sprintf("Drafted by Correlix: Iris could not answer %d %s questions (%s). ", n, words, missLabel(class)) +
		"Replace each step with what your team does, then send it for review.\n"
}
