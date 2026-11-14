// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// repair.go — typo tolerance over the grammar's CLOSED vocabulary (hybrid NLU
// plan A2, owner decision D2).
//
// A misspelt vocabulary word ("shwo", "incidnets", "isues") is corrected and
// DISCLOSED as a Reading ("I read 'shwo' as 'show'"); a word with several
// equally close candidates is offered, never applied. The guards live in
// lex (length, distance, first letter, letters only, uniqueness, plain
// English words). On top of them, a word the caller's own resolver can place
// — an alias, an inventory name, even a partial one — is never "corrected":
// "edge" stays the device word it is.
//
// Entity NAMES are not repaired here: a misspelt name ("dalas") goes to the
// resolver's confirm-only fuzzy rung and comes back as a did-you-mean
// candidate the operator picks (resolve.MethodFuzzyName).

import (
	"context"
	"strings"

	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/lex"
	"netops/backend/internal/nlquery/resolve"
)

// grammarWords are the words this package's rules give meaning to that are
// not framing vocabulary, catalog aliases or shared core words. A test scans
// every regular expression in the package and fails when one of its words is
// missing here (or in the other sources), so a word the grammar reads can
// never be "corrected" into another.
var grammarWords = []string{
	// N-S3 causal change phrasings (causalChangesRe, causedFollowRe).
	"behind", "broke", "came", "lead", "might", "preceded", "preceding", "tied", "trigger", "triggered",
	"above", "below", "under", "over", "exceeds", "exceed", "greater", "higher", "lower", "least", "less",
	"percent", "milliseconds", "millisecond", "confidence", "grouped", "group", "broken", "break", "each",
	"unusual", "abnormal", "normal", "baseline", "anomalous", "elevated", "high", "losing", "dropping",
	"flapping", "packets", "seeing", "established", "idle", "average", "mean", "maximum", "peak", "minimum",
	"total", "most", "best", "worst", "busiest", "highest", "lowest", "rank", "ranked", "recent", "latest",
	"engineers", "engineer", "people", "users", "admins", "admin", "persons", "person", "made", "make", "done",
	"occurred", "happened", "settings", "setting", "things", "diff", "exactly", "else", "actor", "owner",
	"owned", "assigned", "seam", "class", "type", "state", "modifications", "modification", "deploys",
	"deployments", "rolled", "backups", "backup", "captured", "security", "routing", "route", "release",
	"feature", "flags", "flag", "cloud", "infrastructure", "infra", "network", "minutes", "hours", "days",
	"weeks", "months", "quarter", "year", "forever", "beginning", "complete", "history", "full", "entire",
	"tomorrow", "forecast", "predict", "midnight", "noon", "morning", "afternoon", "evening", "night",
	"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "logs", "syslog",
	"messages", "message", "lines", "search", "talkers", "talker", "bandwidth", "using", "sending",
	"traffic", "conversations", "netflow", "flows", "flow", "outages", "problems", "issues", "slow",
	"broken", "down", "flapping", "interfaces", "ports", "links", "intf", "circuits", "underlay", "direct",
	"connect", "neighbours", "neighbors", "sessions", "peers", "devices", "routers", "switches",
	"firewalls", "boxes", "box", "previous", "every", "same", "time", "versus", "compare", "against",
	"since", "changed", "changes", "changing", "modified", "deployed", "touched", "edited", "pushed",
	"open", "active", "ongoing", "closed", "resolved", "confirmed", "suspected", "undetermined", "unexplained",
	"cause", "root", "internet", "explain", "caused", "going", "tell", "please", "could", "would",
	"restart", "reboot", "reload", "shutdown", "disable", "enable", "delete", "remove", "clear", "apply",
	"push", "rollback", "revert", "undo", "configure", "change", "modify", "update", "create", "fix",
	"bounce", "reset", "deploy", "move", "shift", "reroute", "fail", "block", "allow", "ticket", "escalate",
	"install", "upgrade", "downgrade", "kill", "stop", "start", "ignore", "instructions", "system", "prompt",
	"disregard", "rules", "developer", "mode", "override", "jailbreak", "tenants", "tenant", "another",
	"other", "customers", "customer", "seconds", "within", "next", "adjacent", "connected", "attached",
	"beside", "neighbouring", "neighboring", "router", "switch", "firewall", "device", "node",
	"those", "them", "they", "that", "this", "there", "then", "here", "same", "these",
	"back", "edit", "happen", "prior", "roll", "shut", "some", "touch", "will", "your", "mpls",
	"four", "five", "seven", "eight", "nine", "three", "twelve", "fifteen", "twenty", "thirty", "sixty",
	// A4 families: severity, inventory, lookup.
	"critical", "severe", "major", "urgent", "priority", "altogether", "known", "visible", "onboarded",
	"discovered", "monitored", "managed", "inventory", "nodes", "locations", "cannot", "cant", "dont",
	"locate", "lookup", "search", "wrong", "anything", "something",
	// Phrasing eval (2026-11-12): device liveness, standing, BGP state.
	"alarm", "alive", "alright", "check", "doing", "fine", "good", "isis", "manage",
	"monitor", "offline", "okay", "online", "ospf", "reachable", "responding",
	"unreachable", "unresponsive",
	// Follow-ups 2026-11-12: verdict referents, RCA nouns, "connected".
	"identify", "only", "just", "ones", "one", "rca", "rcas", "connected", "platform",
}

// Vocabulary is the grammar's closed vocabulary: BaseVocabulary plus every
// word of the generated word table (its variants and vendor terms are words,
// never typos).
func Vocabulary(cat *catalog.Catalog) *lex.Vocab {
	var table []string
	for _, e := range cat.WordTable() {
		table = append(table, e.From)
	}
	return lex.NewVocab(baseLists(cat), table)
}

// BaseVocabulary is the vocabulary the word table is GENERATED against: the
// framing words, the grammar's own rule words, the shared core words and
// every word of every catalog alias, name and enum value. Code and catalog
// only.
func BaseVocabulary(cat *catalog.Catalog) *lex.Vocab { return lex.NewVocab(baseLists(cat)) }

func baseLists(cat *catalog.Catalog) []string {
	var framing []string
	for w := range questionVocab {
		framing = append(framing, w)
	}
	var fromCat []string
	fromCat = append(fromCat, cat.Aliases()...)
	for _, e := range cat.Entities {
		fromCat = append(fromCat, strings.ReplaceAll(e.Name, "_", " "))
		fromCat = append(fromCat, e.Aliases...)
	}
	for _, m := range cat.Metrics {
		fromCat = append(fromCat, m.Aliases...)
		fromCat = append(fromCat, m.Superlatives...)
	}
	for _, d := range cat.Dimensions {
		fromCat = append(fromCat, strings.ReplaceAll(d.Name, "_", " "))
		fromCat = append(fromCat, d.Aliases...)
		for _, ev := range d.Enum {
			fromCat = append(fromCat, strings.ToLower(strings.ReplaceAll(ev.Value, "_", " ")))
			fromCat = append(fromCat, ev.Aliases...)
		}
	}
	out := append(append(append(framing, grammarWords...), lex.CoreWords()...), fromCat...)
	return out
}

// applySynonyms rewrites the generated catalog variants and abbreviations
// (catalog/synonyms.v1.json) to the catalog word the grammar reads:
// "latencies" → "latency", "utilisation" → "utilization". A variant is the
// same word, so it is not disclosed; an abbreviation is a reading and is.
// Vendor terms stay as typed (vocabulary only). A word the caller's resolver
// places, or a value word, is never rewritten.
func applySynonyms(cat *catalog.Catalog, toks []string, keep func(i int, w string) bool) []lex.Reading {
	table := map[string]catalog.SynonymEntry{}
	for _, e := range cat.WordTable() {
		table[e.From] = e
	}
	var readings []lex.Reading
	for i, t := range toks {
		e, ok := table[t]
		if !ok || e.Kind == catalog.SynTerm || keep(i, t) {
			continue
		}
		toks[i] = e.To
		if e.Kind == catalog.SynAbbrev {
			readings = append(readings, lex.Reading{From: t, To: e.To, Kind: lex.KindSynonym})
		}
	}
	return readings
}

// repairText corrects the misspelt vocabulary words of a normalised question.
// A word the caller's resolver places (rungs 1–6: id, alias, inventory name,
// topology, catalog synonym, partial name) is kept as typed.
func (c Compiler) repairText(ctx context.Context, text string) (lex.Repair, error) {
	var resolveErr error
	values := valueWords(strings.Fields(text))
	keep := func(i int, w string) bool {
		if resolveErr != nil || values[i] {
			return true
		}
		res, err := c.R.Resolve(ctx, w, nil)
		if err != nil {
			resolveErr = err
			return true
		}
		for _, r := range res.Refs {
			if r.Method != resolve.MethodFuzzyName && r.Method != resolve.MethodModelSuggestion {
				return true
			}
		}
		return false
	}
	toks := strings.Fields(text)
	synReadings := applySynonyms(c.Cat, toks, keep)
	rep := Vocabulary(c.Cat).RepairText(strings.Join(toks, " "), keep)
	rep.Readings = append(synReadings, rep.Readings...)
	return rep, resolveErr
}

// valueMarkers introduce a free-text VALUE the grammar copies as typed — an
// owner ("owned by Comcast Business"), an actor ("changes by mlee") — which
// is data, not vocabulary, and is never repaired.
var valueMarkers = map[string]int{"by": 4, "owner": 4, "assigned": 5, "from": 1}

// valueWords marks the token positions that may belong to such a value: up to
// four words after "by"/"owner is", five after "assigned to", one after "from".
func valueWords(toks []string) map[int]bool {
	out := map[int]bool{}
	for i, t := range toks {
		n, ok := valueMarkers[t]
		if !ok {
			continue
		}
		for k := i + 1; k <= i+n && k < len(toks); k++ {
			out[k] = true
		}
	}
	return out
}
