// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package compile is the DETERMINISTIC half of the Iris NL query compiler
// (tracker 337 N-C5; design: iris-nl-query-design.md §6). It turns a question —
// plus the conversation's prior query and page context — into a
// CorrelixQueryAST using a closed grammar over the catalog's own vocabulary,
// with no model involved. What it cannot parse it says so (Unparsed), and the
// model fallback (structured output against the AST schema, the same
// validator) takes over; what it must not do (act, change, reveal another
// tenant) it DECLINES.
//
// The compiler never decides scope: entity mentions go through the caller's
// resolver (own aliases, own inventory), and the AST it returns is validated
// again before anything reads data.
package compile

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/resolve"
)

// Resolver resolves one mention within the caller's scope.
type Resolver interface {
	Resolve(ctx context.Context, text string, types []string) (resolve.Result, error)
}

// Context is what the conversation and the page contribute.
type Context struct {
	PriorAST   *ast.AST
	IncidentID string // the incident on screen, if any
	Loc        *time.Location
	Now        time.Time
}

// Declines (closed vocabulary).
const (
	DeclineNotAQuery = "not_a_query" // an action, a change, an instruction
)

// Result is the compiler's answer.
type Result struct {
	Intent   string        `json:"intent,omitempty"`
	AST      *ast.AST      `json:"ast,omitempty"`
	Entities []resolve.Ref `json:"entities,omitempty"`
	// Clarify lists the candidates of an ambiguous mention — ask the operator.
	Clarify []resolve.Ref `json:"clarify,omitempty"`
	// Decline is set when the question must be refused, not answered.
	Decline string `json:"decline,omitempty"`
	// Unparsed means the grammar did not recognise the question (model fallback).
	Unparsed bool `json:"unparsed,omitempty"`
	// NotUnderstood lists the words that made it Unparsed.
	NotUnderstood []string `json:"not_understood,omitempty"`
}

// Compiler compiles questions.
type Compiler struct {
	Cat *catalog.Catalog
	R   Resolver
}

var (
	punctRe  = regexp.MustCompile(`[^a-z0-9:/._@%&' -]+`)
	actionRe = regexp.MustCompile(`^(?:please\s+|can you\s+|could you\s+|go\s+)?(?:restart|reboot|reload|shut ?down|shutdown|disable|enable|delete|remove|clear|apply|push|rollback|roll back|revert|undo|configure|set|change|modify|update|create|add|fix|bounce|reset|deploy|move|shift|reroute|re-route|fail ?over|block|allow|open a ticket|escalate|install|upgrade|downgrade|kill|stop|start)\b`)
	injectRe = regexp.MustCompile(`ignore (?:all |the )?(?:previous|prior|above) instructions|system prompt|you are now|disregard (?:your|all) (?:rules|instructions)|developer mode|admin mode|act as|^system\b|\boverride\b|jailbreak`)
	crossRe  = regexp.MustCompile(`\b(?:all tenants|every tenant|other tenants?|another tenant|tenant [a-z0-9-]+'s|other customers?|every customer'?s?|all customers'?|customers' )`)
	topNRe   = regexp.MustCompile(`\b(?:top|which|worst|best|busiest|highest|lowest)\s+(\d{1,3})\b|\b(\d{1,3})\s+(?:worst|best|busiest|highest|lowest|most)\b`)
	pctRe    = regexp.MustCompile(`(?:above|over|more than|greater than|exceeds?|>|higher than|at least)\s*(\d+(?:\.\d+)?)\s*(%|percent|ms|milliseconds?)?`)
	belowRe  = regexp.MustCompile(`(?:below|under|less than|lower than|<)\s*(\d+(?:\.\d+)?)\s*(%|percent|ms)?`)
	confRe   = regexp.MustCompile(`confidence\s+(?:above|over|greater than|>|more than)\s*(0?\.\d+|1(?:\.0+)?)`)
	perRe    = regexp.MustCompile(`\b(?:per|by|grouped by|group by|broken down by|break down by|for each|each)\s+(site|device|provider|actor|person|type|seam|owner|seam class|state)\b`)
)

// normalize lower-cases, strips punctuation that carries no meaning here and
// collapses whitespace.
func normalize(q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	q = strings.NewReplacer("’", "'", "‘", "'", "“", " ", "”", " ", "?", " ", "!", " ", ",", " ", ";", " ").Replace(q)
	q = strings.NewReplacer("sd-wan", "sdwan", "sd wan", "sdwan", "'s ", " ", "’s ", " ").Replace(q + " ")
	q = punctRe.ReplaceAllString(q, " ")
	q = strings.TrimRight(q, ". ")
	return strings.Join(strings.Fields(q), " ")
}

// Compile compiles one question.
func (c Compiler) Compile(ctx context.Context, question string, cx Context) (Result, error) {
	if cx.Loc == nil {
		cx.Loc = time.UTC
	}
	if cx.Now.IsZero() {
		cx.Now = time.Now()
	}
	text := normalize(question)
	if text == "" {
		return Result{Unparsed: true}, nil
	}
	if injectRe.MatchString(text) || crossRe.MatchString(text) || actionRe.MatchString(text) {
		return Result{Decline: DeclineNotAQuery}, nil
	}
	if res, ok, err := c.followUp(ctx, text, cx); ok || err != nil {
		return res, err
	}
	var tp timePhrase
	// The comparison window ("with yesterday", "vs last week") is not the
	// question's own window.
	timeText := compareScratchRe.ReplaceAllString(text, " ")
	tp, hasTime := parseTime(timeText, cx.Now, cx.Loc)
	st := &state{c: c, ctx: ctx, text: text, cx: cx, e: newEaten()}
	if hasTime {
		st.time = tp.tr
		st.e.phrase(tp.span)
	}
	// Understood but unanswerable: log and flow questions compile to the
	// reserved query types so the validator refuses them precisely.
	// Coverage is not applied here: whatever else the question names, the
	// answer is the same precise refusal, and it must not degrade to Unparsed.
	if logRe.MatchString(text) {
		return Result{Intent: "search_logs", AST: &ast.AST{V: 1, Type: ast.LogSearch, Target: "device"}}, nil
	}
	if flowRe.MatchString(text) {
		return Result{Intent: "query_flows", AST: &ast.AST{V: 1, Type: ast.FlowTop, Target: "device"}}, nil
	}
	switch {
	case cx.IncidentID != "" && isWhatHappened(text) && !mentionsPlace(text):
		return Result{Intent: "explain_incident", AST: &ast.AST{V: 1, Type: ast.IncidentExplain, Target: "incident", IncidentID: cx.IncidentID}}, nil
	case isChangeQuestion(text):
		r, err := st.changes()
		return st.done(r), err
	}
	m, alias := c.findMetric(text)
	if m == nil {
		m, alias = c.stateMetric(text)
	}
	if m != nil {
		st.e.phrase(alias)
		r, err := st.metric(m)
		if err == nil && r.AST != nil {
			st.compareFromScratch(r.AST)
		}
		return st.done(r), err
	}
	if isIncidentQuestion(text) {
		r, err := st.incidents()
		return st.done(r), err
	}
	return Result{Unparsed: true, NotUnderstood: st.e.leftovers(text)}, nil
}

type state struct {
	c    Compiler
	ctx  context.Context
	text string
	cx   Context
	time ast.TimeRange
	e    *eaten
}

// done enforces coverage on a finished result.
func (s *state) done(r Result) Result {
	if r.AST == nil || r.Decline != "" {
		return r
	}
	if left := s.e.leftovers(s.text); len(left) > 0 {
		return Result{Intent: r.Intent, Unparsed: true, NotUnderstood: left, Entities: r.Entities}
	}
	return r
}

var changeWords = regexp.MustCompile(`\b(?:changed?|changes|changing|modified|modifications?|deployed|deploys?|deployments?|touched|edited|pushed|who touched|config backups?|what else did|rolled out)\b`)

func isChangeQuestion(t string) bool {
	return changeWords.MatchString(t) && !strings.Contains(t, "changed most")
}

var incidentWords = regexp.MustCompile(`\b(?:incidents?|outages?|problems?|issues?|what happened|what's wrong|whats wrong|what is wrong|why is|why are|slow|broken|down)\b`)

func isIncidentQuestion(t string) bool { return incidentWords.MatchString(t) }

var (
	logRe  = regexp.MustCompile(`\b(?:logs?|syslog|log messages?|log lines?|search .* logs)\b`)
	flowRe = regexp.MustCompile(`\b(?:top talkers?|talkers|bandwidth users|using the most bandwidth|who is using|sending traffic|traffic between|conversations|netflow|flows?)\b`)
)

// stateMetric maps "which interfaces are down" / "which bgp sessions are
// down" — questions with no metric word — onto the state metric of the
// named target.
func (c Compiler) stateMetric(text string) ([]catalog.AliasHit, string) {
	if !regexp.MustCompile(`\b(?:down|up|flapping)\b`).MatchString(text) {
		return nil, ""
	}
	pick := func(name, target string) ([]catalog.AliasHit, string) {
		return []catalog.AliasHit{{Kind: "metric", Name: name, For: target}}, ""
	}
	switch {
	case regexp.MustCompile(`\b(?:bgp|peers?|sessions?|neighbou?rs?)\b`).MatchString(text):
		return pick("bgp_session_state", "bgp_peer")
	case regexp.MustCompile(`\b(?:interfaces?|ports?|links?)\b`).MatchString(text) && strings.Contains(text, "flapping"):
		return pick("if_flaps", "interface")
	case regexp.MustCompile(`\b(?:interfaces?|ports?|links?)\b`).MatchString(text):
		return pick("if_oper_status", "interface")
	}
	return nil, ""
}

var compareScratchRe = regexp.MustCompile(`\bcompare\b.*\b(?:with|to|vs|versus|against)\s+(yesterday|last week)\b|\b(?:vs\.?|versus)\s+(yesterday|last week)\b|\bthan (?:the same time )?(yesterday|last week)\b|\bcompare to (yesterday|last week)\b|\bchanged (?:the )?most\b.*\bsince (yesterday|last week)\b|\bcompare\b.*\b(this week)\b.*\b(last week)\b`)

// compareFromScratch turns a metric question that compares against an
// earlier window into compare_windows — the SAME window length shifted back.
func (s *state) compareFromScratch(q *ast.AST) {
	m := compareScratchRe.FindStringSubmatch(s.text)
	if m == nil {
		return
	}
	s.e.phrase(m[0])
	which := ""
	for _, g := range m[1:] {
		if g != "" {
			which = g
		}
	}
	off, dur := "1d", 24*time.Hour
	if which == "last week" {
		off, dur = "7d", 7*24*time.Hour
	}
	switch q.Time.Kind {
	case "", ast.TimeIncident, ast.TimeIncidents:
		q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}
		fallthrough
	case ast.TimeRelative:
		ct := q.Time
		ct.Offset = off
		q.CompareTo = &ct
	case ast.TimeAbsolute:
		f, t := q.Time.From.Add(-dur), q.Time.To.Add(-dur)
		q.CompareTo = &ast.TimeRange{Kind: ast.TimeAbsolute, From: &f, To: &t}
	}
	q.Type, q.Predicate, q.GroupBy = ast.CompareWindows, nil, nil
	if regexp.MustCompile(`\bchanged (?:the )?most\b`).MatchString(s.text) {
		q.OrderBy, q.Limit = []ast.OrderKey{{Field: "delta", Dir: "desc"}}, 10
		s.e.re(regexp.MustCompile(`\bchanged (?:the )?most\b`), s.text)
	} else {
		q.OrderBy, q.Limit = nil, 0
	}
}

func anyTargetWord(t string) bool {
	for _, tw := range targetWords {
		if tw.re.MatchString(t) {
			return true
		}
	}
	return false
}

func isWhatHappened(t string) bool {
	return regexp.MustCompile(`^(?:so\s+)?(?:what happened|what's going on|whats going on|explain (?:this|it)|what caused (?:this|it)|why did this happen|tell me what happened)$`).MatchString(t)
}

func mentionsPlace(t string) bool {
	return regexp.MustCompile(`\b(?:at|in|to|on)\s+\w`).MatchString(t) && !strings.HasSuffix(t, "in this incident")
}

// ---- entities --------------------------------------------------------------

// stop words that never start or end an entity mention.
var stopword = map[string]bool{"the": true, "a": true, "an": true, "at": true, "in": true, "on": true, "to": true, "for": true,
	"of": true, "from": true, "show": true, "me": true, "all": true, "any": true, "every": true, "which": true, "what": true,
	"is": true, "are": true, "was": true, "were": true, "with": true, "and": true, "or": true, "my": true, "our": true,
	"last": true, "past": true, "today": true, "yesterday": true, "this": true, "week": true, "hour": true, "hours": true,
	"day": true, "days": true, "minutes": true, "now": true, "right": true, "over": true, "by": true, "per": true, "had": true,
	"has": true, "have": true, "did": true, "do": true, "does": true, "who": true, "how": true, "much": true, "many": true,
	"there": true, "any's": true, "anything": true, "anywhere": true, "across": true, "each": true, "than": true, "more": true,
	"above": true, "below": true, "under": true, "top": true, "it": true, "that": true, "those": true, "these": true, "them": true,
	"only": true, "just": true, "please": true, "whats": true, "what's": true}

// mentions resolves every entity mention in the text: the longest n-gram
// (up to 4 words) the resolver matches at rungs 1–3 wins; a partial-name or
// ambiguous match is returned for clarification instead of being used.
func (s *state) mentions(types []string) ([]resolve.Ref, []resolve.Ref, error) {
	words := strings.Fields(s.text)
	used := make([]bool, len(words))
	var refs, clarify []resolve.Ref
	for n := 4; n >= 1; n-- {
		for i := 0; i+n <= len(words); i++ {
			if anyUsed(used[i:i+n]) || stopword[words[i]] || stopword[words[i+n-1]] {
				continue
			}
			phrase := strings.Join(words[i:i+n], " ")
			if len(phrase) < 2 {
				continue
			}
			res, err := s.c.R.Resolve(s.ctx, phrase, types)
			if err != nil {
				return nil, nil, err
			}
			if len(res.Refs) == 0 {
				continue
			}
			if res.Refs[0].Method == resolve.MethodPartialName {
				continue // too weak to use unasked; the model path may ask
			}
			if res.Ambiguous {
				clarify = append(clarify, res.Refs...)
			} else {
				refs = append(refs, res.Refs[0])
			}
			if s.e != nil {
				s.e.phrase(phrase)
			}
			for k := i; k < i+n; k++ {
				used[k] = true
			}
		}
	}
	sort.SliceStable(refs, func(i, j int) bool {
		return strings.Index(s.text, strings.ToLower(refs[i].InputText)) < strings.Index(s.text, strings.ToLower(refs[j].InputText))
	})
	return refs, clarify, nil
}

func anyUsed(b []bool) bool {
	for _, x := range b {
		if x {
			return true
		}
	}
	return false
}

func astRefs(rs []resolve.Ref) []ast.EntityRef {
	var out []ast.EntityRef
	seen := map[string]bool{}
	for _, r := range rs {
		k := r.EntityType + "|" + r.EntityID
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ast.EntityRef{Type: r.EntityType, ID: r.EntityID})
	}
	return out
}

// ---- metrics -----------------------------------------------------------------

// findMetric returns the catalog metric whose alias (or name) is the longest
// match in the text.
func (c Compiler) findMetric(text string) ([]catalog.AliasHit, string) {
	best, bestLen, bestAlias := []catalog.AliasHit(nil), 0, ""
	for _, a := range c.Cat.Aliases() {
		if len(a) <= bestLen || !containsPhrase(text, a) {
			continue
		}
		var hits []catalog.AliasHit
		for _, h := range c.Cat.Lookup(a) {
			if h.Kind == "metric" {
				hits = append(hits, h)
			}
		}
		if len(hits) > 0 {
			best, bestLen, bestAlias = hits, len(a), a
		}
	}
	return best, bestAlias
}

func containsPhrase(text, phrase string) bool {
	i := strings.Index(" "+text+" ", " "+phrase+" ")
	return i >= 0
}

var targetWords = []struct {
	re     *regexp.Regexp
	target string
}{
	{regexp.MustCompile(`\b(?:interfaces?|ports?|links?|intf)\b`), "interface"},
	{regexp.MustCompile(`\b(?:circuits?|underlay|wan|sdwan underlay|direct connect|mpls)\b`), "circuit"},
	{regexp.MustCompile(`\b(?:bgp|peers?|neighbou?rs?|sessions?)\b`), "bgp_peer"},
	{regexp.MustCompile(`\b(?:devices?|routers?|switch(?:es)?|firewalls?|boxes)\b`), "device"},
}

func (s *state) metric(hits []catalog.AliasHit) (Result, error) {
	// Choose the target: an explicit target word that one of the hits applies
	// to, else the first applicable entity type of the first hit.
	var m *catalog.Metric
	target := ""
	for _, tw := range targetWords {
		s.e.re(tw.re, s.text)
	}
	for _, tw := range targetWords {
		if !tw.re.MatchString(s.text) {
			continue
		}
		for _, h := range hits {
			if strings.Contains(","+h.For+",", ","+tw.target+",") {
				mm, _ := s.c.Cat.Metric(h.Name)
				m, target = mm, tw.target
				break
			}
		}
		if m != nil {
			break
		}
	}
	if m == nil {
		m, _ = s.c.Cat.Metric(hits[0].Name)
		target = m.EntityTypes[0]
	}
	// Every entity type is offered: a mention the target cannot be narrowed
	// by (an application on an interface metric) must reach the validator
	// and be refused there, not be silently dropped here.
	refs, clarify, err := s.mentions([]string{"site", "device", "interface", "circuit", "bgp_peer", "provider", "probe_target", "application"})
	if err != nil {
		return Result{}, err
	}
	if len(clarify) > 0 {
		return Result{Intent: "query_metric", Clarify: clarify}, nil
	}
	refs = s.interfaceAfterDevice(refs)
	// A named probe target / circuit / peer decides WHICH same-word metric is
	// meant ("latency to 8.8.8.8" is the probe's, not a circuit's).
	for _, r := range refs {
		for _, h := range hits {
			if strings.Contains(","+h.For+",", ","+r.EntityType+",") && !anyTargetWord(s.text) {
				mm, _ := s.c.Cat.Metric(h.Name)
				m, target = mm, r.EntityType
			}
		}
	}
	// No target word: the question is ABOUT the entity it names ("packet loss
	// on dfw-edge-1" is about a device) — the validator decides if it applies.
	if !anyTargetWord(s.text) && len(refs) > 0 && refs[0].EntityType != "site" && refs[0].EntityType != "provider" {
		if _, ok := s.c.Cat.Entity(refs[0].EntityType); ok && !contains(m.EntityTypes, refs[0].EntityType) {
			target = refs[0].EntityType
		}
	}
	q := &ast.AST{V: 1, Type: ast.MetricSeries, Target: target, Metric: m.Name, Agg: s.aggFor(m), Refs: astRefs(refs), Time: s.time}
	if g := perRe.FindStringSubmatch(s.text); g != nil && (g[1] == "site" || g[1] == "device" || g[1] == "provider") {
		q.GroupBy = []string{g[1]}
		s.e.phrase(g[0])
	}
	switch {
	case s.e.re(topNRe, s.text) || s.e.re(regexp.MustCompile(`\b(?:top|busiest|highest|worst|most|lowest|best)\b`), s.text):
		q.Type, q.Limit = ast.MetricTopK, s.topN() // 0 = the validator's default
		dir := "desc"
		if strings.Contains(s.text, "worst") && m.Unit == "score" || strings.Contains(s.text, "lowest") {
			dir = "asc"
		}
		q.OrderBy = []ast.OrderKey{{Field: "value", Dir: dir}}
	case s.e.re(regexp.MustCompile(`\b(?:unusual|abnormal|higher than normal|above normal|above baseline|anomalous|than normal)\b`), s.text):
		q.Type, q.Predicate = ast.MetricFilter, &ast.Predicate{Op: "above_baseline"}
	case s.e.re(pctRe, s.text):
		v, _ := strconv.ParseFloat(pctRe.FindStringSubmatch(s.text)[1], 64)
		q.Type, q.Predicate = ast.MetricFilter, &ast.Predicate{Op: "gt", Value: v}
	case s.e.re(belowRe, s.text):
		v, _ := strconv.ParseFloat(belowRe.FindStringSubmatch(s.text)[1], 64)
		q.Type, q.Predicate = ast.MetricFilter, &ast.Predicate{Op: "lt", Value: v}
	case s.stateQuestion(m, q):
	case s.e.re(regexp.MustCompile(`\b(?:high|elevated|too high)\b`), s.text) && m.DefaultThreshold != nil:
		q.Type, q.Predicate = ast.MetricFilter, &ast.Predicate{Op: "gt", Value: *m.DefaultThreshold}
	case len(q.GroupBy) == 0 && (s.e.re(regexp.MustCompile(`\b(?:any|anything|are there|were there|is there|losing|dropping|flapping|packets|seeing)\b`), s.text) ||
		m.Unit == "count" || regexp.MustCompile(`^which\b.*\b(?:have|has|had)\b`).MatchString(s.text)):
		// Presence: "is 8.8.8.8 losing packets", "any flaps", "show BGP flaps".
		q.Type, q.Predicate = ast.MetricFilter, &ast.Predicate{Op: "gt", Value: 0}
	}
	return Result{Intent: "query_metric", AST: q, Entities: refs}, nil
}

// stateQuestion handles "which interfaces are down" / "which bgp sessions are
// down" over enum metrics.
// ifNameRe matches an interface name (ge-0/0/0, xe-1/0/1, Gi0/0, eth0, Ethernet1).
var ifNameRe = regexp.MustCompile(`^(?:[a-z]{1,12}-?\d+(?:/\d+){0,3}(?:\.\d+)?)$`)

// interfaceAfterDevice turns "<device> <ifname>" into ONE interface ref: the
// device was resolved, and the next word names a port on it.
func (s *state) interfaceAfterDevice(refs []resolve.Ref) []resolve.Ref {
	words := strings.Fields(s.text)
	out := refs[:0]
	for _, r := range refs {
		if r.EntityType != "device" {
			out = append(out, r)
			continue
		}
		name := strings.ToLower(r.InputText)
		replaced := false
		for i := 0; i+1 < len(words); i++ {
			if words[i] == name && ifNameRe.MatchString(words[i+1]) {
				dev := r.EntityID[strings.IndexByte(r.EntityID, ':')+1:]
				out = append(out, resolve.Ref{InputText: words[i] + " " + words[i+1], EntityType: "interface",
					EntityID: "interface:" + dev + "/" + words[i+1], Confidence: r.Confidence, Method: r.Method})
				s.e.phrase(words[i+1])
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, r)
		}
	}
	return out
}

func (s *state) stateQuestion(m *catalog.Metric, q *ast.AST) bool {
	if len(m.ValueEnum) == 0 || !s.e.re(regexp.MustCompile(`\b(?:down|up|established|not established|idle)\b`), s.text) {
		return false
	}
	q.Type = ast.MetricFilter
	if q.Time.Kind == "" {
		q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "5m"}
	}
	switch {
	case m.Name == "bgp_session_state" && strings.Contains(s.text, "down"):
		q.Predicate = &ast.Predicate{Op: "ne", Value: m.ValueEnum["established"]}
	case strings.Contains(s.text, "down"):
		q.Predicate = &ast.Predicate{Op: "eq", Value: m.ValueEnum["down"]}
	default:
		q.Predicate = &ast.Predicate{Op: "eq", Value: m.ValueEnum["up"]}
	}
	return true
}

func (s *state) topN() int {
	m := topNRe.FindStringSubmatch(s.text)
	if m == nil {
		return 0
	}
	for _, g := range m[1:] {
		if n, err := strconv.Atoi(g); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// aggFor picks the aggregation the question names, else the metric default.
func (s *state) aggFor(m *catalog.Metric) string {
	for word, agg := range map[string]string{"p95": "p95", "95th": "p95", "average": "avg", "avg": "avg", "mean": "avg",
		"max": "max", "maximum": "max", "peak": "max", "min": "min", "minimum": "min", "total": "sum"} {
		if hasWord(s.text, word) && contains(m.Aggregations, agg) {
			s.e.phrase(word)
			return agg
		}
	}
	return m.DefaultAgg
}

// ---- changes -------------------------------------------------------------------

var (
	listLimitRe = regexp.MustCompile(`\b(?:the\s+)?(?:(\d{1,3})\s+most recent|most recent\s+(\d{1,3})|last\s+(\d{1,3})|latest\s+(\d{1,3})|(\d{1,3})\s+latest)\b`)
	actorRe     = regexp.MustCompile(`\b(?:by|did|made by|changes? by|from)\s+([a-z][a-z0-9._-]{1,30})(?:\s+(?:or|and)\s+([a-z][a-z0-9._-]{1,30}))?\b`)
	changeIDRe  = regexp.MustCompile(`\bchange\s+([a-z]{2,6}-\d{1,9})\b`)
	everyIncRe  = regexp.MustCompile(`\b(\d{1,3})\s*(minutes?|mins?|hours?)\s+before\s+(?:every|each|all)\s+(sdwan|vpn|cloud|wan|isp|internet|dia)?\s*(?:incidents?|outages?)\b`)
	notTypeRe   = regexp.MustCompile(`\bnon[- ]?(dns|config|cloud|security|route|routing|network)\b`)
	actorWords  = map[string]bool{"type": true, "site": true, "actor": true, "person": true, "seam": true, "device": true, "owner": true,
		"they": true, "he": true, "she": true, "them": true, "it": true, "someone": true, "anyone": true, "you": true, "we": true, "i": true}
)

var timeUnitWord = regexp.MustCompile(`^(?:minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|months?)$`)

// listLimit reads "the 10 most recent", "last 5", "most recent 3".
func (s *state) listLimit() int {
	loc := listLimitRe.FindStringSubmatchIndex(s.text)
	if loc == nil {
		return 0
	}
	m := listLimitRe.FindStringSubmatch(s.text)
	// "last 7 days" is a TIME window, not "the last 7 items".
	if next := strings.Fields(s.text[loc[1]:]); len(next) > 0 && timeUnitWord.MatchString(next[0]) {
		return 0
	}
	for _, g := range m[1:] {
		if n, err := strconv.Atoi(g); err == nil && n > 0 {
			s.e.phrase(m[0])
			s.e.phrase("recent")
			return n
		}
	}
	return 0
}

func (s *state) changes() (Result, error) {
	if res, ok := s.changesAroundEveryIncident(); ok {
		return res, nil
	}
	refs, clarify, err := s.mentions([]string{"site", "device", "application"})
	if err != nil {
		return Result{}, err
	}
	if len(clarify) > 0 {
		return Result{Intent: "list_changes", Clarify: clarify}, nil
	}
	s.e.re(changeWords, s.text)
	s.e.re(regexp.MustCompile(`\b(?:who|made|make|did|done|occurred|happened|policy|policies|settings?|things|diff|exactly)\b`), s.text)
	q := &ast.AST{V: 1, Type: ast.ChangeList, Target: "change", Refs: astRefs(refs), Time: s.time,
		OrderBy: []ast.OrderKey{{Field: "event_at", Dir: "desc"}}, Limit: s.listLimit()}
	if m := changeIDRe.FindStringSubmatch(s.text); m != nil {
		q.Refs = append(q.Refs, ast.EntityRef{Type: "change", ID: "change:" + m[1]})
		s.e.phrase(m[0])
		q.Limit = 1
		if q.Time.Kind == "" {
			q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "30d"}
		}
	}
	if m := notTypeRe.FindStringSubmatch(s.text); m != nil {
		st := &state{text: m[1] + " changes"}
		if f := st.changeTypeFilter(); f != nil {
			f.Op = "ne"
			q.Filters = append(q.Filters, *f)
			s.e.phrase(m[0])
		}
	}
	if m := actorRe.FindStringSubmatch(s.text); m != nil && !actorWords[m[1]] && !questionVocab[m[1]] && !s.isKnownWord(m[1]) {
		vals := []string{m[1]}
		if m[2] != "" && !actorWords[m[2]] && !questionVocab[m[2]] {
			vals = append(vals, m[2])
		}
		op := "eq"
		if len(vals) > 1 {
			op = "in"
		}
		q.Filters = append(q.Filters, ast.Filter{Field: "actor", Op: op, Values: vals})
		s.e.phrase(strings.Join(vals, " "))
	}
	if s.e.re(regexp.MustCompile(`\b(?:which|what) (?:engineers?|people|users|admins?|persons?) (?:made|did|pushed)\b|\bwho (?:made|pushed) (?:the most )?changes\b`), s.text) {
		q.GroupBy = []string{"actor"}
	}
	if f := s.changeTypeFilter(); f != nil && !notTypeRe.MatchString(s.text) {
		q.Filters = append(q.Filters, *f)
	}
	if strings.Contains(s.text, "config backup") || strings.Contains(s.text, "backups were captured") {
		q.Filters = append(q.Filters, ast.Filter{Field: "source", Op: "eq", Values: []string{"config_capture"}})
	}
	if g := perRe.FindStringSubmatch(s.text); g != nil {
		dim := map[string]string{"site": "site", "actor": "actor", "person": "actor", "type": "type", "seam": "seam"}[g[1]]
		if dim != "" {
			q.GroupBy = []string{dim}
			s.e.phrase(g[0])
		}
	}
	// The incident on screen anchors "who changed it" / "what changed before this".
	if s.cx.IncidentID != "" && q.Time.Kind == "" && s.e.re(regexp.MustCompile(`\b(?:it|this|that|the incident|before this|before the incident|incident|he|she|they)\b`), s.text) {
		q.Time = ast.TimeRange{Kind: ast.TimeIncident, Anchor: &ast.Anchor{IncidentID: s.cx.IncidentID, Before: "30m", After: "10m"}}
	}
	return Result{Intent: "list_changes", AST: q, Entities: refs}, nil
}

// changeTypeFilter maps change-type words to the catalog's type/class values.
// isKnownWord reports a word the grammar gives meaning to elsewhere (a
// change-type word, a time word), so it is never taken as an actor name.
func (s *state) isKnownWord(w string) bool {
	st := &state{text: w + " changes"}
	return st.changeTypeFilter() != nil || regexp.MustCompile(`^(?:yesterday|today|week|hour|day|month|type|site|dallas|austin)$`).MatchString(w)
}

// changesAroundEveryIncident answers "what changed 30 minutes before every
// SD-WAN incident this week".
func (s *state) changesAroundEveryIncident() (Result, bool) {
	m := everyIncRe.FindStringSubmatch(s.text)
	if m == nil {
		return Result{}, false
	}
	s.e.phrase(m[0])
	unit := "m"
	if strings.HasPrefix(m[2], "h") {
		unit = "h"
	}
	set := &ast.IncidentSet{Time: s.time}
	if set.Time.Kind == "" {
		set.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "7d"}
	}
	if m[3] != "" {
		v := map[string]string{"internet": "isp", "dia": "isp"}[m[3]]
		if v == "" {
			v = m[3]
		}
		set.Filters = []ast.Filter{{Field: "seam_class", Op: "eq", Values: []string{v}}}
	}
	s.e.re(changeWords, s.text)
	q := &ast.AST{V: 1, Type: ast.ChangeList, Target: "change",
		Time:    ast.TimeRange{Kind: ast.TimeIncidents, Anchor: &ast.Anchor{Incidents: set, Before: m[1] + unit, After: "1m"}},
		OrderBy: []ast.OrderKey{{Field: "event_at", Dir: "desc"}}}
	return Result{Intent: "list_changes", AST: q}, true
}

func (s *state) changeTypeFilter() *ast.Filter {
	type rule struct {
		re    *regexp.Regexp
		field string
		value string
	}
	rules := []rule{
		{regexp.MustCompile(`\broute and network policy\b|\bwan (?:related )?changes?\b|\bwan policy\b`), "class", "wan"},
		{regexp.MustCompile(`\b(?:security policy|firewall|acls?)\b`), "type", "SECURITY_POLICY_CHANGE"},
		{regexp.MustCompile(`\b(?:routing|route|bgp policy|routing policy)\b`), "type", "ROUTE_CHANGE"},
		{regexp.MustCompile(`\b(?:sdwan policy|network policy|network change)\b`), "type", "NETWORK_CHANGE"},
		{regexp.MustCompile(`\bdns\b`), "type", "DNS_CHANGE"},
		{regexp.MustCompile(`\b(?:deploy(?:ed|ment|ments)?|release)\b`), "type", "APPLICATION_DEPLOY"},
		{regexp.MustCompile(`\bfeature flags?\b`), "type", "FEATURE_FLAG_CHANGE"},
		{regexp.MustCompile(`\bcloud\b`), "type", "CLOUD_CHANGE"},
		{regexp.MustCompile(`\b(?:config|configuration)\b`), "type", "CONFIG_CHANGE"},
		{regexp.MustCompile(`\b(?:infrastructure|infra)\b`), "class", "infrastructure"},
	}
	for _, r := range rules {
		if r.re.MatchString(s.text) && (s.e == nil || s.e.re(r.re, s.text)) {
			if strings.Contains(s.text, "config backup") && r.value == "CONFIG_CHANGE" {
				return nil
			}
			return &ast.Filter{Field: r.field, Op: "eq", Values: []string{r.value}}
		}
	}
	if seam := regexp.MustCompile(`\b(sdwan|vpn|dia|dx|cloud backbone) seam\b`); seam.MatchString(s.text) {
		v := strings.ToUpper(strings.ReplaceAll(seam.FindStringSubmatch(s.text)[1], " ", "_"))
		if s.e != nil {
			s.e.re(seam, s.text)
		}
		return &ast.Filter{Field: "seam", Op: "eq", Values: []string{v}}
	}
	return nil
}

// ---- incidents -----------------------------------------------------------------

func (s *state) incidents() (Result, error) {
	refs, clarify, err := s.mentions([]string{"site", "device", "application"})
	if err != nil {
		return Result{}, err
	}
	if len(clarify) > 0 {
		return Result{Intent: "list_incidents", Clarify: clarify}, nil
	}
	s.e.re(incidentWords, s.text)
	q := &ast.AST{V: 1, Type: ast.IncidentList, Target: "incident", Refs: astRefs(refs), Time: s.time,
		OrderBy: []ast.OrderKey{{Field: "created_at", Dir: "desc"}}, Limit: s.listLimit()}
	// Filter words inside an owner name ("cloud-team") are not filters.
	filterText := regexp.MustCompile(`(?:owned by|assigned to|owner is) \S+`).ReplaceAllString(s.text, " ")
	for _, r := range []struct {
		re           *regexp.Regexp
		field, value string
	}{
		{regexp.MustCompile(`\bopen\b|\bactive\b|\bongoing\b`), "state", "open"},
		{regexp.MustCompile(`\bclosed\b|\bresolved\b`), "state", "closed"},
		{regexp.MustCompile(`\bconfirmed\b`), "verdict_tier", "confirmed"},
		{regexp.MustCompile(`\bsuspected\b`), "verdict_tier", "suspected"},
		{regexp.MustCompile(`\bundetermined\b|\bno root cause\b|\bunexplained\b`), "verdict_tier", "undetermined"},
		{regexp.MustCompile(`\bsdwan\b`), "seam_class", "sdwan"},
		{regexp.MustCompile(`\bvpn\b`), "seam_class", "vpn"},
		{regexp.MustCompile(`\bcloud\b|\bdirect connect\b`), "seam_class", "cloud"},
		{regexp.MustCompile(`\binternet\b|\bisp\b|\bdia\b`), "seam_class", "isp"},
	} {
		if r.re.MatchString(filterText) && s.e.re(r.re, filterText) {
			q.Filters = append(q.Filters, ast.Filter{Field: r.field, Op: "eq", Values: []string{r.value}})
		}
	}
	if m := confRe.FindStringSubmatch(s.text); m != nil && s.e.re(confRe, s.text) {
		q.Filters = append(q.Filters, ast.Filter{Field: "top_confidence", Op: "gt", Values: []string{m[1]}})
	}
	if m := regexp.MustCompile(`(?:owned by|assigned to|owner is) ([a-z0-9&.-]+(?: [a-z0-9&.-]+){0,3})`).FindStringSubmatch(s.text); m != nil {
		var ow []string
		for _, w := range strings.Fields(m[1]) {
			if questionVocab[w] || w == "in" || w == "this" || w == "last" || w == "over" || w == "since" {
				break
			}
			ow = append(ow, w)
		}
		owner := strings.Join(ow, " ")
		s.e.phrase(m[0][:strings.Index(m[0], " ")] + " " + owner)
		s.e.re(regexp.MustCompile(`\b(?:owned by|assigned to|owner is)\b`), s.text)
		q.Filters = append(q.Filters, ast.Filter{Field: "owner", Op: "eq", Values: []string{owner}})
	}
	if g := perRe.FindStringSubmatch(s.text); g != nil {
		if dim := map[string]string{"owner": "owner", "seam": "seam_class", "seam class": "seam_class", "state": "state"}[g[1]]; dim != "" {
			q.GroupBy = []string{dim}
			s.e.phrase(g[0])
		}
	}
	if strings.HasPrefix(s.text, "what happened") {
		q.Limit = 5
	}
	return Result{Intent: "list_incidents", AST: q, Entities: refs}, nil
}

// ---- follow-ups ------------------------------------------------------------------

var (
	onlyRe        = regexp.MustCompile(`^(?:now\s+)?(?:only|just)\s+(.+?)(?:\s+changes?)?$`)
	compareRe     = regexp.MustCompile(`\bcompare (?:it|that|this|them) (?:with|to|against) (yesterday|last week|the previous \w+)`)
	lastNRe       = regexp.MustCompile(`^(?:show|now show|and)?\s*(?:me\s+)?(?:the\s+)?(?:last|past)\s+`)
	changedMostRe = regexp.MustCompile(`\bwhich (?:interfaces?|devices?|circuits?|sites?) changed (?:the )?most\b`)
)

// followUp rewrites the PRIOR query for a conversational refinement. It only
// fires when there is a prior query and the text is a recognised refinement.
func (c Compiler) followUp(ctx context.Context, text string, cx Context) (Result, bool, error) {
	p := cx.PriorAST
	if p == nil {
		return Result{}, false, nil
	}
	q := p.Clone()
	if q == nil {
		return Result{}, false, nil
	}
	switch {
	case compareRe.MatchString(text):
		if !q.Type.IsMetric() {
			return Result{}, false, nil
		}
		off := map[string]string{"yesterday": "1d", "last week": "7d"}[compareRe.FindStringSubmatch(text)[1]]
		if off == "" {
			off = "1d"
		}
		if q.Time.Kind == "" {
			q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}
		}
		ct := q.Time
		ct.Offset = off
		q.Type, q.CompareTo, q.Predicate, q.GroupBy = ast.CompareWindows, &ct, nil, nil
		return Result{Intent: "compare_windows", AST: q}, true, nil
	case changedMostRe.MatchString(text):
		if !q.Type.IsMetric() {
			return Result{}, false, nil
		}
		if q.Type != ast.CompareWindows {
			ct := q.Time
			if ct.Kind == "" {
				ct = ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}
				q.Time = ct
			}
			ct.Offset = "1d"
			q.Type, q.CompareTo = ast.CompareWindows, &ct
		}
		q.OrderBy, q.Limit = []ast.OrderKey{{Field: "delta", Dir: "desc"}}, 10
		return Result{Intent: "compare_windows", AST: q}, true, nil
	case lastNRe.MatchString(text) || strings.HasPrefix(text, "show the last") || strings.HasPrefix(text, "for the last"):
		if tp, ok := parseTime(text, cx.Now, cx.Loc); ok && len(strings.Fields(text)) <= 7 {
			if q.Time.Kind == ast.TimeIncidents && q.Time.Anchor != nil && q.Time.Anchor.Incidents != nil {
				// "show the last 30 days" over a per-incident query widens the
				// INCIDENT set, keeping each incident's own window.
				q.Time.Anchor.Incidents.Time = tp.tr
			} else {
				q.Time = tp.tr
			}
			return Result{Intent: "refine_time", AST: q}, true, nil
		}
	case onlyRe.MatchString(text):
		what := onlyRe.FindStringSubmatch(text)[1]
		st := &state{c: c, ctx: ctx, text: what, cx: cx}
		if q.Type == ast.ChangeList {
			st.text = what + " changes"
			if f := st.changeTypeFilter(); f != nil {
				q.Filters = replaceFilter(q.Filters, *f)
				return Result{Intent: "refine_filter", AST: q}, true, nil
			}
		}
		refs, _, err := st.mentions([]string{"site", "device", "circuit", "provider", "application"})
		if err != nil {
			return Result{}, true, err
		}
		if len(refs) == 1 {
			q.Refs = replaceRefType(q.Refs, ast.EntityRef{Type: refs[0].EntityType, ID: refs[0].EntityID})
			return Result{Intent: "refine_entity", AST: q, Entities: refs}, true, nil
		}
	}
	return Result{}, false, nil
}

func replaceFilter(fs []ast.Filter, f ast.Filter) []ast.Filter {
	var out []ast.Filter
	for _, x := range fs {
		if x.Field != f.Field && !(x.Field == "type" && f.Field == "class") && !(x.Field == "class" && f.Field == "type") {
			out = append(out, x)
		}
	}
	return append(out, f)
}

// replaceRefType swaps the ref of the same type (or adds it): "only Dallas"
// replaces the site, keeps the provider.
func replaceRefType(rs []ast.EntityRef, r ast.EntityRef) []ast.EntityRef {
	var out []ast.EntityRef
	for _, x := range rs {
		if x.Type != r.Type {
			out = append(out, x)
		}
	}
	return append(out, r)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
