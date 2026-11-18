// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// change_review.go — "review this change plan" / "is CHG0012345 ready?": Iris
// checks a proposed change for readiness. READ-ONLY change assistance (owner
// decision 2026-11-18, "will go with readonly"): Iris reads the plan and the
// caller's own network, and recommends. It never changes a device, never opens or
// edits a ticket, and every answer says "No action has been executed."
//
// THE PLAN IS DATA. It arrives pasted in the question (at most 8 KB) or read from
// the workspace's own ITSM connection by its ticket reference (one GET through
// TroubleshootDeps.ChangeTicket). Either way it is customer-written text: it is
// matched against a closed checklist by the server, quoted back only inside
// quotation marks and labelled as quoted, and never sent to a model as
// instructions — this arm makes no model call at all (§15 LLM01).
//
// THE CHECKLIST (closed): scope — the devices the plan names, resolved through
// the CALLER's inventory (§3a: another tenant's device is simply not found);
// pre-checks; success checks; rollback; a maintenance window; then, from the
// caller's own network, what the change could disturb (neighbours and paths),
// active incidents and recent configuration changes on the named devices, and
// whether a baseline was taken. NetClaw's change-review method is the idea
// (re-expressed in Correlix's own words; Apache-2.0, see NOTICE); the evidence is
// Correlix's.
//
// source: https://github.com/automateyournetwork/netclaw/blob/cfafa46c3227356ca6ef38261fa9c1f4ba4711cb/workspace/skills/jev-change-review/SKILL.md
//
// Why a deterministic arm and not a compiled skill: a skill narrates its
// evidence through a model, and the question — here, the customer's plan — rides
// in that prompt. Keeping the review server-side means the plan is never model
// input at all.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MaxChangePlanBytes bounds a pasted plan (§15 LLM04).
const MaxChangePlanBytes = 8 << 10

// Caps on what one review reads.
const (
	maxReviewCandidates = 20
	maxReviewDevices    = 10
	maxQuoteChars       = 140
)

// ErrChangeTicketUnavailable: the workspace has no connection for the system the
// reference belongs to.
var ErrChangeTicketUnavailable = errors.New("no ticketing connection is configured for that system")

// ChangeTicket is a change record read from the caller's ITSM system. Every text
// field is customer-written and untrusted.
type ChangeTicket struct {
	Ref                string
	System             string // "servicenow" | "jira"
	Title              string
	Description        string
	ImplementationPlan string
	BackoutPlan        string
	TestPlan           string
	Risk               string
	State              string
	Start              string
	End                string
}

// The checklist (closed).
const (
	ChangeCheckScope    = "scope"
	ChangeCheckPre      = "pre_checks"
	ChangeCheckSuccess  = "success_checks"
	ChangeCheckRollback = "rollback"
	ChangeCheckWindow   = "window"
)

// changeCheckOrder is the order a review reports the plan items in.
var changeCheckOrder = []string{ChangeCheckPre, ChangeCheckSuccess, ChangeCheckRollback, ChangeCheckWindow}

var changeCheckLabel = map[string]string{
	ChangeCheckScope:    "Scope",
	ChangeCheckPre:      "Pre-checks",
	ChangeCheckSuccess:  "Success checks",
	ChangeCheckRollback: "Rollback",
	ChangeCheckWindow:   "Maintenance window",
}

// changeCheckAdvice is the recommendation when an item is missing.
var changeCheckAdvice = map[string]string{
	ChangeCheckPre:      "Add pre-checks: what is confirmed before the change starts (device health, no active incident, a baseline of interfaces, neighbours and routes).",
	ChangeCheckSuccess:  "Add success checks: how you will know the change worked (what is compared with the baseline, and what must match before the change is closed).",
	ChangeCheckRollback: "Add a rollback: the exact steps that undo the change, and the point at which you stop and roll back.",
	ChangeCheckWindow:   "State the maintenance window: the date, start and end time with the time zone, and who approved it.",
}

var (
	reChangePre      = regexp.MustCompile(`(?i)\b(pre[- ]?(checks?|change|validation|flight)|before (the )?(change|window|work|upgrade|reload|cut ?over)|baseline|health ?checks?|capture (the )?(current )?(state|config(uration)?))\b`)
	reChangeSuccess  = regexp.MustCompile(`(?i)\b(post[- ]?(checks?|change|validation)|success (criteria|checks?)|validat(e|ion)|verif(y|ication)|test plan|confirm (that|the)|after (the )?(change|upgrade|reload|window|cut ?over))\b`)
	reChangeRollback = regexp.MustCompile(`(?i)\b(roll ?back|back ?out|revert|fall ?back|restore (the )?(previous|prior|old|backup|saved) ?(config(uration)?|image|release|version)?)\b`)
	reChangeWindow   = regexp.MustCompile(`(?i)(\b(maintenance|change) window\b|\b\d{1,2}:\d{2}\b|\b\d{4}-\d{2}-\d{2}\b|\b(utc|gmt|est|edt|cst|cdt|pst|pdt|cet|ist)\b|\b(mon|tues|wednes|thurs|fri|satur|sun)day\b|\btonight\b)`)

	// A ServiceNow change number, or a Jira-style key the operator calls a
	// ticket/change/issue (a bare "SW-12" is far more often a device name).
	reChangeSnowRef = regexp.MustCompile(`\bCHG\d{4,12}\b`)
	reChangeJiraRef = regexp.MustCompile(`(?i)\b(?:ticket|change|issue|jira|cr)\s+#?([A-Za-z][A-Za-z0-9]{1,9}-\d{1,9})\b`)
	reJiraKeyShape  = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}-\d{1,9}$`)

	// A word that could be a device name: letters with digits, or joined by - _ .
	reHostCandidate = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)+\b|\b[A-Za-z]+\d+[A-Za-z0-9]*\b`)
	// Words that look like that and are not devices: versions, interfaces,
	// tickets, files and product names.
	reNotHost = regexp.MustCompile(`(?i)^(v?\d+(\.\d+)+[a-z]*|(gi|te|fo|hu|eth|ge|xe|et|ethernet|gigabitethernet|tengigabitethernet|port-channel|po|vlan|lo|loopback|tunnel|mgmt)[-/]?\d.*|chg\d+|inc\d+|[a-z]+\.(conf|bin|swi|tgz|txt|cfg|pkg)|ios-xe|ios_xe|nx-os|nx_os|ios-xr|junos|eos|ipv4|ipv6|mp-bgp|e-bgp|i-bgp|ebgp|ibgp|ospfv[23]|bfd|l2|l3|p1|p2|p3|p4|sev\d|tier\d|24h|48h|\d+[hms])$`)
)

// changePlan is the text a review reads, from the question or a ticket.
type changePlan struct {
	ticket *ChangeTicket
	text   string // every plan field joined, for the checklist and the scope
}

// changeTicketRef returns the change reference a question names, or "".
func changeTicketRef(question string) string {
	if m := reChangeSnowRef.FindString(question); m != "" {
		return m
	}
	if m := reChangeJiraRef.FindStringSubmatch(question); m != nil && reJiraKeyShape.MatchString(m[1]) {
		return m[1]
	}
	return ""
}

// quoteLine is the first line of text matching re, clipped and quoted — data,
// never an instruction.
func quoteLine(text string, re *regexp.Regexp) string {
	for _, line := range strings.Split(text, "\n") {
		if re.MatchString(line) {
			return quoteData(line)
		}
	}
	return ""
}

func quoteData(s string) string {
	s = promptLine(s)
	s = strings.NewReplacer("“", "\"", "”", "\"").Replace(s)
	if len(s) > maxQuoteChars {
		cut := maxQuoteChars
		for cut > 0 && !utf8RuneStart(s[cut]) {
			cut--
		}
		s = strings.TrimSpace(s[:cut]) + " …"
	}
	return "“" + s + "”"
}

// changeChecks evaluates the plan items of the closed checklist.
func changeChecks(plan changePlan) map[string]string {
	found := map[string]string{} // item → quoted evidence ("" = missing)
	if t := plan.ticket; t != nil {
		if strings.TrimSpace(t.BackoutPlan) != "" {
			found[ChangeCheckRollback] = "the ticket's backout plan: " + quoteData(t.BackoutPlan)
		}
		if strings.TrimSpace(t.TestPlan) != "" {
			found[ChangeCheckSuccess] = "the ticket's test plan: " + quoteData(t.TestPlan)
		}
		if strings.TrimSpace(t.Start) != "" && strings.TrimSpace(t.End) != "" {
			found[ChangeCheckWindow] = fmt.Sprintf("the ticket's planned window: %s to %s", quoteData(t.Start), quoteData(t.End))
		}
	}
	for item, re := range map[string]*regexp.Regexp{
		ChangeCheckPre: reChangePre, ChangeCheckSuccess: reChangeSuccess,
		ChangeCheckRollback: reChangeRollback, ChangeCheckWindow: reChangeWindow,
	} {
		if found[item] != "" {
			continue
		}
		if q := quoteLine(plan.text, re); q != "" {
			found[item] = "the plan: " + q
		}
	}
	return found
}

// hostCandidates returns the words of text that could name a device, in order,
// without repeats, capped.
func hostCandidates(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range reHostCandidate.FindAllString(text, -1) {
		w = strings.Trim(w, ".-_")
		k := strings.ToLower(w)
		if len(w) < 3 || len(w) > 64 || seen[k] || reNotHost.MatchString(w) || reJiraKeyShape.MatchString(w) && strings.Contains(text, "ticket") {
			continue
		}
		seen[k] = true
		out = append(out, w)
		if len(out) == maxReviewCandidates {
			break
		}
	}
	return out
}

// reviewedDevice is one device the plan names, with what the caller's own
// network says about it.
type reviewedDevice struct {
	ref       DeviceRef
	problems  []Problem
	changes   []DeviceChange
	changesNA string // why changes could not be read ("" = read)
	neighbors int
	paths     int
	topoRead  bool
	baseline  string // "" = not checked; "none" = none exists; else when it was taken
}

func deviceCiteID(d DeviceRef) string { return "device:" + d.ID }

func deviceCite(d DeviceRef) Citation {
	return Citation{ID: deviceCiteID(d), Kind: "device", Label: d.Name,
		Href: "#/infrastructure/devices?q=" + d.Name, Class: ClassObserved}
}

// changeReviewModule is the module whose permission a review needs to read the
// caller's incidents and device facts (the same gate the incident answers take).
const changeReviewModule = "correlations_rca"

// answerChangeReviewGoverned answers ModeChangeReview. Without permission to
// query the RCA module the plan's checklist is still reviewed, and the answer
// says the network was not read.
func (o *Orchestrator) answerChangeReviewGoverned(ctx context.Context, p Principal, question string) (Answer, error) {
	if d := o.policy().EvaluateModule(changeReviewModule, p); !d.Allow {
		return o.answerChangeReview(ctx, p, question, []string{"Iris did not read your network for this review: " + d.Reason + "."}, false)
	}
	return o.answerChangeReview(ctx, p, question, nil, true)
}

// answerChangeReview reviews the plan; network=false skips everything read from
// the caller's network (scope resolution, incidents, changes, topology).
func (o *Orchestrator) answerChangeReview(ctx context.Context, p Principal, question string, disc []string, network bool) (Answer, error) {
	base := Answer{Mode: ModeChangeReview, Intent: "change_review", Modules: []string{changeReviewModule},
		Title: "Change plan review", Citations: []Citation{}, ModeBadges: []string{"Change review", "Read-only"},
		EvidenceOnly: true}
	var st []Statement
	say := func(class string, grounded bool, text string, cites ...string) {
		st = append(st, Statement{Text: text + "\n", Class: class, Grounded: grounded, Citations: cites})
	}
	var recs []string
	recommend := func(text string, cites ...string) {
		say(ClassRecommendation, true, text, cites...)
		recs = append(recs, text)
	}
	finish := func() Answer {
		var b strings.Builder
		for _, s := range st {
			b.WriteString(s.Text)
		}
		base.Text = strings.TrimSpace(b.String())
		base.Statements = st
		base.NextActions = recs
		base.Disclaimers = append(disc, NoActionNotice,
			"Iris reviews a change; it never makes one. The plan's own text is quoted as data and was not sent to an AI model.")
		return base
	}

	// 1. The plan: a named ticket, else the question itself.
	plan := changePlan{text: question}
	planCite := "change-plan:question"
	if ref := changeTicketRef(question); ref != "" {
		if o.Troubleshoot.ChangeTicket == nil {
			say(ClassObserved, true, fmt.Sprintf("Iris can't read change tickets on this deployment, so %s was not opened.", ref))
			recommend("Paste the change plan into the question (up to 8 KB) and Iris reviews it against the checklist.")
			return finish(), nil
		}
		t, err := o.Troubleshoot.ChangeTicket(ctx, p, ref)
		switch {
		case errors.Is(err, ErrNotFound):
			say(ClassObserved, true, fmt.Sprintf("Change %s isn't in your workspace's ticketing system, or the connection's account can't see it.", ref))
			recommend("Check the reference, or paste the change plan into the question instead.")
			return finish(), nil
		case errors.Is(err, ErrChangeTicketUnavailable):
			say(ClassObserved, true, fmt.Sprintf("Your workspace has no ticketing connection that holds %s, so Iris could not read it.", ref))
			recommend("Connect the ticketing system under Administration, or paste the change plan into the question.")
			return finish(), nil
		case err != nil:
			say(ClassObserved, true, fmt.Sprintf("The ticketing system did not answer for %s, so the plan could not be read.", ref))
			recommend("Try again shortly, or paste the change plan into the question.")
			base.MissingEvidence = append(base.MissingEvidence, "the change ticket could not be read")
			return finish(), nil
		}
		t.Ref = ref
		plan.ticket = &t
		plan.text = strings.Join([]string{t.Title, t.Description, t.ImplementationPlan, t.BackoutPlan, t.TestPlan}, "\n")
		planCite = "ticket:" + ref
		base.Title = "Change plan review — " + ref
		base.Citations = append(base.Citations, Citation{ID: planCite, Kind: "ticket", Label: ref + " " + promptLine(t.Title), Class: ClassObserved})
		state := ""
		if s := strings.TrimSpace(t.State); s != "" {
			state = fmt.Sprintf(", state %s", quoteData(s))
		}
		say(ClassObserved, true, fmt.Sprintf("Reviewed change %s (%s%s), read from your ticketing system.", ref, quoteData(t.Title), state), planCite)
	} else {
		if len(question) > MaxChangePlanBytes {
			say(ClassObserved, true, fmt.Sprintf("The pasted plan is %d bytes; Iris reviews at most %d.", len(question), MaxChangePlanBytes))
			recommend("Paste the plan's steps, pre-checks, success checks, rollback and window only, or name its change ticket.")
			return finish(), nil
		}
		base.Citations = append(base.Citations, Citation{ID: planCite, Kind: "plan", Label: "The plan in your question", Class: ClassObserved})
		say(ClassObserved, true, "Reviewed the plan in your question against Iris's change checklist.", planCite)
	}

	// 2. The plan items.
	found := changeChecks(plan)
	missing := 0
	for _, item := range changeCheckOrder {
		if ev := found[item]; ev != "" {
			st = append(st, Statement{Text: fmt.Sprintf("%s: present — %s\n", changeCheckLabel[item], ev), Class: ClassObserved,
				Grounded: true, Citations: []string{planCite}, Note: "quoted from the plan as data"})
			continue
		}
		missing++
		recommend(changeCheckAdvice[item], planCite)
	}

	// 3. Scope: the devices the plan names, through the caller's own inventory.
	var devices []reviewedDevice
	var unresolved []string
	if network {
		devices, unresolved = o.reviewScope(ctx, p, plan.text)
	}
	switch {
	case !network:
		say(ClassObserved, true, "The devices the plan names were not checked against your network.")
	case o.Troubleshoot.ResolveDevice == nil:
		say(ClassObserved, true, "Iris can't check device names against the inventory on this deployment, so the scope was not verified.")
	case len(devices) == 0:
		missing++
		recommend("Name the devices the change touches, as they appear in Correlix, so Iris can check their incidents, recent changes and what depends on them.", planCite)
	default:
		names := make([]string, 0, len(devices))
		cites := []string{planCite}
		for _, d := range devices {
			names = append(names, d.ref.Name)
			base.Citations = append(base.Citations, deviceCite(d.ref))
			cites = append(cites, deviceCiteID(d.ref))
		}
		say(ClassObserved, true, fmt.Sprintf("%s: the plan names %s, found in your inventory.", changeCheckLabel[ChangeCheckScope], strings.Join(names, ", ")), cites...)
	}
	if len(unresolved) > 0 {
		recommend(fmt.Sprintf("Check these names in the plan: %s. They are not devices in your inventory, so Iris could not assess them.", strings.Join(quoteAll(unresolved), ", ")), planCite)
	}

	// 4. What the caller's own network says about each named device.
	conflicts, baselines := 0, 0
	for _, d := range devices {
		dc := deviceCiteID(d.ref)
		if d.topoRead {
			say(ClassObserved, true, fmt.Sprintf("%s has %s and %s through it; a disruption there reaches them.",
				d.ref.Name, plural(d.neighbors, "neighbour"), plural(d.paths, "measured path")), dc)
		}
		for _, pr := range d.problems {
			conflicts++
			pc := "problem:" + pr.ID
			base.Citations = append(base.Citations, Citation{ID: pc, Kind: "finding", Label: pr.Display(),
				Href: "#/monitoring/correlations?id=" + pr.ID, Class: ClassCorrelixRCA})
			say(ClassObserved, true, fmt.Sprintf("%s is part of an active incident: %s (%s).", d.ref.Name, pr.Display(), promptLine(pr.Title)), pc, dc)
			recommend(fmt.Sprintf("Hold the change on %s until %s is understood, or record in the plan why it is safe to go ahead.", d.ref.Name, pr.Display()), pc)
		}
		switch {
		case d.changesNA != "":
			say(ClassObserved, true, fmt.Sprintf("Recent configuration changes on %s could not be read: %s.", d.ref.Name, d.changesNA))
		case len(d.changes) > 0:
			conflicts++
			cc := "changes:" + d.ref.ID
			base.Citations = append(base.Citations, Citation{ID: cc, Kind: "change", Label: "Recent changes on " + d.ref.Name,
				Href: "#/infrastructure/devices?q=" + d.ref.Name, Class: ClassObserved})
			say(ClassObserved, true, fmt.Sprintf("%s changed configuration %s in the last 24 hours.", d.ref.Name, plural(len(d.changes), "time")), cc, dc)
			recommend(fmt.Sprintf("Confirm the recent changes on %s are finished and are not part of this one before the window.", d.ref.Name), cc)
		}
		switch d.baseline {
		case "", "none":
			recommend(fmt.Sprintf("Take a baseline of %s before the window — interface states, neighbours and route counts — so the result can be compared afterwards.", d.ref.Name), dc)
			baselines++
		default:
			say(ClassObserved, true, fmt.Sprintf("A baseline of %s was taken %s.", d.ref.Name, d.baseline), dc)
		}
	}

	// 5. The verdict, derived only from the items above. A missing baseline is
	// work before the window, not a gap in the plan, so it is said separately.
	then := ""
	if baselines > 0 {
		then = " Then take the " + plural(baselines, "baseline") + " above before the window."
	}
	if missing == 0 && conflicts == 0 && len(unresolved) == 0 {
		say(ClassDerived, true, "Every checklist item is present and nothing on the named devices conflicts with the change. Iris has not judged whether the change itself is correct."+then, planCite)
	} else {
		say(ClassDerived, true, fmt.Sprintf("Not ready yet: %s to address before scheduling.", plural(missing+conflicts+len(unresolvedOnce(unresolved)), "item"))+then, planCite)
	}
	return finish(), nil
}

func unresolvedOnce(u []string) []string {
	if len(u) == 0 {
		return nil
	}
	return u[:1] // the names are one recommendation
}

func quoteAll(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, quoteData(s))
	}
	return out
}

// reviewScope resolves the plan's device names through the CALLER's inventory and
// reads, for each one found, what the caller's own network says. unresolved lists
// names that look like devices and were not found (capped).
func (o *Orchestrator) reviewScope(ctx context.Context, p Principal, text string) ([]reviewedDevice, []string) {
	if o.Troubleshoot.ResolveDevice == nil {
		return nil, nil
	}
	var devices []reviewedDevice
	var unresolved []string
	seen := map[string]bool{}
	for _, cand := range hostCandidates(text) {
		ref, err := o.Troubleshoot.ResolveDevice(ctx, p, cand)
		if err != nil || ref.ID == "" {
			if looksLikeDeviceName(cand) && len(unresolved) < 5 {
				unresolved = append(unresolved, cand)
			}
			continue
		}
		if seen[ref.ID] {
			continue
		}
		seen[ref.ID] = true
		if ref.Name == "" {
			ref.Name = cand
		}
		devices = append(devices, reviewedDevice{ref: ref})
		if len(devices) == maxReviewDevices {
			break
		}
	}
	if len(devices) == 0 {
		return nil, unresolved
	}

	var active []Problem
	if o.DS != nil {
		if probs, err := o.DS.ListActiveProblems(ctx, p, 100); err == nil {
			active = probs
		}
	}
	for i := range devices {
		d := &devices[i]
		for _, pr := range active {
			if problemTouches(pr, d.ref) {
				d.problems = append(d.problems, pr)
			}
		}
		sort.SliceStable(d.problems, func(a, b int) bool { return PriorityScore(d.problems[a]) > PriorityScore(d.problems[b]) })
		if len(d.problems) > 3 {
			d.problems = d.problems[:3]
		}
		if o.Troubleshoot.RecentChanges == nil {
			d.changesNA = "configuration backup is not enabled on this deployment"
		} else {
			rep, err := o.Troubleshoot.RecentChanges(ctx, p, ChangeQuery{DeviceID: d.ref.ID, SinceSeconds: 86400, Limit: 20})
			switch {
			case err != nil:
				d.changesNA = "the change history did not answer"
			case rep.NotWired != "":
				d.changesNA = promptLine(rep.NotWired)
			default:
				d.changes = rep.Changes
			}
		}
		if o.Troubleshoot.TopologyContext != nil {
			if tc, err := o.Troubleshoot.TopologyContext(ctx, p, d.ref.ID); err == nil {
				d.topoRead, d.neighbors, d.paths = true, len(tc.Neighbors), len(tc.Paths)
			}
		}
		if o.Troubleshoot.DeviceBaselineAt != nil {
			d.baseline = "none"
			if at, ok, err := o.Troubleshoot.DeviceBaselineAt(ctx, p, d.ref.ID); err == nil && ok {
				d.baseline = "at " + at.UTC().Format("2006-01-02 15:04 UTC")
			}
		}
	}
	return devices, unresolved
}

// looksLikeDeviceName is the narrower test for reporting a name as unresolved:
// letters and digits joined by a separator ("core-sw-1", "edge_7").
func looksLikeDeviceName(s string) bool {
	return strings.ContainsAny(s, "-_") && strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
}

// problemTouches reports whether an incident involves the device.
func problemTouches(pr Problem, d DeviceRef) bool {
	for _, dev := range pr.Devices {
		if strings.EqualFold(dev, d.ID) || (d.Name != "" && strings.EqualFold(dev, d.Name)) {
			return true
		}
	}
	return false
}
