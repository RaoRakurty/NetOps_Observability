// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_probes.go — get_probe_results, the read of the caller's own
// synthetic probes (NetClaw ingestion Batch 3, 2026-11-13).
//
// A synthetic probe is a check the OPERATOR declared in Correlix (DNS, HTTP,
// TCP or ICMP, internal/dem) and that Correlix's own prober runs on a timer.
// This tool reads what those probes already measured — the per-run records the
// prober published — and folds each probe's recent runs into one line. Nothing
// is sent anywhere: it never starts a probe, never resolves a name itself, and
// never originates anything from a customer device (owner rule, 2026-11-13).
//
// WHY IT EXISTS. "The site is down but ping by IP works" is the classic name
// resolution signature, and until now Iris had no way to see the one piece of
// evidence that settles it: a DNS probe that is failing, and HOW it fails. A
// resolver that never answers (timeout) is a path problem to the resolver; a
// name the resolver says does not exist (nxdomain) is a record or zone change;
// a probe that resolves fine moves the question past name resolution.
//
// §3a: the seam reads ONE concrete tenant's catalogue and run rings — the same
// stores the Experience view reads. A caller with no concrete tenant (the
// platform scope) reads nothing and is told to pick a workspace, exactly as
// the DEM API refuses it; an operator-restricted workspace reads nothing.
//
// §15: every value is data. A destination or resolver that IS an address is
// never shown ("an address"), an HTTP destination is shown as scheme and host
// only (a path or query string can carry a token), lists are capped with the
// true totals, and the machine facts (state:probe, state:dns) are derived from
// the run OUTCOMES the server read — never from probe names or reasons.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProbeResults is the caller's synthetic probes, as the server read them.
type ProbeResults struct {
	// Scoped is false when no concrete workspace could be resolved (the
	// platform scope): nothing was read, and the answer must say why.
	Scoped bool
	// CollectionOn says the prober runs on this deployment (FEATURE_DEM).
	// With it off, the catalogue still exists but no probe has run.
	CollectionOn bool
	// Configured is how many probes the workspace has declared of ANY kind,
	// so "no DNS probe" can be told apart from "no probe at all".
	Configured int
	// Probes are the probes that matched the filter, ProbesTotal how many
	// matched before the cap.
	Probes      []ProbeSummary
	ProbesTotal int
	Notes       []string
}

// ProbeSummary is one probe and the fold of its recent runs.
type ProbeSummary struct {
	Name string
	Kind string // dns | http | tcp | icmp
	// Destination is what the probe checks, already made safe to show: ""
	// when it is an address (rendered as "an address").
	Destination string
	// ResolverPinned says a DNS probe uses a declared resolver rather than
	// the prober's system resolver; Resolver is its safe name ("" = address).
	ResolverPinned bool
	Resolver       string
	Site, App      string
	Paused         bool
	// Runs is how many recent runs were read; Success / Failure / Errors fold
	// them. Errors are the RUNNER failing, never the target failing.
	Runs, Success, Failure, Errors int
	// LastOutcome / LastReason are the most recent run's outcome and its
	// failure class (dns: nxdomain | timeout | dns; http/tcp: the class the
	// prober recorded). LastAt is when it ran.
	LastOutcome string
	LastReason  string
	LastAt      time.Time
	// MedianMs is the median duration of the successful runs (0 = none).
	MedianMs float64
	// Vantages is how many distinct probers measured it — one vantage is
	// never its own second opinion.
	Vantages int
}

// Probe kinds the tool accepts as a filter (internal/dem's closed set).
var probeKinds = map[string]bool{"dns": true, "http": true, "tcp": true, "icmp": true}

// Run outcomes (byte-identical to internal/dem's wire vocabulary).
const (
	probeRunSuccess = "success"
	probeRunFailure = "failure"
	probeRunError   = "error"
)

// DNS failure classes the prober records (collectors/dem.go classifyDNSErr).
const (
	probeReasonNXDomain = "nxdomain"
	probeReasonTimeout  = "timeout"
)

// maxProbeItems bounds the rendered probes.
const maxProbeItems = 20

// ProbeResultsCitationPrefix is the citation namespace of the probe items.
const ProbeResultsCitationPrefix = "prb:"

// ProbeQuery is the validated filter of one read.
type ProbeQuery struct {
	Kind   string // "" = every kind
	Site   string // "" = every site
	Target string // "" = every probe; else a probe name or id
}

type probeResultsTool struct{ deps TroubleshootDeps }

func (t probeResultsTool) Name() string            { return "get_probe_results" }
func (t probeResultsTool) Module() string          { return "telemetry" }
func (t probeResultsTool) Capability() Capability  { return CapRead }
func (t probeResultsTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t probeResultsTool) Freshness() Freshness    { return FreshnessRecent }

func (t probeResultsTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	q, err := probeQueryFromArgs(args)
	if err != nil {
		return ToolResult{}, err
	}
	res, err := t.deps.ProbeResults(ctx, p, q)
	if err != nil {
		return ToolResult{}, err
	}
	return RenderProbeResults(res, q), nil
}

// probeQueryFromArgs validates the three optional filters against closed
// shapes: a kind from the closed set, and a site / probe name of bounded,
// printable characters (names are operator-entered and may hold spaces).
func probeQueryFromArgs(args ToolArgs) (ProbeQuery, error) {
	var q ProbeQuery
	if v := strings.ToLower(strings.TrimSpace(args["kind"])); v != "" {
		if !probeKinds[v] {
			return ProbeQuery{}, fmt.Errorf("kind must be one of dns, http, tcp, icmp")
		}
		q.Kind = v
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"site", &q.Site}, {"target", &q.Target}} {
		v := strings.TrimSpace(args[f.name])
		if v == "" {
			continue
		}
		if len(v) > 128 {
			return ProbeQuery{}, fmt.Errorf("%s is too long (max 128 characters)", f.name)
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return ProbeQuery{}, fmt.Errorf("%s contains an unsupported character", f.name)
			}
		}
		*f.dst = v
	}
	return q, nil
}

// ProbeMatches reports whether one probe passes the query's filters. Exported
// for the server seam so the filter is defined once.
func (q ProbeQuery) ProbeMatches(id, name, kind, site string) bool {
	if q.Kind != "" && !strings.EqualFold(kind, q.Kind) {
		return false
	}
	if q.Site != "" && !strings.EqualFold(site, q.Site) {
		return false
	}
	if q.Target != "" && !strings.EqualFold(name, q.Target) && id != q.Target {
		return false
	}
	return true
}

// SafeProbeDestination renders what a probe checks without an address, a
// path or a query string: an address becomes "", an http(s) URL becomes its
// scheme and host, a host:port keeps its port.
func SafeProbeDestination(kind, host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if kind == "http" {
		u, err := url.Parse(host)
		if err != nil {
			// An unparseable destination is withheld, not guessed at: the line
			// then reads "checks an address", which is honest about not saying.
			return ""
		}
		if u.Host == "" {
			return "" // a URL with no host names nothing safe to show
		}
		h := u.Hostname()
		if h == "" || isAddressText(h) {
			return ""
		}
		out := u.Scheme + "://" + h
		if p := u.Port(); p != "" {
			out += ":" + p
		}
		return clampText(out, 120)
	}
	h, p := host, ""
	if hh, pp, err := net.SplitHostPort(host); err == nil {
		h, p = hh, pp
	}
	if isAddressText(h) || strings.ContainsAny(h, "/?#@ ") {
		return ""
	}
	if p == "" && port > 0 {
		p = strconv.Itoa(port)
	}
	if p != "" {
		return clampText(h+":"+p, 120)
	}
	return clampText(h, 120)
}

// probeSignals derives the machine facts of a probe read. A probe that has
// not run yet declares nothing about health: unmeasured is never passing.
//
//	state:probe  over every matched, unpaused probe with runs: passing | partial | failing,
//	             or none when the workspace has NO probe matching the filter
//	state:dns    over the matched DNS probes: resolving, or the WORST failure class
//	             (timeout > nxdomain > failing), or none when no DNS probe is declared
func probeSignals(res ProbeResults, q ProbeQuery) []string {
	if !res.Scoped {
		return nil
	}
	var out []string
	measured, failing := 0, 0
	dnsSeen, dnsMeasured := false, 0
	dnsTimeout, dnsNX, dnsFail := false, false, false
	for _, pr := range res.Probes {
		if pr.Kind == "dns" {
			dnsSeen = true
		}
		if pr.Paused || pr.LastOutcome == "" || pr.LastOutcome == probeRunError {
			continue // unmeasured or the runner broke: no fact about the target
		}
		measured++
		if pr.LastOutcome == probeRunFailure {
			failing++
		}
		if pr.Kind == "dns" {
			dnsMeasured++
			if pr.LastOutcome == probeRunFailure {
				switch pr.LastReason {
				case probeReasonTimeout:
					dnsTimeout = true
				case probeReasonNXDomain:
					dnsNX = true
				default:
					dnsFail = true
				}
			}
		}
	}
	switch {
	case res.ProbesTotal == 0 && len(res.Probes) == 0:
		out = append(out, CondStatePrefix+"probe=none")
	case measured == 0:
		// declared but not measured yet: no fact
	case failing == 0:
		out = append(out, CondStatePrefix+"probe=passing")
	case failing == measured:
		out = append(out, CondStatePrefix+"probe=failing")
	default:
		out = append(out, CondStatePrefix+"probe=partial")
	}
	if q.Kind == "" || q.Kind == "dns" {
		switch {
		case !dnsSeen && res.ProbesTotal <= len(res.Probes):
			// No DNS probe among the (uncapped) matches: none declared.
			out = append(out, CondStatePrefix+"dns=none")
		case dnsMeasured == 0:
			// declared but unmeasured (or capped out of view): no fact
		case dnsTimeout:
			out = append(out, CondStatePrefix+"dns=timeout")
		case dnsNX:
			out = append(out, CondStatePrefix+"dns=nxdomain")
		case dnsFail:
			out = append(out, CondStatePrefix+"dns=failing")
		default:
			out = append(out, CondStatePrefix+"dns=resolving")
		}
	}
	return out
}

// RenderProbeResults turns a probe read into bounded evidence.
func RenderProbeResults(res ProbeResults, q ProbeQuery) ToolResult {
	const href = "#/operations/digital-experience/synthetics"
	tr := ToolResult{}
	item := func(id, text string) {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: ProbeResultsCitationPrefix + id, Kind: "metric",
			Text: clampText(text, maxToolTextChars), Href: href,
		})
	}
	scope := "probes"
	if q.Kind != "" {
		scope = strings.ToUpper(q.Kind) + " probes"
	}
	if !res.Scoped {
		tr.Notes = append(tr.Notes, "no single workspace is in scope, so no synthetic probe was read — say the probe results are UNKNOWN and that they are read per workspace")
		return tr
	}
	if !res.CollectionOn {
		tr.Notes = append(tr.Notes, "synthetic probing is switched off on this deployment, so no probe has run — say probe results are UNKNOWN, never that the targets are healthy")
	}
	if len(res.Probes) == 0 {
		if res.Configured == 0 {
			item("none", "no synthetic probe is configured in this workspace, so nothing measures name resolution or service reachability from Correlix's own probers")
		} else {
			item("none", fmt.Sprintf("no %s match this question (%s configured in the workspace)", scope, plural(res.Configured, "probe")))
		}
		tr.Notes = append(tr.Notes, "with no probe to read, say what is NOT measured (name resolution, service reachability) and that a probe can be added on the Digital Experience page (Synthetics) — never infer the result")
		tr.Notes = append(tr.Notes, res.Notes...)
		tr.Signals = probeSignals(res, q)
		return tr
	}
	ps := append([]ProbeSummary(nil), res.Probes...)
	sort.SliceStable(ps, func(i, j int) bool { return probeRank(ps[i]) < probeRank(ps[j]) })
	if len(ps) > maxProbeItems {
		ps = ps[:maxProbeItems]
		tr.Truncated = true
	}
	for i, pr := range ps {
		item(strconv.Itoa(i+1), probeLine(pr))
	}
	if total := max(res.ProbesTotal, len(res.Probes)); total > len(ps) {
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d %s, failing first", len(ps), total, scope))
	}
	tr.Notes = append(tr.Notes,
		"a probe measures from Correlix's own prober, not from the users' machines — a passing probe says the service answered the prober, not that every user can reach it")
	tr.Notes = append(tr.Notes, res.Notes...)
	tr.Signals = probeSignals(res, q)
	return tr
}

// probeRank orders failing probes first, then unmeasured, then passing.
func probeRank(p ProbeSummary) int {
	switch {
	case p.LastOutcome == probeRunFailure:
		return 0
	case p.LastOutcome == probeRunError:
		return 1
	case p.LastOutcome == "" || p.Paused:
		return 2
	default:
		return 3
	}
}

// probeLine is one probe's rendered evidence.
func probeLine(p ProbeSummary) string {
	name := firstNonEmpty(clampText(p.Name, 80), "an unnamed probe")
	dest := firstNonEmpty(p.Destination, "an address")
	var b strings.Builder
	fmt.Fprintf(&b, "%s probe %q checks %s", strings.ToUpper(firstNonEmpty(p.Kind, "?")), name, dest)
	if p.Kind == "dns" {
		if p.ResolverPinned {
			b.WriteString(" through the pinned resolver " + firstNonEmpty(p.Resolver, "at an address"))
		} else {
			b.WriteString(" through the prober's system resolver")
		}
	}
	if site := safeLabel(p.Site); site != "" {
		b.WriteString(", site " + site)
	}
	if app := clampText(p.App, 60); app != "" {
		b.WriteString(", app " + app)
	}
	b.WriteString(": ")
	switch {
	case p.Paused:
		b.WriteString("paused, not measuring")
	case p.Runs == 0:
		b.WriteString("no run recorded yet — its result is UNKNOWN")
	default:
		last := "last run " + p.LastOutcome
		if p.LastOutcome == probeRunFailure && p.LastReason != "" {
			last += " (" + probeReasonHuman(p.Kind, p.LastReason) + ")"
		}
		if p.LastOutcome == probeRunError {
			last += " (the prober itself failed — not a result about the target)"
		}
		if !p.LastAt.IsZero() {
			last += " at " + p.LastAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "%s; %d of %d recent runs succeeded", last, p.Success, p.Runs)
		if p.Errors > 0 {
			fmt.Fprintf(&b, ", %d prober errors", p.Errors)
		}
		if p.MedianMs > 0 {
			fmt.Fprintf(&b, ", median %.0f ms when it succeeds", p.MedianMs)
		}
		if p.Vantages == 1 {
			b.WriteString(", from one prober")
		} else if p.Vantages > 1 {
			fmt.Fprintf(&b, ", from %d probers", p.Vantages)
		}
	}
	return b.String()
}

// probeReasonHuman renders a failure class in words. Unknown classes are
// passed through clamped: they are prober-written, never device or user text.
func probeReasonHuman(kind, reason string) string {
	switch reason {
	case probeReasonNXDomain:
		return "the resolver answered that the name does not exist"
	case probeReasonTimeout:
		if kind == "dns" {
			return "the resolver did not answer in time"
		}
		return "no answer in time"
	case "dns":
		if kind == "dns" {
			return "the resolver returned an error"
		}
		return "the name did not resolve"
	}
	return clampText(reason, 40)
}
