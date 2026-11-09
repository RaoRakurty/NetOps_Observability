// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Delta is what changed between two reports, named.
type Delta struct {
	// Fingerprint lists each input that moved ("prompts: problem").
	Fingerprint []string `json:"fingerprint,omitempty"`
	// Pins lists version pins that differ. A mismatch is reported, never
	// substituted.
	Pins []string `json:"pins,omitempty"`
	// ModelLeg is set when the two runs used different legs.
	ModelLeg string `json:"model_leg,omitempty"`
	// Added and Removed are cases on one side only.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	// Cases lists every case that differs and how.
	Cases []CaseDelta `json:"cases,omitempty"`
	// Regressed lists the cases that went from a pass to anything else.
	Regressed []string `json:"regressed,omitempty"`
	// Identical is true when nothing differs but timing.
	Identical bool `json:"identical"`
}

// CaseDelta is one case's differences.
type CaseDelta struct {
	ID      string   `json:"id"`
	Changes []string `json:"changes"`
}

// ReadReport strictly decodes a report.
func ReadReport(raw []byte) (Report, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return Report{}, fmt.Errorf("report: %w", err)
	}
	if r.SchemaVersion == 0 {
		return Report{}, errors.New("report: no schema_version")
	}
	return r, nil
}

// Compare produces the delta from a to b.
func Compare(a, b Report) (Delta, error) {
	if a.SchemaVersion != b.SchemaVersion {
		return Delta{}, fmt.Errorf("the reports have different schemas (%d and %d); a difference would be the format", a.SchemaVersion, b.SchemaVersion)
	}
	d := Delta{Fingerprint: compareFingerprints(a.Fingerprint, b.Fingerprint)}
	if a.ModelLeg != b.ModelLeg {
		d.ModelLeg = a.ModelLeg + " -> " + b.ModelLeg
	}
	byID := map[string]*CaseReport{}
	for i := range a.Cases {
		byID[a.Cases[i].ID] = &a.Cases[i]
	}
	seen := map[string]bool{}
	for i := range b.Cases {
		cb := &b.Cases[i]
		seen[cb.ID] = true
		ca, ok := byID[cb.ID]
		if !ok {
			d.Added = append(d.Added, cb.ID)
			continue
		}
		d.Pins = append(d.Pins, comparePins(ca, cb)...)
		if ch := compareCase(ca, cb); len(ch) > 0 {
			d.Cases = append(d.Cases, CaseDelta{ID: cb.ID, Changes: ch})
		}
		if ca.Result == ResultPass && cb.Result != ResultPass {
			d.Regressed = append(d.Regressed, cb.ID)
		}
	}
	for i := range a.Cases {
		if !seen[a.Cases[i].ID] {
			d.Removed = append(d.Removed, a.Cases[i].ID)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	d.Identical = len(d.Fingerprint)+len(d.Pins)+len(d.Added)+len(d.Removed)+len(d.Cases) == 0 && d.ModelLeg == ""
	return d, nil
}

func compareFingerprints(a, b Fingerprint) []string {
	if a.SHA256 == b.SHA256 {
		return nil
	}
	comps := map[string]bool{}
	for c := range a.Items {
		comps[c] = true
	}
	for c := range b.Items {
		comps[c] = true
	}
	var out []string
	for comp := range comps {
		names := map[string]bool{}
		for n := range a.Items[comp] {
			names[n] = true
		}
		for n := range b.Items[comp] {
			names[n] = true
		}
		for n := range names {
			av, aok := a.Items[comp][n]
			bv, bok := b.Items[comp][n]
			switch {
			case !aok:
				out = append(out, comp+": added "+n)
			case !bok:
				out = append(out, comp+": removed "+n)
			case av != bv:
				out = append(out, comp+": changed "+n)
			}
		}
	}
	sort.Strings(out)
	return out
}

func comparePins(a, b *CaseReport) []string {
	var out []string
	cur := map[string]PinCheck{}
	for _, p := range a.Pins {
		cur[p.Field] = p
	}
	for _, p := range b.Pins {
		q, ok := cur[p.Field]
		if ok && (q.Case != p.Case || q.Current != p.Current) {
			out = append(out, fmt.Sprintf("%s %s: case %q reader %q -> case %q reader %q", b.ID, p.Field, q.Case, q.Current, p.Case, p.Current))
		}
	}
	return out
}

// compareCase names each measure that moved. Latency is left out: it is the
// machine's, not the case's, and a report's Latency field carries it.
func compareCase(a, b *CaseReport) []string {
	var out []string
	note := func(what string, x, y any) {
		if !reflect.DeepEqual(x, y) {
			out = append(out, fmt.Sprintf("%s: %s -> %s", what, render(x), render(y)))
		}
	}
	note("result", a.Result, b.Result)
	note("rca.agreement", a.RCA.Agreement, b.RCA.Agreement)
	note("rca.shipped_verdict", a.RCA.ShippedVerdict, b.RCA.ShippedVerdict)
	note("rca.stored_leading", a.RCA.StoredLeading, b.RCA.StoredLeading)
	note("rca.contradicting", a.RCA.Contradicting, b.RCA.Contradicting)
	note("evidence.citations", a.Evidence.Citations, b.Evidence.Citations)
	note("evidence.required_missing", a.Evidence.RequiredMissing, b.Evidence.RequiredMissing)
	note("evidence.forbidden_present", a.Evidence.ForbiddenPresent, b.Evidence.ForbiddenPresent)
	note("evidence.stripped", a.Evidence.Stripped, b.Evidence.Stripped)
	note("evidence.forbidden_in_answer", a.Evidence.ForbiddenInAnswer, b.Evidence.ForbiddenInAnswer)
	note("evidence.forbidden_in_prompts", a.Evidence.ForbiddenInPrompts, b.Evidence.ForbiddenInPrompts)
	note("tools.sequence", a.Tools.Sequence, b.Tools.Sequence)
	note("tools.not_registered", a.Tools.NotRegistered, b.Tools.NotRegistered)
	note("tools.prohibited_ran", a.Tools.ProhibitedRan, b.Tools.ProhibitedRan)
	note("cost.status", a.Cost.Status, b.Cost.Status)
	note("cost.provider_calls", a.Cost.ProviderCalls, b.Cost.ProviderCalls)
	note("cost.input_tokens", a.Cost.InputTokens, b.Cost.InputTokens)
	note("cost.output_tokens", a.Cost.OutputTokens, b.Cost.OutputTokens)
	note("cost.usd", a.Cost.USD, b.Cost.USD)
	note("claims.unsupported", a.Claims.Unsupported, b.Claims.Unsupported)
	note("claims.ungrounded", a.Claims.Ungrounded, b.Claims.Ungrounded)
	note("claims.overclaim_hits", a.Claims.OverclaimHits, b.Claims.OverclaimHits)
	note("claims.guard_firings", a.Claims.GuardFirings, b.Claims.GuardFirings)
	note("audit.complete", a.Audit.Complete, b.Audit.Complete)
	note("answer", a.AnswerSHA256, b.AnswerSHA256)
	note("prompts", a.PromptsSHA256, b.PromptsSHA256)
	return out
}

func render(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// DeltaMarkdown renders a delta.
func DeltaMarkdown(d Delta) string {
	var b strings.Builder
	b.WriteString("# Iris replay comparison\n\n")
	if d.Identical {
		b.WriteString("Nothing changed but timing.\n")
		return b.String()
	}
	section := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		fmt.Fprintf(&b, "## %s\n\n", title)
		for _, l := range lines {
			fmt.Fprintf(&b, "- %s\n", l)
		}
		b.WriteString("\n")
	}
	section("Inputs that changed", d.Fingerprint)
	section("Version pins that differ (reported, never substituted)", d.Pins)
	if d.ModelLeg != "" {
		section("Model leg", []string{d.ModelLeg})
	}
	section("Regressions", d.Regressed)
	section("Cases added", d.Added)
	section("Cases removed", d.Removed)
	for _, c := range d.Cases {
		section("Case "+c.ID, c.Changes)
	}
	return b.String()
}

// Markdown renders a report.
func Markdown(r Report) string {
	var b strings.Builder
	a := r.Aggregate
	fmt.Fprintf(&b, "# Iris replay report\n\nGenerated %s. Model leg: %s. Fingerprint `%s`.\n\n", r.GeneratedAt, r.ModelLeg, r.Fingerprint.SHA256)
	b.WriteString("## What this run does not prove\n\n")
	for _, l := range r.Limits {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	b.WriteString("\n## Summary\n\n| Measure | Value |\n|---|---|\n")
	row := func(k string, v any) { fmt.Fprintf(&b, "| %s | %v |\n", k, v) }
	row("cases", a.Cases)
	row("pass / xfail / fail / xpass", fmt.Sprintf("%d / %d / %d / %d", a.Results[ResultPass], a.Results[ResultXFail], a.Results[ResultFail], a.Results[ResultXPass]))
	row("pass by split (dev, held-out)", fmt.Sprintf("%d of %d, %d of %d", a.PassBySplit["dev"], a.Splits["dev"], a.PassBySplit["heldout"], a.Splits["heldout"]))
	row("RCA agreement (non-gating)", fmt.Sprintf("%d of %d", a.RCAAgree, a.RCAChecked))
	row("tool calls", a.ToolCalls)
	row("requests for unregistered tools", a.NotRegistered)
	row("prohibited tools that ran", a.ProhibitedRan)
	row("citations stripped by VerifyGrounding", a.CitationsStrip)
	row("unsupported statements", a.Unsupported)
	row("overclaim vocabulary hits", a.OverclaimHits)
	row("incomplete audit records", a.AuditIncomplete)
	row("version pin mismatches", a.PinMismatches)
	row("provider calls", a.ProviderCalls)
	row("cases with measured tokens", a.TokensMeasured)
	row("cases with censored cost", a.CostCensored)
	row("live data moved since the decision", a.LiveDataMoved)
	row("latency total (ms, this machine, no provider)", a.LatencyTotalMS)
	b.WriteString("\n## Cases\n\n| Case | Result | Split | RCA | Citations | Stripped | Tools | Not registered | Unsupported | Overclaim | Cost |\n|---|---|---|---|---|---|---|---|---|---|---|\n")
	for i := range r.Cases {
		c := &r.Cases[i]
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %d | %d | %d | %d | %d | %s |\n", c.ID, c.Result, c.Split, c.RCA.Agreement,
			c.Evidence.Citations, c.Evidence.Stripped, c.Tools.Ran, len(c.Tools.NotRegistered), c.Claims.Unsupported, len(c.Claims.OverclaimHits), c.Cost.Status)
	}
	b.WriteString("\n")
	for i := range r.Cases {
		c := &r.Cases[i]
		if len(c.Failures)+len(c.Findings)+len(c.Provenance) == 0 {
			continue
		}
		fmt.Fprintf(&b, "### %s\n\n", c.ID)
		for _, l := range c.Provenance {
			fmt.Fprintf(&b, "- provenance: %s\n", l)
		}
		for _, l := range c.Findings {
			fmt.Fprintf(&b, "- finding: %s\n", l)
		}
		for _, l := range c.Failures {
			fmt.Fprintf(&b, "- failure: %s\n", l)
		}
		b.WriteString("\n")
	}
	return b.String()
}
