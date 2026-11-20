// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// upgrade_answer.go — "how do I upgrade a Catalyst 9300?": Iris shows Correlix's
// built-in upgrade procedure for that platform family (internal/upgrademop), step
// by step, with the public document it was written from.
//
// READ-ONLY (owner decision 2026-11-18). The procedure is for a PERSON: every step
// says the engineer performs it, and names the read-only show command Iris can run
// to confirm it. Iris runs none of the steps. The platform comes from the
// question, else from a device the question or the screen names (resolved through
// the caller's own inventory); with neither, Iris lists the procedures it has
// rather than guessing.

import (
	"context"
	"fmt"
	"strings"

	"netops/backend/internal/upgrademop"
	"netops/backend/internal/vendorprofile"
)

// answerUpgradeProcedure answers ModeUpgradeProcedure.
func (o *Orchestrator) answerUpgradeProcedure(ctx context.Context, p Principal, question string, plan Plan, disc []string) (Answer, error) {
	base := Answer{Mode: ModeUpgradeProcedure, Intent: "upgrade_procedure", Modules: []string{"network_expert_kb"},
		Title: "Upgrade procedure", Citations: []Citation{}, ModeBadges: []string{"Procedure", "Read-only"},
		EvidenceOnly: true}

	// The device's own platform label (e.g. "Catalyst 9300") is matched like the
	// question's words, and its vendor profile id as the fallback.
	dialect, device, cueText := "", "", question
	if ref := strings.TrimSpace(plan.Entities["device"]); ref != "" && o.Troubleshoot.ResolveDevice != nil {
		if d, err := o.Troubleshoot.ResolveDevice(ctx, p, ref); err == nil && d.ID != "" {
			device = firstNonEmpty(d.Name, ref)
			dialect = deviceDialect(d)
			cueText = question + "\n" + d.Platform
		}
	}
	tpl, ok := upgrademop.Match(cueText, dialect)
	if !ok {
		var b strings.Builder
		b.WriteString("Iris has step-by-step upgrade procedures for these platforms — say which one you are upgrading:\n")
		for _, t := range upgrademop.All() {
			fmt.Fprintf(&b, "• %s %s — %s\n", t.Vendor, t.Family, t.AppliesTo)
		}
		b.WriteString("Each one is for an engineer to follow; Iris runs only the read-only checks.")
		base.Text = b.String()
		base.Disclaimers = append(disc, NoActionNotice)
		return base, nil
	}

	docCite := "doc:upgrade:" + tpl.Name
	base.Title = tpl.Title
	base.Citations = append(base.Citations, Citation{ID: docCite, Kind: "knowledge",
		Label: tpl.Doc.Title + " (" + tpl.Doc.Version + ")", Href: tpl.Doc.URL, Class: ClassDocumentation})

	var st []Statement
	say := func(class, text string, cites ...string) {
		st = append(st, Statement{Text: text + "\n", Class: class, Grounded: true, Citations: cites})
	}
	if device != "" {
		say(ClassObserved, fmt.Sprintf("%s runs %s %s, so this is its procedure.", device, tpl.Vendor, tpl.Family))
	}
	say(ClassDocumentation, tpl.Intro, docCite)
	for i, s := range tpl.Steps {
		say(ClassDocumentation, fmt.Sprintf("%d. %s", i+1, s.StepLine()), docCite)
	}
	say(ClassDocumentation, fmt.Sprintf("Written in Correlix's own words from %s (%s, read %s): %s",
		tpl.Doc.Title, tpl.Doc.Version, tpl.Doc.Read, tpl.Doc.URL), docCite)

	var b strings.Builder
	for _, s := range st {
		b.WriteString(s.Text)
	}
	base.Text = strings.TrimSpace(b.String())
	base.Statements = st
	base.Disclaimers = append(disc, NoActionNotice,
		"Iris never runs these steps: the engineer performs every change. Check the release notes for your exact model and release first; commands differ between releases.",
		"To make it your team's runbook, adopt it under Administration → Iris → Knowledge → Runbooks → Vendor procedures.")
	return base, nil
}

// deviceDialect maps a resolved device's vendor and platform onto a vendor
// profile id ("cisco/ios_xe", "juniper/junos", …) through the vendor registry —
// the one vendor vocabulary — or "" when no profile claims the label.
func deviceDialect(d DeviceRef) string {
	label := strings.TrimSpace(d.Vendor + " " + d.Platform)
	if p, ok := vendorprofile.Default().ProfileForPlatformText(label); ok {
		return p.ID
	}
	return ""
}
