// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// baseline_answer.go — Iris change assistance: take a before-change baseline of
// one device, and afterwards compare a fresh read against it ("what came back,
// what did not, which counts changed").
//
// Nothing here changes a device. The server seam (TroubleshootDeps.
// DeviceBaseline) reads the device with the closed read-only state battery and
// stores the baseline in the device's own tenant; every line this answer shows
// is an OBSERVED statement built by the server from typed rows — the answer
// never says why something changed, and no model writes it.
//
// The method — baseline before, verify after — is re-expressed from NetClaw's
// change-management skills (Apache-2.0, see NOTICE); their configuration-push
// step is deliberately not taken.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// upgradeReadinessSkill is the compiled method the upgrade_readiness route runs.
const upgradeReadinessSkill = "upgrade-readiness"

// Baseline operations.
const (
	BaselineTake    = "take"
	BaselineCompare = "compare"
)

// BaselineRequest is a validated baseline ask. DeviceID is a device reference
// the server resolves through the caller's own inventory.
type BaselineRequest struct {
	DeviceID string
	Op       string // BaselineTake | BaselineCompare
	Label    string
}

// BaselineReport is the server's answer: what it read and stored (take) or
// what changed against the newest baseline (compare). Lines are OBSERVED
// statements, worst first.
type BaselineReport struct {
	DeviceID   string
	DeviceName string
	Op         string
	// NotWired says why nothing was read (no live transport, no write access,
	// an unsupported platform, no baseline yet to compare with). Empty when
	// the read ran.
	NotWired string
	// The baseline taken (take) or compared against (compare).
	BaselineID    string
	BaselineAt    time.Time
	BaselineLabel string
	ReadAt        time.Time
	// Summary is the take card's one-line inventory ("5 interfaces, 3
	// routing neighbours, 10 routes, version 17.03.02").
	Summary string
	Lines   []string
	Changes int
	// NotRead names every section the read could not collect.
	NotRead []string
}

// maxBaselineLines bounds the rendered diff (the device page shows all of it).
const maxBaselineLines = 25

var (
	reBaselineWord    = regexp.MustCompile(`\b(baseline|snapshot|snap shot|before picture|pre[- ]?(change|upgrade|maintenance|mw) (state|check|capture|read))\b`)
	reBaselineTake    = regexp.MustCompile(`\b(take|taking|capture|grab|record|save|store|make|snap|baseline)\b`)
	reBaselineCompare = regexp.MustCompile(`\b(compare|comparing|comparison|diff|vs|versus|against|changed|came back|come back|still|missing|lost|post[- ]?(change|upgrade|maintenance|mw)|after (the |my |our )?(change|upgrade|maintenance|reload|work))\b`)
	// A traffic or metric baseline is the anomaly engine's idea, not a change
	// baseline: those questions keep their own routes.
	// "snapshot it so I can compare later" is a TAKE.
	reBaselineCompareLater = regexp.MustCompile(`\b((so (that )?(i|we) can|in order to|to) compare|compare (it |them )?later|for (comparison )?later)\b`)
	reMetricBaseline       = regexp.MustCompile(`\b(cpu|memory|traffic|latency|jitter|bandwidth|utili[sz]ation|throughput|anomal\w*|metric|kpi)\b`)
)

// classifyBaseline returns the baseline intent a question asks for, or "".
func classifyBaseline(q string) string {
	if !reBaselineWord.MatchString(q) || reMetricBaseline.MatchString(q) {
		return ""
	}
	switch {
	case reBaselineCompareLater.MatchString(q):
		return "baseline_take"
	case reBaselineCompare.MatchString(q):
		return "baseline_compare"
	case reBaselineTake.MatchString(q):
		return "baseline_take"
	}
	return ""
}

func baselinePlan(intent string, ent map[string]string) Plan {
	return Plan{Intent: intent, Modules: []string{"device_state"}, Mode: ModeDeviceBaseline,
		Entities: ent, Freshness: FreshnessLive}
}

// answerBaseline answers ModeDeviceBaseline.
func (o *Orchestrator) answerBaseline(ctx context.Context, p Principal, question string, plan Plan, uiContext map[string]string, disc []string) (Answer, error) {
	op := BaselineTake
	if plan.Intent == "baseline_compare" {
		op = BaselineCompare
	}
	base := Answer{Mode: ModeDeviceBaseline, Intent: plan.Intent, Modules: plan.Modules, Citations: []Citation{},
		ModeBadges: []string{"Change"}, Disclaimers: disc}
	if o.Troubleshoot.DeviceBaseline == nil {
		base.Mode = ModeUnavailable
		base.Text = "Change baselines aren't available on this deployment."
		base.Disclaimers = append(base.Disclaimers, "The device baseline store is not wired here.")
		return base, nil
	}
	ents := o.resolveSkillEntities(ctx, p, question, uiContext)
	device := firstNonEmpty(ents.values["device_id"], strings.TrimSpace(plan.Entities["device"]))
	if device == "" {
		if op == BaselineCompare {
			base.Text = "Which device should I compare with its baseline? Name it in the question, or ask from the device's page."
		} else {
			base.Text = "Which device should I take a baseline of? Name it in the question, or ask from the device's page."
		}
		return base, nil
	}
	rep, err := o.Troubleshoot.DeviceBaseline(ctx, p, BaselineRequest{DeviceID: device, Op: op})
	if errors.Is(err, ErrNotFound) {
		base.Text = fmt.Sprintf("Device %q isn't available in your scope.", promptLine(device))
		base.Disclaimers = append(base.Disclaimers, "Not found, or it belongs to another tenant.")
		return base, nil
	}
	if err != nil {
		return Answer{}, err
	}
	name := promptLine(firstNonEmpty(rep.DeviceName, rep.DeviceID))
	href := "#/infrastructure/devices?q=" + rep.DeviceID
	base.Citations = append(base.Citations, Citation{ID: "device:" + rep.DeviceID, Kind: "device", Label: name, Href: href})
	if rep.NotWired != "" {
		base.Text = promptLine(rep.NotWired)
		base.Disclaimers = append(base.Disclaimers, noDeviceChangeNote)
		return base, nil
	}
	var b strings.Builder
	switch op {
	case BaselineTake:
		fmt.Fprintf(&b, "Baseline of %s taken at %s: %s.", name, rep.BaselineAt.UTC().Format("2006-01-02 15:04 UTC"), promptLine(rep.Summary))
		fmt.Fprintf(&b, "\nAfter your change, ask me to compare %s with its baseline, or use Compare with baseline on the device page.", name)
		base.Citations = append(base.Citations, baselineCitation(rep, name, href))
	default:
		label := ""
		if rep.BaselineLabel != "" {
			label = " (" + promptLine(rep.BaselineLabel) + ")"
		}
		fmt.Fprintf(&b, "Compared %s now with its baseline from %s%s:", name, rep.BaselineAt.UTC().Format("2006-01-02 15:04 UTC"), label)
		lines := rep.Lines
		if len(lines) > maxBaselineLines {
			lines = lines[:maxBaselineLines]
		}
		for _, l := range lines {
			b.WriteString("\n• " + promptLine(l))
		}
		if len(rep.Lines) > len(lines) {
			fmt.Fprintf(&b, "\n• %d more lines are on the device page.", len(rep.Lines)-len(lines))
		}
		base.Citations = append(base.Citations, baselineCitation(rep, name, href),
			Citation{ID: "device_state:" + rep.DeviceID + ":" + rep.ReadAt.UTC().Format(time.RFC3339), Kind: "device",
				Label: "Read of " + name + " at " + rep.ReadAt.UTC().Format("15:04 UTC"), Href: href, Class: ClassObserved})
	}
	base.Text = b.String()
	for _, n := range rep.NotRead {
		base.Disclaimers = append(base.Disclaimers, "Not read: "+promptLine(n)+".")
	}
	base.Disclaimers = append(base.Disclaimers, noDeviceChangeNote)
	return base, nil
}

// noDeviceChangeNote closes every baseline answer.
const noDeviceChangeNote = "Nothing on the device was changed: only read-only show commands ran."

func baselineCitation(rep BaselineReport, name, href string) Citation {
	return Citation{ID: "baseline:" + rep.BaselineID, Kind: "baseline",
		Label: "Baseline of " + name + ", " + rep.BaselineAt.UTC().Format("2006-01-02 15:04 UTC"), Href: href, Class: ClassObserved}
}
