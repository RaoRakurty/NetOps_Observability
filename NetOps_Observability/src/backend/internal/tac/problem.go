package tac

// problem.go — Correlix's PROBLEM STATEMENT: what happened, when, what was
// checked, what was ruled out, and where TAC should look first.
//
// It is the single most valuable page in the bundle and the one most likely to
// be wrong, so it is built under one rule and one rule only:
//
//	EVERY CLAIM CARRIES AN EVIDENCE ID.
//
// A sentence that asserts something about the network must cite an item that is
// IN THIS BUNDLE — [A1] an alert, [H2] a hypothesis, [C3] a captured command,
// [L4] a log excerpt, [F5] a finding, [T6] a topology fact. A sentence that
// cites nothing is not "unsupported", it is REMOVED. That is what makes the
// statement safe to hand to a stranger who will act on it.
//
// §15 (LLM). Iris may WRITE this text, and Iris never chooses what goes into it.
// The evidence set is closed and assembled by this package from data the caller
// already owns; the instruction is server-controlled and cannot be influenced by
// a request; the model's output is treated as UNTRUSTED and is accepted only if
// every claim line cites an id that was actually in the input and cites NO id
// that was not. Anything else — a refusal, a timeout, a fabricated citation, an
// uncited claim — falls back to the deterministic template, silently to the
// operator's workflow but recorded honestly in the MANIFEST. There is no tool
// loop, no retrieval, no device access, and no way for model output to become a
// command.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// EvidenceItem is one citable fact in the bundle.
type EvidenceItem struct {
	// ID is the citation token, e.g. "A1", "H2", "C3". Assigned by this package.
	ID string `json:"id"`
	// Kind is one of: alert | hypothesis | command | log | finding | topology |
	// incident | device.
	Kind string `json:"kind"`
	// Ref is the underlying identifier (alert name, template id, intent, …).
	Ref string `json:"ref"`
	// Text is the fact itself, already redacted, clipped for the prompt.
	Text string `json:"text"`
	// At is when the fact is dated, when it is dated at all.
	At time.Time `json:"at,omitzero"`
}

// ProblemInput is everything the statement is written from.
type ProblemInput struct {
	TenantID     string
	IncidentID   string
	IncidentRef  string // the operator-facing handle (INC-3FA2C1 / problem id)
	Title        string
	WindowStart  time.Time
	WindowEnd    time.Time
	Hostname     string
	Platform     string
	DialectLabel string
	Class        Classification
	Plan         *Plan
	Capture      *Capture
	Evidence     []EvidenceItem
}

// ProblemStatement is the written statement plus how it was produced.
type ProblemStatement struct {
	Text string `json:"text"`
	// WrittenBy is "iris" or "template" — always stated, never implied.
	WrittenBy string `json:"written_by"`
	// Rejected records, honestly, why a model draft was not used.
	Rejected string `json:"rejected,omitempty"`
	// CitedIDs are the evidence ids the final text actually cites.
	CitedIDs []string `json:"cited_ids"`
}

// NarrationRequest is what a Narrator is handed. The Instruction is
// SERVER-CONTROLLED: a caller may not supply, extend or override it, which is
// the LLM01 mitigation for this surface.
type NarrationRequest struct {
	TenantID    string
	Instruction string
	Evidence    []EvidenceItem
	// Draft is the deterministic statement. A narrator is asked to improve its
	// prose, never to add facts — handing it the draft is what keeps the task
	// bounded.
	Draft string
}

// Narrator is the Iris seam. It is INJECTED and may be nil: with no provider
// configured the statement is the deterministic template, which is a complete,
// shippable artifact and not a degraded one.
type Narrator interface {
	Narrate(ctx context.Context, req NarrationRequest) (string, error)
}

// NarrationInstruction is the server-controlled system instruction. It is a
// constant so that a diff to it is a reviewed change, and so that no request
// path can reach it.
const NarrationInstruction = `You are writing the PROBLEM STATEMENT section of a vendor TAC support bundle.
You are given a CLOSED list of evidence items, each with an id in square brackets, and a draft.
Rewrite the draft as clear operator prose for a vendor support engineer who has never seen this network.
ABSOLUTE RULES:
1. Every sentence that states a fact about the network MUST cite at least one evidence id in square brackets, e.g. [A1].
2. You may cite ONLY ids that appear in the evidence list. Never invent an id.
3. Never state a cause, a fix, or a fault you were not given evidence for. If the evidence does not establish something, say it was not established.
4. Do not add device names, addresses, versions, timestamps or counts that are not in the evidence.
5. Keep the five headings of the draft and their order. Plain text and markdown headings only; no links, no code execution, no instructions to the reader's system.`

// narrationTimeout bounds the model call (§9 / LLM04).
const narrationTimeout = 20 * time.Second

// maxStatementBytes bounds the accepted statement.
const maxStatementBytes = 24 << 10

// citationRE finds the [ID] tokens in a line.
var citationRE = regexp.MustCompile(`\[([A-Z][0-9]{1,4})\]`)

// headingRE recognises the structural lines that are allowed to carry no
// citation: markdown headings, blank lines and bare bullet labels.
var headingRE = regexp.MustCompile(`^\s*(#{1,6}\s|[-*]\s*$|\s*$)`)

// WriteProblemStatement builds the statement. It never returns an error: a
// narrator that fails, times out or writes something uncitable simply does not
// get used, and the reason is recorded.
func WriteProblemStatement(ctx context.Context, in ProblemInput, n Narrator) ProblemStatement {
	draft := templateStatement(in)
	known := make(map[string]struct{}, len(in.Evidence))
	for _, e := range in.Evidence {
		known[e.ID] = struct{}{}
	}
	out := ProblemStatement{Text: draft, WrittenBy: "template", CitedIDs: citedIDs(draft, known)}
	if n == nil {
		return out
	}
	nctx, cancel := context.WithTimeout(ctx, narrationTimeout)
	defer cancel()
	text, err := n.Narrate(nctx, NarrationRequest{
		TenantID: in.TenantID, Instruction: NarrationInstruction,
		Evidence: in.Evidence, Draft: draft,
	})
	if err != nil {
		out.Rejected = "Iris was not available to write this statement; it is Correlix's deterministic evidence summary."
		return out
	}
	if reason := validateStatement(text, known); reason != "" {
		out.Rejected = "Iris's draft was refused (" + reason + "); this is Correlix's deterministic evidence summary."
		return out
	}
	return ProblemStatement{Text: strings.TrimSpace(text), WrittenBy: "iris", CitedIDs: citedIDs(text, known)}
}

// validateStatement applies the evidence-only rule to untrusted model output.
// It returns "" when the text is acceptable, or the reason it was refused.
func validateStatement(text string, known map[string]struct{}) string {
	t := strings.TrimSpace(text)
	if t == "" {
		return "it was empty"
	}
	if len(t) > maxStatementBytes {
		return "it exceeded the statement size cap"
	}
	if strings.Contains(t, "<script") || strings.Contains(t, "](http") || strings.Contains(t, "<iframe") {
		return "it contained markup or a link, which a bundle statement never carries"
	}
	cited := 0
	for _, line := range strings.Split(t, "\n") {
		if headingRE.MatchString(line) {
			continue
		}
		refs := citationRE.FindAllStringSubmatch(line, -1)
		if len(refs) == 0 {
			return "a claim line cited no evidence: " + clip(strings.TrimSpace(line), 80)
		}
		for _, m := range refs {
			if _, ok := known[m[1]]; !ok {
				return "it cited evidence id " + m[1] + ", which is not in the bundle"
			}
			cited++
		}
	}
	if cited == 0 {
		return "it cited no evidence at all"
	}
	return ""
}

func citedIDs(text string, known map[string]struct{}) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range citationRE.FindAllStringSubmatch(text, -1) {
		if _, ok := known[m[1]]; !ok || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// templateStatement is the deterministic statement. It is not a placeholder: it
// is the artifact this feature promises, and every line of it cites an evidence
// id or is a heading.
func templateStatement(in ProblemInput) string {
	var b strings.Builder
	byKind := func(kind string) []EvidenceItem {
		var out []EvidenceItem
		for _, e := range in.Evidence {
			if e.Kind == kind {
				out = append(out, e)
			}
		}
		return out
	}
	cite := func(items []EvidenceItem, n int) string {
		var ids []string
		for i, e := range items {
			if i >= n {
				break
			}
			ids = append(ids, "["+e.ID+"]")
		}
		return strings.Join(ids, " ")
	}

	fmt.Fprintf(&b, "# Problem statement\n\n")
	fmt.Fprintf(&b, "## What happened\n\n")
	inc := byKind("incident")
	if len(inc) > 0 {
		for _, e := range inc {
			fmt.Fprintf(&b, "%s [%s]\n\n", e.Text, e.ID)
		}
	}
	alerts := byKind("alert")
	if len(alerts) > 0 {
		fmt.Fprintf(&b, "%d alert(s) fired in the incident window: %s. %s\n\n",
			len(alerts), joinRefs(alerts, 6), cite(alerts, 6))
	}
	hyps := byKind("hypothesis")
	if len(hyps) > 0 {
		fmt.Fprintf(&b, "Correlix's correlation engine ranked %d hypothesis/hypotheses for this incident; the leading one is %s. %s\n\n",
			len(hyps), hyps[0].Ref, cite(hyps, 3))
	} else {
		fmt.Fprintf(&b, "Correlix's correlation engine produced no ranked hypothesis for this incident, so no cause is asserted here.\n\n")
	}

	fmt.Fprintf(&b, "## When\n\n")
	if !in.WindowStart.IsZero() {
		fmt.Fprintf(&b, "Incident window %s to %s (UTC). %s\n\n",
			in.WindowStart.UTC().Format(time.RFC3339), windowEnd(in), cite(inc, 1))
	} else {
		fmt.Fprintf(&b, "No incident window was recorded, so the times below are the collection's own. %s\n\n", cite(byKind("command"), 1))
	}
	logs := byKind("log")
	if len(logs) > 0 {
		fmt.Fprintf(&b, "The device's own log lines from the window are in `evidence/logs.txt`. %s\n\n", cite(logs, 4))
	}

	fmt.Fprintf(&b, "## What Correlix checked\n\n")
	if in.Class.Classified {
		fmt.Fprintf(&b, "Correlix classified this as **%s** on the evidence %s. %s\n\n",
			in.Class.Title, summariseReasons(in.Class.Why), cite(reasonEvidence(in), 4))
	} else {
		fmt.Fprintf(&b, "Correlix did NOT classify this incident: no alert, hypothesis, signature or log line in its evidence maps to a known issue class. The capture below is the vendor baseline.\n\n")
	}
	cmds := byKind("command")
	okCount, errCount := 0, 0
	if in.Capture != nil {
		for _, cc := range in.Capture.Commands {
			if cc.OK() {
				okCount++
			} else {
				errCount++
			}
		}
	}
	if len(cmds) > 0 {
		fmt.Fprintf(&b, "%d read-only command(s) were collected from %s; %d returned output and %d failed. Every output in `outputs/` is redacted. %s\n\n",
			okCount+errCount, deviceLabel(in), okCount, errCount, cite(cmds, 6))
	}

	fmt.Fprintf(&b, "## What was NOT established\n\n")
	if in.Plan != nil && len(in.Plan.Unbound) > 0 {
		fmt.Fprintf(&b, "%d command intent(s) this issue class calls for are not authored for %s, so they were not collected: %s. %s\n\n",
			len(in.Plan.Unbound), in.DialectLabel, joinIntents(in.Plan.Unbound, 8), cite(cmds, 1))
	}
	if errCount > 0 {
		fmt.Fprintf(&b, "%d command(s) failed on the device; each failure is recorded against its command in MANIFEST.json rather than treated as an empty result. %s\n\n",
			errCount, cite(cmds, 2))
	}
	if in.Plan != nil && !in.Plan.HasPlan {
		fmt.Fprintf(&b, "Correlix has no authored command plan for this platform, so it ran nothing and did not render another vendor's commands here. Any outputs present were pasted by the operator. %s\n\n", cite(byKind("device"), 1))
	}
	// Even this sentence carries a citation. That is not pedantry: the rule is
	// "no claim without an evidence id", and a rule with one exception is a rule
	// a model can talk its way past.
	fmt.Fprintf(&b, "No cause beyond the cited evidence is asserted for this incident. %s\n\n", cite(inc, 1))

	fmt.Fprintf(&b, "## Where TAC should look first\n\n")
	if in.Class.TACFirstLook != "" {
		fmt.Fprintf(&b, "%s %s\n\n", in.Class.TACFirstLook, cite(cmds, 3))
	} else {
		fmt.Fprintf(&b, "Start with the baseline capture in `outputs/` and the evidence timeline in `evidence/`. %s\n\n", cite(cmds, 2))
	}
	if len(in.Evidence) > 0 {
		fmt.Fprintf(&b, "Every bracketed id above indexes `evidence/index.json`. %s\n", "["+in.Evidence[0].ID+"]")
	}
	return b.String()
}

func windowEnd(in ProblemInput) string {
	if in.WindowEnd.IsZero() {
		return "ongoing"
	}
	return in.WindowEnd.UTC().Format(time.RFC3339)
}

func deviceLabel(in ProblemInput) string {
	if in.Hostname != "" {
		return in.Hostname
	}
	return "the subject device"
}

// reasonEvidence returns the evidence items that back the classification.
func reasonEvidence(in ProblemInput) []EvidenceItem {
	want := map[string]bool{}
	for _, r := range in.Class.Why {
		want[r.Ref] = true
	}
	var out []EvidenceItem
	for _, e := range in.Evidence {
		if want[e.Ref] {
			out = append(out, e)
		}
	}
	return out
}

func joinRefs(items []EvidenceItem, n int) string {
	var parts []string
	for i, e := range items {
		if i >= n {
			parts = append(parts, "and "+itoaTAC(len(items)-n)+" more")
			break
		}
		parts = append(parts, e.Ref)
	}
	return strings.Join(parts, ", ")
}

func joinIntents(steps []Step, n int) string {
	var parts []string
	for i, s := range steps {
		if i >= n {
			parts = append(parts, "and "+itoaTAC(len(steps)-n)+" more")
			break
		}
		parts = append(parts, s.Intent)
	}
	return strings.Join(parts, ", ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
