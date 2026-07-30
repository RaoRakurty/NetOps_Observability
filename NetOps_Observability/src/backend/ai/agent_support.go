package ai

// agent_support.go — the agent-loop support pieces (Phase-2 W4.13, extracted
// from package main's copilot_agent.go): the operator doctrine block, the
// per-tenant daily token budget with UTC rollover, the coarse token
// estimator, and the DLP-redacting tool-reply renderer. The loop itself, tool
// execution, eligibility and audit stay in main (they hold srv + claims).

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// toolsReplyMaxChars bounds one tool reply in the prompt (LLM04 budget).
const toolsReplyMaxChars = 4000

// AgentDoctrine is the investigation playbook appended to the server-owned
// system prompt on tool-enabled turns. It exists because models — especially
// small ones — default to interrogating the operator ("which source? exact
// timestamps?") instead of investigating. A NOC assistant acts first: the
// current-time anchor lets it resolve relative phrases itself, and the
// incidents-first rule points it at the platform's already-merged view instead
// of offering a logs/metrics/flows menu.
func AgentDoctrine(now time.Time) string {
	return "CURRENT TIME (UTC): " + now.Format("Monday, 2006-01-02 15:04") + `

INVESTIGATION DOCTRINE — how to answer with the tools:
- Act first, ask later. NEVER ask which data source to check, and NEVER ask for exact timestamps. Run the lookups, answer, then state what you covered and offer to narrow.
- Resolve relative time yourself against the current time above: "last night" or "today" → window 12h or 24h; "this week" or "past month" → 7d (the widest available — say what you covered).
- "Any issues / what's wrong / what happened" → start with the incident tools: get_incident_history for past windows, get_active_major_incidents for right now. They are the platform's already-correlated view across logs, metrics, flows and paths — never offer the operator a menu of raw sources instead.
- For a named device, corroborate with get_device_health and search_logs, and MERGE everything into ONE answer with citations.
- Outage triage narrows in this order — real impact → blast radius → what changed → transport (links/tunnels) → routing → policy/firewall → front door (DNS/LB) → brownout vs hard-down → provider vs us → safest mitigation. Answer with where the evidence points and what would close the next question; a question closes only when its evidence threshold is met (e.g. two independent streams agree).
- Ask a clarifying question ONLY when a required argument is truly unknowable (for example, two devices share the same name).

WORDING (NOC operator voice): answer as "[Confidence label] [fault domain] affecting [scope]. Evidence: [signal A], [signal B], [time window]. Next: [specific check or mitigation]." Lead with impact and scope, never a deep mechanism. Separate symptom from hypothesis. Confidence labels — confirmed: multiple independent evidence classes agree, use sparingly live; likely: strong directional evidence, safe to act on; suspected: incomplete or contradicted — say what would confirm it; unknown: state symptom and impact only, never imply a root cause. Never show a bare percentage alone — pair it with the label ("Likely, 85% model confidence"). Name contradictions and gaps instead of hiding them; blameless language. Live verbs: investigating, identified, likely, suspected, monitoring, mitigated, resolved. Never: certainly, definitely, root cause found, proven.`
}

// DailyBudget is an in-memory per-tenant daily token meter. Estimates are
// coarse (chars/4) — the point is a hard ceiling on provider spend, not
// accounting-grade metering. Resets at UTC midnight; fail-closed callers fall
// back to chat-without-tools when exhausted.
type DailyBudget struct {
	mu   sync.Mutex
	day  string
	used map[string]int
}

func NewDailyBudget() *DailyBudget { return &DailyBudget{used: map[string]int{}} }

// Allow reports whether the tenant is under its daily token limit (resolved by
// the caller — per-tenant override or platform default; <=0 disables metering).
func (b *DailyBudget) Allow(tenant string, limit int) bool {
	if limit <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollover()
	return b.used[tenant] < limit
}

// Charge adds usage against the tenant's daily budget.
func (b *DailyBudget) Charge(tenant string, tokens int) {
	if tokens <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollover()
	b.used[tenant] += tokens
}

func (b *DailyBudget) rollover() {
	today := time.Now().UTC().Format("2006-01-02")
	if b.day != today {
		b.day = today
		b.used = map[string]int{}
	}
}

// EstTokens is the coarse chars/4 token estimate used for budget metering.
func EstTokens(turns []AgentTurn, text string) int {
	n := len(text)
	for _, t := range turns {
		n += len(t.Content)
		for _, r := range t.Replies {
			n += len(r.Content)
		}
	}
	return n / 4
}

// RenderToolReply turns a tool result into the bounded text block that is fed
// back into the conversation and therefore SHIPPED TO THE PROVIDER.
//
// This is an egress boundary, so the outbound DLP filter runs here (PIPE-MED-5:
// the loop used to render raw store rows straight into the prompt — only the
// syslog tool redacted anything). Redact masks credential-shaped material
// AND direct identifiers, because everything in a tool result is
// server-originated tenant data, not something the operator typed.
//
// Redaction runs on the ASSEMBLED block rather than per item: one pass instead
// of N, and the mask never lengthens a line enough to matter against the
// character budget (it only ever replaces a longer secret with "***").
func RenderToolReply(result *ToolResult) string {
	var b strings.Builder
	for _, it := range result.Items {
		line := fmt.Sprintf("[%s] %s\n", it.CitationID, it.Text)
		if b.Len()+len(line) > toolsReplyMaxChars {
			result.Truncated = true
			break
		}
		b.WriteString(line)
	}
	for _, n := range result.Notes {
		b.WriteString("note: " + n + "\n")
	}
	if result.Truncated {
		b.WriteString("note: results truncated.\n")
	}
	if b.Len() == 0 {
		b.WriteString("no data.\n")
	}
	return Redact(b.String())
}
