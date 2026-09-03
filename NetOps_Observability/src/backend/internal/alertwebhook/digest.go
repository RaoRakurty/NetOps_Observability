package alertwebhook

// digest.go — the WARNING DIGEST for the host-monitoring route.
//
// THE DEFECT THIS CLOSES (observed live, 2026-09-03 ~04:00 UTC). The api log
// carried a repeating
//
//	platform alert push to host monitoring FAILED … error: "ntfy: status 429"
//
// for VectorComponentErrors at tier=warning. ntfy.sh's free public server
// rate-limits per topic/IP, and the route was spending that budget one push at
// a time on CHRONIC warnings — conditions that are true for hours and re-post
// on every vmalert resend, so each one buzzes once per cool-down forever. Two
// costs, and the second is the serious one:
//
//  1. the phone becomes noise, which is how a pager gets muted;
//  2. the budget those warnings burn is budget a real PAGE needs. A page
//     refused with 429 because a disk-headroom warning spent the last token is
//     the alerting path failing in exactly the way this whole module exists to
//     end.
//
// THE RULE. A warning is never pushed on its own. It is folded into a
// per-topic accumulator and rendered as ONE digest message at most every
// EnvWarningDigestInterval — alertname × count × first/last seen × one summary
// line. A warning that RESOLVES inside the window is folded into the SAME
// entry as resolved and never pushed alone: a condition that came and went
// inside half an hour did not need to interrupt anyone, but it is still worth
// seeing.
//
// PAGES ARE NOT DIGESTED. The page tier, and the resolution of a page, go out
// immediately as before. The digest exists to keep the page lane clear, not to
// slow it down.
//
// TIMING. The flush is driven by request arrival (serve → maybeFlushDigest),
// not by a background timer, and that is deliberate: vmalert carries an
// ALWAYS-FIRING AlertingHeartbeat rule, so the receiver is POSTed to on every
// evaluation interval whether or not anything is wrong. The digest therefore
// leaves within one evaluation of its deadline with no goroutine, no timer to
// leak and no wall-clock dependency the tests have to sleep through. If
// vmalert stops posting entirely, a pending digest waits — and that is the
// right failure: "the notifier died" is the heartbeat gauge's alert to raise,
// not a stale warning summary's.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/notify"
)

// Digest bounds (§9: every queue bounded). The accumulator is keyed by
// alertname, so its natural size is the number of DISTINCT warning rules
// firing — ~140 rules exist, and a body listing all of them would be truncated
// on the wire anyway. Past the cap, further NEW names are counted as overflow
// and named as a total; already-tracked names keep accumulating.
const (
	maxDigestEntries  = 40
	maxDigestBody     = 3000 // well inside notify's 4096 wire cap
	maxDigestSummary  = 120  // one line per entry, not a paragraph
	digestOverflowFmt = "… +%d more warning rule(s) not listed (digest cap %d)"
)

// tierDigest is the metric tier label for the digest push itself. It is part of
// the same CLOSED label set as page/warning/resolved (§10: no cardinality
// bombs) and is deliberately its OWN value: counting a digest as a warning
// would make netops_alert_webhook_pushed_total{tier="warning"} read as "one
// warning was pushed" when what happened is "twelve warnings were summarized".
const tierDigest = "digest"

// digestEntry is one alertname's accumulated state inside the current window.
type digestEntry struct {
	name string
	// count is how many FIRING occurrences were folded. A window that saw only
	// a resolution leaves this at 0 and the entry still renders — the operator
	// wants to know the condition cleared.
	count     int
	first     time.Time
	last      time.Time
	summary   string
	resolved  bool
	severity  string
	resolveAt time.Time
}

// foldDigest adds one non-page alert to the accumulator. Called only for
// alerts that already passed the tenant/customer refusals and the cool-down,
// so the same identical alert cannot be folded twice inside a cool-down window
// — the count reflects distinct occurrences, not vmalert's resend cadence.
func (r *receiver) foldDigest(name, summary, severity, tier string, at time.Time) {
	r.digestMu.Lock()
	defer r.digestMu.Unlock()
	if r.digest == nil {
		r.digest = make(map[string]*digestEntry, 16)
	}
	e, ok := r.digest[name]
	if !ok {
		if len(r.digest) >= maxDigestEntries {
			// Bounded, and LOUD in the metric rather than silent (§10). The
			// rendered digest names the overflow count too, so the operator is
			// never shown a summary that quietly omits rules.
			r.digestOverflow++
			r.deps.Metrics.inc(&r.deps.Metrics.hostDigestOverflow)
			return
		}
		e = &digestEntry{name: name, first: at}
		r.digest[name] = e
	}
	e.last = at
	if s := strings.TrimSpace(summary); s != "" && s != name && e.summary == "" {
		e.summary = s
	}
	if sev := strings.TrimSpace(severity); sev != "" {
		e.severity = sev
	}
	if tier == tierResolved {
		e.resolved = true
		e.resolveAt = at
	} else {
		// A re-fire inside the window un-resolves the entry: what the operator
		// needs to read is the state the condition is in NOW.
		e.count++
		e.resolved = false
	}
	r.deps.Metrics.inc(&r.deps.Metrics.hostDigestFolded)
}

// maybeFlushDigest emits the accumulated warnings if the window has elapsed.
// Called once per accepted request (serve), so "at most one digest per
// interval" is enforced on the clock, not on the traffic.
//
// The BUDGET IS TAKEN BEFORE THE MAP IS DRAINED. If there is no token for
// non-privileged traffic, the accumulator is left exactly as it is and the
// digest goes out next window with the accumulated content — which is the
// whole reason a digest may not retry: re-sending is free and automatic.
func (r *receiver) maybeFlushDigest(now time.Time) {
	if r.deps.HostRoute == nil {
		return
	}
	r.digestMu.Lock()
	if len(r.digest) == 0 || now.Sub(r.digestLast) < r.digestInterval {
		r.digestMu.Unlock()
		return
	}
	r.digestMu.Unlock()

	if !r.budget.Take(false) {
		r.deps.Metrics.inc(&r.deps.Metrics.hostBudgetExhausted)
		r.logBudgetRefusal(tierDigest, "digest", now)
		return
	}

	r.digestMu.Lock()
	// Re-check under the second acquisition: a concurrent request may have
	// flushed while we were taking the token. The token is not returned — a
	// bucket that can be repaid is a bucket that can be raced into overdraft,
	// and one unspent token per contended flush is the cheaper error.
	if len(r.digest) == 0 || now.Sub(r.digestLast) < r.digestInterval {
		r.digestMu.Unlock()
		return
	}
	entries := make([]*digestEntry, 0, len(r.digest))
	for _, e := range r.digest {
		entries = append(entries, e)
	}
	overflow := r.digestOverflow
	r.digest = nil
	r.digestOverflow = 0
	r.digestLast = now
	window := r.digestInterval
	r.digestMu.Unlock()

	push := renderDigest(entries, overflow, window)
	r.enqueueHost(hostJob{name: "PlatformWarningDigest", tier: tierDigest, push: push})
}

// logBudgetRefusal reports a push the budget refused. Rate-limited to one line
// per digest window per kind, because the condition it reports repeats on every
// request and a per-request warning is its own outage (the same reasoning as
// the "no topic configured" hostOnce).
func (r *receiver) logBudgetRefusal(tier, name string, now time.Time) {
	r.digestMu.Lock()
	if !r.budgetLoggedAt.IsZero() && now.Sub(r.budgetLoggedAt) < r.digestInterval {
		r.digestMu.Unlock()
		return
	}
	r.budgetLoggedAt = now
	r.digestMu.Unlock()
	r.log("warn", "platform alert push SKIPPED: the outbound push budget for this topic is spent", map[string]any{
		"route": RouteHostMonitoring, "alertname": name, "tier": tier,
		"env": EnvPushBudget, "reserve_env": EnvPushBudgetPageReserve,
	})
}

// renderDigest composes the single message. Deterministic: entries are sorted
// by name so two identical windows render identically, and the body is bounded
// with an explicit overflow line — a truncated summary that does not say it was
// truncated is a lie the operator cannot see.
func renderDigest(entries []*digestEntry, overflow int, window time.Duration) notify.NtfyPush {
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	firing, resolved, events := 0, 0, 0
	var first, last time.Time
	for _, e := range entries {
		events += e.count
		if e.resolved {
			resolved++
		} else {
			firing++
		}
		if first.IsZero() || e.first.Before(first) {
			first = e.first
		}
		if e.last.After(last) {
			last = e.last
		}
	}

	title := fmt.Sprintf("[DIGEST] %d platform warning(s) in %s", len(entries)+overflow, window)
	if resolved > 0 {
		title = fmt.Sprintf("[DIGEST] %d warning(s), %d resolved, in %s", firing+overflow, resolved, window)
	}
	if len(title) > maxHostTitle {
		title = title[:maxHostTitle]
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d warning rule(s), %d occurrence(s) — %s → %s UTC\n",
		len(entries)+overflow, events, digestStamp(first), digestStamp(last))
	shown := 0
	for _, e := range entries {
		line := digestLine(e)
		if b.Len()+len(line) > maxDigestBody {
			overflow += len(entries) - shown
			break
		}
		b.WriteString(line)
		shown++
	}
	if overflow > 0 {
		fmt.Fprintf(&b, digestOverflowFmt+"\n", overflow, maxDigestEntries)
	}
	return notify.NtfyPush{
		Title:    title,
		Body:     strings.TrimRight(b.String(), "\n"),
		Priority: notify.NtfyPriorityDefault, // never wakes anyone: that is the page lane's job
		Tags:     "bar_chart",
	}
}

// digestLine renders one entry: what fired, how often, over what span, whether
// it is still true, and one line of why.
func digestLine(e *digestEntry) string {
	var b strings.Builder
	b.WriteString("• ")
	b.WriteString(e.name)
	if e.count > 1 {
		fmt.Fprintf(&b, " x%d", e.count)
	}
	if e.severity != "" && e.severity != "warning" {
		b.WriteString(" [" + e.severity + "]")
	}
	if e.resolved {
		b.WriteString(" RESOLVED")
	}
	fmt.Fprintf(&b, " %s→%s", digestStamp(e.first), digestStamp(e.last))
	b.WriteString("\n")
	if s := e.summary; s != "" {
		if len(s) > maxDigestSummary {
			s = s[:maxDigestSummary]
		}
		b.WriteString("  " + s + "\n")
	}
	return b.String()
}

func digestStamp(t time.Time) string {
	if t.IsZero() {
		return "--:--"
	}
	return t.UTC().Format("15:04")
}
