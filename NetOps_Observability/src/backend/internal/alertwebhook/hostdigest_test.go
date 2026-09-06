// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alertwebhook

// hostdigest_test.go — the WARNING DIGEST, the page-tier retry ladder and the
// outbound push budget (2026-09-03).
//
// The defect these cover was observed live at ~04:00 UTC: the api log carried a
// repeating `platform alert push to host monitoring FAILED … "ntfy: status 429"`
// for VectorComponentErrors at tier=warning. Chronic warnings were spending a
// rate budget a real PAGE needs. Every test here is written against that
// failure — what the phone receives, in what order, and what happens when the
// server refuses.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/notify"
)

// tick posts the always-firing heartbeat. It delivers nothing and dispatches
// nothing, so it is the honest way to represent "vmalert evaluated again" —
// which is what drives the digest flush (digest.go: no background timer).
func (r *hostRig) tick(t *testing.T) {
	t.Helper()
	body := fmt.Sprintf(`[{"status":"firing","labels":{"alertname":%q,"severity":"info"}}]`, HeartbeatAlertName)
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("heartbeat post: status = %d", w.Code)
	}
}

// warnJSON is one warning-tier alert (no tier label = the matrix's "watch").
func warnJSON(name, summary, status string) string {
	return fmt.Sprintf(`[{"status":%q,"labels":{"alertname":%q,"severity":"warning","layer":"ingest"},`+
		`"annotations":{"summary":%q}}]`, status, name, summary)
}

// ── aggregation ─────────────────────────────────────────────────────────────

// The digest is the whole point: N warnings over a window become ONE push that
// still says which rules, how many times, and over what span.
func TestDigestAggregatesCountFirstSeenAndLastSeen(t *testing.T) {
	r := newHostRigWith(t, time.Minute, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = 30 * time.Minute
	})
	// VectorComponentErrors three times across 20 minutes — the live case.
	for i := 0; i < 3; i++ {
		if w := r.post(t, warnJSON("VectorComponentErrors", "vector component errors observed", "firing"), bearer); w.Code != http.StatusOK {
			t.Fatalf("post %d: status = %d", i, w.Code)
		}
		if i < 2 {
			r.clock.advance(10 * time.Minute)
		}
	}
	// A second rule, once.
	if w := r.post(t, warnJSON("DiskHeadroomLow", "root filesystem at 91%", "firing"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.quiet(t) // nothing has been pushed yet: the window is still open

	r.clock.advance(11 * time.Minute) // 12:31 — past the 30m window
	r.tick(t)
	p := r.push.await(t, 1)[0]

	if !strings.Contains(p.Title, "[DIGEST]") || !strings.Contains(p.Title, "2 platform warning(s)") {
		t.Errorf("title = %q, want a digest naming 2 warning rules", p.Title)
	}
	if p.Priority != notify.NtfyPriorityDefault {
		t.Errorf("Priority = %q — a digest must never wake anyone", p.Priority)
	}
	for _, want := range []string{
		"VectorComponentErrors x3",
		"12:00→12:20",             // first → last seen for the repeated rule
		"12:20→12:20",             // the single-occurrence rule
		"vector component errors", // one summary line each
		"root filesystem at 91%",
		"4 occurrence(s)",
	} {
		if !strings.Contains(p.Body, want) {
			t.Errorf("digest body is missing %q:\n%s", want, p.Body)
		}
	}
	txt := metricsText(r.mx)
	if !strings.Contains(txt, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="digest"} 1`) {
		t.Errorf("the digest push was not counted under its own tier:\n%s", txt)
	}
	if !strings.Contains(txt, "netops_alert_webhook_digest_alerts_total 4") {
		t.Errorf("4 alerts were folded and the counter disagrees:\n%s", txt)
	}
	r.push.quiet(t)
}

// A warning that fires and clears INSIDE the window never buzzes at all — it is
// folded into its own entry and reported as resolved. Nobody needs to be
// interrupted twice for a condition that lasted ten minutes.
func TestDigestFoldsAWarningThatResolvedInsideTheWindow(t *testing.T) {
	r := newHostRigWith(t, time.Minute, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = 30 * time.Minute
	})
	if w := r.post(t, warnJSON("CorrDeadLettersRising", "dead letters rising", "firing"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.clock.advance(10 * time.Minute)
	if w := r.post(t, warnJSON("CorrDeadLettersRising", "dead letters rising", "resolved"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.quiet(t)
	if n := r.push.count(); n != 0 {
		t.Fatalf("pushes = %d, want 0 — neither leg of a warning may be pushed alone", n)
	}
	r.clock.advance(21 * time.Minute)
	r.tick(t)
	p := r.push.await(t, 1)[0]
	if !strings.Contains(p.Body, "CorrDeadLettersRising") || !strings.Contains(p.Body, "RESOLVED") {
		t.Errorf("the digest must fold the resolution, not drop it:\n%s", p.Body)
	}
	if !strings.Contains(p.Title, "resolved") {
		t.Errorf("title = %q, want it to say something already cleared", p.Title)
	}
	// The product dispatcher still saw both legs.
	if fired, resolved := r.disp.counts(); fired != 1 || resolved != 1 {
		t.Fatalf("product legs = %d firing / %d resolved, want 1/1", fired, resolved)
	}
}

// A re-fire after a resolution inside the same window un-resolves the entry:
// what the operator reads must be the state the condition is in NOW.
func TestDigestRefireAfterResolveIsReportedAsFiring(t *testing.T) {
	r := newHostRigWith(t, time.Second, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = 10 * time.Minute
	})
	for _, status := range []string{"firing", "resolved", "firing"} {
		if w := r.post(t, warnJSON("VectorEventsDiscarded", "events discarded", status), bearer); w.Code != http.StatusOK {
			t.Fatalf("status = %d", w.Code)
		}
		r.clock.advance(time.Minute)
	}
	r.clock.advance(10 * time.Minute)
	r.tick(t)
	p := r.push.await(t, 1)[0]
	if strings.Contains(p.Body, "RESOLVED") {
		t.Errorf("a rule that re-fired must not be reported as resolved:\n%s", p.Body)
	}
	if !strings.Contains(p.Body, "VectorEventsDiscarded x2") {
		t.Errorf("both firing occurrences must be counted:\n%s", p.Body)
	}
}

// The digest is BOUNDED (§9) and says so. A summary that silently omits rules
// is worse than one that admits it was truncated.
func TestDigestEntriesAreCappedAndTheOverflowIsNamed(t *testing.T) {
	r := newHostRigWith(t, time.Minute, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = 5 * time.Minute
	})
	const total = maxDigestEntries + 7
	for i := 0; i < total; i++ {
		body := warnJSON(fmt.Sprintf("WarnRule%02d", i), "a chronic condition", "firing")
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("post %d: status = %d", i, w.Code)
		}
	}
	r.clock.advance(6 * time.Minute)
	r.tick(t)
	p := r.push.await(t, 1)[0]
	if !strings.Contains(p.Body, "not listed") {
		t.Errorf("the overflow must be named in the body:\n%s", p.Body)
	}
	if len(p.Body) > maxDigestBody+len(fmt.Sprintf(digestOverflowFmt, total, maxDigestEntries))+1 {
		t.Errorf("digest body = %d bytes, want it bounded near %d", len(p.Body), maxDigestBody)
	}
	if !strings.Contains(metricsText(r.mx), fmt.Sprintf("netops_alert_webhook_digest_overflow_total %d", total-maxDigestEntries)) {
		t.Errorf("the overflow was not counted:\n%s", metricsText(r.mx))
	}
}

// ── cadence ─────────────────────────────────────────────────────────────────

// AT MOST ONE digest per window, however many requests arrive. This is the
// property that bounds what the route can spend on the warning tier.
func TestDigestCadenceIsAtMostOnePerWindow(t *testing.T) {
	r := newHostRigWith(t, time.Second, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = 30 * time.Minute
	})
	// 40 minutes of traffic, one warning + one heartbeat every two minutes.
	for i := 0; i < 20; i++ {
		body := warnJSON("VectorComponentErrors", "vector component errors observed", "firing")
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("post %d: status = %d", i, w.Code)
		}
		r.tick(t)
		r.clock.advance(2 * time.Minute)
	}
	r.push.await(t, 1)
	r.push.quiet(t)
	if n := r.push.count(); n != 1 {
		t.Fatalf("pushes = %d over 40 minutes of a 30m window, want exactly 1", n)
	}
	// Past a second window it buzzes again with what accumulated since the
	// first flush — the digest DELAYS warnings, it does not silence them.
	r.clock.advance(31 * time.Minute)
	r.tick(t)
	r.push.await(t, 1)
	if n := r.push.count(); n != 2 {
		t.Fatalf("pushes = %d, want 2 — the next window must carry the next digest", n)
	}
	// And with nothing left to report, a further window pushes nothing at all:
	// an empty digest is not a message, it is noise.
	r.clock.advance(31 * time.Minute)
	r.tick(t)
	r.push.quiet(t)
	if n := r.push.count(); n != 2 {
		t.Fatalf("pushes = %d — an empty window must not push", n)
	}
}

// ── the page lane stays clear ───────────────────────────────────────────────

// THE POINT OF THE WHOLE CHANGE: a warning storm must not delay, dilute or
// out-spend a page.
func TestPageIsImmediateUnderAWarningStorm(t *testing.T) {
	r := newHostRigWith(t, time.Second, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = 30 * time.Minute
	})
	for i := 0; i < 60; i++ {
		body := warnJSON(fmt.Sprintf("Chronic%02d", i), "a chronic condition", "firing")
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("warning %d: status = %d", i, w.Code)
		}
	}
	r.push.quiet(t)
	page := alertJSON("CorrelationConsumerDead", "critical", "correlation", "page", "firing",
		"correlation consumer group has zero members")
	if w := r.post(t, page, bearer); w.Code != http.StatusOK {
		t.Fatalf("page: status = %d", w.Code)
	}
	p := r.push.await(t, 1)[0]
	if p.Priority != notify.NtfyPriorityHigh || !strings.Contains(p.Title, "CorrelationConsumerDead") {
		t.Fatalf("the FIRST push after a 60-warning storm must be the page, got %+v", p)
	}
	// And the resolution of that page is immediate too — never digested.
	resolve := alertJSON("CorrelationConsumerDead", "critical", "correlation", "page", "resolved", "consumer rejoined")
	if w := r.post(t, resolve, bearer); w.Code != http.StatusOK {
		t.Fatalf("resolve: status = %d", w.Code)
	}
	if got := r.push.await(t, 1)[0]; got.Priority != notify.NtfyPriorityLow || !strings.Contains(got.Title, "RESOLVED") {
		t.Fatalf("the resolution of a page must stay immediate and low, got %+v", got)
	}
}

// ── 429 / 5xx handling ──────────────────────────────────────────────────────

func rateLimited(after time.Duration) error {
	return &notify.NtfyStatusError{Status: http.StatusTooManyRequests, RetryAfter: after}
}

// 429 → backoff → success. The page lands, the retries are counted, and no
// failure is recorded: a page that arrives on the third attempt is a page that
// arrived.
func TestRateLimitedPageRetriesWithBackoffThenSucceeds(t *testing.T) {
	p := newFakePusher()
	p.script = []error{rateLimited(0), rateLimited(0)}
	r := newHostRig(t, 30*time.Minute, p)
	body := alertJSON("ClickHouseWritesRejected", "critical", "clickhouse", "page", "firing", "writes rejected")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d — a push failure must never 5xx vmalert into a retry storm", w.Code)
	}
	r.push.await(t, 3)
	waitForMetric(t, r.mx, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 1`)
	txt := metricsText(r.mx)
	if !strings.Contains(txt, "netops_alert_webhook_push_retries_total 2") {
		t.Errorf("two retries were not counted:\n%s", txt)
	}
	for _, must := range []string{
		`netops_alert_webhook_push_failures_total{route="host_monitoring",reason="rate_limited"} 0`,
		`netops_alert_webhook_push_failures_total{route="host_monitoring",reason="send_error"} 0`,
	} {
		if !strings.Contains(txt, must) {
			t.Errorf("a page that eventually landed was counted as failed:\n%s", txt)
		}
	}
	// Capped exponential with jitter: each wait in [d/2, d] for d = base<<n.
	waits := r.naps.waits()
	if len(waits) != 2 {
		t.Fatalf("waits = %v, want 2", waits)
	}
	for i, w := range waits {
		d := hostRetryBase << i
		if w < d/2 || w > d {
			t.Errorf("wait[%d] = %v, want jittered inside [%v, %v]", i, w, d/2, d)
		}
	}
}

// 429 to exhaustion: bounded attempts, ERROR (not warn) because a page-worthy
// condition reached nobody, and the rate_limited reason so the operator can
// tell "the server is throttling us" from "the send broke".
func TestRateLimitedPageExhaustionLogsErrorAndCountsRateLimited(t *testing.T) {
	p := newFakePusher()
	p.err = rateLimited(0)
	r := newHostRig(t, 30*time.Minute, p)
	body := alertJSON("ContainerDown", "critical", "stack", "page", "firing", "api is down")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.await(t, hostMaxAttempts)
	waitForMetric(t, r.mx, `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="rate_limited"} 1`)
	if n := r.push.count(); n != hostMaxAttempts {
		t.Fatalf("attempts = %d, want exactly %d — the ladder must be BOUNDED", n, hostMaxAttempts)
	}
	if !strings.Contains(metricsText(r.mx), `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="send_error"} 0`) {
		t.Error("a rate-limit refusal must not also be counted as a send error")
	}
	if n := r.logs.countContaining("error: platform alert push to host monitoring FAILED"); n != 1 {
		t.Fatalf("a dropped PAGE must be logged at ERROR exactly once, got %d", n)
	}
	// Total wall time is bounded by the deadline even in the worst case.
	var total time.Duration
	for _, w := range r.naps.waits() {
		total += w
	}
	if total >= hostRetryDeadline {
		t.Fatalf("backoff total = %v, want under the %v deadline", total, hostRetryDeadline)
	}
}

// Retry-After is the server telling us when its budget refills. It wins over
// our own backoff — pushing sooner is how a 429 becomes a ban.
func TestRetryAfterIsHonoured(t *testing.T) {
	p := newFakePusher()
	p.script = []error{rateLimited(7 * time.Second)}
	r := newHostRig(t, 30*time.Minute, p)
	body := alertJSON("OpenSearchRed", "critical", "storage", "page", "firing", "cluster red")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.await(t, 2)
	waitForMetric(t, r.mx, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 1`)
	waits := r.naps.waits()
	if len(waits) != 1 || waits[0] != 7*time.Second {
		t.Fatalf("waits = %v, want exactly the server's Retry-After (7s)", waits)
	}
}

// A 4xx that is NOT a rate limit is a statement about the request (bad token,
// unknown topic). Retrying it cannot help and spends the budget the 429 case
// needs.
func TestNonRetryableStatusIsNotRetried(t *testing.T) {
	p := newFakePusher()
	p.err = &notify.NtfyStatusError{Status: http.StatusForbidden}
	r := newHostRig(t, 30*time.Minute, p)
	body := alertJSON("ContainerDown", "critical", "stack", "page", "firing", "api is down")
	if w := r.post(t, body, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.push.await(t, 1)
	waitForMetric(t, r.mx, `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="send_error"} 1`)
	if n := r.push.count(); n != 1 {
		t.Fatalf("attempts = %d, want 1 — a 403 will not fix itself", n)
	}
	if w := r.naps.waits(); len(w) != 0 {
		t.Fatalf("waits = %v, want none", w)
	}
}

// A DIGEST never retries: it is re-sent next window with the accumulated
// content, so a second immediate attempt spends budget for no new information.
func TestDigestIsNotRetried(t *testing.T) {
	p := newFakePusher()
	p.err = rateLimited(0)
	r := newHostRigWith(t, time.Second, p, func(d *Deps) { d.WarningDigestInterval = time.Minute })
	if w := r.post(t, warnJSON("VectorComponentErrors", "errors observed", "firing"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.clock.advance(2 * time.Minute)
	r.tick(t)
	r.push.await(t, 1)
	r.push.quiet(t)
	if n := r.push.count(); n != 1 {
		t.Fatalf("attempts = %d, want exactly 1 for a digest", n)
	}
	if w := r.naps.waits(); len(w) != 0 {
		t.Fatalf("a digest must not sleep on a retry ladder, waits = %v", w)
	}
}

// ── the push budget ─────────────────────────────────────────────────────────

// The reserve is the guarantee: warnings and digests stop at it, a page spends
// through it. Live, this is what keeps "DiskHeadroomLow spent the last token"
// from ever explaining a missed page again.
func TestBudgetReservesCapacityForPages(t *testing.T) {
	r := newHostRigWith(t, time.Second, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = time.Millisecond
		d.PushBudget = 3
		d.PageReserve = 2
	})
	// Flush #1: 3 tokens, the non-privileged floor is 2 → allowed, 2 left.
	if w := r.post(t, warnJSON("WarnA", "chronic", "firing"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.clock.advance(time.Millisecond)
	r.tick(t)
	r.push.await(t, 1)

	// Flush #2: 2 tokens left, all of them reserved for pages → REFUSED, and
	// the accumulated content is kept for the next window rather than lost.
	if w := r.post(t, warnJSON("WarnB", "chronic", "firing"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.clock.advance(time.Millisecond)
	r.tick(t)
	r.push.quiet(t)
	if !strings.Contains(metricsText(r.mx), `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="budget_exhausted"} 1`) {
		t.Errorf("the refusal was not counted:\n%s", metricsText(r.mx))
	}

	// The page still goes out — that is the whole reason the reserve exists.
	page := alertJSON("CorrelationConsumerDead", "critical", "correlation", "page", "firing", "consumer group empty")
	if w := r.post(t, page, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	got := r.push.await(t, 1)[0]
	if got.Priority != notify.NtfyPriorityHigh {
		t.Fatalf("the reserved capacity did not carry the page: %+v", got)
	}
	if rem := r.mx.PushBudgetRemaining(); rem != 1 {
		t.Errorf("remaining = %d, want 1 (3 - digest - page)", rem)
	}
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_push_budget_remaining 1") {
		t.Errorf("the budget gauge is not exposed:\n%s", metricsText(r.mx))
	}
	// The refusal is logged, but ONCE per window — the condition repeats on
	// every request and a per-request warning is its own outage.
	if n := r.logs.countContaining("outbound push budget for this topic is spent"); n != 1 {
		t.Errorf("budget refusal logged %d times, want exactly 1", n)
	}
}

// A page the budget itself refuses is the worst case in this file: it is an
// ERROR, it is counted, and it is never silent.
func TestBudgetExhaustedPageIsLoggedAtError(t *testing.T) {
	r := newHostRigWith(t, time.Nanosecond, newFakePusher(), func(d *Deps) {
		d.PushBudget = 2
		d.PageReserve = 0
	})
	for i := 0; i < 3; i++ {
		body := alertJSON(fmt.Sprintf("Page%d", i), "critical", "stack", "page", "firing", "down")
		if w := r.post(t, body, bearer); w.Code != http.StatusOK {
			t.Fatalf("post %d: status = %d", i, w.Code)
		}
		r.clock.advance(time.Nanosecond)
	}
	r.push.await(t, 2)
	r.push.quiet(t)
	if n := r.push.count(); n != 2 {
		t.Fatalf("pushes = %d, want 2 — the third had no token", n)
	}
	if !strings.Contains(metricsText(r.mx), `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="budget_exhausted"} 1`) {
		t.Errorf("the refused page was not counted:\n%s", metricsText(r.mx))
	}
	if n := r.logs.countContaining("error: platform alert push SKIPPED"); n != 1 {
		t.Fatalf("a page the budget refused must be an ERROR, got %d such lines", n)
	}
}

// The bucket ARITHMETIC moved to notify/pushbudget_test.go together with the
// bucket itself (2026-09-03: it is keyed by push SERVER now, shared with the
// product ntfy channel, so its contract is no longer this package's). What is
// still asserted HERE is what this route does with it — the reserve floor and
// the refusal path above, and the wiring test below.

// TestSharedBudgetIsHonouredAcrossRoutes pins the DEFECT this change exists to
// fix. ntfy.sh rate-limits per SOURCE IP, so the product notification channel
// and this host route spend ONE allowance. The route must therefore draw from
// the SHARED per-server bucket — tokens the product channel already spent must
// be gone here, and the page reserve must survive them.
func TestSharedBudgetIsHonouredAcrossRoutes(t *testing.T) {
	c := &testClock{t: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)}
	reg := notify.NewPushBudgets(3, 2, c.now)
	// The PRODUCT channel's draw, in a DIFFERENT spelling of the same server:
	// one non-reserved token spent before this route ever sees an alert.
	if !reg.For("NTFY.SH").Take(false) {
		t.Fatal("the product channel could not take its first token")
	}
	r := newHostRigWith(t, time.Second, newFakePusher(), func(d *Deps) {
		d.WarningDigestInterval = time.Millisecond
		d.Budgets = reg
		d.HostServer = "https://ntfy.sh/"
	})
	// A warning digest now finds only the RESERVED tokens and must be refused —
	// under the old per-topic bucket it would have found a full bucket and
	// spent a token the page below needs.
	if w := r.post(t, warnJSON("WarnA", "chronic", "firing"), bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	r.clock.advance(time.Millisecond)
	r.tick(t)
	r.push.quiet(t)
	if !strings.Contains(metricsText(r.mx), `netops_alert_webhook_push_failures_total{route="host_monitoring",reason="budget_exhausted"} 1`) {
		t.Errorf("the shared-bucket refusal was not counted:\n%s", metricsText(r.mx))
	}
	// The reserve is intact for a PAGE — across both routes, which is the point.
	page := alertJSON("CorrelationConsumerDead", "critical", "correlation", "page", "firing", "consumer group empty")
	if w := r.post(t, page, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got := r.push.await(t, 1)[0]; got.Priority != notify.NtfyPriorityHigh {
		t.Fatalf("the shared reserve did not carry the page: %+v", got)
	}
	// One bucket, two routes: 3 - 1 (product) - 1 (page) = 1.
	if rem := r.mx.PushBudgetRemaining(); rem != 1 {
		t.Errorf("remaining = %d, want 1 — the gauge must reflect BOTH routes' draws", rem)
	}
	if got := reg.For("https://ntfy.sh").Remaining(); got != 1 {
		t.Errorf("the registry handed out a second bucket for the same host (remaining = %d)", got)
	}
}

// ── config parsing ──────────────────────────────────────────────────────────

func TestParseDigestIntervalAndCountAreLoudAboutTypos(t *testing.T) {
	spy := &logSpy{}
	if got := ParseDigestInterval("", nil); got != DefaultWarningDigestInterval {
		t.Errorf("empty = %v, want the default", got)
	}
	if got := ParseDigestInterval("45m", nil); got != 45*time.Minute {
		t.Errorf("45m = %v", got)
	}
	for _, bad := range []string{"nonsense", "0", "-5m"} {
		if got := ParseDigestInterval(bad, spy.log); got != DefaultWarningDigestInterval {
			t.Errorf("%q = %v, want the default — a typo must never mean 'push every warning'", bad, got)
		}
	}
	if n := spy.countContaining("invalid " + EnvWarningDigestInterval); n != 3 {
		t.Errorf("bad durations logged %d times, want 3", n)
	}
	if got := ParseCount("", DefaultPushBudget, EnvPushBudget, nil); got != DefaultPushBudget {
		t.Errorf("empty = %d", got)
	}
	if got := ParseCount("7", DefaultPushBudget, EnvPushBudget, nil); got != 7 {
		t.Errorf("7 = %d", got)
	}
	if got := ParseCount("-1", DefaultPushBudget, EnvPushBudget, nil); got != -1 {
		t.Errorf("-1 = %d — a negative budget is the documented 'no guard' setting", got)
	}
	if got := ParseCount("lots", DefaultPushBudget, EnvPushBudget, spy.log); got != DefaultPushBudget {
		t.Errorf("garbage = %d, want the default", got)
	}
	if n := spy.countContaining("invalid " + EnvPushBudget); n != 1 {
		t.Errorf("a bad count logged %d times, want 1", n)
	}
}
