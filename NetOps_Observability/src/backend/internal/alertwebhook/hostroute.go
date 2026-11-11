// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alertwebhook

// hostroute.go — the HOST-MONITORING delivery route.
//
// Owner decision, 2026-09-03: "Correlix alerts should be alerted to the host
// monitoring." There are two alert AUDIENCES and they are not the same people:
//
//   1. PLATFORM self-health — everything vmalert sends through this receiver
//      (layers stack/host/clickhouse/platform, the four page conditions listed
//      at pageRuleCount below, the warning tier). This is the stack reporting
//      on ITSELF, and it belongs on the same phone channel the external
//      watchdog already uses (scripts/stack-watchdog.sh → ntfy). That is the
//      route in this file.
//   2. PRODUCT/tenant alerts — monitor rules, BGP watch, per-tenant security
//      findings. Those keep the configured notify channels, including the
//      refusal to reuse the watchdog topic (notify_config.go). Untouched.
//
// WHY A SEPARATE ROUTE AND NOT JUST A CHANNEL. The product channel set is
// tenant-facing alert routing (severity gates, contact points, PlatformScope
// filtering). The platform route is the stack reporting on ITSELF, to the
// operator, by tier — a different audience with a different policy.
//
// WHERE ITS DESTINATIONS COME FROM (owner decision 2026-11-11, binding):
// "Platform self-health alerts should be configured from the GUI and not via
// env." Until then this route was configured ONLY from PLATFORM_ALERTS_NTFY_*
// env (falling back to WATCHDOG_NTFY_TOPIC), so a fresh install self-reported
// with zero config. That env contract is RETIRED: the destinations (ntfy and
// Twilio SMS, with per-tier routing) are a platform-global setting edited on
// Platform → Platform alerts and resolved per push through the HostRouter
// seam below (internal/platformalert implements it, with an in-memory
// last-good copy so a store outage never silences the route). What survives of
// the old property is that this package depends on no configured state to
// RUN — and that an unconfigured route is LOUD (gauge, log, admin banner),
// never quiet. The external watchdog (scripts/stack-watchdog.sh) stays
// env/file-based on the host: it is the layer that must outlive the stack.
//
// The product ntfy channel still refuses the watchdog topic and the platform
// route's topic (notify_config.go), so a tenant-facing channel can never be
// pointed at the operator's host-monitoring topic.
//
// Delivery is ASYNC and BOUNDED (§9). vmalert's POST must not wait on an
// external push — a single batch can carry hundreds of alerts and vmalert
// retries anything that is slow or 5xx, turning a blocking push into a
// self-inflicted request storm.

import (
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// Environment contract for this route: install-default POLICY knobs only (the
// owner's rule — env = install defaults). The DESTINATIONS are no longer env:
// see "WHERE ITS DESTINATIONS COME FROM" above. Declared here for the same
// reason as EnvToken: one spelling of each name, greppable against the compose
// plumbing.
const (
	// ── noise + rate-limit control (2026-09-03) ─────────────────────────────
	//
	// EnvWarningDigestInterval is how often the accumulated WARNING tier may be
	// summarized into a single push (digest.go). A Go duration ("30m", "1h").
	// Warnings are never pushed individually; the page tier is unaffected.
	// Invalid or <=0 falls back to DefaultWarningDigestInterval, LOUDLY —
	// "0" must not silently mean "push every warning again".
	EnvWarningDigestInterval = "PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL"
	// EnvPushBudget is the sustained outbound push allowance per hour for the
	// push SERVER HOST this route talks to — SHARED with the product ntfy
	// notification channel, because ntfy.sh rate-limits per source IP and both
	// senders leave this box on the same address (notify/pushbudget.go). The
	// name is unchanged; its scope widened from "this route's topic" on
	// 2026-09-03. 0 or negative DISABLES the guard, which is the documented
	// escape hatch for a self-hosted ntfy with no limits of its own.
	EnvPushBudget = "PLATFORM_ALERTS_PUSH_BUDGET"
	// EnvPushBudgetPageReserve is how many of those tokens only a PAGE may
	// spend, so a warning digest — or a chronic product warning — can never be
	// the reason a page is refused. The reserve is honoured ACROSS both routes:
	// on this route a page is `tier: page` (or the resolution of one); on the
	// product side it is a `critical` alert on an ntfy channel the operator
	// configured as a pager (min_severity=critical). Clamped into [0, budget-1].
	EnvPushBudgetPageReserve = "PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE"
)

// DefaultWarningDigestInterval matches DefaultCooldown: a chronic warning
// repeats at most once per cool-down, so a digest window of the same length
// carries at most one line per rule and the phone buzzes at most twice an hour
// for the whole warning tier.
const DefaultWarningDigestInterval = 30 * time.Minute

// Page-tier retry policy (§9: every network call retries with backoff+jitter,
// and every retry is BOUNDED).
//
// Only the page lane retries. A digest deliberately does not: it is re-sent on
// the next window with the accumulated content, so a retry would spend the very
// budget the digest exists to protect for no new information (digest.go).
const (
	// hostMaxAttempts counts the FIRST send too: 1 send + 4 retries.
	hostMaxAttempts = 5
	// hostRetryBase is the first backoff; it doubles per attempt.
	hostRetryBase = 2 * time.Second
	// hostRetryCap bounds one wait, hostRetryDeadline bounds the whole delivery.
	// The drain worker is serial, so the deadline is also the longest one page
	// can hold the queue — kept well under the queue's own drain headroom.
	hostRetryCap      = 30 * time.Second
	hostRetryDeadline = 2 * time.Minute
)

// RouteHostMonitoring is the `route` label value on the push metrics and the
// route name in the structured logs.
const RouteHostMonitoring = "host_monitoring"

// Push tiers. A CLOSED set — it is a metric label, and an open label set on a
// counter is a cardinality bomb (§10).
//
//	tierPage     a page-worthy condition (label tier="page") → high
//	tierWarning  every other firing alert                    → default
//	tierResolved a resolution of either                      → low
//
// The heartbeat is NOT a tier: it is never pushed at all (see handleAlert).
const (
	tierPage     = "page"
	tierWarning  = "warning"
	tierResolved = "resolved"
)

// The tier names a HostRouter is asked about. Exported so the router (in its
// own package) routes on the SAME closed set this receiver classifies into,
// rather than on a copy of the strings.
//
//	TierPage     a page-worthy condition, pushed immediately
//	TierResolved the resolution of a page, pushed immediately — it goes where
//	             pages go: an operator who was woken must be told it is over
//	TierWarning  an individual warning (only reached when the warning tier is
//	             routed nowhere; a routed warning is folded into the digest)
//	TierDigest   the periodic warning summary — it goes where warnings go
const (
	TierPage     = tierPage
	TierResolved = tierResolved
	TierWarning  = tierWarning
	TierDigest   = tierDigest
)

// Host channel names: the CLOSED set a HostTarget may carry (it is a log field
// and a test-verdict key — never an open label).
const (
	ChannelNtfy = "ntfy"
	ChannelSMS  = "sms"
)

// HostTarget is ONE destination of the host route for one push: a sender, the
// outbound budget it spends, and the channel name it is reported under.
//
// One target per RECIPIENT, not per channel: an SMS channel with two numbers is
// two targets, so a retry after one number failed re-sends to that number only
// (never a second, billable SMS to the number that already got it), and each
// message spends one token of the SMS budget.
type HostTarget struct {
	Channel string
	Pusher  HostPusher
	// Budget is taken at ENQUEUE (see pushHost). nil = no guard.
	Budget *notify.PushBudget
}

// HostRouter resolves the host route's destinations for a tier AT PUSH TIME.
// It is how the destinations became configurable without a restart: the
// receiver is built once at boot, and asks the router on every push.
//
// An empty answer for every tier means the route is NOT CONFIGURED, which is
// counted (not_configured), logged once, and reported on
// netops_alert_webhook_host_route_enabled. An empty answer for one tier while
// another tier has destinations is a deliberate choice by the administrator
// ("warnings go nowhere") and is counted separately (unrouted), never as a
// failure.
type HostRouter interface {
	Targets(tier string) []HostTarget
}

// staticRouter adapts the legacy single-pusher wiring (Deps.HostRoute) onto
// the router seam: every tier goes to the one pusher, under the receiver's own
// budget. Kept so an embedder (and the receiver's own tests) can wire a fixed
// destination without a store.
type staticRouter struct{ t HostTarget }

func (s staticRouter) Targets(string) []HostTarget { return []HostTarget{s.t} }

// FOUR PAGE CONDITIONS, ELEVEN RULES — and that is not a contradiction.
//
// The owner ruling (CLAUDE.md "Monitoring") is that page fires on exactly FOUR
// conditions. `grep -c 'tier: page' src/config/rules-scale-slo.yaml` returns
// ELEVEN, because one condition is implemented by several per-engine/per-lane
// rules whose first response differs — the rules are the same condition seen
// from a different vantage point, not extra conditions:
//
//	(1) an engine consumer is not consuming   — 6 rules
//	      CorrelationConsumerDead    broker view: the correlation group has zero members
//	      CorrelationLagGrowing      joined but draining nothing (the stuck shape)
//	      RouterConsumerDead         the same pair `by (consumergroup)` over the
//	      RouterConsumerLagGrowing     netops-router-* lanes, so a new lane is covered
//	      CorrConsumerNotRunning     the engine's OWN corr_consumer_running gauge
//	      CorrConsumerRestartLoop    a supervision loop that never stays up
//	(2) ingest silent when it should not be    — 2 rules
//	      IngestPipelineSilent       the vector-aggregator funnel (SNMP-guarded)
//	      NMSIngestSilent            the NMS controller lane (owner D4,
//	                                   2026-10-24): an integration that has
//	                                   delivered before went silent past
//	                                   max(3 x interval, 15m)
//	(3) storage refusing writes                — 1 rule: ClickHouseWritesRejected
//	(4) the alerting path broken               — 2 rules
//	      AlertDeliveryBroken        the front half: no heartbeat reached the
//	                                   receiver (vmalert -> notifier -> api)
//	      PlatformAlertsReachNobody  the last hop: the receiver is fed but no
//	                                   channel set up on Platform -> Platform
//	                                   alerts receives pages, or the settings
//	                                   were never readable since start-up
//	                                   (review 2026-11-11; same condition, not
//	                                   a fifth)
//
// The page tier lives ENTIRELY in rules-scale-slo.yaml (vmalert-only, so it
// keeps firing when the api is the thing that is down); rules.yaml carries no
// `tier: page` rule at all. Both claims are pinned mechanically by
// TestPageTierRuleCountMatchesTheComment in pagetier_test.go, so this comment
// fails the build rather than rotting the next time a rule is added.
const pageRuleCount = 11

// hostQueueSize bounds the pending pushes. Beyond it, enqueue fails LOUDLY
// (counted + logged) rather than blocking vmalert's request or growing forever.
const hostQueueSize = 256

// maxHostTitle bounds the composed title; notify.Ntfy bounds it again at the
// wire.
const maxHostTitle = 180

// bodyLabels are the labels carried into the push body, in this order. A fixed
// list, not "every label": the body is a phone notification, and an unbounded
// label dump makes the one line that matters unreadable.
var bodyLabels = [...]string{"severity", "layer", "rule_layer", "tier", "service", "instance", "job", "consumergroup", "container"}

// HostPusher is the push seam (§5: interfaces for external dependencies). It is
// satisfied by *notify.Ntfy — the SAME sender the product channel uses — and by
// the SMS adapter in internal/platformalert. A typed failure that implements
// Retryable()/RateLimited() (notify.NtfyStatusError, notify.TwilioStatusError)
// drives the page-tier retry policy below.
type HostPusher interface {
	Push(p notify.NtfyPush) error
}

// hostJob is one composed push plus the metric/log context it is counted under.
type hostJob struct {
	push notify.NtfyPush
	tier string
	name string
	// target is the destination this job is bound to (one per recipient).
	target HostTarget
	// onOK runs once after a successful delivery. Paired with onFail so a
	// digest fanned out to several targets is restored only when it reached
	// NONE of them (see fanout).
	onOK func()
	// onFail runs on EVERY path that ends without delivery: after the last
	// attempt has failed (deliverHost), and when the job was never attempted at
	// all because the queue was full or no topic is configured (enqueueHost). It
	// exists for content that non-delivery would otherwise destroy: the digest
	// drains its accumulator to compose the message, so without this the
	// window's warnings are gone even though nothing was sent (review 3.9-09).
	// Nil for every job whose content survives its own delivery.
	onFail func()
}

// retryable reports whether this job may be re-sent on a transient failure.
// PAGE ONLY, by design: a page that is refused must never be dropped silently
// (§10), while a digest is re-sent next window for free and a warning is not
// worth a second request against a rate-limited server.
func (j hostJob) retryable() bool { return j.tier == tierPage }

// privileged reports whether this job may spend the budget's page reserve.
// True for exactly the traffic that is pushed IMMEDIATELY — the page tier and
// the resolution of a page. Digested traffic is never privileged.
func (j hostJob) privileged() bool { return j.tier == tierPage || j.tier == tierResolved }

// pushHost composes and enqueues the host-monitoring push for an accepted
// alert. It is called only for alerts that already passed the tenant refusal
// and the cool-down, so the dedup window governs this route exactly as it
// governs the product dispatcher — one push per identical alert per window.
func (r *receiver) pushHost(a models.Alert, labels map[string]string, status string) {
	tier := hostTier(status, labels["tier"])

	// THE WARNING TIER IS NEVER PUSHED ON ITS OWN (digest.go). Folding happens
	// only when there is a destination to fold FOR: with no warning-tier
	// destination the alert falls through, and is counted as not_configured
	// (no route at all) or unrouted (the administrator sent warnings nowhere)
	// instead of accumulating a digest nobody can ever send.
	if hostDigested(labels["tier"]) && len(r.hostTargets(tierDigest)) > 0 {
		r.foldDigest(a.Rule, a.Summary, labels["severity"], tier, r.now())
		return
	}

	j := hostJob{
		name: a.Rule,
		tier: tier,
		push: notify.NtfyPush{
			Title:    hostTitle(tier, a.Rule, a.Summary),
			Body:     hostBody(tier, a, labels),
			Priority: hostPriority(tier),
			Tags:     hostTags(tier),
		},
	}
	targets := r.hostTargets(tier)
	if len(targets) == 0 {
		r.noHostTarget(j)
		return
	}
	for _, t := range targets {
		jt := j
		jt.target = t
		// The budget is taken at ENQUEUE, synchronously with the request, so a
		// refusal is decided (and counted) at a point the operator can
		// correlate with the alert that caused it rather than inside a drain
		// goroutine. Per TARGET: an SMS budget that is spent must not stop the
		// ntfy push of the same page, and vice versa.
		if !t.Budget.Take(jt.privileged()) {
			r.deps.Metrics.inc(&r.deps.Metrics.hostBudgetExhausted)
			// A PAGE that the budget refuses is an ERROR, never a warning: the
			// operator is not being told about a page-worthy condition on this
			// channel and must learn that from the log if nowhere else (§10).
			level := "warn"
			if jt.tier == tierPage {
				level = "error"
			}
			r.log(level, "platform alert push SKIPPED: the outbound push budget for this channel is spent", map[string]any{
				"route": RouteHostMonitoring, "alertname": jt.name, "tier": jt.tier, "channel": t.Channel,
				"env": EnvPushBudget, "reserve_env": EnvPushBudgetPageReserve,
				// The ntfy budget is per SERVER and shared with the product
				// channel, so name the server: "the topic is quiet" is not the
				// same fact as "this host's whole ntfy allowance is spent" (§10).
				"server": t.Budget.Server(),
			})
			continue
		}
		r.enqueueHost(jt)
	}
}

// hostTargets asks the router for a tier's destinations. Nil router (no route
// wired at all) answers none.
func (r *receiver) hostTargets(tier string) []HostTarget {
	if r.router == nil {
		return nil
	}
	return r.router.Targets(tier)
}

// hostConfigured reports whether the route has ANY destination for any tier.
// It is what separates "not configured" (nobody will ever hear from this
// stack) from "unrouted" (the administrator chose to send this tier nowhere).
func (r *receiver) hostConfigured() bool {
	return len(r.hostTargets(tierPage)) > 0 || len(r.hostTargets(tierDigest)) > 0
}

// noHostTarget accounts for a job with no destination for its tier.
func (r *receiver) noHostTarget(j hostJob) {
	if r.hostConfigured() {
		// A deliberate routing choice, not a failure: counted, never logged per
		// alert (it would repeat on every cool-down, forever).
		r.deps.Metrics.inc(&r.deps.Metrics.hostUnrouted)
		if j.onFail != nil {
			j.onFail()
		}
		return
	}
	r.enqueueHost(j) // the not_configured accounting lives there
}

// hostDigested reports whether an alert belongs in the warning digest rather
// than on the wire now. The discriminator is the SERVER-CONTROLLED `tier`
// label and nothing else: tier=page fires immediately, and so does the
// RESOLUTION of a page (vmalert carries the same labels on the resolved leg),
// because an operator who was woken must be told it is over. Everything else —
// the whole chronic-warning tier, and the resolution of a warning — is folded.
func hostDigested(tierLabel string) bool {
	return !strings.EqualFold(strings.TrimSpace(tierLabel), tierPage)
}

// hostTier classifies an alert for this route. Only the server-controlled
// `tier` label promotes to page — NOT severity: the rule files carry ~140
// critical/warning rules and only four conditions are page-worthy, carried by
// the pageRuleCount rules enumerated above (see also
// docs/runbooks/engine-liveness-matrix.md). Promoting on severity would page
// for all of them, and a pager that cries wolf gets muted.
func hostTier(status, tierLabel string) string {
	if strings.EqualFold(strings.TrimSpace(status), "resolved") {
		return tierResolved
	}
	if strings.EqualFold(strings.TrimSpace(tierLabel), tierPage) {
		return tierPage
	}
	return tierWarning
}

func hostPriority(tier string) string {
	switch tier {
	case tierPage:
		return notify.NtfyPriorityHigh
	case tierResolved:
		return notify.NtfyPriorityLow
	default:
		return notify.NtfyPriorityDefault
	}
}

func hostTags(tier string) string {
	switch tier {
	case tierPage:
		return "rotating_light"
	case tierResolved:
		return "white_check_mark"
	default:
		return "warning"
	}
}

// hostTitle is what lands on the lock screen: the tier, the rule name, and the
// summary — in that order, because the first two words decide whether the
// operator gets out of bed.
func hostTitle(tier, name, summary string) string {
	title := "[" + strings.ToUpper(tier) + "] " + name
	if s := strings.TrimSpace(summary); s != "" && s != name {
		title += ": " + s
	}
	if len(title) > maxHostTitle {
		title = title[:maxHostTitle]
	}
	return title
}

// hostBody is the push body. Deterministic (fixed label order) so two identical
// alerts render identically, and free of anything tenant-shaped — an alert
// carrying a tenant label never reaches here (see handleAlert).
func hostBody(tier string, a models.Alert, labels map[string]string) string {
	var b strings.Builder
	if tier == tierResolved {
		b.WriteString("RESOLVED — ")
	}
	b.WriteString(a.Rule)
	if s := strings.TrimSpace(a.Summary); s != "" && s != a.Rule {
		b.WriteString(": ")
		b.WriteString(s)
	}
	var kv []string
	for _, k := range bodyLabels {
		if v := strings.TrimSpace(labels[k]); v != "" {
			kv = append(kv, k+"="+v)
		}
	}
	if len(kv) > 0 {
		b.WriteString("\n")
		b.WriteString(strings.Join(kv, " "))
	}
	if d := strings.TrimSpace(a.Description); d != "" && tier != tierResolved {
		b.WriteString("\n")
		b.WriteString(d)
	}
	return b.String()
}

// enqueueHost hands the job to the drain worker. It never blocks: a full queue
// is counted and logged, and a missing route is counted and logged ONCE.
func (r *receiver) enqueueHost(j hostJob) {
	if j.target.Pusher == nil {
		r.deps.Metrics.inc(&r.deps.Metrics.hostNotConfigured)
		// ONCE, not per alert: a stack with no destination configured would
		// otherwise write one warning per alert per cool-down forever, which is
		// its own outage (the log volume, and the signal buried in it). The
		// gauge (netops_alert_webhook_host_route_enabled 0) and the banner on
		// the admin page stay loud for as long as the condition lasts.
		r.hostOnce.Do(func() {
			r.log("warn", "platform alerts are NOT pushed to host monitoring: no channel is configured — "+
				"set one up in "+GUILocation+" or the stack cannot report its own failures to a phone",
				map[string]any{"route": RouteHostMonitoring, "where": GUILocation})
		})
		// Never delivered, so content that lives only inside this job comes back
		// (review 3.9-09). Unreachable for the digest today — maybeFlushDigest
		// returns before it composes anything when there is no route — and wired
		// anyway, because the invariant is "a job that was not delivered does not
		// take its content with it", not "the one path we happened to notice".
		if j.onFail != nil {
			j.onFail()
		}
		return
	}
	select {
	case r.hostQ <- j:
	default:
		r.deps.Metrics.inc(&r.deps.Metrics.hostQueueFull)
		r.log("warn", "platform alert DROPPED: the host-monitoring push queue is full", map[string]any{
			"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier, "queue": hostQueueSize,
			"content_kept": j.onFail != nil,
		})
		// THE DIGEST DRAINED ITS ACCUMULATOR TO COMPOSE THIS JOB, so a job the
		// queue refuses destroys the window's warnings exactly as a failed push
		// did (review 3.9-09) — and a full queue is the wedged-ntfy state the
		// bound exists for, which is the same 429 storm that motivated the
		// digest. deliverHost's handback covers the attempted-and-failed case;
		// this covers the never-attempted one.
		if j.onFail != nil {
			j.onFail()
		}
		return
	}
	r.hostMu.Lock()
	if !r.hostRunning {
		r.hostRunning = true
		go r.drainHost()
	}
	r.hostMu.Unlock()
}

// drainHost delivers queued pushes one at a time and EXITS when the queue is
// empty, so an idle receiver holds no goroutine. Serial by design: pushes are
// rare (the cool-down sees to that) and ordering is what makes a phone's
// notification list readable.
func (r *receiver) drainHost() {
	for {
		select {
		case j := <-r.hostQ:
			r.deliverHost(j)
		default:
			r.hostMu.Lock()
			// Re-check UNDER the lock. An enqueue whose channel send landed
			// after the empty read above has not yet taken this lock, or has
			// already taken it and seen hostRunning=true; either way, seeing a
			// non-empty queue here is what keeps that job from being orphaned.
			if len(r.hostQ) > 0 {
				r.hostMu.Unlock()
				continue
			}
			r.hostRunning = false
			r.hostMu.Unlock()
			return
		}
	}
}

// deliverHost performs one push and records it.
//
// A PAGE RETRIES (§9: backoff + jitter, bounded attempts AND a deadline). The
// live 429 storm of 2026-09-03 proved the old "the next vmalert resend is the
// retry" reasoning wrong for the page lane: the cool-down suppresses the
// repost of an identical alert for 30 minutes, so a page refused with 429 was
// not retried in a minute — it was dropped for half an hour, with only a WARN
// line to show for it. Everything else still takes exactly one attempt: a
// digest is re-sent next window with the accumulated content, so retrying it
// would spend budget for no new information.
func (r *receiver) deliverHost(j hostJob) {
	deadline := r.now().Add(hostRetryDeadline)
	var err error
	for attempt := 1; ; attempt++ {
		if err = j.target.Pusher.Push(j.push); err == nil {
			r.deps.Metrics.incHostPushed(j.tier)
			r.log("info", "platform alert pushed to host monitoring", map[string]any{
				"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier,
				"channel": j.target.Channel, "priority": j.push.Priority, "attempts": attempt,
			})
			if j.onOK != nil {
				j.onOK()
			}
			return
		}
		if !j.retryable() || attempt >= hostMaxAttempts || !retryableErr(err) {
			break
		}
		wait := hostBackoff(attempt, retryAfterOf(err))
		if !r.now().Add(wait).Before(deadline) {
			break
		}
		r.deps.Metrics.inc(&r.deps.Metrics.hostRetries)
		r.sleep(wait)
	}

	reason := "send_error"
	switch {
	case errors.Is(err, notify.ErrPushBudgetExhausted):
		// A sender that carries its own bucket refused locally: the request
		// was never made. Same account as a refusal at enqueue.
		reason = "budget_exhausted"
		r.deps.Metrics.inc(&r.deps.Metrics.hostBudgetExhausted)
	case isRateLimited(err):
		reason = "rate_limited"
		r.deps.Metrics.inc(&r.deps.Metrics.hostRateLimited)
	default:
		r.deps.Metrics.inc(&r.deps.Metrics.hostFailed)
	}
	// A page that never landed is an ERROR: nobody was told about a
	// page-worthy condition, and this line is the only remaining trace (§10).
	level := "warn"
	if j.tier == tierPage {
		level = "error"
	}
	// The error is already topic-free (notify.Ntfy scrubs the URL) — the
	// topic is a credential and never appears in a log line.
	r.log(level, "platform alert push to host monitoring FAILED", map[string]any{
		"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier, "channel": j.target.Channel,
		"error": err.Error(), "reason": reason, "retried": j.retryable(),
		"content_kept": j.onFail != nil,
	})
	if j.onFail != nil {
		j.onFail()
	}
}

// sleep is the injected wait (Deps.Sleep), so the backoff is asserted in tests
// without spending the wall-clock time it describes.
func (r *receiver) sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	if r.deps.Sleep != nil {
		r.deps.Sleep(d)
		return
	}
	time.Sleep(d)
}

// hostBackoff is capped exponential backoff with jitter. The server's own
// Retry-After wins when it sent one — it is the only party that knows when its
// budget refills — and it arrives already clamped by notify.parseRetryAfter, so
// a hostile value cannot park the queue.
func hostBackoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	d := hostRetryBase << (attempt - 1)
	if d > hostRetryCap || d <= 0 {
		d = hostRetryCap
	}
	// Decorrelate concurrent senders: half the computed delay plus a random
	// half. Full-zero jitter would let two api instances sharing a topic retry
	// in lockstep and re-create the burst that earned the 429.
	// #nosec G404 -- retry jitter, not a security context: this randomness
	// only decorrelates backoff timing and never gates a decision.
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

// retryableErr decides whether re-sending can succeed. A typed ntfy status
// answers for itself (429/5xx yes, other 4xx no — a bad token will not fix
// itself and retrying it only burns budget). An UNTYPED error is a transport
// failure (connect/timeout) and is retried: that is the classic transient.
//
// A LOCAL budget refusal (notify.ErrPushBudgetExhausted) is never retried: the
// request was not made, and hammering a spent bucket only defers the refusal.
func retryableErr(err error) bool {
	if errors.Is(err, notify.ErrPushBudgetExhausted) {
		return false
	}
	var se pushStatus
	if errors.As(err, &se) {
		return se.Retryable()
	}
	return err != nil
}

// pushStatus is the typed-failure shape every host sender shares
// (notify.NtfyStatusError, notify.TwilioStatusError), so the retry policy is
// written once rather than per provider.
type pushStatus interface {
	error
	Retryable() bool
	RateLimited() bool
}

// retryDelayer is the optional server-supplied Retry-After, already clamped by
// the sender.
type retryDelayer interface {
	error
	RetryDelay() time.Duration
}

func isRateLimited(err error) bool {
	var se pushStatus
	return errors.As(err, &se) && se.RateLimited()
}

func retryAfterOf(err error) time.Duration {
	var se retryDelayer
	if errors.As(err, &se) {
		return se.RetryDelay()
	}
	return 0
}

// ParseDigestInterval parses EnvWarningDigestInterval. An invalid value logs
// and yields the default: a typo must never silently turn the digest off and
// put the whole warning tier back on the wire one push at a time.
func ParseDigestInterval(raw string, log LogFunc) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultWarningDigestInterval
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		if log != nil {
			log("warn", "invalid "+EnvWarningDigestInterval+" — using the default", map[string]any{
				"value": raw, "default": DefaultWarningDigestInterval.String(),
			})
		}
		return DefaultWarningDigestInterval
	}
	return d
}

// ParseCount parses one of the integer budget knobs. Same contract as
// ParseDigestInterval: loud about a typo, never silently degraded. A NEGATIVE
// value is accepted for EnvPushBudget alone, where it means "no budget guard";
// the caller documents that, this function only refuses garbage.
func ParseCount(raw string, def int, env string, log LogFunc) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		if log != nil {
			log("warn", "invalid "+env+" — using the default", map[string]any{
				"value": raw, "default": def,
			})
		}
		return def
	}
	return n
}

// GUILocation is where an administrator configures this route. One spelling,
// shared by the not-configured log line, the boot warning about retired env,
// and the admin page's own heading (src/frontend nav: Platform → Platform
// alerts).
const GUILocation = "Platform → Platform alerts"
