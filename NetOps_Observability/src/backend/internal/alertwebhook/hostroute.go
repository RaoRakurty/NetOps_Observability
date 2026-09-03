package alertwebhook

// hostroute.go — the HOST-MONITORING delivery route.
//
// Owner decision, 2026-09-03: "Correlix alerts should be alerted to the host
// monitoring." There are two alert AUDIENCES and they are not the same people:
//
//   1. PLATFORM self-health — everything vmalert sends through this receiver
//      (layers stack/host/clickhouse/platform, the four page conditions, the
//      warning tier). This is the stack reporting on ITSELF, and it belongs on
//      the same phone channel the external watchdog already uses
//      (scripts/stack-watchdog.sh → ntfy). That is the route in this file.
//   2. PRODUCT/tenant alerts — monitor rules, BGP watch, per-tenant security
//      findings. Those keep the configured notify channels, including the
//      refusal to reuse the watchdog topic (notify_config.go). Untouched.
//
// WHY A SEPARATE ROUTE AND NOT JUST A CHANNEL. The product channel set is
// operator-CONFIGURED state: it can be empty, disabled, or misconfigured, and
// it lives behind the same api this route reports on. A stack that can only
// tell you it is broken through a channel someone had to configure first is not
// self-reporting. This route depends on nothing but an env-provided topic, so
// it works on a fresh install with zero notification config — which is exactly
// the install where "the correlation engine has consumed nothing for 3 hours"
// most needs to reach a human.
//
// WHY IT REUSES THE WATCHDOG'S TOPIC BY DEFAULT. The watchdog's independence
// requirement (#101) is about the SENDER, not the topic: the watchdog must be
// able to report the stack's death from OUTSIDE the stack, which it still does.
// The product channel refusal stays in force so a TENANT-facing channel can
// never be pointed at the operator's host-monitoring topic.
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

// Environment contract for this route. Declared here for the same reason as
// EnvToken: one spelling of each name, greppable against the compose plumbing.
const (
	// EnvHostTopic is the host-monitoring ntfy topic. EMPTY falls back to
	// EnvWatchdogTopic — the phone channel the operator already carries.
	EnvHostTopic = "PLATFORM_ALERTS_NTFY_TOPIC"
	// EnvHostServer / EnvHostToken override the ntfy server and bearer token
	// for this route only. Empty falls back to the product ntfy wiring below,
	// then to https://ntfy.sh.
	EnvHostServer = "PLATFORM_ALERTS_NTFY_SERVER"
	// #nosec G101 -- the NAME of an environment variable, not a credential.
	EnvHostToken = "PLATFORM_ALERTS_NTFY_TOKEN"
	// EnvWatchdogTopic is the external watchdog's topic (scripts/stack-watchdog.env,
	// already passed into the api container so notify_config.go can REFUSE it
	// for product alerting). It is this route's default destination.
	EnvWatchdogTopic = "WATCHDOG_NTFY_TOPIC"
	// The product ntfy wiring, used only as the server/token fallback — never
	// as the topic fallback: a platform alert must not land on a product topic.
	EnvProductNtfyServer = "NTFY_ALERT_SERVER"
	// #nosec G101 -- the NAME of an environment variable, not a credential.
	EnvProductNtfyToken = "NTFY_ALERT_TOKEN"

	// ── noise + rate-limit control (2026-09-03) ─────────────────────────────
	//
	// EnvWarningDigestInterval is how often the accumulated WARNING tier may be
	// summarized into a single push (digest.go). A Go duration ("30m", "1h").
	// Warnings are never pushed individually; the page tier is unaffected.
	// Invalid or <=0 falls back to DefaultWarningDigestInterval, LOUDLY —
	// "0" must not silently mean "push every warning again".
	EnvWarningDigestInterval = "PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL"
	// EnvPushBudget is the sustained outbound push allowance per hour for this
	// route's topic (pushbudget.go). 0 or negative DISABLES the guard, which is
	// the documented escape hatch for a self-hosted ntfy with no limits of its
	// own.
	EnvPushBudget = "PLATFORM_ALERTS_PUSH_BUDGET"
	// EnvPushBudgetPageReserve is how many of those tokens only a PAGE (or the
	// resolution of one) may spend, so a warning digest can never be the reason
	// a page is refused. Clamped into [0, budget-1].
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
//	tierPage     the four page-worthy conditions (label tier="page") → high
//	tierWarning  every other firing alert                            → default
//	tierResolved a resolution of either                              → low
//
// The heartbeat is NOT a tier: it is never pushed at all (see handleAlert).
const (
	tierPage     = "page"
	tierWarning  = "warning"
	tierResolved = "resolved"
)

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
// satisfied by *notify.Ntfy — the SAME sender the product channel uses, so
// there is exactly one ntfy HTTP client in the process. A nil HostPusher means
// the route is not configured: pushes are counted as not_configured and warned
// about ONCE, never per alert.
type HostPusher interface {
	Push(p notify.NtfyPush) error
}

// hostJob is one composed push plus the metric/log context it is counted under.
type hostJob struct {
	push notify.NtfyPush
	tier string
	name string
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
	// only when there is a route to fold FOR: with no topic configured the
	// alert still goes to enqueueHost, which is what counts the
	// not_configured failure per alert instead of accumulating a digest nobody
	// can ever send.
	if r.deps.HostRoute != nil && hostDigested(labels["tier"]) {
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
	// The budget is taken at ENQUEUE, synchronously with the request, so a
	// refusal is decided (and counted) at a point the operator can correlate
	// with the alert that caused it rather than inside a drain goroutine.
	if r.deps.HostRoute != nil && !r.budget.take(j.privileged()) {
		r.deps.Metrics.inc(&r.deps.Metrics.hostBudgetExhausted)
		// A PAGE that the budget refuses is an ERROR, never a warning: the
		// operator is not being told about a page-worthy condition and must
		// learn that from the log if nowhere else (§10 — no silent failures).
		level := "warn"
		if j.tier == tierPage {
			level = "error"
		}
		r.log(level, "platform alert push SKIPPED: the outbound push budget for this topic is spent", map[string]any{
			"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier,
			"env": EnvPushBudget, "reserve_env": EnvPushBudgetPageReserve,
		})
		return
	}
	r.enqueueHost(j)
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
// critical/warning rules and only four conditions are page-worthy (see
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
	if r.deps.HostRoute == nil {
		r.deps.Metrics.inc(&r.deps.Metrics.hostNotConfigured)
		// ONCE, not per alert: a stack with no host topic configured would
		// otherwise write one warning per alert per cool-down forever, which is
		// its own outage (the log volume, and the signal buried in it).
		r.hostOnce.Do(func() {
			r.log("warn", "platform alerts are NOT pushed to host monitoring: no topic configured — set "+
				EnvHostTopic+" (or "+EnvWatchdogTopic+") or the stack cannot report its own failures to a phone",
				map[string]any{"route": RouteHostMonitoring, "env": EnvHostTopic})
		})
		return
	}
	select {
	case r.hostQ <- j:
	default:
		r.deps.Metrics.inc(&r.deps.Metrics.hostQueueFull)
		r.log("warn", "platform alert DROPPED: the host-monitoring push queue is full", map[string]any{
			"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier, "queue": hostQueueSize,
		})
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
		if err = r.deps.HostRoute.Push(j.push); err == nil {
			r.deps.Metrics.incHostPushed(j.tier)
			r.log("info", "platform alert pushed to host monitoring", map[string]any{
				"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier,
				"priority": j.push.Priority, "attempts": attempt,
			})
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

	reason, rateLimited := "send_error", isRateLimited(err)
	if rateLimited {
		reason = "rate_limited"
		r.deps.Metrics.inc(&r.deps.Metrics.hostRateLimited)
	} else {
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
		"route": RouteHostMonitoring, "alertname": j.name, "tier": j.tier,
		"error": err.Error(), "reason": reason, "retried": j.retryable(),
	})
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
func retryableErr(err error) bool {
	var se *notify.NtfyStatusError
	if errors.As(err, &se) {
		return se.Retryable()
	}
	return err != nil
}

func isRateLimited(err error) bool {
	var se *notify.NtfyStatusError
	return errors.As(err, &se) && se.RateLimited()
}

func retryAfterOf(err error) time.Duration {
	var se *notify.NtfyStatusError
	if errors.As(err, &se) {
		return se.RetryAfter
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

// HostRouteLogFields renders the route's configuration for the wiring layer's
// boot log line. The TOPIC IS NEVER A FIELD: knowing an ntfy topic is enough to
// read every alert published to it and to publish forgeries (§8).
func HostRouteLogFields(server string, tokenSet bool, source string) map[string]any {
	return map[string]any{
		"route": RouteHostMonitoring, "server": server, "token_set": tokenSet, "topic_from": source,
	}
}
