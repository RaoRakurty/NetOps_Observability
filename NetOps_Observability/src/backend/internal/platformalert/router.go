// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"errors"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/alertwebhook"
	"netops/backend/notify"
)

// router.go — alertwebhook.HostRouter over the record in force.
//
// TIER → CHANNEL. A page, and the all-clear that follows it, go to every live
// channel with Tiers.Page; the warning digest goes to every live channel with
// Tiers.Warning. Defaults: pages to ntfy AND SMS, the digest to ntfy only.
//
// BUDGETS (the 2026-09-19 lesson: ntfy answered 429 to 4,231 page-tier pushes
// during a three-day outage). Every target carries a token bucket the receiver
// spends at ENQUEUE:
//
//   - ntfy: the process's SHARED per-server bucket (notify.PushBudgets), the
//     same one the product ntfy channel draws from — ntfy.sh rate-limits per
//     source IP, so both senders must see one allowance. The page reserve is
//     honoured across both.
//   - SMS: a bucket of its own, capped at Config.SMS.MaxPerHour messages an
//     hour (default 10), one token per message (per recipient). HALF the cap is
//     reserved for pages, so a warning digest the administrator chose to send
//     by SMS can never be the reason a page is not texted. Past the cap the
//     receiver refuses the SMS locally, counts it
//     (netops_alert_webhook_push_failures_total{reason="budget_exhausted"}) and
//     logs an ERROR for a page — ntfy still carries it if it is enabled.
//
// The page lane's storm control upstream is unchanged: the receiver's cool-down
// sends one push per identical alert per 30 minutes, and warnings are folded
// into one digest per window.

// RouterDeps are the router's injected collaborators (§5).
type RouterDeps struct {
	Store *Store
	// Budgets is the shared per-push-server registry. nil = no ntfy guard.
	Budgets *notify.PushBudgets
	// Now drives the SMS bucket's refill. nil = time.Now.
	Now func() time.Time
	// TwilioBase overrides the Twilio API origin. Production leaves it empty;
	// tests point it at an httptest server so no real SMS is ever sent.
	TwilioBase string
}

// Router resolves destinations per tier. Safe for concurrent use.
type Router struct {
	d RouterDeps

	mu        sync.Mutex
	built     uint64 // store version the targets were built from (0 = never)
	page      []alertwebhook.HostTarget
	warning   []alertwebhook.HostTarget
	smsBudget *notify.PushBudget
	smsCap    int
}

// NewRouter builds the router.
func NewRouter(d RouterDeps) *Router {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Router{d: d}
}

// Targets implements alertwebhook.HostRouter.
func (r *Router) Targets(tier string) []alertwebhook.HostTarget {
	if r == nil || r.d.Store == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rebuildLocked()
	switch tier {
	case alertwebhook.TierPage, alertwebhook.TierResolved:
		return append([]alertwebhook.HostTarget(nil), r.page...)
	case alertwebhook.TierWarning, alertwebhook.TierDigest:
		return append([]alertwebhook.HostTarget(nil), r.warning...)
	default:
		// An unknown tier reaches nobody: the tier set is closed, and a value
		// outside it is a bug that must not quietly page someone.
		return nil
	}
}

// rebuildLocked rebuilds the senders when the record changed. The SMS bucket
// survives a rebuild unless the cap changed, so re-saving the page cannot be
// used to refill a spent SMS allowance.
func (r *Router) rebuildLocked() {
	v := r.d.Store.Version()
	if v == r.built {
		return
	}
	cfg := r.d.Store.Current()
	r.page, r.warning = nil, nil
	if cfg.ntfyLive() {
		t := alertwebhook.HostTarget{
			Channel: alertwebhook.ChannelNtfy,
			// NO budget on the sender itself: the receiver takes the token at
			// enqueue, so a budget here would spend two tokens per push.
			Pusher: notify.NewNtfy(cfg.Ntfy.Server, cfg.Ntfy.Topic, cfg.Ntfy.Token),
			Budget: r.d.Budgets.For(cfg.Ntfy.Server),
		}
		if cfg.Ntfy.Tiers.Page {
			r.page = append(r.page, t)
		}
		if cfg.Ntfy.Tiers.Warning {
			r.warning = append(r.warning, t)
		}
	}
	if cfg.smsLive() {
		r.ensureSMSBudgetLocked(cfg.SMS.MaxPerHour)
		for _, to := range cfg.SMS.To {
			t := alertwebhook.HostTarget{
				Channel: alertwebhook.ChannelSMS,
				Pusher:  smsPusher{tw: r.twilio(cfg.SMS, to)},
				Budget:  r.smsBudget,
			}
			if cfg.SMS.Tiers.Page {
				r.page = append(r.page, t)
			}
			if cfg.SMS.Tiers.Warning {
				r.warning = append(r.warning, t)
			}
		}
	}
	r.built = v
}

func (r *Router) twilio(c SMSChannel, to string) *notify.Twilio {
	tw := notify.NewTwilio(c.AccountSID, c.AuthToken, c.From, to)
	if r.d.TwilioBase != "" {
		tw.WithEndpoint(r.d.TwilioBase)
	}
	return tw
}

// ensureSMSBudgetLocked makes the SMS bucket exist at the configured cap. ONE
// bucket for the process's life: a change of the cap RESIZES it and carries the
// hour's usage over (notify.PushBudget.Resize), so editing max_per_hour — or
// re-saving the page — can never refill a spent allowance.
//
// What a token buys: one message to one number. A page that Twilio answers with
// a 5xx/429 is retried by the receiver (internal/alertwebhook) up to 5 POSTs in
// total under the SAME token, so the worst case per page token is 5 billable
// attempts; Twilio does not bill a request it refused with an error, so in
// practice a retry costs only when an earlier attempt silently succeeded.
func (r *Router) ensureSMSBudgetLocked(perHour int) *notify.PushBudget {
	switch {
	case r.smsBudget == nil:
		r.smsBudget = notify.NewPushBudget(notify.DefaultTwilioAPIBase, perHour, perHour/2, r.d.Now)
	case r.smsCap != perHour:
		r.smsBudget.Resize(perHour, perHour/2)
	}
	r.smsCap = perHour
	return r.smsBudget
}

// SMSBudgetRemaining is the SMS allowance left this hour (-1 = SMS not live).
func (r *Router) SMSBudgetRemaining() int {
	if r == nil {
		return -1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.d.Store == nil {
		return -1
	}
	r.rebuildLocked()
	if !r.d.Store.Current().smsLive() {
		return -1
	}
	return r.smsBudget.Remaining()
}

// smsPusher adapts one single-recipient Twilio sender onto the host route's
// push seam. The SMS is the push TITLE — tier, rule and summary, in the order
// that decides whether someone gets out of bed — bounded to one segment by
// notify.Twilio.Text.
type smsPusher struct{ tw *notify.Twilio }

func (s smsPusher) Push(p notify.NtfyPush) error { return s.tw.Text(smsText(p)) }

func smsText(p notify.NtfyPush) string {
	t := strings.TrimSpace(p.Title)
	if t == "" {
		t = strings.TrimSpace(p.Body)
	}
	return "Correlix " + t
}

// ── test send ───────────────────────────────────────────────────────────────

// Verdict is the plain result of a test message. A CLOSED set: the UI maps it
// to a sentence, and nothing a provider answers is ever echoed (a response
// body can carry account detail and destination numbers).
type Verdict string

const (
	VerdictOK            Verdict = "ok"
	VerdictAuthRejected  Verdict = "auth_rejected"
	VerdictRateLimited   Verdict = "rate_limited"
	VerdictUnreachable   Verdict = "unreachable"
	VerdictRefused       Verdict = "refused"
	VerdictNotConfigured Verdict = "not_configured"
)

// TestResult is what POST …/test answers.
type TestResult struct {
	Channel string  `json:"channel"`
	Verdict Verdict `json:"verdict"`
	Message string  `json:"message"`
}

// testPush is the message a test sends.
func testPush() notify.NtfyPush {
	return notify.NtfyPush{
		Title:    "[TEST] Platform alerts are reaching this channel",
		Body:     "This is a test from Correlix (Platform → Platform alerts). No action is needed.",
		Priority: notify.NtfyPriorityDefault,
		Tags:     "white_check_mark",
	}
}

// Test sends one test message through a channel's SAVED settings. A disabled
// channel may be tested (an administrator checks before turning it on), but
// it must be complete. A test spends the same budget a real alert does — it
// hits the same provider limits, and a refusal is the honest answer.
func (r *Router) Test(channel string) TestResult {
	cfg := r.d.Store.Current()
	switch channel {
	case alertwebhook.ChannelNtfy:
		if cfg.Ntfy.Topic == "" {
			return result(channel, VerdictNotConfigured, nil)
		}
		if !r.d.Budgets.For(cfg.Ntfy.Server).Take(false) {
			return result(channel, VerdictRateLimited, notify.ErrPushBudgetExhausted)
		}
		err := notify.NewNtfy(cfg.Ntfy.Server, cfg.Ntfy.Topic, cfg.Ntfy.Token).Push(testPush())
		return result(channel, classify(err), err)
	case alertwebhook.ChannelSMS:
		probe := cfg
		probe.SMS.Enabled = true
		if !probe.smsLive() {
			return result(channel, VerdictNotConfigured, nil)
		}
		r.mu.Lock()
		r.rebuildLocked()
		// SMS saved but disabled has no bucket from the rebuild: make it, so the
		// cap holds for tests too (and a test's spend counts once it is enabled).
		b := r.ensureSMSBudgetLocked(cfg.SMS.MaxPerHour)
		r.mu.Unlock()
		var firstErr error
		for _, to := range cfg.SMS.To {
			if !b.Take(false) {
				return result(channel, VerdictRateLimited, notify.ErrPushBudgetExhausted)
			}
			if err := r.twilio(cfg.SMS, to).Text(smsText(testPush())); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return result(channel, classify(firstErr), firstErr)
	default:
		return TestResult{Channel: "", Verdict: VerdictRefused, Message: "Choose ntfy or text messages."}
	}
}

// authRejecter / statusCoder are the typed-failure shapes of both senders.
type authRejecter interface {
	error
	AuthRejected() bool
	RateLimited() bool
	Retryable() bool
}

func classify(err error) Verdict {
	if err == nil {
		return VerdictOK
	}
	if errors.Is(err, notify.ErrPushBudgetExhausted) {
		return VerdictRateLimited
	}
	var se authRejecter
	if errors.As(err, &se) {
		switch {
		case se.AuthRejected():
			return VerdictAuthRejected
		case se.RateLimited():
			return VerdictRateLimited
		case se.Retryable(): // 5xx: the service is up but failing
			return VerdictUnreachable
		default:
			return VerdictRefused
		}
	}
	// Untyped = transport (DNS, connect, TLS, timeout).
	return VerdictUnreachable
}

func result(channel string, v Verdict, err error) TestResult {
	return TestResult{Channel: channel, Verdict: v, Message: verdictMessage(channel, v, err)}
}

// verdictMessage is the sentence shown to the administrator. Plain language,
// and never the provider's own words.
func verdictMessage(channel string, v Verdict, err error) string {
	sms := channel == alertwebhook.ChannelSMS
	switch v {
	case VerdictOK:
		if sms {
			return "Sent. Check the phones you listed for a text from your Twilio number."
		}
		return "Sent. Check the phone or app subscribed to this topic."
	case VerdictAuthRejected:
		if sms {
			return "Twilio refused the Account SID or auth token. Check both and save again."
		}
		return "The ntfy server refused access. Check the access token, or whether the topic needs one."
	case VerdictRateLimited:
		if errors.Is(err, notify.ErrPushBudgetExhausted) {
			return "Correlix's own hourly sending limit for this channel is used up. Try again later."
		}
		return "The service is limiting how often Correlix may send right now. Try again in a few minutes."
	case VerdictUnreachable:
		if sms {
			return "Correlix could not reach Twilio. Check this installation's internet access."
		}
		return "Correlix could not reach the ntfy server. Check the server address and this installation's internet access."
	case VerdictRefused:
		if sms {
			return "Twilio refused the message. Check the number to send from and the numbers to text."
		}
		return "The ntfy server refused the message. Check the topic."
	case VerdictNotConfigured:
		return "Save this channel's settings first, then send a test."
	}
	return "The test could not be sent."
}
