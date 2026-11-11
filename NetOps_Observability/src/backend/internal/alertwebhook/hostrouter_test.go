// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alertwebhook

// hostrouter_test.go — the HostRouter seam (owner decision 2026-11-11: the
// destinations are configured in the GUI and resolved per push). The router
// implementation lives in internal/platformalert; these tests pin the
// receiver's side of the contract with a scripted router.

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/notify"
)

// scriptRouter answers per tier from a mutable table.
type scriptRouter struct {
	mu sync.Mutex
	by map[string][]HostTarget
}

func (s *scriptRouter) Targets(tier string) []HostTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]HostTarget(nil), s.by[tier]...)
}

func (s *scriptRouter) set(tier string, ts ...HostTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.by == nil {
		s.by = map[string][]HostTarget{}
	}
	s.by[tier] = ts
}

func routedRig(t *testing.T, sr *scriptRouter) *hostRig {
	t.Helper()
	return newHostRigWith(t, time.Minute, nil, func(d *Deps) { d.HostRouter = sr })
}

func metricsOf(r *hostRig) string {
	var b strings.Builder
	r.mx.Write(&b)
	return b.String()
}

// A page fans out to every target; each target is its own delivery.
func TestRouterFansAPageOutToEveryTarget(t *testing.T) {
	a, b := newFakePusher(), newFakePusher()
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelNtfy, Pusher: a}, HostTarget{Channel: ChannelSMS, Pusher: b})
	r := routedRig(t, sr)
	r.post(t, alertJSON("CorrelationConsumerDead", "critical", "platform", "page", "firing", "s"), bearer)
	a.await(t, 1)
	b.await(t, 1)
	if !strings.Contains(metricsOf(r), `netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 2`) {
		t.Fatalf("each destination is one push:\n%s", metricsOf(r))
	}
}

// The configuration is read per push: a router that gains a target after the
// receiver was built is used at once, and the gauge follows it.
func TestRouterChangesApplyWithoutARestart(t *testing.T) {
	sr := &scriptRouter{}
	r := routedRig(t, sr)
	if !strings.Contains(metricsOf(r), "netops_alert_webhook_host_route_enabled 0") {
		t.Fatal("an empty router is not configured")
	}
	r.post(t, alertJSON("AlertDeliveryBroken", "critical", "platform", "page", "firing", "s"), bearer)
	if !strings.Contains(metricsOf(r), `reason="not_configured"} 1`) {
		t.Fatalf("not_configured not counted:\n%s", metricsOf(r))
	}
	p := newFakePusher()
	sr.set(TierPage, HostTarget{Channel: ChannelNtfy, Pusher: p})
	r.post(t, alertJSON("IngestPipelineSilent", "critical", "platform", "page", "firing", "s"), bearer)
	p.await(t, 1)
	if !strings.Contains(metricsOf(r), "netops_alert_webhook_host_route_enabled 1") {
		t.Fatal("the gauge must follow the router on the next request")
	}
}

// A sender that refuses locally on its own budget is accounted as
// budget_exhausted and NEVER retried (the request was not made).
func TestRouterLocalBudgetRefusalIsNotRetried(t *testing.T) {
	p := newFakePusher()
	p.err = notify.ErrPushBudgetExhausted
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelSMS, Pusher: p})
	r := routedRig(t, sr)
	r.post(t, alertJSON("ClickHouseWritesRejected", "critical", "platform", "page", "firing", "s"), bearer)
	p.await(t, 1)
	p.quiet(t)
	if len(r.naps.waits()) != 0 {
		t.Fatal("a local budget refusal must not be retried")
	}
	if !strings.Contains(metricsOf(r), `reason="budget_exhausted"} 1`) {
		t.Fatalf("budget refusal not counted:\n%s", metricsOf(r))
	}
}

// A Twilio 5xx is retried exactly like an ntfy 5xx, and a Twilio 4xx is not.
func TestRouterRetriesTypedTwilioFailures(t *testing.T) {
	p := newFakePusher()
	p.script = []error{&notify.TwilioStatusError{Status: 503}, &notify.TwilioStatusError{Status: 429, RetryAfter: 3 * time.Second}}
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelSMS, Pusher: p})
	r := routedRig(t, sr)
	r.post(t, alertJSON("CorrConsumerNotRunning", "critical", "platform", "page", "firing", "s"), bearer)
	p.await(t, 3)
	w := r.naps.waits()
	if len(w) != 2 || w[1] != 3*time.Second {
		t.Fatalf("retry waits = %v (the server's Retry-After must win)", w)
	}
	q := newFakePusher()
	q.err = &notify.TwilioStatusError{Status: 400}
	sr.set(TierPage, HostTarget{Channel: ChannelSMS, Pusher: q})
	r.post(t, alertJSON("RouterConsumerDead", "critical", "platform", "page", "firing", "s"), bearer)
	q.await(t, 1)
	q.quiet(t)
}

// Warnings routed nowhere BY CHOICE are "unrouted", not a fault; with no
// warning destination nothing is folded into a digest nobody can send.
func TestRouterUnroutedTierIsCountedSeparately(t *testing.T) {
	p := newFakePusher()
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelSMS, Pusher: p})
	r := routedRig(t, sr)
	r.post(t, alertJSON("DiskHeadroomLow", "warning", "host", "", "firing", "s"), bearer)
	txt := metricsOf(r)
	if !strings.Contains(txt, "netops_alert_webhook_host_unrouted_total 1") || !strings.Contains(txt, `reason="not_configured"} 0`) ||
		!strings.Contains(txt, "netops_alert_webhook_digest_alerts_total 0") {
		t.Fatalf("unrouted accounting:\n%s", txt)
	}
	p.quiet(t)
}

// A digest fanned out to two targets comes back for the next window ONLY when
// it reached neither — a partial success must not re-send the whole window to
// the target that already has it.
func TestRouterDigestRestoredOnlyWhenNoTargetDelivered(t *testing.T) {
	ok, bad := newFakePusher(), newFakePusher()
	bad.err = errors.New("dial tcp: connection refused")
	sr := &scriptRouter{}
	sr.set(TierDigest, HostTarget{Channel: ChannelNtfy, Pusher: ok}, HostTarget{Channel: ChannelSMS, Pusher: bad})
	r := routedRig(t, sr)
	r.post(t, alertJSON("VectorComponentErrors", "warning", "platform", "", "firing", "s"), bearer)
	r.clock.advance(DefaultWarningDigestInterval + time.Second)
	r.post(t, alertJSON("Trigger", "warning", "platform", "", "firing", "s"), bearer)
	ok.await(t, 1)
	bad.await(t, 1)
	time.Sleep(50 * time.Millisecond) // let both outcomes land
	if r.logs.countContaining("kept for the next window") != 0 {
		t.Fatal("a digest that reached one target must not be restored")
	}

	// Both fail → restored once.
	ok2, bad2 := newFakePusher(), newFakePusher()
	ok2.err, bad2.err = errors.New("refused"), errors.New("refused")
	sr.set(TierDigest, HostTarget{Channel: ChannelNtfy, Pusher: ok2}, HostTarget{Channel: ChannelSMS, Pusher: bad2})
	r.clock.advance(time.Minute)
	r.post(t, alertJSON("Another", "warning", "platform", "", "firing", "s"), bearer)
	r.clock.advance(DefaultWarningDigestInterval + time.Second)
	r.post(t, alertJSON("Trigger2", "warning", "platform", "", "firing", "s"), bearer)
	ok2.await(t, 1)
	bad2.await(t, 1)
	deadline := time.Now().Add(2 * time.Second)
	for r.logs.countContaining("kept for the next window") != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("a digest that reached no target must be restored exactly once (got %d)", r.logs.countContaining("kept for the next window"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Per-target budgets: a spent SMS bucket must not stop the ntfy push of the
// same page.
func TestRouterPerTargetBudget(t *testing.T) {
	n, s := newFakePusher(), newFakePusher()
	spent := notify.NewPushBudget("https://api.twilio.com", 1, 0, nil)
	spent.Take(true)
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelNtfy, Pusher: n}, HostTarget{Channel: ChannelSMS, Pusher: s, Budget: spent})
	r := routedRig(t, sr)
	r.post(t, alertJSON("NMSIngestSilent", "critical", "platform", "page", "firing", "s"), bearer)
	n.await(t, 1)
	s.quiet(t)
	if r.logs.countContaining("error: platform alert push SKIPPED") != 1 {
		t.Fatal("a page refused by a channel budget is an ERROR line")
	}
}
