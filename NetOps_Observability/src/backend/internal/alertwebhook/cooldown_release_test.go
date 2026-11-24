// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alertwebhook

// cooldown_release_test.go — tracker 314: the cool-down was stamped on
// ACCEPTANCE and kept on failure, so a page whose whole delivery failed was
// suppressed for the full window when vmalert re-sent it. The host route now
// releases its stamp when an immediate push reached NO channel, re-admits
// after hostRedeliverAfter (bounded), and never re-sends the product leg.

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/notify"
)

const pageBody = `[{"status":"firing","labels":{"alertname":"CorrelationConsumerDead","severity":"critical","layer":"platform","tier":"page"},` +
	`"annotations":{"summary":"s"},"startsAt":"2026-09-03T11:45:00Z"}]`

func refused() error { return &notify.TwilioStatusError{Status: 400} } // not retryable: one attempt

func postPage(t *testing.T, r *hostRig) {
	t.Helper()
	if w := r.post(t, pageBody, bearer); w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
}

func firedCount(r *hostRig) int {
	f, _ := r.disp.counts()
	return f
}

// The fix itself: a failed page is retried by the next resend once the gap
// has passed — on the host route only; the product channel is not re-sent.
func TestAFailedPageIsRetriedByAResendAfterTheGap(t *testing.T) {
	p := newFakePusher()
	p.err = refused()
	r := newHostRig(t, 30*time.Minute, p)
	postPage(t, r)
	p.await(t, 1)
	waitForMetric(t, r.mx, "netops_alert_webhook_host_released_total 1")

	// Inside the gap: still suppressed (no resend storm on a wedged channel).
	postPage(t, r)
	p.quiet(t)
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_suppressed_total 1") {
		t.Fatalf("a resend inside the gap must be suppressed:\n%s", metricsText(r.mx))
	}

	// After the gap the channel has recovered: the resend is delivered.
	p.mu.Lock()
	p.err = nil
	p.mu.Unlock()
	r.clock.advance(hostRedeliverAfter)
	postPage(t, r)
	p.await(t, 1)
	waitForMetric(t, r.mx, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 1`)
	waitForMetric(t, r.mx, "netops_alert_webhook_host_redelivered_total 1")
	if n := firedCount(r); n != 1 {
		t.Fatalf("product dispatcher fired %d times, want 1 — a host retry must not re-send product channels", n)
	}
}

// A retryable failure runs the whole ladder first; the release follows the
// LAST attempt, exactly once.
func TestTheReleaseFollowsTheWholeRetryLadder(t *testing.T) {
	p := newFakePusher()
	p.err = errors.New("dial tcp: connection refused") // retryable
	r := newHostRig(t, 30*time.Minute, p)
	postPage(t, r)
	p.await(t, hostMaxAttempts)
	waitForMetric(t, r.mx, "netops_alert_webhook_host_released_total 1")
	p.quiet(t)
	r.clock.advance(hostRedeliverAfter)
	postPage(t, r)
	p.await(t, 1) // a fresh ladder starts
}

// A delivered page keeps the full cool-down.
func TestADeliveredPageStaysSuppressedForTheWholeWindow(t *testing.T) {
	p := newFakePusher()
	r := newHostRig(t, 30*time.Minute, p)
	postPage(t, r)
	p.await(t, 1)
	waitForMetric(t, r.mx, `netops_alert_webhook_pushed_total{route="host_monitoring",tier="page"} 1`)
	r.clock.advance(hostRedeliverAfter)
	postPage(t, r)
	p.quiet(t)
	txt := metricsText(r.mx)
	if !strings.Contains(txt, "netops_alert_webhook_host_released_total 0") ||
		!strings.Contains(txt, "netops_alert_webhook_suppressed_total 1") {
		t.Fatalf("a delivered page must stay suppressed and release nothing:\n%s", txt)
	}
}

// Partial fan-out: one channel reached the operator, so the cool-down holds —
// re-sending would buzz the channel that already has it.
func TestOneDeliveredTargetKeepsTheCooldown(t *testing.T) {
	ok, bad := newFakePusher(), newFakePusher()
	bad.err = refused()
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelNtfy, Pusher: ok}, HostTarget{Channel: ChannelSMS, Pusher: bad})
	r := routedLongRig(t, sr)
	postPage(t, r)
	ok.await(t, 1)
	bad.await(t, 1)
	waitForMetric(t, r.mx, `reason="send_error"} 1`)
	r.clock.advance(hostRedeliverAfter)
	postPage(t, r)
	ok.quiet(t)
	bad.quiet(t)
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_host_released_total 0") {
		t.Fatalf("partial delivery must not release:\n%s", metricsText(r.mx))
	}
}

// Every target failed: released exactly once, and the retry goes to both.
func TestAllTargetsFailingReleasesOnce(t *testing.T) {
	a, b := newFakePusher(), newFakePusher()
	a.err, b.err = refused(), refused()
	sr := &scriptRouter{}
	sr.set(TierPage, HostTarget{Channel: ChannelNtfy, Pusher: a}, HostTarget{Channel: ChannelSMS, Pusher: b})
	r := routedLongRig(t, sr)
	postPage(t, r)
	a.await(t, 1)
	b.await(t, 1)
	waitForMetric(t, r.mx, "netops_alert_webhook_host_released_total 1")
	a.quiet(t)
	if !strings.Contains(metricsText(r.mx), "netops_alert_webhook_host_released_total 1") {
		t.Fatalf("two failed targets must release ONCE:\n%s", metricsText(r.mx))
	}
	r.clock.advance(hostRedeliverAfter)
	postPage(t, r)
	a.await(t, 1)
	b.await(t, 1)
}

// Two resends in flight never both deliver: the stamp is taken at admission,
// before the push lands.
func TestConcurrentResendsDeliverOnce(t *testing.T) {
	p := newFakePusher()
	p.gate = make(chan struct{})
	r := newHostRig(t, 30*time.Minute, p)
	postPage(t, r)
	<-p.entered // the drain worker holds the first push
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); postPage(t, r) }()
	}
	wg.Wait()
	close(p.gate)
	p.await(t, 1)
	p.quiet(t)
	waitForMetric(t, r.mx, "netops_alert_webhook_suppressed_total 8")
	if n := firedCount(r); n != 1 {
		t.Fatalf("product dispatcher fired %d times, want 1", n)
	}
}

// No channel at all: nothing could ever deliver it, so nothing is released
// (a release would only make every resend spin through the same nothing).
func TestNoChannelNeverReleases(t *testing.T) {
	r := newHostRig(t, 30*time.Minute, nil)
	postPage(t, r)
	waitForMetric(t, r.mx, `reason="not_configured"} 1`)
	r.clock.advance(hostRedeliverAfter)
	postPage(t, r)
	txt := metricsText(r.mx)
	if !strings.Contains(txt, "netops_alert_webhook_host_released_total 0") ||
		!strings.Contains(txt, "netops_alert_webhook_suppressed_total 1") {
		t.Fatalf("no channel must not release:\n%s", txt)
	}
}

// A stale release (an old failure) never shortens a newer stamp.
func TestAStaleReleaseLeavesANewerStampAlone(t *testing.T) {
	base := newRig(t, 30*time.Minute)
	rec := handlerReceiver(t, base)
	rec.cooldown = 30 * time.Minute
	old, ok := rec.admitAt(hostKey("fp"))
	if !ok {
		t.Fatal("first admit refused")
	}
	base.clock.advance(31 * time.Minute)
	newer, ok := rec.admitAt(hostKey("fp"))
	if !ok {
		t.Fatal("admit after the window refused")
	}
	rec.releaseHost(hostKey("fp"), old)
	rec.mu.Lock()
	got := rec.seen[hostKey("fp")]
	rec.mu.Unlock()
	if !got.Equal(newer) {
		t.Fatalf("stamp = %v, want the newer %v untouched", got, newer)
	}
}

// The gap never exceeds a shorter cool-down.
func TestTheRetryGapIsClampedToTheCooldown(t *testing.T) {
	p := newFakePusher()
	p.err = refused()
	r := newHostRig(t, time.Minute, p)
	postPage(t, r)
	p.await(t, 1)
	waitForMetric(t, r.mx, "netops_alert_webhook_host_released_total 1")
	p.mu.Lock()
	p.err = nil
	p.mu.Unlock()
	r.clock.advance(time.Minute)
	postPage(t, r)
	p.await(t, 1)
}

// routedLongRig is routedRig with a 30-minute cool-down: routedRig's one-minute
// window would expire on its own before hostRedeliverAfter and prove nothing.
func routedLongRig(t *testing.T, sr *scriptRouter) *hostRig {
	t.Helper()
	return newHostRigWith(t, 30*time.Minute, nil, func(d *Deps) { d.HostRouter = sr })
}
