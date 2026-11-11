// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/alertwebhook"
	"netops/backend/notify"
)

type routerRig struct {
	kv     *memKV
	store  *Store
	router *Router
	ntfy   *fakeProvider
	twilio *fakeProvider
	clock  *time.Time
}

func newRouterRig(t *testing.T, c func(*Config)) *routerRig {
	t.Helper()
	ntfy, tw := newFakeProvider(t), newFakeProvider(t)
	kv := newMemKV()
	cfg := liveConfig(ntfy, tw)
	if c != nil {
		c(&cfg)
	}
	kv.put(t, sealedForKV(t, cfg))
	store := newTestStore(t, kv, &logSpy{})
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	clock := &now
	router := NewRouter(RouterDeps{
		Store:      store,
		Budgets:    notify.NewPushBudgets(30, 10, func() time.Time { return *clock }),
		Now:        func() time.Time { return *clock },
		TwilioBase: tw.srv.URL,
	})
	return &routerRig{kv: kv, store: store, router: router, ntfy: ntfy, twilio: tw, clock: clock}
}

func channels(ts []alertwebhook.HostTarget) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Channel)
	}
	return out
}

// Default routing: pages → ntfy + one SMS target PER RECIPIENT; the digest →
// ntfy only. The all-clear goes where pages go. An unknown tier reaches nobody.
func TestRouterTierRouting(t *testing.T) {
	r := newRouterRig(t, nil)
	if got := strings.Join(channels(r.router.Targets(alertwebhook.TierPage)), ","); got != "ntfy,sms,sms" {
		t.Fatalf("page targets = %s, want ntfy,sms,sms (one SMS target per recipient)", got)
	}
	if got := strings.Join(channels(r.router.Targets(alertwebhook.TierResolved)), ","); got != "ntfy,sms,sms" {
		t.Fatalf("resolved targets = %s — the all-clear must follow the page", got)
	}
	if got := strings.Join(channels(r.router.Targets(alertwebhook.TierDigest)), ","); got != "ntfy" {
		t.Fatalf("digest targets = %s, want ntfy only (SMS off the warning tier by default)", got)
	}
	if got := r.router.Targets("bogus"); len(got) != 0 {
		t.Fatalf("an unknown tier must reach nobody: %v", channels(got))
	}
	// The ntfy target spends the SHARED per-server bucket; SMS its own.
	page := r.router.Targets(alertwebhook.TierPage)
	if page[0].Budget == nil || page[1].Budget == nil || page[0].Budget == page[1].Budget {
		t.Fatal("ntfy and SMS must each carry their own budget")
	}
	if page[1].Budget != page[2].Budget {
		t.Fatal("all SMS recipients share ONE SMS cap")
	}
}

// A change to the record is picked up on the next push, without a restart.
func TestRouterFollowsTheStore(t *testing.T) {
	r := newRouterRig(t, nil)
	next := r.store.Current()
	next.SMS.Enabled = false
	next.Ntfy.Server = "https://ntfy.example.com"
	if err := r.store.Save(next, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(channels(r.router.Targets(alertwebhook.TierPage)), ","); got != "ntfy" {
		t.Fatalf("after disabling SMS, page targets = %s", got)
	}
	next.Ntfy.Enabled = false
	if err := r.store.Save(next, false); err != nil {
		t.Fatal(err)
	}
	if got := r.router.Targets(alertwebhook.TierPage); len(got) != 0 {
		t.Fatalf("nothing enabled must mean no targets: %v", channels(got))
	}
}

// The SMS cap: one token per message, half reserved for pages, and re-saving
// the record does not refill a spent allowance.
func TestSMSBudgetCapsAndReservesForPages(t *testing.T) {
	r := newRouterRig(t, func(c *Config) { c.SMS.MaxPerHour = 4; c.SMS.Tiers.Warning = true })
	sms := r.router.Targets(alertwebhook.TierDigest)[1].Budget
	if r.router.SMSBudgetRemaining() != 4 {
		t.Fatalf("remaining = %d, want 4", r.router.SMSBudgetRemaining())
	}
	// Warnings stop at the reserve (4/2 = 2 reserved for pages).
	for i := 0; i < 2; i++ {
		if !sms.Take(false) {
			t.Fatalf("warning %d: warnings may spend the unreserved half", i+1)
		}
	}
	if sms.Take(false) {
		t.Fatal("a warning must never spend the page reserve")
	}
	for i := 0; i < 2; i++ {
		if !sms.Take(true) {
			t.Fatalf("page %d: pages may spend the reserve", i+1)
		}
	}
	if sms.Take(true) {
		t.Fatal("past the cap even a page is refused locally — the cap is a hard money limit")
	}
	cur := r.store.Current()
	cur.SMS.To = []string{phoneB}
	r.kv.put(t, sealedForKV(t, cur)) // the fake ntfy is http; Save rightly insists on https
	if err := r.store.Refresh(); err != nil {
		t.Fatal(err)
	}
	if got := channels(r.router.Targets(alertwebhook.TierPage)); len(got) != 2 {
		t.Fatalf("the router must have rebuilt for the new recipient list: %v", got)
	}
	if got := r.router.SMSBudgetRemaining(); got != 0 {
		t.Fatalf("re-saving must not refill the SMS allowance: remaining %d", got)
	}
}

// ── test sends ──────────────────────────────────────────────────────────────

func TestTestSendVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		channel string
		want    Verdict
	}{
		{"ntfy ok", 200, alertwebhook.ChannelNtfy, VerdictOK},
		{"ntfy auth", 401, alertwebhook.ChannelNtfy, VerdictAuthRejected},
		{"ntfy forbidden", 403, alertwebhook.ChannelNtfy, VerdictAuthRejected},
		{"ntfy 429", 429, alertwebhook.ChannelNtfy, VerdictRateLimited},
		{"ntfy 500", 500, alertwebhook.ChannelNtfy, VerdictUnreachable},
		{"ntfy 400", 400, alertwebhook.ChannelNtfy, VerdictRefused},
		{"sms ok", 201, alertwebhook.ChannelSMS, VerdictOK},
		{"sms auth", 401, alertwebhook.ChannelSMS, VerdictAuthRejected},
		{"sms 429", 429, alertwebhook.ChannelSMS, VerdictRateLimited},
		{"sms 503", 503, alertwebhook.ChannelSMS, VerdictUnreachable},
		{"sms bad number", 400, alertwebhook.ChannelSMS, VerdictRefused},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRouterRig(t, nil)
			r.ntfy.setStatus(tc.status)
			r.twilio.setStatus(tc.status)
			res := r.router.Test(tc.channel)
			if res.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s (%s)", res.Verdict, tc.want, res.Message)
			}
			if strings.Contains(res.Message, "PROVIDER-BODY") || strings.Contains(res.Message, "+1415") {
				t.Fatalf("a provider body or a phone number leaked into the verdict: %q", res.Message)
			}
			if res.Message == "" {
				t.Fatal("every verdict carries a plain sentence")
			}
		})
	}
}

// What the test actually sends: ntfy gets the bearer token on the configured
// topic; Twilio gets one form POST per recipient under Basic auth (SID +
// token) on the account's Messages resource, bounded to one segment.
func TestTestSendWireShape(t *testing.T) {
	r := newRouterRig(t, nil)
	if res := r.router.Test(alertwebhook.ChannelNtfy); res.Verdict != VerdictOK {
		t.Fatal(res)
	}
	n := r.ntfy.await(t, 1)[0]
	if n.Path != "/corr-platform-test" || n.Auth != "Bearer "+fakeSecret("ntfy") || !strings.Contains(n.Title, "TEST") {
		t.Fatalf("ntfy request: %+v", n)
	}
	if res := r.router.Test(alertwebhook.ChannelSMS); res.Verdict != VerdictOK {
		t.Fatal(res)
	}
	got := r.twilio.await(t, 2)
	tos := map[string]bool{}
	for _, c := range got {
		if c.Path != "/2010-04-01/Accounts/"+fakeSID()+"/Messages.json" || c.User != fakeSID() || c.Pass != fakeSecret("twilio") {
			t.Fatalf("twilio request: %+v", c)
		}
		if len([]rune(c.Body)) > 160 {
			t.Fatalf("an SMS must fit one segment: %d chars", len([]rune(c.Body)))
		}
		tos[c.To] = true
	}
	if !tos[phoneA] || !tos[phoneB] {
		t.Fatalf("one message per recipient: %v", tos)
	}
}

func TestTestSendTransportFailuresAreUnreachable(t *testing.T) {
	// A server that accepts and hangs up mid-request, and an address nothing
	// listens on: both are the transport class (a client timeout lands on the
	// same untyped-error path).
	hangup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close() // test fake: the point is the abrupt close
		}
	}))
	defer hangup.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	_ = ln.Close() // nothing listens there now

	for _, base := range []string{hangup.URL, dead} {
		r := newRouterRig(t, func(c *Config) { c.Ntfy.Server = base })
		r.router.d.TwilioBase = base
		r.router.built = 0
		if res := r.router.Test(alertwebhook.ChannelNtfy); res.Verdict != VerdictUnreachable {
			t.Errorf("ntfy via %s: %s", base, res.Verdict)
		}
		if res := r.router.Test(alertwebhook.ChannelSMS); res.Verdict != VerdictUnreachable {
			t.Errorf("sms via %s: %s", base, res.Verdict)
		}
	}
}

func TestTestSendNotConfiguredAndBudget(t *testing.T) {
	r := newRouterRig(t, func(c *Config) {
		c.Ntfy.Topic = ""
		c.SMS.To = nil
	})
	if res := r.router.Test(alertwebhook.ChannelNtfy); res.Verdict != VerdictNotConfigured {
		t.Fatalf("ntfy without a topic: %s", res.Verdict)
	}
	if res := r.router.Test(alertwebhook.ChannelSMS); res.Verdict != VerdictNotConfigured {
		t.Fatalf("sms without numbers: %s", res.Verdict)
	}
	if r.ntfy.count()+r.twilio.count() != 0 {
		t.Fatal("an unconfigured test must not reach any provider")
	}
	// The SMS cap applies to tests (each costs money): 2 recipients, cap 2,
	// half reserved for pages → a test can send at most 1 message.
	r2 := newRouterRig(t, func(c *Config) { c.SMS.MaxPerHour = 2 })
	res := r2.router.Test(alertwebhook.ChannelSMS)
	if res.Verdict != VerdictRateLimited || !strings.Contains(res.Message, "Correlix's own hourly") {
		t.Fatalf("a test past the SMS cap must be refused locally: %+v", res)
	}
	// A DISABLED but complete channel can be tested before it is turned on.
	r3 := newRouterRig(t, func(c *Config) { c.SMS.Enabled = false; c.Ntfy.Enabled = false })
	if res := r3.router.Test(alertwebhook.ChannelSMS); res.Verdict != VerdictOK {
		t.Fatalf("disabled-but-complete SMS test: %+v", res)
	}
	if res := r3.router.Test(alertwebhook.ChannelNtfy); res.Verdict != VerdictOK {
		t.Fatalf("disabled-but-complete ntfy test: %+v", res)
	}
}
