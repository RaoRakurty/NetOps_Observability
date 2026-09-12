// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/session"
	"netops/backend/internal/users"
	"netops/backend/notify"
)

// newNotifyCfgServer wires a server with the identity stores + a real
// notifyConfigStore, exercised through the router + auth middleware.
func newNotifyCfgServer(t *testing.T) (*httptest.Server, *server) {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	us, err := users.NewFileStore(dir+"/users.json", userDeps())
	must(err)
	rs, err := newRoleStore(dir + "/roles.json")
	must(err)
	ts, err := newTenantStore(dir + "/tenants.json")
	must(err)
	rf, err := session.NewRefreshStore(dir+"/refresh.json", time.Hour, platformKV{})
	must(err)
	must(us.SeedAdmin("admin", "Passw0rd!2345"))
	s := &server{users: us, roles: rs, tenants: ts, refresh: rf, startedAt: time.Now().UTC()}
	s.notifyCfg = newNotifyConfigStore(dir+"/notify.json", s)
	mux := http.NewServeMux()
	s.routes(mux)
	srv := httptest.NewServer(s.withAuth(mux))
	t.Cleanup(srv.Close)
	return srv, s
}

// Characterization of the five channel-config PUT/GET handlers (#147 T4):
// write-only secret redaction + preservation, per-channel defaulting, severity
// validation, the ntfy watchdog-topic refusal, and the 405 posture.
func TestNotifyChannelConfigHandlers(t *testing.T) {
	t.Setenv("WATCHDOG_NTFY_TOPIC", "wd-topic")
	srv, s := newNotifyCfgServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token

	type ch struct {
		path       string
		put        map[string]any // valid PUT carrying the secret
		secret     string         // raw secret that must never appear in a response
		setKey     string         // the *_set boolean key in the public view
		defSev     string         // min_severity default applied on empty
		stored     func() string  // reads the stored secret from the config store
		defaulted  func() bool    // channel-specific defaults applied?
		defaultDoc string
	}
	channels := []ch{
		{path: "/api/notify/smtp",
			put:    map[string]any{"enabled": true, "host": "smtp.example.com", "port": 587, "from": "a@b.c", "user": "u", "pass": "smtp-secret", "to": "x@y.z"},
			secret: "smtp-secret", setKey: `"pass_set":true`, defSev: `"min_severity":"warning"`,
			stored:    func() string { return s.notifyCfg.cfg.SMTP.Pass },
			defaulted: func() bool { return s.notifyCfg.cfg.SMTP.Security == "starttls" }, defaultDoc: "security=starttls"},
		{path: "/api/notify/twilio",
			put:    map[string]any{"enabled": true, "account_sid": "AC123", "auth_token": "tw-secret", "from": "+1555", "to": "+1666"},
			secret: "tw-secret", setKey: `"token_set":true`, defSev: `"min_severity":"critical"`,
			stored:    func() string { return s.notifyCfg.cfg.Twilio.AuthToken },
			defaulted: func() bool { return true }},
		{path: "/api/notify/ntfy",
			put:    map[string]any{"enabled": true, "topic": "alerts", "token": "ntfy-secret"},
			secret: "ntfy-secret", setKey: `"token_set":true`, defSev: `"min_severity":"critical"`,
			stored:    func() string { return s.notifyCfg.cfg.Ntfy.Token },
			defaulted: func() bool { return s.notifyCfg.cfg.Ntfy.Server == "https://ntfy.sh" }, defaultDoc: "server=ntfy.sh"},
		{path: "/api/notify/slack",
			put:    map[string]any{"enabled": true, "webhook_url": "https://hooks.slack.example/slack-secret"},
			secret: "slack-secret", setKey: `"webhook_set":true`, defSev: `"min_severity":"warning"`,
			stored:    func() string { return s.notifyCfg.cfg.Slack.WebhookURL },
			defaulted: func() bool { return true }},
		{path: "/api/notify/pagerduty",
			put:    map[string]any{"enabled": true, "routing_key": "pd-secret"},
			secret: "pd-secret", setKey: `"routing_set":true`, defSev: `"min_severity":"critical"`,
			stored:    func() string { return s.notifyCfg.cfg.PagerDuty.RoutingKey },
			defaulted: func() bool { return true }},
	}
	for _, c := range channels {
		t.Run(strings.TrimPrefix(c.path, "/api/notify/"), func(t *testing.T) {
			// Invalid severity → 400, nothing stored.
			bad := map[string]any{"min_severity": "shrug"}
			if st, _ := do(t, srv, "PUT", c.path, tok, bad); st != 400 {
				t.Fatalf("invalid min_severity: status %d, want 400", st)
			}
			// Valid PUT with the secret → 200, response redacts.
			st, b := do(t, srv, "PUT", c.path, tok, c.put)
			if st != 200 {
				t.Fatalf("PUT status %d: %s", st, b)
			}
			if strings.Contains(string(b), c.secret) {
				t.Fatalf("PUT response leaked secret: %s", b)
			}
			if !strings.Contains(string(b), c.setKey) {
				t.Fatalf("expected %s in %s", c.setKey, b)
			}
			if !strings.Contains(string(b), c.defSev) {
				t.Fatalf("expected default %s in %s", c.defSev, b)
			}
			if !c.defaulted() {
				t.Fatalf("channel default not applied (%s)", c.defaultDoc)
			}
			// GET → same redaction.
			st, b = do(t, srv, "GET", c.path, tok, nil)
			if st != 200 || strings.Contains(string(b), c.secret) || !strings.Contains(string(b), c.setKey) {
				t.Fatalf("GET redaction failed: %d %s", st, b)
			}
			// Empty-secret PUT preserves the stored secret.
			repeat := map[string]any{}
			for k, v := range c.put {
				repeat[k] = v
			}
			for _, k := range []string{"pass", "auth_token", "token", "webhook_url", "routing_key"} {
				delete(repeat, k)
			}
			if st, b := do(t, srv, "PUT", c.path, tok, repeat); st != 200 {
				t.Fatalf("re-PUT status %d: %s", st, b)
			}
			if got := c.stored(); !strings.Contains(got, c.secret) {
				t.Fatalf("write-only secret not preserved on empty PUT: %q", got)
			}
			// Method posture.
			if st, _ := do(t, srv, "DELETE", c.path, tok, nil); st != 405 {
				t.Fatalf("DELETE: status %d, want 405", st)
			}
		})
	}
	// ntfy refuses the watchdog topic (watchdog independence, #101).
	st, b := do(t, srv, "PUT", "/api/notify/ntfy", tok, map[string]any{"enabled": true, "topic": "wd-topic"})
	if st != 400 || !strings.Contains(string(b), "watchdog") {
		t.Fatalf("watchdog topic must be refused: %d %s", st, b)
	}
}

func TestPublicSlackMasksSecret(t *testing.T) {
	s := &notifyConfigStore{cfg: notify.ChannelConfig{Slack: notify.SlackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/pathgraph.ISOZPtr(t *timeX", MinSeverity: "warning"}}}
	p := s.publicSlack()
	if !p.Enabled || !p.WebhookSet || p.MinSeverity != "warning" {
		t.Fatalf("unexpected public slack: %+v", p)
	}
	// The public view must never carry the raw webhook URL — only the boolean.
	if got := s.publicSlack(); got.WebhookSet != true {
		t.Fatalf("webhook_set should be true when configured")
	}
	empty := (&notifyConfigStore{cfg: notify.ChannelConfig{}}).publicSlack()
	if empty.WebhookSet {
		t.Fatalf("webhook_set should be false when unset")
	}
}

func TestPublicPagerDutyMasksSecret(t *testing.T) {
	s := &notifyConfigStore{cfg: notify.ChannelConfig{PagerDuty: notify.PagerDutyConfig{Enabled: true, RoutingKey: "abc123", MinSeverity: "critical"}}}
	p := s.publicPagerDuty()
	if !p.Enabled || !p.RoutingSet || p.MinSeverity != "critical" {
		t.Fatalf("unexpected public pagerduty: %+v", p)
	}
	if (&notifyConfigStore{cfg: notify.ChannelConfig{}}).publicPagerDuty().RoutingSet {
		t.Fatalf("routing_set should be false when unset")
	}
}

func TestBuildSlackPagerDutyChannelNames(t *testing.T) {
	// The dispatcher keys channels by Name() for Replace/Remove — the severity
	// gate must preserve the inner channel's name.
	if n := notify.BuildSlackChannel(notify.SlackConfig{WebhookURL: "x", MinSeverity: "warning"}).Name(); n != "slack" {
		t.Fatalf("slack channel name = %q, want slack", n)
	}
	if n := notify.BuildPagerDutyChannel(notify.PagerDutyConfig{RoutingKey: "x", MinSeverity: "critical"}, os.Getenv("PLATFORM_ENV"), os.Getenv("PLATFORM_REGION")).Name(); n != "pagerduty" {
		t.Fatalf("pagerduty channel name = %q, want pagerduty", n)
	}
}

func TestSeedFromEnv(t *testing.T) {
	t.Setenv("FEATURE_SLACK_NOTIFICATIONS", "true")
	t.Setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/SEED")
	t.Setenv("FEATURE_PAGERDUTY_NOTIFICATIONS", "true")
	t.Setenv("PAGERDUTY_KEY", "seedkey")
	s := &notifyConfigStore{}
	s.seedFromEnv()
	if !s.cfg.Slack.Enabled || s.cfg.Slack.WebhookURL != "https://hooks.slack.com/services/SEED" {
		t.Fatalf("slack not seeded from env: %+v", s.cfg.Slack)
	}
	if !s.cfg.PagerDuty.Enabled || s.cfg.PagerDuty.RoutingKey != "seedkey" {
		t.Fatalf("pagerduty not seeded from env: %+v", s.cfg.PagerDuty)
	}
}

// ---- #101 first-customer alert-delivery gate --------------------------------

func TestSeedNtfyFromEnv(t *testing.T) {
	t.Setenv("FEATURE_NTFY_NOTIFICATIONS", "true")
	t.Setenv("NTFY_ALERT_TOPIC", "correlix-critical-seed")
	t.Setenv("NTFY_ALERT_TOKEN", "tok")
	s := &notifyConfigStore{}
	s.seedFromEnv()
	if !s.cfg.Ntfy.Enabled || s.cfg.Ntfy.Topic != "correlix-critical-seed" || s.cfg.Ntfy.Token != "tok" {
		t.Fatalf("ntfy not seeded from env: %+v", s.cfg.Ntfy)
	}
}

func TestSeedNtfyRefusesWatchdogTopic(t *testing.T) {
	// Watchdog independence is intentional: the external watchdog must be able
	// to report the stack's own death, so product alerting may never share its
	// topic. Seeding with the watchdog topic must be refused, not honored.
	t.Setenv("FEATURE_NTFY_NOTIFICATIONS", "true")
	t.Setenv("NTFY_ALERT_TOPIC", "wd-topic")
	t.Setenv("WATCHDOG_NTFY_TOPIC", "wd-topic")
	s := &notifyConfigStore{}
	s.seedFromEnv()
	if s.cfg.Ntfy.Enabled || s.cfg.Ntfy.Topic != "" {
		t.Fatalf("watchdog topic must not seed the product channel: %+v", s.cfg.Ntfy)
	}
}

func TestSeedNtfyRequiresTopic(t *testing.T) {
	t.Setenv("FEATURE_NTFY_NOTIFICATIONS", "true")
	t.Setenv("NTFY_ALERT_TOPIC", "")
	s := &notifyConfigStore{}
	s.seedFromEnv()
	if s.cfg.Ntfy.Enabled {
		t.Fatal("ntfy must not enable without a topic")
	}
}

func TestNtfyChannelDefaultsToCriticalGate(t *testing.T) {
	// The recommended critical-push channel must default to min_severity
	// critical (phone pushes for criticals only) and keep its dispatcher name.
	c := notify.DefaultChannelConfig().Ntfy
	if c.MinSeverity != "critical" {
		t.Fatalf("ntfy default min_severity = %q, want critical", c.MinSeverity)
	}
	if n := notify.BuildNtfyChannel(notify.NtfyConfig{Topic: "x", MinSeverity: "critical"}, nil).Name(); n != "ntfy" {
		t.Fatalf("ntfy channel name = %q, want ntfy", n)
	}
}

// ---- #101 on the UPGRADE path ------------------------------------------------
//
// The seed runs only when there is no stored config. An appliance UPGRADED in
// place always has one, so until migrateNtfyFromEnv() existed an operator could
// set FEATURE_NTFY_NOTIFICATIONS + NTFY_ALERT_TOPIC in .env, restart, and get
// nothing at all — no channel, no log line. These tests pin both boot paths to
// the SAME semantics and the same once-and-only-once latch.

// storedNotifyConfig writes a config file the way a pre-upgrade deployment would
// have left one, and returns its path.
func storedNotifyConfig(t *testing.T, mutate func(*notifyConfigStore)) string {
	t.Helper()
	path := t.TempDir() + "/notify.json"
	pre := newTestNotifyStore(t, path)
	if mutate != nil {
		mutate(pre)
	}
	if err := pre.save(); err != nil {
		t.Fatal(err)
	}
	if pre.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("precondition: ntfy must not be latched yet")
	}
	return path
}

func ntfyEnv(t *testing.T, topic string) {
	t.Helper()
	t.Setenv("FEATURE_NTFY_NOTIFICATIONS", "true")
	t.Setenv("NTFY_ALERT_TOPIC", topic)
	t.Setenv("NTFY_ALERT_SERVER", "https://ntfy.example.invalid")
	t.Setenv("NTFY_ALERT_TOKEN", "tk_upgrade")
	t.Setenv("WATCHDOG_NTFY_TOPIC", "")
}

// TestNtfyEnvSeedOnFirstRunLatchesAndPersists: a FRESH install still seeds, and
// now records the latch so the second boot is a no-op rather than a re-seed.
func TestNtfyEnvSeedOnFirstRunLatchesAndPersists(t *testing.T) {
	ntfyEnv(t, "correlix-critical-fresh")
	path := t.TempDir() + "/notify.json"

	first := newNotifyConfigStore(path, nil)
	if !first.cfg.Ntfy.Enabled || first.cfg.Ntfy.Topic != "correlix-critical-fresh" {
		t.Fatalf("first run did not seed ntfy: %+v", first.cfg.Ntfy)
	}
	if first.cfg.Ntfy.Server != "https://ntfy.example.invalid" || first.cfg.Ntfy.Token != "tk_upgrade" {
		t.Errorf("server/token not seeded: %+v", first.cfg.Ntfy)
	}
	if first.cfg.Ntfy.MinSeverity != "critical" {
		t.Errorf("seeded ntfy floor = %q, want critical (#101)", first.cfg.Ntfy.MinSeverity)
	}
	if !first.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("the first-run seed must latch — it is the same code path as the upgrade")
	}
	// The latch has to be on disk, or "once" means once per process.
	if second := newNotifyConfigStore(path, nil); !second.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("latch did not persist across a restart")
	}
}

// TestNtfyEnvMigratesOnTheUpgradePath is the defect itself: a stored config
// exists (so the seed never fires) and the .env wiring must still take effect.
func TestNtfyEnvMigratesOnTheUpgradePath(t *testing.T) {
	path := storedNotifyConfig(t, func(pre *notifyConfigStore) {
		pre.cfg.Slack.Enabled = true
		pre.cfg.Slack.WebhookURL = "https://hooks.slack.example/T/B/C"
	})
	ntfyEnv(t, "correlix-critical-upgrade")

	up := newNotifyConfigStore(path, nil)
	if !up.cfg.Ntfy.Enabled || up.cfg.Ntfy.Topic != "correlix-critical-upgrade" {
		t.Fatalf("upgrade path did not enable ntfy from env: %+v", up.cfg.Ntfy)
	}
	if up.cfg.Ntfy.Server != "https://ntfy.example.invalid" || up.cfg.Ntfy.Token != "tk_upgrade" {
		t.Errorf("server/token not migrated: %+v", up.cfg.Ntfy)
	}
	if up.cfg.Ntfy.MinSeverity != "critical" {
		t.Errorf("migrated ntfy floor = %q, want critical", up.cfg.Ntfy.MinSeverity)
	}
	if !up.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("migration must latch")
	}
	if !up.cfg.Slack.Enabled {
		t.Fatal("migration must not disturb existing channels")
	}
}

// TestNtfyEnvMigrationIsOnceAndOnlyOnce: the operator turns ntfy off in the UI
// with NTFY_ALERT_TOPIC still in .env. The next boot must not resurrect it.
func TestNtfyEnvMigrationIsOnceAndOnlyOnce(t *testing.T) {
	path := storedNotifyConfig(t, nil)
	ntfyEnv(t, "correlix-critical-once")

	up := newNotifyConfigStore(path, nil)
	if !up.cfg.Ntfy.Enabled {
		t.Fatalf("precondition: first migration must enable ntfy: %+v", up.cfg.Ntfy)
	}
	if up.migrateEnvChannels() {
		t.Fatal("migration must be idempotent — a second run must report no change")
	}

	// Admin disables the channel; the env is untouched.
	up.cfg.Ntfy.Enabled = false
	if err := up.save(); err != nil {
		t.Fatal(err)
	}
	again := newNotifyConfigStore(path, nil)
	if again.cfg.Ntfy.Enabled {
		t.Fatal("the persisted latch must stop .env from re-enabling a channel the operator disabled")
	}
	if !again.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("latch did not persist")
	}
}

// TestNtfyEnvMigrationDoesNotOverwriteAUIConfiguredChannel: an operator who
// already pointed ntfy somewhere from the admin UI owns that setting. The env is
// latched (it stops being consulted) but must change NOTHING.
func TestNtfyEnvMigrationDoesNotOverwriteAUIConfiguredChannel(t *testing.T) {
	path := storedNotifyConfig(t, func(pre *notifyConfigStore) {
		pre.cfg.Ntfy.Enabled = true
		pre.cfg.Ntfy.Topic = "operator-chosen"
		pre.cfg.Ntfy.Server = "https://ntfy.operator.invalid"
		pre.cfg.Ntfy.Token = "operator-token"
		pre.cfg.Ntfy.MinSeverity = "warning"
	})
	ntfyEnv(t, "env-topic-that-must-lose")

	up := newNotifyConfigStore(path, nil)
	got := up.cfg.Ntfy
	if got.Topic != "operator-chosen" || got.Server != "https://ntfy.operator.invalid" ||
		got.Token != "operator-token" || got.MinSeverity != "warning" || !got.Enabled {
		t.Fatalf("env overwrote an admin-configured ntfy channel: %+v", got)
	}
	if !up.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("an already-configured channel must still latch, so the env stops being consulted")
	}
}

// TestNtfyEnvMigrationRefusesTheWatchdogTopicOnUpgrade: watchdog independence is
// not a first-run-only rule. The refusal must NOT latch — it is an operator-
// fixable env defect and has to stay loud every boot.
func TestNtfyEnvMigrationRefusesTheWatchdogTopicOnUpgrade(t *testing.T) {
	path := storedNotifyConfig(t, nil)
	ntfyEnv(t, "wd-topic")
	t.Setenv("WATCHDOG_NTFY_TOPIC", "wd-topic")

	up := newNotifyConfigStore(path, nil)
	if up.cfg.Ntfy.Enabled || up.cfg.Ntfy.Topic != "" {
		t.Fatalf("the watchdog topic must never become the product channel: %+v", up.cfg.Ntfy)
	}
	if up.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("a refused migration must stay loud, not latch")
	}
	// Operator fixes .env → the migration then works, proving the refusal did
	// not silently burn the one-shot.
	t.Setenv("NTFY_ALERT_TOPIC", "correlix-critical-fixed")
	fixed := newNotifyConfigStore(path, nil)
	if !fixed.cfg.Ntfy.Enabled || fixed.cfg.Ntfy.Topic != "correlix-critical-fixed" {
		t.Fatalf("a corrected env must migrate on the next boot: %+v", fixed.cfg.Ntfy)
	}
}

// TestNtfyEnvMigrationRequiresTheFeatureFlag: a topic alone must not enable a
// push channel — the flag is the opt-in, on both paths.
func TestNtfyEnvMigrationRequiresTheFeatureFlag(t *testing.T) {
	path := storedNotifyConfig(t, nil)
	t.Setenv("FEATURE_NTFY_NOTIFICATIONS", "false")
	t.Setenv("NTFY_ALERT_TOPIC", "correlix-critical-noflag")
	t.Setenv("WATCHDOG_NTFY_TOPIC", "")

	up := newNotifyConfigStore(path, nil)
	if up.cfg.Ntfy.Enabled || up.cfg.Ntfy.Topic != "" {
		t.Fatalf("ntfy must stay off without FEATURE_NTFY_NOTIFICATIONS: %+v", up.cfg.Ntfy)
	}
	if up.cfg.IsEnvSeeded("ntfy") {
		t.Fatal("nothing was migrated — the latch must stay open")
	}
}
