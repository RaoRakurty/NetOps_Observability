package backend

import (
	"os"
	"testing"

	"netops/backend/notify"
)

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
	if n := notify.BuildNtfyChannel(notify.NtfyConfig{Topic: "x", MinSeverity: "critical"}).Name(); n != "ntfy" {
		t.Fatalf("ntfy channel name = %q, want ntfy", n)
	}
}
