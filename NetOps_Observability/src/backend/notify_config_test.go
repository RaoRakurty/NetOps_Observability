package main

import "testing"

func TestPublicSlackMasksSecret(t *testing.T) {
	s := &notifyConfigStore{cfg: notifyConfig{Slack: slackConfig{Enabled: true, WebhookURL: "https://hooks.slack.com/services/XXX", MinSeverity: "warning"}}}
	p := s.publicSlack()
	if !p.Enabled || !p.WebhookSet || p.MinSeverity != "warning" {
		t.Fatalf("unexpected public slack: %+v", p)
	}
	// The public view must never carry the raw webhook URL — only the boolean.
	if got := s.publicSlack(); got.WebhookSet != true {
		t.Fatalf("webhook_set should be true when configured")
	}
	empty := (&notifyConfigStore{cfg: notifyConfig{}}).publicSlack()
	if empty.WebhookSet {
		t.Fatalf("webhook_set should be false when unset")
	}
}

func TestPublicPagerDutyMasksSecret(t *testing.T) {
	s := &notifyConfigStore{cfg: notifyConfig{PagerDuty: pagerDutyConfig{Enabled: true, RoutingKey: "abc123", MinSeverity: "critical"}}}
	p := s.publicPagerDuty()
	if !p.Enabled || !p.RoutingSet || p.MinSeverity != "critical" {
		t.Fatalf("unexpected public pagerduty: %+v", p)
	}
	if (&notifyConfigStore{cfg: notifyConfig{}}).publicPagerDuty().RoutingSet {
		t.Fatalf("routing_set should be false when unset")
	}
}

func TestBuildSlackPagerDutyChannelNames(t *testing.T) {
	// The dispatcher keys channels by Name() for Replace/Remove — the severity
	// gate must preserve the inner channel's name.
	if n := buildSlackChannel(slackConfig{WebhookURL: "x", MinSeverity: "warning"}).Name(); n != "slack" {
		t.Fatalf("slack channel name = %q, want slack", n)
	}
	if n := buildPagerDutyChannel(pagerDutyConfig{RoutingKey: "x", MinSeverity: "critical"}).Name(); n != "pagerduty" {
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
