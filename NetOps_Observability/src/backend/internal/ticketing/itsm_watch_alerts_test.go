// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// itsm_watch_alerts_test.go — tracker 359: the per-lane "send my own watch
// alerts here" choice. Defaults (Slack ON, PagerDuty OFF), an omitted choice
// keeps the stored one, an explicit choice sticks, and the choice is per
// tenant.

import (
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestWatchAlertsDefaults(t *testing.T) {
	if !(SlackRCAConfig{}).WatchAlertsOn() {
		t.Fatal("Slack must default ON (never chosen = on)")
	}
	if (PagerDutyRCAConfig{}).WatchAlertsOn() {
		t.Fatal("PagerDuty must default OFF (never chosen = off — a page wakes someone)")
	}
	if (SlackRCAConfig{WatchAlerts: boolPtr(false)}).WatchAlertsOn() {
		t.Fatal("an explicit Slack opt-out must stick")
	}
	if !(PagerDutyRCAConfig{WatchAlerts: boolPtr(true)}).WatchAlertsOn() {
		t.Fatal("an explicit PagerDuty opt-in must stick")
	}
}

func TestWatchAlertsChoiceSurvivesOmittedUpdates(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // no DNS in the save-time URL pre-check
	st := newTestITSMStore(t)

	if err := st.SetPagerDutyRCA("acme", PagerDutyRCAConfig{Enabled: true, RoutingKey: "rk-acme", WatchAlerts: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSlackRCA("acme", SlackRCAConfig{Enabled: true, WebhookURL: "https://hooks.example/A", WatchAlerts: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	// A later save that does not mention the choice (an older UI, or a key
	// rotation) keeps it — it must not silently flip PagerDuty back off or
	// Slack back on.
	if err := st.SetPagerDutyRCA("acme", PagerDutyRCAConfig{Enabled: true, RoutingKey: "rk-acme-2"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSlackRCA("acme", SlackRCAConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// The combined ITSM save carries pagerduty/slack blocks without the choice.
	if err := st.Set("acme", ITSMConfig{PagerDuty: PagerDutyRCAConfig{Enabled: true}, Slack: SlackRCAConfig{Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	cfg, ok := st.ConfigFor("acme")
	if !ok {
		t.Fatal("acme config missing")
	}
	if !cfg.PagerDuty.WatchAlertsOn() || cfg.Slack.WatchAlertsOn() {
		t.Fatalf("omitted updates changed the choice: pd=%v slack=%v", cfg.PagerDuty.WatchAlertsOn(), cfg.Slack.WatchAlertsOn())
	}
	if cfg.PagerDuty.RoutingKey != "rk-acme-2" || cfg.Slack.WebhookURL != "https://hooks.example/A" {
		t.Fatal("write-only secrets must still merge as before")
	}

	pub := st.Public("acme")
	if pub["pagerduty"].(map[string]any)["watch_alerts"] != true || pub["slack"].(map[string]any)["watch_alerts"] != false {
		t.Fatalf("Public must report the effective choice: %v", pub)
	}
	// Another tenant never set anything: it sees the DEFAULTS, not acme's choice.
	other := st.Public("globex")
	if other["pagerduty"].(map[string]any)["watch_alerts"] != false || other["slack"].(map[string]any)["watch_alerts"] != true {
		t.Fatalf("a tenant's choice leaked into another tenant's view: %v", other)
	}
	// Public never returns the secrets themselves.
	for _, lane := range []string{"pagerduty", "slack"} {
		for k, v := range pub[lane].(map[string]any) {
			if s, isStr := v.(string); isStr && (s == "rk-acme-2" || s == "https://hooks.example/A") {
				t.Fatalf("Public leaked %s.%s", lane, k)
			}
		}
	}
}

// TestWatchAlertsChoicePersists: the choice round-trips through the persisted
// envelope (the kv/file blob the store reloads on restart).
func TestWatchAlertsChoicePersists(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	st := newTestITSMStore(t)
	if err := st.SetPagerDutyRCA("acme", PagerDutyRCAConfig{Enabled: true, RoutingKey: "rk", WatchAlerts: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	re := &ITSMConfigStore{path: st.path, cfgs: map[string]ITSMConfig{}, live: map[string]*itsmLive{}}
	if !re.load() {
		t.Fatal("persisted config did not load")
	}
	cfg, _ := re.ConfigFor("acme")
	if !cfg.PagerDuty.WatchAlertsOn() {
		t.Fatal("the PagerDuty opt-in was lost across a reload")
	}
}
