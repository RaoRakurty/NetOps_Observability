// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"errors"
	"strings"
	"testing"
)

func validNtfyOnly() Config {
	c := DefaultConfig()
	c.Ntfy.Enabled = true
	c.Ntfy.Topic = "corr-platform-1"
	return c
}

func validSMSOnly() Config {
	c := DefaultConfig()
	c.SMS.Enabled = true
	c.SMS.AccountSID = fakeSID()
	c.SMS.AuthToken = fakeSecret("twilio")
	c.SMS.From = phoneFrom
	c.SMS.To = []string{phoneA}
	return c
}

// The shipped posture: nothing routed (and therefore loud), ntfy takes both
// tiers when enabled, SMS takes pages only — SMS costs money.
func TestDefaultConfigRoutesNothingAndKeepsSMSOffTheWarningTier(t *testing.T) {
	c := DefaultConfig()
	if c.PageRouted() || c.WarningRouted() {
		t.Fatal("a fresh install must route nothing until an administrator configures a channel")
	}
	if !c.Ntfy.Tiers.Page || !c.Ntfy.Tiers.Warning {
		t.Error("ntfy must default to pages AND the warning summary")
	}
	if !c.SMS.Tiers.Page || c.SMS.Tiers.Warning {
		t.Error("SMS must default to pages only, never the warning summary")
	}
	if c.SMS.MaxPerHour != DefaultSMSPerHour || c.Ntfy.Server != DefaultNtfyServer {
		t.Errorf("defaults: %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("the default record must itself be valid: %v", err)
	}
}

func TestRoutingPredicates(t *testing.T) {
	n := validNtfyOnly()
	if !n.PageRouted() || !n.WarningRouted() {
		t.Error("ntfy-only routes both tiers")
	}
	s := validSMSOnly()
	if !s.PageRouted() || s.WarningRouted() {
		t.Error("SMS-only routes pages, not warnings")
	}
	// Enabled but incomplete on the read side (a record valid under older
	// rules) must not count as routed.
	broken := validSMSOnly()
	broken.SMS.AuthToken = ""
	if broken.PageRouted() {
		t.Error("an SMS channel without credentials does not route anything")
	}
	off := validNtfyOnly()
	off.Ntfy.Tiers.Page = false
	if off.PageRouted() {
		t.Error("ntfy with pages unticked does not route pages")
	}
}

func TestValidateRefusesHostileAndMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want error
	}{
		{"plain http server", func(c *Config) { c.Ntfy.Server = "http://ntfy.sh" }, ErrNtfyServer},
		{"userinfo in server", func(c *Config) { c.Ntfy.Server = "https://u:p@ntfy.sh" }, ErrNtfyServer},
		{"query in server", func(c *Config) { c.Ntfy.Server = "https://ntfy.sh/?x=1" }, ErrNtfyServer},
		{"no host", func(c *Config) { c.Ntfy.Server = "https://" }, ErrNtfyServer},
		{"javascript scheme", func(c *Config) { c.Ntfy.Server = "javascript:alert(1)" }, ErrNtfyServer},
		{"oversize server", func(c *Config) { c.Ntfy.Server = "https://" + strings.Repeat("a", 260) + ".sh" }, ErrNtfyServer},
		{"topic with slash", func(c *Config) { c.Ntfy.Topic = "a/../b" }, ErrNtfyTopic},
		{"topic with space", func(c *Config) { c.Ntfy.Topic = "a b" }, ErrNtfyTopic},
		{"topic too long", func(c *Config) { c.Ntfy.Topic = strings.Repeat("a", 65) }, ErrNtfyTopic},
		{"token with CRLF", func(c *Config) { c.Ntfy.Token = "abc\r\nX-Evil: 1" }, ErrNtfyToken},
		{"enabled, no topic", func(c *Config) { c.Ntfy.Topic = "" }, ErrNtfyIncomplete},
		{"enabled, no tier", func(c *Config) { c.Ntfy.Tiers = Tiers{} }, ErrNoTierSelected},
		{"bad SID", func(c *Config) { c.SMS.AccountSID = "AC123" }, ErrSMSSID},
		{"SID path injection", func(c *Config) { c.SMS.AccountSID = "AC" + strings.Repeat("a", 30) + "/.." }, ErrSMSSID},
		{"short auth token", func(c *Config) { c.SMS.AuthToken = "short" }, ErrSMSAuthToken},
		{"from not E.164", func(c *Config) { c.SMS.From = "4155550199" }, ErrSMSNumber},
		{"to not E.164", func(c *Config) { c.SMS.To = []string{"+0123"} }, ErrSMSNumber},
		{"to has letters", func(c *Config) { c.SMS.To = []string{"+1415555O100"} }, ErrSMSNumber},
		{"duplicate to", func(c *Config) { c.SMS.To = []string{phoneA, phoneA} }, ErrSMSRecipients},
		{"too many to", func(c *Config) {
			c.SMS.To = []string{"+14155550101", "+14155550102", "+14155550103", "+14155550104", "+14155550105", "+14155550106"}
		}, ErrSMSRecipients},
		{"from is a target", func(c *Config) { c.SMS.To = []string{phoneFrom} }, ErrSMSFromIsTarget},
		{"cap too high", func(c *Config) { c.SMS.MaxPerHour = MaxSMSPerHour + 1 }, ErrSMSCap},
		{"cap negative", func(c *Config) { c.SMS.MaxPerHour = -1 }, ErrSMSCap},
		{"sms enabled, no numbers", func(c *Config) { c.SMS.To = nil }, ErrSMSIncomplete},
		{"sms enabled, no token", func(c *Config) { c.SMS.AuthToken = "" }, ErrSMSIncomplete},
		{"sms enabled, no tier", func(c *Config) { c.SMS.Tiers = Tiers{} }, ErrNoTierSelected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validNtfyOnly()
			s := validSMSOnly()
			c.SMS = s.SMS
			tc.mut(&c)
			if err := c.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsAStagedDisabledChannel(t *testing.T) {
	c := DefaultConfig()
	c.SMS.AccountSID = fakeSID() // staged, not enabled, incomplete: allowed
	c.Ntfy.Topic = "staged-topic"
	if err := c.Validate(); err != nil {
		t.Fatalf("a disabled, partly filled channel must save: %v", err)
	}
	ok := validNtfyOnly()
	ok.Ntfy.Server = "https://ntfy.example.com/push"
	if err := ok.Validate(); err != nil {
		t.Fatalf("an https server with a path prefix is valid: %v", err)
	}
}

func TestRetiredEnvIsReportedNeverRead(t *testing.T) {
	env := map[string]string{
		"PLATFORM_ALERTS_NTFY_TOPIC":  "old-topic",
		"PLATFORM_ALERTS_NTFY_SERVER": "   ",
		"WATCHDOG_NTFY_TOPIC":         "wd",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	got := RetiredEnvSet(lookup)
	if len(got) != 1 || got[0] != "PLATFORM_ALERTS_NTFY_TOPIC" {
		t.Fatalf("RetiredEnvSet = %v (blank values are not 'set')", got)
	}
	if !WatchdogFallbackIgnored(lookup, DefaultConfig()) {
		t.Error("watchdog topic set + no ntfy destination: must be reported as no longer the fallback")
	}
	if WatchdogFallbackIgnored(lookup, validNtfyOnly()) {
		t.Error("with an ntfy destination configured there is nothing to report")
	}
}
