package notify

// channel_config.go — the notification channel-config model + constructors
// (Phase-2 W3.8, extracted from package main's notify_config.go): the five
// channel configs (SMTP / Twilio / ntfy / Slack / PagerDuty), the safe
// defaults, the channel builders and the severity vocabulary. The kv store,
// env seeding, vault custody and handlers stay in main (they hold srv).

import (
	"strconv"
	"strings"
)

type SMTPConfig struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	From        string `json:"from"`
	User        string `json:"user"`
	Pass        string `json:"pass,omitempty"` // write-only
	To          string `json:"to"`             // comma-separated
	Security    string `json:"security"`       // starttls | tls | none
	MinSeverity string `json:"min_severity"`   // gate for broadcast alerts (default: warning)
}

type TwilioConfig struct {
	Enabled     bool   `json:"enabled"`
	AccountSID  string `json:"account_sid"`
	AuthToken   string `json:"auth_token,omitempty"` // write-only
	From        string `json:"from"`
	To          string `json:"to"`           // comma-separated
	MinSeverity string `json:"min_severity"` // default: critical (phone alerts on critical)
}

type NtfyConfig struct {
	Enabled     bool   `json:"enabled"`
	Server      string `json:"server"` // default https://ntfy.sh
	Topic       string `json:"topic"`
	Token       string `json:"token,omitempty"` // write-only (optional, for protected topics)
	MinSeverity string `json:"min_severity"`    // default: critical
}

type SlackConfig struct {
	Enabled     bool   `json:"enabled"`
	WebhookURL  string `json:"webhook_url,omitempty"` // write-only (a webhook URL embeds a secret token)
	MinSeverity string `json:"min_severity"`          // default: warning (channel chatter)
}

type PagerDutyConfig struct {
	Enabled     bool   `json:"enabled"`
	RoutingKey  string `json:"routing_key,omitempty"` // write-only (Events API v2 integration key)
	MinSeverity string `json:"min_severity"`          // default: critical (on-call escalation)
	// Scope (#103): "platform" (default) = this global key pages ONLY Correlix
	// self-health alerts (layer allowlist); customer-network paging goes through
	// the per-tenant RCA incident-policy lane. "all" = legacy raw-alert behavior
	// (explicit opt-back, documented as deprecated).
	Scope string `json:"scope,omitempty"`
}

type ChannelConfig struct {
	SMTP      SMTPConfig      `json:"smtp"`
	Twilio    TwilioConfig    `json:"twilio"`
	Ntfy      NtfyConfig      `json:"ntfy"`
	Slack     SlackConfig     `json:"slack"`
	PagerDuty PagerDutyConfig `json:"pagerduty"`
}

func DefaultChannelConfig() ChannelConfig {
	return ChannelConfig{
		SMTP:      SMTPConfig{Port: 587, Security: "starttls", MinSeverity: "warning"},
		Twilio:    TwilioConfig{MinSeverity: "critical"},
		Ntfy:      NtfyConfig{Server: "https://ntfy.sh", MinSeverity: "critical"},
		Slack:     SlackConfig{MinSeverity: "warning"},
		PagerDuty: PagerDutyConfig{MinSeverity: "critical"},
	}
}

func HostPort(host string, port int) string {
	if port <= 0 {
		port = 587
	}
	return host + ":" + strconv.Itoa(port)
}

// BuildEmailChannel constructs the email Channel (gated by min_severity for the
// broadcast alert path; reports bypass the gate via DispatchTo).
func BuildEmailChannel(c SMTPConfig) Channel {
	e := NewEmail(HostPort(c.Host, c.Port), c.From).
		WithAuth(c.User, c.Pass).
		WithRecipients(c.To).
		WithTLSOnConnect(strings.EqualFold(c.Security, "tls"))
	return NewSeverityGate(e, c.MinSeverity)
}

// emailSenderTo builds a one-off, ungated email send to an explicit recipient
// list using the configured SMTP transport — the path report contact-point
// delivery uses (resolved recipients, not the global To, and no severity gate).
// Returns false if SMTP isn't usably configured or there are no recipients. The
// concrete *Email also exposes SendDocument, so the reporting pipeline can
// deliver a rendered HTML artifact as the body; it still satisfies Channel
// for the plain-text alert path.
func BuildTwilioChannel(c TwilioConfig) Channel {
	t := NewTwilio(c.AccountSID, c.AuthToken, c.From, c.To)
	return NewSeverityGate(t, c.MinSeverity)
}

func BuildNtfyChannel(c NtfyConfig) Channel {
	n := NewNtfy(c.Server, c.Topic, c.Token)
	return NewSeverityGate(n, c.MinSeverity)
}

func BuildSlackChannel(c SlackConfig) Channel {
	return NewSeverityGate(NewSlack(c.WebhookURL), c.MinSeverity)
}

func BuildPagerDutyChannel(c PagerDutyConfig, platformEnv, platformRegion string) Channel {
	pd := NewPagerDuty(c.RoutingKey)
	// #103-H E5: deployment identity from TRUSTED config only (installer env,
	// passed by the caller), never from event data. Unset = legacy behavior.
	if platformEnv != "" || platformRegion != "" {
		pd = pd.WithDeploymentIdentity(platformEnv, platformRegion)
	}
	ch := NewSeverityGate(pd, c.MinSeverity)
	if strings.ToLower(strings.TrimSpace(c.Scope)) == "all" {
		return ch // legacy raw-alert paging — explicit opt-back only
	}
	return NewPlatformScopeFilter(ch)
}

func ValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info", "notice", "warning", "error", "critical":
		return true
	}
	return false
}

// ---- SMTP handlers ---------------------------------------------------------

type PublicSMTP struct {
	Enabled     bool   `json:"enabled"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	From        string `json:"from"`
	User        string `json:"user"`
	PassSet     bool   `json:"pass_set"`
	To          string `json:"to"`
	Security    string `json:"security"`
	MinSeverity string `json:"min_severity"`
}
