// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

// channel_config.go — the notification channel-config model + constructors
// (Phase-2 W3.8, extracted from package main's notify_config.go): the seven
// managed channel configs (SMTP / Twilio / ntfy / Slack / PagerDuty / Teams /
// SNS), the safe defaults, the channel builders, the input validators and the
// severity vocabulary. The kv store, env seeding, vault custody and handlers
// stay in main (they hold srv).
//
// G10: Teams and SNS used to be env-only — registered straight from
// TEAMS_WEBHOOK_URL / SNS_* in main.go with NO admin surface and NO severity
// gate, so they fired on every alert at every severity and could not be
// changed without a restart. They are now managed exactly like Slack and
// PagerDuty: stored config, write-only secrets, a severity floor, live
// Replace/Remove, and a one-shot env migration (see notify_config.go).

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
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

// TeamsConfig is the Microsoft Teams Incoming Webhook channel. Shape mirrors
// SlackConfig exactly — Teams is the same CHAT class of destination (channel
// chatter, floor "warning"), so it deliberately carries no platform Scope knob:
// scope exists for the paging classes whose global credential wakes a human.
type TeamsConfig struct {
	Enabled     bool   `json:"enabled"`
	WebhookURL  string `json:"webhook_url,omitempty"` // write-only (a webhook URL embeds a secret token)
	MinSeverity string `json:"min_severity"`          // default: warning (channel chatter)
}

// SNSConfig is the Amazon SNS channel (SMS to E.164 numbers and/or publish to a
// topic ARN).
//
// CREDENTIALS ARE NOT PART OF THIS STRUCT, deliberately (CLAUDE.md §8): the AWS
// access key / secret key stay in the process environment (AWS_ACCESS_KEY_ID /
// AWS_SECRET_ACCESS_KEY, or whatever the deployment's secret injector puts
// there) and are passed to BuildSNSChannel by the caller — exactly the way
// BuildPagerDutyChannel takes the trusted deployment identity. Nothing here is
// ever persisted to the config file, so the admin surface can only reference
// the credential ("credentials_set: true"), never read, write or leak it.
type SNSConfig struct {
	Enabled  bool   `json:"enabled"`
	TopicARN string `json:"topic_arn"`
	// Region for the SNS endpoint. Empty = derived from TopicARN. Validated to a
	// strict region grammar because it is interpolated into the endpoint host.
	Region string `json:"region"`
	// PhoneNumbers is a comma-separated E.164 list (optional; a topic ARN alone
	// is a valid destination).
	PhoneNumbers string `json:"phone_numbers"`
	MinSeverity  string `json:"min_severity"` // default: critical (it wakes a phone)
	// Scope, PagerDuty-style (#103): "platform" restricts this globally-credentialled
	// pager to Correlix self-health alerts (layer allowlist); "all" is the legacy
	// raw-alert behavior. NOTE the default differs from PagerDuty's on purpose:
	// SNS has no per-tenant RCA adapter to route customer alerts to, so a
	// platform-only default would silently give a freshly-configured channel
	// nowhere to send. Empty/unknown = "all"; operators paging humans should set
	// "platform". The env MIGRATION also seeds "all" so an existing
	// FEATURE_SNS_NOTIFICATIONS deployment keeps the behavior it has today.
	Scope string `json:"scope,omitempty"`
}

type ChannelConfig struct {
	SMTP      SMTPConfig      `json:"smtp"`
	Twilio    TwilioConfig    `json:"twilio"`
	Ntfy      NtfyConfig      `json:"ntfy"`
	Slack     SlackConfig     `json:"slack"`
	PagerDuty PagerDutyConfig `json:"pagerduty"`
	Teams     TeamsConfig     `json:"teams"`
	SNS       SNSConfig       `json:"sns"`

	// EnvSeeded records which channels have already had their legacy env
	// wiring migrated into this config. It is a LATCH, not a cache: once a
	// channel is marked, the deprecated env path never touches it again, so an
	// operator who disables Teams in the admin UI does not get it re-enabled by
	// a TEAMS_WEBHOOK_URL that is still sitting in .env. Persisted with the
	// config so "once" means once per deployment, not once per process.
	EnvSeeded EnvSeededChannels `json:"env_seeded,omitempty"`
}

// EnvSeededChannels is the per-channel migration latch. A STRUCT of bools, not
// a map, on purpose: ChannelConfig must stay comparable (secrets_config_test
// and the config round-trip guards compare whole configs with ==), and the set
// of env-wired channels is closed and known.
//
// Ntfy joined Teams/SNS here because its env wiring (FEATURE_NTFY_NOTIFICATIONS
// + NTFY_ALERT_*) used to be applied ONLY on a first run, so an appliance
// upgraded in place could never enable it from .env. It now runs on both boot
// paths and therefore needs the same once-and-only-once latch.
type EnvSeededChannels struct {
	Teams bool `json:"teams,omitempty"`
	SNS   bool `json:"sns,omitempty"`
	Ntfy  bool `json:"ntfy,omitempty"`
}

// MarkEnvSeeded latches a channel as env-migrated (idempotent). An unknown
// channel name is a no-op: only the env-wired channels have a latch.
func (c *ChannelConfig) MarkEnvSeeded(channel string) {
	switch channel {
	case "teams":
		c.EnvSeeded.Teams = true
	case "sns":
		c.EnvSeeded.SNS = true
	case "ntfy":
		c.EnvSeeded.Ntfy = true
	}
}

// IsEnvSeeded reports whether the legacy env wiring for a channel has already
// been migrated.
func (c ChannelConfig) IsEnvSeeded(channel string) bool {
	switch channel {
	case "teams":
		return c.EnvSeeded.Teams
	case "sns":
		return c.EnvSeeded.SNS
	case "ntfy":
		return c.EnvSeeded.Ntfy
	}
	return false
}

func DefaultChannelConfig() ChannelConfig {
	return ChannelConfig{
		SMTP:      SMTPConfig{Port: 587, Security: "starttls", MinSeverity: "warning"},
		Twilio:    TwilioConfig{MinSeverity: "critical"},
		Ntfy:      NtfyConfig{Server: "https://ntfy.sh", MinSeverity: "critical"},
		Slack:     SlackConfig{MinSeverity: "warning"},
		PagerDuty: PagerDutyConfig{MinSeverity: "critical"},
		Teams:     TeamsConfig{MinSeverity: "warning"},
		SNS:       SNSConfig{MinSeverity: "critical"},
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

// BuildNtfyChannel constructs the product ntfy channel.
//
// budgets is the process's SHARED per-push-server token-bucket registry
// (pushbudget.go); a nil registry leaves the channel unguarded, which is what
// every test that does not care about rate limiting wants. The channel's
// configured min_severity does double duty: the gate below, and the page policy
// that decides whether a critical alert on THIS channel may spend the shared
// budget's page reserve (only a channel gated at `critical` is a pager).
func BuildNtfyChannel(c NtfyConfig, budgets *PushBudgets) Channel {
	n := NewNtfy(c.Server, c.Topic, c.Token).
		WithBudget(budgets.For(c.Server)).
		WithPagePolicy(c.MinSeverity)
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

// BuildTeamsChannel constructs the severity-gated Teams channel. Same shape as
// BuildSlackChannel: the gate preserves the inner Name() ("teams") so the
// dispatcher's Replace/Remove keying keeps working.
func BuildTeamsChannel(c TeamsConfig) Channel {
	return NewSeverityGate(NewTeams(c.WebhookURL), c.MinSeverity)
}

// BuildSNSChannel constructs the severity-gated (and optionally platform-scoped)
// SNS channel. accessKey/secretKey come from the TRUSTED process environment,
// never from the stored config — see SNSConfig's doc comment.
func BuildSNSChannel(c SNSConfig, accessKey, secretKey string) Channel {
	region := strings.TrimSpace(c.Region)
	if region == "" {
		region = SNSRegionFromARN(c.TopicARN)
	}
	ch := NewSeverityGate(NewSNS(accessKey, secretKey, region, c.PhoneNumbers, c.TopicARN), c.MinSeverity)
	if NormalizeSNSScope(c.Scope) == "platform" {
		return NewPlatformScopeFilter(ch)
	}
	return ch
}

// NormalizeSNSScope collapses the stored scope to the two legal values. Unlike
// PagerDuty (whose unknown/empty scope means "platform"), an unset SNS scope
// means "all" — see SNSConfig.Scope for why.
func NormalizeSNSScope(s string) string {
	if strings.ToLower(strings.TrimSpace(s)) == "platform" {
		return "platform"
	}
	return "all"
}

// ---- input validation (zero trust, CLAUDE.md §3) ---------------------------

// awsRegionRe is a strict region grammar (us-east-1, eu-west-2, us-gov-west-1,
// cn-north-1). It is strict on purpose: the region is INTERPOLATED INTO THE SNS
// ENDPOINT HOST, so anything permitting "/", ".", "@" or ":" would let an admin
// redirect signed, credentialled requests at a host of their choosing.
var awsRegionRe = regexp.MustCompile(`^[a-z]{2,}(-[a-z0-9]+)+$`)

// snsTopicNameRe is the SNS topic-name grammar (alphanumeric, hyphen,
// underscore; FIFO topics end in .fifo).
var snsTopicNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}(\.fifo)?$`)

// awsAccountRe is the 12-digit AWS account id.
var awsAccountRe = regexp.MustCompile(`^[0-9]{12}$`)

// ValidateWebhookURL enforces the ONE scheme a secret-bearing webhook may use.
// A webhook URL embeds a bearer token in its path; over http:// that token (and
// every alert body) crosses the wire in clear text, so plaintext is refused at
// the boundary rather than "warned about". Empty is allowed — that is how a
// channel is left unconfigured / how an admin PUT preserves the stored secret.
func ValidateWebhookURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("webhook_url is not a valid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("webhook_url must use https (a webhook URL carries a bearer secret; http would send it in clear text)")
	}
	if u.Host == "" {
		return errors.New("webhook_url must include a host")
	}
	if u.User != nil {
		return errors.New("webhook_url must not embed credentials in the URL userinfo")
	}
	return nil
}

// ValidateAWSRegion checks the region against the strict endpoint-safe grammar.
// Empty is allowed (derived from the topic ARN).
func ValidateAWSRegion(region string) error {
	region = strings.TrimSpace(region)
	if region == "" {
		return nil
	}
	if !awsRegionRe.MatchString(region) {
		return fmt.Errorf("region %q is not a valid AWS region (expected e.g. us-east-1)", region)
	}
	return nil
}

// ValidateSNSTopicARN checks the ARN is well-formed:
// arn:<partition>:sns:<region>:<12-digit account>:<topic>. Empty is allowed —
// an SNS channel may target phone numbers only.
func ValidateSNSTopicARN(arn string) error {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return nil
	}
	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return errors.New("topic_arn must look like arn:aws:sns:<region>:<account-id>:<topic>")
	}
	if parts[0] != "arn" {
		return errors.New("topic_arn must start with \"arn:\"")
	}
	switch parts[1] {
	case "aws", "aws-cn", "aws-us-gov":
	default:
		return fmt.Errorf("topic_arn partition %q is not an AWS partition", parts[1])
	}
	if parts[2] != "sns" {
		return fmt.Errorf("topic_arn service must be \"sns\", got %q", parts[2])
	}
	if !awsRegionRe.MatchString(parts[3]) {
		return fmt.Errorf("topic_arn region %q is not a valid AWS region", parts[3])
	}
	if !awsAccountRe.MatchString(parts[4]) {
		return errors.New("topic_arn account id must be 12 digits")
	}
	if !snsTopicNameRe.MatchString(parts[5]) {
		return errors.New("topic_arn topic name contains characters SNS does not allow")
	}
	return nil
}

// SNSRegionFromARN extracts the region field of a well-formed topic ARN ("" if
// the ARN is empty or malformed).
func SNSRegionFromARN(arn string) string {
	parts := strings.Split(strings.TrimSpace(arn), ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "sns" {
		return ""
	}
	return parts[3]
}

// ValidateSNSConfig is the whole-channel check the admin PUT runs before
// anything is stored: region + ARN grammar, region/ARN agreement, and the
// "enabled with nowhere to send" case.
func ValidateSNSConfig(c SNSConfig) error {
	if err := ValidateAWSRegion(c.Region); err != nil {
		return err
	}
	if err := ValidateSNSTopicARN(c.TopicARN); err != nil {
		return err
	}
	if arnRegion := SNSRegionFromARN(c.TopicARN); arnRegion != "" &&
		strings.TrimSpace(c.Region) != "" && arnRegion != strings.TrimSpace(c.Region) {
		return fmt.Errorf("region %q does not match the topic ARN's region %q", c.Region, arnRegion)
	}
	for _, n := range SplitList(c.PhoneNumbers) {
		if err := ValidateE164(n); err != nil {
			return err
		}
	}
	if c.Enabled {
		if strings.TrimSpace(c.TopicARN) == "" && len(SplitList(c.PhoneNumbers)) == 0 {
			return errors.New("configure a topic ARN or at least one phone number before enabling SNS")
		}
		if strings.TrimSpace(c.Region) == "" && SNSRegionFromARN(c.TopicARN) == "" {
			return errors.New("region is required when SNS is enabled without a topic ARN to derive it from")
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Scope)) {
	case "", "all", "platform":
	default:
		return errors.New("scope must be \"all\" or \"platform\"")
	}
	return nil
}

// ValidateTeamsConfig is the whole-channel check for the Teams admin PUT.
func ValidateTeamsConfig(c TeamsConfig) error {
	if err := ValidateWebhookURL(c.WebhookURL); err != nil {
		return err
	}
	if c.Enabled && strings.TrimSpace(c.WebhookURL) == "" {
		return errors.New("configure a webhook url before enabling Teams")
	}
	return nil
}

// e164Re is the E.164 phone grammar SNS accepts: + followed by 7-15 digits.
var e164Re = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// ValidateE164 checks one destination phone number.
func ValidateE164(n string) error {
	if !e164Re.MatchString(strings.TrimSpace(n)) {
		return fmt.Errorf("phone number %q is not E.164 (expected e.g. +14155550123)", n)
	}
	return nil
}

// SplitList splits a comma-separated operator-entered list, dropping blanks.
func SplitList(csv string) []string {
	var out []string
	for _, v := range strings.Split(csv, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
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
