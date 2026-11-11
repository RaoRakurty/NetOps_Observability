// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package platformalert is the CONFIGURATION of the platform self-health alert
// route: where the stack's own alerts (everything vmalert POSTs to the api's
// receiver — engines not consuming, storage refusing writes, ingest silent, the
// warning digest) are pushed.
//
// Owner decision, 2026-11-11 (binding): "Platform self-health alerts should be
// configured from the GUI and not via env. Block that option. Ensure it's
// possible via GUI. It should have options via Twilio and ntfy." The delivery
// mechanics stay in internal/alertwebhook (tiers, digest, retry, budgets); this
// package owns what an administrator sets on Platform → Platform alerts:
//
//   - the Store: one platform-global record in the platform kv (app_kv on the
//     Postgres backend, a 0600 file on the file backend), secrets sealed with
//     the platform DEK, cached in memory as the LAST GOOD copy so an unreadable
//     store never silences the route (and is loud about it);
//   - the Router: alertwebhook.HostRouter over the current record — which
//     channels each tier reaches, each with its outbound budget;
//   - the API: GET/PUT the record, POST a test message, platform-admin only.
//
// TENANCY (CLAUDE.md §3a rule 3): platform-GLOBAL plumbing. There is exactly
// one record, it carries no tenant data, and every route is gated by the
// integrator's requirePlatformAdmin — a tenant/org admin holds
// administration:admin and must never reach it.
//
// WHAT THIS PACKAGE IS NOT: the external watchdog (scripts/stack-watchdog.sh)
// stays env/file-based on the host. It is the layer that must survive the
// stack's death, so it can never depend on a setting stored inside the stack.
package platformalert

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Shipped defaults.
const (
	// DefaultNtfyServer is the public ntfy server.
	DefaultNtfyServer = "https://ntfy.sh"
	// DefaultSMSPerHour is the SMS cap: at most this many text messages an
	// hour for the whole route (one message per recipient). SMS costs money and
	// a page storm must not run up a bill: the warning digest is never sent by
	// SMS unless the administrator turns it on, and half of the cap is
	// reserved for pages (see Router).
	DefaultSMSPerHour = 10
	// MinSMSPerHour / MaxSMSPerHour bound the cap an administrator may set.
	MinSMSPerHour = 1
	MaxSMSPerHour = 60
	// MaxSMSRecipients bounds the recipient list (§9: bounded fan-out).
	MaxSMSRecipients = 5
)

// Tiers says which kinds of platform alert a channel receives.
//
// Page is the four page conditions (an engine not consuming, ingest silent,
// storage refusing writes, the alerting heartbeat missing) and the all-clear
// that follows each. Warning is the periodic summary of everything else.
type Tiers struct {
	Page    bool `json:"page"`
	Warning bool `json:"warning"`
}

// NtfyChannel is the ntfy push destination.
type NtfyChannel struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	// Topic is a CREDENTIAL: knowing it is enough to read every alert published
	// to it and to publish forgeries. Returned to the platform admin (who must
	// subscribe a phone to it), never logged, never audited by value.
	Topic string `json:"topic"`
	// Token is the optional bearer token for a protected topic. Sealed at rest,
	// write-only over the API.
	Token string `json:"token,omitempty"`
	Tiers Tiers  `json:"tiers"`
}

// SMSChannel is the Twilio SMS destination.
type SMSChannel struct {
	Enabled    bool   `json:"enabled"`
	AccountSID string `json:"account_sid"`
	// AuthToken is sealed at rest and write-only over the API.
	AuthToken string   `json:"auth_token,omitempty"`
	From      string   `json:"from"`
	To        []string `json:"to"`
	Tiers     Tiers    `json:"tiers"`
	// MaxPerHour caps text messages per hour across all recipients.
	MaxPerHour int `json:"max_per_hour"`
}

// Config is the whole platform-global record.
type Config struct {
	Ntfy      NtfyChannel `json:"ntfy"`
	SMS       SMSChannel  `json:"sms"`
	UpdatedBy string      `json:"updated_by,omitempty"`
	UpdatedAt time.Time   `json:"updated_at,omitempty"`
}

// DefaultConfig is the shipped posture: nothing enabled (an install has no
// destination until an administrator gives it one — and is loud until then),
// ntfy routes both tiers when enabled, SMS routes pages only.
func DefaultConfig() Config {
	return Config{
		Ntfy: NtfyChannel{Server: DefaultNtfyServer, Tiers: Tiers{Page: true, Warning: true}},
		SMS:  SMSChannel{Tiers: Tiers{Page: true, Warning: false}, MaxPerHour: DefaultSMSPerHour},
	}
}

// normalize fills shipped defaults into blanks so a record written by an older
// build (or a hand-edited one) reads the same as a fresh one.
func (c Config) normalize() Config {
	if strings.TrimSpace(c.Ntfy.Server) == "" {
		c.Ntfy.Server = DefaultNtfyServer
	}
	c.Ntfy.Server = strings.TrimRight(strings.TrimSpace(c.Ntfy.Server), "/")
	c.Ntfy.Topic = strings.TrimSpace(c.Ntfy.Topic)
	if c.SMS.MaxPerHour == 0 {
		c.SMS.MaxPerHour = DefaultSMSPerHour
	}
	c.SMS.AccountSID = strings.TrimSpace(c.SMS.AccountSID)
	c.SMS.From = strings.TrimSpace(c.SMS.From)
	to := make([]string, 0, len(c.SMS.To))
	for _, n := range c.SMS.To {
		if n = strings.TrimSpace(n); n != "" {
			to = append(to, n)
		}
	}
	c.SMS.To = to
	return c
}

// ntfyLive / smsLive report whether a channel is enabled AND complete enough to
// send. Validate refuses to SAVE an enabled incomplete channel; these guard the
// read side against a record that was valid under different rules.
func (c Config) ntfyLive() bool { return c.Ntfy.Enabled && c.Ntfy.Topic != "" }

func (c Config) smsLive() bool {
	return c.SMS.Enabled && c.SMS.AccountSID != "" && c.SMS.AuthToken != "" && c.SMS.From != "" && len(c.SMS.To) > 0
}

// PageRouted reports whether a page reaches at least one live channel. This is
// THE question: a route whose pages reach nobody is unconfigured, whatever
// else it does.
func (c Config) PageRouted() bool {
	return (c.ntfyLive() && c.Ntfy.Tiers.Page) || (c.smsLive() && c.SMS.Tiers.Page)
}

// WarningRouted reports whether the warning digest reaches a live channel.
func (c Config) WarningRouted() bool {
	return (c.ntfyLive() && c.Ntfy.Tiers.Warning) || (c.smsLive() && c.SMS.Tiers.Warning)
}

// Input validation (§3: every input is hostile). The patterns are anchored and
// bounded; nothing here is ever interpreted, but a topic rides a URL path and a
// token rides a header, so both are held to the narrow charsets their
// protocols actually allow.
var (
	// ntfy's own topic rule: [-_A-Za-z0-9]{1,64}.
	topicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	// A bearer token: printable ASCII with no whitespace (it rides a header).
	tokenRE = regexp.MustCompile(`^[\x21-\x7e]{1,512}$`)
	// Twilio Account SID: "AC" + 32 hex.
	sidRE = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)
	// Twilio auth token: 32 hex for an account token; a wider printable run is
	// accepted for API-key secrets, still header-safe.
	authTokenRE = regexp.MustCompile(`^[\x21-\x7e]{16,128}$`)
	// E.164: "+", a non-zero leading digit, 7-15 digits in total.
	e164RE = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
)

// Validation errors are plain sentences: they are shown to the administrator
// verbatim, so they say what to fix, not what failed.
var (
	ErrNtfyServer      = errors.New("The ntfy server must be an https:// address, for example https://ntfy.sh.")
	ErrNtfyTopic       = errors.New("The ntfy topic may use only letters, digits, - and _ (at most 64).")
	ErrNtfyToken       = errors.New("The ntfy access token has characters a token cannot have (spaces or control characters).")
	ErrNtfyIncomplete  = errors.New("To turn on ntfy, enter a topic.")
	ErrSMSSID          = errors.New("The Twilio Account SID starts with AC followed by 32 letters and digits.")
	ErrSMSAuthToken    = errors.New("The Twilio auth token does not look right (16 to 128 characters, no spaces).")
	ErrSMSNumber       = errors.New("Phone numbers must be in international format, for example +14155550100.")
	ErrSMSRecipients   = fmt.Errorf("Enter between 1 and %d phone numbers to text, without repeats.", MaxSMSRecipients)
	ErrSMSIncomplete   = errors.New("To turn on text messages, enter the Account SID, auth token, the number to send from and at least one number to text.")
	ErrSMSCap          = fmt.Errorf("The text-message limit must be between %d and %d an hour.", MinSMSPerHour, MaxSMSPerHour)
	ErrNoTierSelected  = errors.New("A channel that is turned on must receive pages, the warning summary, or both.")
	ErrSMSFromIsTarget = errors.New("The number to send from cannot also be a number to text.")
)

// Validate checks a complete, merged record (secrets included) before it is
// saved. A DISABLED channel may be incomplete — an administrator can stage
// settings — but whatever it holds must still be well-formed.
func (c Config) Validate() error {
	c = c.normalize()
	if err := validServer(c.Ntfy.Server); err != nil {
		return err
	}
	if c.Ntfy.Topic != "" && !topicRE.MatchString(c.Ntfy.Topic) {
		return ErrNtfyTopic
	}
	if c.Ntfy.Token != "" && !tokenRE.MatchString(c.Ntfy.Token) {
		return ErrNtfyToken
	}
	if c.Ntfy.Enabled {
		if c.Ntfy.Topic == "" {
			return ErrNtfyIncomplete
		}
		if !c.Ntfy.Tiers.Page && !c.Ntfy.Tiers.Warning {
			return ErrNoTierSelected
		}
	}
	if c.SMS.AccountSID != "" && !sidRE.MatchString(c.SMS.AccountSID) {
		return ErrSMSSID
	}
	if c.SMS.AuthToken != "" && !authTokenRE.MatchString(c.SMS.AuthToken) {
		return ErrSMSAuthToken
	}
	if c.SMS.From != "" && !e164RE.MatchString(c.SMS.From) {
		return ErrSMSNumber
	}
	if len(c.SMS.To) > MaxSMSRecipients {
		return ErrSMSRecipients
	}
	seen := make(map[string]bool, len(c.SMS.To))
	for _, n := range c.SMS.To {
		if !e164RE.MatchString(n) {
			return ErrSMSNumber
		}
		if seen[n] {
			return ErrSMSRecipients
		}
		seen[n] = true
		if n == c.SMS.From {
			return ErrSMSFromIsTarget
		}
	}
	if c.SMS.MaxPerHour < MinSMSPerHour || c.SMS.MaxPerHour > MaxSMSPerHour {
		return ErrSMSCap
	}
	if c.SMS.Enabled {
		if c.SMS.AccountSID == "" || c.SMS.AuthToken == "" || c.SMS.From == "" || len(c.SMS.To) == 0 {
			return ErrSMSIncomplete
		}
		if !c.SMS.Tiers.Page && !c.SMS.Tiers.Warning {
			return ErrNoTierSelected
		}
	}
	return nil
}

// validServer accepts an https origin (optionally with a path prefix, for an
// ntfy behind a reverse proxy) and nothing else: no userinfo (a credential in
// a URL ends up in logs), no query, no fragment. Plain http is refused — the
// push body names the stack's failures and the token rides a header.
func validServer(raw string) error {
	if len(raw) > 256 {
		return ErrNtfyServer
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return ErrNtfyServer
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return ErrNtfyServer
	}
	return nil
}
