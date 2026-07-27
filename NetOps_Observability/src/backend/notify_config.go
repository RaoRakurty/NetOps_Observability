package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/vault"
	"os"
	"strconv"
	"strings"
	"sync"

	"netops/backend/models"
	"netops/backend/notify"
)

// notify_config.go — UI-configurable SMTP (email) and Twilio (SMS) notification
// channels, replacing the env-only wiring. Mirrors the oidc_config.go pattern:
// kv-backed, secrets are WRITE-ONLY (GET returns a *_set boolean, a PUT that
// omits the secret preserves it), every change rebuilds the live channel and
// swaps it into the dispatcher (notify.Dispatcher.Replace/Remove) so it takes
// effect without a restart.
//
// Critical-alert routing: each channel carries a min_severity. Broadcast alert
// dispatch is wrapped in a notify.SeverityGate, so e.g. Twilio only sends on
// critical. Scheduled reports use DispatchTo, which bypasses the gate (an
// explicit send is intentional) — so reports still email at any severity.

type smtpConfig struct {
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

type twilioConfig struct {
	Enabled     bool   `json:"enabled"`
	AccountSID  string `json:"account_sid"`
	AuthToken   string `json:"auth_token,omitempty"` // write-only
	From        string `json:"from"`
	To          string `json:"to"`           // comma-separated
	MinSeverity string `json:"min_severity"` // default: critical (phone alerts on critical)
}

type ntfyConfig struct {
	Enabled     bool   `json:"enabled"`
	Server      string `json:"server"` // default https://ntfy.sh
	Topic       string `json:"topic"`
	Token       string `json:"token,omitempty"` // write-only (optional, for protected topics)
	MinSeverity string `json:"min_severity"`    // default: critical
}

type slackConfig struct {
	Enabled     bool   `json:"enabled"`
	WebhookURL  string `json:"webhook_url,omitempty"` // write-only (a webhook URL embeds a secret token)
	MinSeverity string `json:"min_severity"`          // default: warning (channel chatter)
}

type pagerDutyConfig struct {
	Enabled     bool   `json:"enabled"`
	RoutingKey  string `json:"routing_key,omitempty"` // write-only (Events API v2 integration key)
	MinSeverity string `json:"min_severity"`          // default: critical (on-call escalation)
	// Scope (#103): "platform" (default) = this global key pages ONLY Correlix
	// self-health alerts (layer allowlist); customer-network paging goes through
	// the per-tenant RCA incident-policy lane. "all" = legacy raw-alert behavior
	// (explicit opt-back, documented as deprecated).
	Scope string `json:"scope,omitempty"`
}

type notifyConfig struct {
	SMTP      smtpConfig      `json:"smtp"`
	Twilio    twilioConfig    `json:"twilio"`
	Ntfy      ntfyConfig      `json:"ntfy"`
	Slack     slackConfig     `json:"slack"`
	PagerDuty pagerDutyConfig `json:"pagerduty"`
}

type notifyConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  notifyConfig
	srv  *server
}

// defaultNotifyConfig is the shipped channel posture: push-class channels
// (Twilio/ntfy/PagerDuty) gate at critical, chatter-class (email/Slack) at
// warning. The #101 first-customer gate asserts ntfy's critical default.
func defaultNotifyConfig() notifyConfig {
	return notifyConfig{
		SMTP:      smtpConfig{Port: 587, Security: "starttls", MinSeverity: "warning"},
		Twilio:    twilioConfig{MinSeverity: "critical"},
		Ntfy:      ntfyConfig{Server: "https://ntfy.sh", MinSeverity: "critical"},
		Slack:     slackConfig{MinSeverity: "warning"},
		PagerDuty: pagerDutyConfig{MinSeverity: "critical"},
	}
}

func newNotifyConfigStore(path string, srv *server) *notifyConfigStore {
	s := &notifyConfigStore{path: path, srv: srv}
	s.cfg = defaultNotifyConfig()
	if b, err := kvLoad(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
		if dec, derr := mapNotify(s.cfg, openFn(s.vault())); derr != nil {
			logError("notify.config", "decrypt secrets", errf(derr))
		} else {
			s.cfg = dec
		}
	} else {
		// First run (no stored config): seed Slack/PagerDuty from the legacy
		// env wiring so an existing env-driven deployment keeps working, then
		// becomes editable from the admin UI. (SMTP/Twilio/ntfy predate this and
		// have always defaulted off; only Slack/PagerDuty were env-only.)
		s.seedFromEnv()
		if err := s.save(); err != nil {
			// Boot-time seed: log loudly, but a failed seed must not stop the
			// server from starting — the env wiring still drives the channels.
			logError("notify.config", "seed config persist failed", errf(err))
		}
	}
	s.apply()
	return s
}

// seedFromEnv carries the legacy FEATURE_*_NOTIFICATIONS env wiring into the
// config on first run (called only when no stored config exists).
func (s *notifyConfigStore) seedFromEnv() {
	if os.Getenv("FEATURE_SLACK_NOTIFICATIONS") == "true" {
		s.cfg.Slack.Enabled = true
		s.cfg.Slack.WebhookURL = os.Getenv("SLACK_WEBHOOK_URL")
	}
	if os.Getenv("FEATURE_PAGERDUTY_NOTIFICATIONS") == "true" {
		s.cfg.PagerDuty.Enabled = true
		s.cfg.PagerDuty.RoutingKey = os.Getenv("PAGERDUTY_KEY")
	}
	// #101 first-customer gate: critical alerts must LEAVE the app — ntfy is
	// the recommended push channel, so appliance installs can arrive with it
	// already wired from .env (then UI-editable like Slack/PagerDuty). The
	// topic is deployment config, never hardcoded. min_severity keeps its
	// critical default. The watchdog topic is refused: watchdog independence
	// is intentional (it must be able to report the stack's own death).
	if os.Getenv("FEATURE_NTFY_NOTIFICATIONS") == "true" {
		topic := os.Getenv("NTFY_ALERT_TOPIC")
		if wd := os.Getenv("WATCHDOG_NTFY_TOPIC"); wd != "" && topic == wd {
			logError("notify.config", "NTFY_ALERT_TOPIC equals the watchdog topic — refusing to seed (product alerting must stay independent of the watchdog)", nil)
			topic = ""
		}
		if topic != "" {
			s.cfg.Ntfy.Enabled = true
			s.cfg.Ntfy.Topic = topic
			if v := os.Getenv("NTFY_ALERT_SERVER"); v != "" {
				s.cfg.Ntfy.Server = v
			}
			s.cfg.Ntfy.Token = os.Getenv("NTFY_ALERT_TOKEN")
		}
	}
}

// vault returns the secret-custody Vault (nil → dormant/passthrough; e.g. tests
// without a wired server).
func (s *notifyConfigStore) vault() *vault.Vault {
	if s.srv == nil {
		return nil
	}
	return s.srv.vault
}

// save persists the config, returning any failure.
//
// F-78: this used to return NOTHING and discard three separate failures — an
// encrypt error returned early, a marshal error skipped the write, and kvSave's
// error went to `_`. Every notification-channel PUT then answered 200. An
// operator configured the pager for an outage, saw it saved, and had nothing
// written: the channel reverted at the next restart, silently, on the surface
// whose entire job is to tell someone that something broke.
//
// Callers MUST surface this. The existing TestNoVoidSaveLocked guard did not
// catch it because that guard matched `saveLocked()` by name — an instance fix,
// not a class fix. TestNoVoidSaveFuncs (architecture_guards_test.go) now covers
// the `save()` spelling too.
func (s *notifyConfigStore) save() error {
	// Encrypt secrets at rest (platform DEK); the in-memory s.cfg stays plaintext.
	c, err := mapNotify(s.cfg, sealFn(s.vault()))
	if err != nil {
		logError("notify.config", "encrypt secrets", errf(err))
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		logError("notify.config", "marshal config", errf(err))
		return err
	}
	if err := kvSave(s.path, b); err != nil {
		logError("notify.config", "persist config", errf(err))
		return err
	}
	return nil
}

// apply (re)registers the live channels in the dispatcher per the current config.
func (s *notifyConfigStore) apply() {
	if s.srv == nil || s.srv.notifier == nil {
		return
	}
	// Email
	if s.cfg.SMTP.Enabled && s.cfg.SMTP.Host != "" {
		s.srv.notifier.Replace(buildEmailChannel(s.cfg.SMTP))
	} else {
		s.srv.notifier.Remove("email")
	}
	// Twilio
	if s.cfg.Twilio.Enabled && s.cfg.Twilio.AccountSID != "" {
		s.srv.notifier.Replace(buildTwilioChannel(s.cfg.Twilio))
	} else {
		s.srv.notifier.Remove("twilio")
	}
	// ntfy
	if s.cfg.Ntfy.Enabled && s.cfg.Ntfy.Topic != "" {
		s.srv.notifier.Replace(buildNtfyChannel(s.cfg.Ntfy))
	} else {
		s.srv.notifier.Remove("ntfy")
	}
	// Slack
	if s.cfg.Slack.Enabled && s.cfg.Slack.WebhookURL != "" {
		s.srv.notifier.Replace(buildSlackChannel(s.cfg.Slack))
	} else {
		s.srv.notifier.Remove("slack")
	}
	// PagerDuty
	if s.cfg.PagerDuty.Enabled && s.cfg.PagerDuty.RoutingKey != "" {
		s.srv.notifier.Replace(buildPagerDutyChannel(s.cfg.PagerDuty))
	} else {
		s.srv.notifier.Remove("pagerduty")
	}
}

func hostPort(host string, port int) string {
	if port <= 0 {
		port = 587
	}
	return host + ":" + strconv.Itoa(port)
}

// buildEmailChannel constructs the email Channel (gated by min_severity for the
// broadcast alert path; reports bypass the gate via DispatchTo).
func buildEmailChannel(c smtpConfig) notify.Channel {
	e := notify.NewEmail(hostPort(c.Host, c.Port), c.From).
		WithAuth(c.User, c.Pass).
		WithRecipients(c.To).
		WithTLSOnConnect(strings.EqualFold(c.Security, "tls"))
	return notify.NewSeverityGate(e, c.MinSeverity)
}

// emailSenderTo builds a one-off, ungated email send to an explicit recipient
// list using the configured SMTP transport — the path report contact-point
// delivery uses (resolved recipients, not the global To, and no severity gate).
// Returns false if SMTP isn't usably configured or there are no recipients. The
// concrete *notify.Email also exposes SendDocument, so the reporting pipeline can
// deliver a rendered HTML artifact as the body; it still satisfies notify.Channel
// for the plain-text alert path.
func (s *notifyConfigStore) emailSenderTo(recipients []string) (*notify.Email, bool) {
	s.mu.RLock()
	c := s.cfg.SMTP
	s.mu.RUnlock()
	if !c.Enabled || c.Host == "" || len(recipients) == 0 {
		return nil, false
	}
	e := notify.NewEmail(hostPort(c.Host, c.Port), c.From).
		WithAuth(c.User, c.Pass).
		WithRecipients(strings.Join(recipients, ",")).
		WithTLSOnConnect(strings.EqualFold(c.Security, "tls"))
	return e, true
}

func buildTwilioChannel(c twilioConfig) notify.Channel {
	t := notify.NewTwilio(c.AccountSID, c.AuthToken, c.From, c.To)
	return notify.NewSeverityGate(t, c.MinSeverity)
}

func buildNtfyChannel(c ntfyConfig) notify.Channel {
	n := notify.NewNtfy(c.Server, c.Topic, c.Token)
	return notify.NewSeverityGate(n, c.MinSeverity)
}

func buildSlackChannel(c slackConfig) notify.Channel {
	return notify.NewSeverityGate(notify.NewSlack(c.WebhookURL), c.MinSeverity)
}

func buildPagerDutyChannel(c pagerDutyConfig) notify.Channel {
	pd := notify.NewPagerDuty(c.RoutingKey)
	// #103-H E5: deployment identity from TRUSTED config only (installer env),
	// never from event data. Unset = legacy single-deployment behavior.
	if env, region := os.Getenv("PLATFORM_ENV"), os.Getenv("PLATFORM_REGION"); env != "" || region != "" {
		pd = pd.WithDeploymentIdentity(env, region)
	}
	ch := notify.NewSeverityGate(pd, c.MinSeverity)
	if strings.ToLower(strings.TrimSpace(c.Scope)) == "all" {
		return ch // legacy raw-alert paging — explicit opt-back only
	}
	return notify.NewPlatformScopeFilter(ch)
}

func validSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info", "notice", "warning", "error", "critical":
		return true
	}
	return false
}

// ---- SMTP handlers ---------------------------------------------------------

type publicSMTP struct {
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

func (s *notifyConfigStore) publicSMTP() publicSMTP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.SMTP
	return publicSMTP{c.Enabled, c.Host, c.Port, c.From, c.User, c.Pass != "", c.To, c.Security, c.MinSeverity}
}

func (s *server) handleSMTPConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.notifyCfg.publicSMTP())
	case http.MethodPut:
		var in smtpConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !validSeverity(in.MinSeverity) {
			writeError(w, http.StatusBadRequest, errors.New("invalid min_severity"))
			return
		}
		s.notifyCfg.mu.Lock()
		if in.Pass == "" {
			in.Pass = s.notifyCfg.cfg.SMTP.Pass // preserve write-only secret
		}
		if in.Security == "" {
			in.Security = "starttls"
		}
		if in.MinSeverity == "" {
			in.MinSeverity = "warning"
		}
		s.notifyCfg.cfg.SMTP = in
		saveErr := s.notifyCfg.save()
		s.notifyCfg.mu.Unlock()
		if saveErr != nil {
			// F-78: do NOT apply or report success for a config that was not
			// written — it would work until the next restart and then vanish.
			writeError(w, http.StatusInternalServerError, errors.New("notification settings could not be saved"))
			return
		}
		s.notifyCfg.apply()
		writeJSON(w, http.StatusOK, s.notifyCfg.publicSMTP())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.SMTP
	s.notifyCfg.mu.RUnlock()
	if c.Host == "" || c.To == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure host and recipients first"))
		return
	}
	ch := buildEmailChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
	if err := ch.Send(testAlert()); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---- Twilio handlers -------------------------------------------------------

type publicTwilio struct {
	Enabled     bool   `json:"enabled"`
	AccountSID  string `json:"account_sid"`
	TokenSet    bool   `json:"token_set"`
	From        string `json:"from"`
	To          string `json:"to"`
	MinSeverity string `json:"min_severity"`
}

func (s *notifyConfigStore) publicTwilio() publicTwilio {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.Twilio
	return publicTwilio{c.Enabled, c.AccountSID, c.AuthToken != "", c.From, c.To, c.MinSeverity}
}

func (s *server) handleTwilioConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.notifyCfg.publicTwilio())
	case http.MethodPut:
		var in twilioConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !validSeverity(in.MinSeverity) {
			writeError(w, http.StatusBadRequest, errors.New("invalid min_severity"))
			return
		}
		s.notifyCfg.mu.Lock()
		if in.AuthToken == "" {
			in.AuthToken = s.notifyCfg.cfg.Twilio.AuthToken
		}
		if in.MinSeverity == "" {
			in.MinSeverity = "critical"
		}
		s.notifyCfg.cfg.Twilio = in
		saveErr := s.notifyCfg.save()
		s.notifyCfg.mu.Unlock()
		if saveErr != nil {
			// F-78: do NOT apply or report success for a config that was not
			// written — it would work until the next restart and then vanish.
			writeError(w, http.StatusInternalServerError, errors.New("notification settings could not be saved"))
			return
		}
		s.notifyCfg.apply()
		writeJSON(w, http.StatusOK, s.notifyCfg.publicTwilio())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleTwilioTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.Twilio
	s.notifyCfg.mu.RUnlock()
	if c.AccountSID == "" || c.To == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure account and recipients first"))
		return
	}
	ch := buildTwilioChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
	if err := ch.Send(testAlert()); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---- ntfy handlers ---------------------------------------------------------

type publicNtfy struct {
	Enabled     bool   `json:"enabled"`
	Server      string `json:"server"`
	Topic       string `json:"topic"`
	TokenSet    bool   `json:"token_set"`
	MinSeverity string `json:"min_severity"`
}

func (s *notifyConfigStore) publicNtfy() publicNtfy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.Ntfy
	return publicNtfy{c.Enabled, c.Server, c.Topic, c.Token != "", c.MinSeverity}
}

func (s *server) handleNtfyConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.notifyCfg.publicNtfy())
	case http.MethodPut:
		var in ntfyConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !validSeverity(in.MinSeverity) {
			writeError(w, http.StatusBadRequest, errors.New("invalid min_severity"))
			return
		}
		// #101: the external stack watchdog's topic is off-limits for product
		// alerting — it must stay able to report the stack's own death, so the
		// two must never share a channel. Enforced when the deployment exports
		// WATCHDOG_NTFY_TOPIC; the first-customer gate script also checks
		// host-side against the watchdog's own env file.
		if wd := os.Getenv("WATCHDOG_NTFY_TOPIC"); wd != "" && in.Topic == wd {
			writeError(w, http.StatusBadRequest, errors.New("this topic is reserved for the stack watchdog — use a dedicated topic for platform alerts (watchdog independence)"))
			return
		}
		s.notifyCfg.mu.Lock()
		if in.Token == "" {
			in.Token = s.notifyCfg.cfg.Ntfy.Token
		}
		if in.Server == "" {
			in.Server = "https://ntfy.sh"
		}
		if in.MinSeverity == "" {
			in.MinSeverity = "critical"
		}
		s.notifyCfg.cfg.Ntfy = in
		saveErr := s.notifyCfg.save()
		s.notifyCfg.mu.Unlock()
		if saveErr != nil {
			// F-78: do NOT apply or report success for a config that was not
			// written — it would work until the next restart and then vanish.
			writeError(w, http.StatusInternalServerError, errors.New("notification settings could not be saved"))
			return
		}
		s.notifyCfg.apply()
		writeJSON(w, http.StatusOK, s.notifyCfg.publicNtfy())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleNtfyTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.Ntfy
	s.notifyCfg.mu.RUnlock()
	if c.Topic == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure a topic first"))
		return
	}
	ch := buildNtfyChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
	if err := ch.Send(testAlert()); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---- Slack handlers --------------------------------------------------------

type publicSlack struct {
	Enabled     bool   `json:"enabled"`
	WebhookSet  bool   `json:"webhook_set"`
	MinSeverity string `json:"min_severity"`
}

func (s *notifyConfigStore) publicSlack() publicSlack {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.Slack
	return publicSlack{c.Enabled, c.WebhookURL != "", c.MinSeverity}
}

// slackIncidentTarget returns the webhook + min-severity for posting interactive
// incident messages, and whether Slack is enabled + configured. Used by the
// incident outbound action-button push (#43a).
func (s *notifyConfigStore) slackIncidentTarget() (url, minSeverity string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.Slack
	if !c.Enabled || c.WebhookURL == "" {
		return "", "", false
	}
	return c.WebhookURL, c.MinSeverity, true
}

func (s *server) handleSlackConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.notifyCfg.publicSlack())
	case http.MethodPut:
		var in slackConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !validSeverity(in.MinSeverity) {
			writeError(w, http.StatusBadRequest, errors.New("invalid min_severity"))
			return
		}
		s.notifyCfg.mu.Lock()
		if in.WebhookURL == "" {
			in.WebhookURL = s.notifyCfg.cfg.Slack.WebhookURL // preserve write-only secret
		}
		if in.MinSeverity == "" {
			in.MinSeverity = "warning"
		}
		s.notifyCfg.cfg.Slack = in
		saveErr := s.notifyCfg.save()
		s.notifyCfg.mu.Unlock()
		if saveErr != nil {
			// F-78: do NOT apply or report success for a config that was not
			// written — it would work until the next restart and then vanish.
			writeError(w, http.StatusInternalServerError, errors.New("notification settings could not be saved"))
			return
		}
		s.notifyCfg.apply()
		writeJSON(w, http.StatusOK, s.notifyCfg.publicSlack())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSlackTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.Slack
	s.notifyCfg.mu.RUnlock()
	if c.WebhookURL == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure a webhook url first"))
		return
	}
	ch := buildSlackChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
	if err := ch.Send(testAlert()); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---- PagerDuty handlers ----------------------------------------------------

type publicPagerDuty struct {
	Enabled     bool   `json:"enabled"`
	RoutingSet  bool   `json:"routing_set"`
	MinSeverity string `json:"min_severity"`
	Scope       string `json:"scope"`
}

func (s *notifyConfigStore) publicPagerDuty() publicPagerDuty {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.PagerDuty
	scope := strings.ToLower(strings.TrimSpace(c.Scope))
	if scope != "all" {
		scope = "platform"
	}
	return publicPagerDuty{c.Enabled, c.RoutingKey != "", c.MinSeverity, scope}
}

func (s *server) handlePagerDutyConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.notifyCfg.publicPagerDuty())
	case http.MethodPut:
		var in pagerDutyConfig
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !validSeverity(in.MinSeverity) {
			writeError(w, http.StatusBadRequest, errors.New("invalid min_severity"))
			return
		}
		s.notifyCfg.mu.Lock()
		if in.RoutingKey == "" {
			in.RoutingKey = s.notifyCfg.cfg.PagerDuty.RoutingKey // preserve write-only secret
		}
		if in.MinSeverity == "" {
			in.MinSeverity = "critical"
		}
		s.notifyCfg.cfg.PagerDuty = in
		saveErr := s.notifyCfg.save()
		s.notifyCfg.mu.Unlock()
		if saveErr != nil {
			// F-78: do NOT apply or report success for a config that was not
			// written — it would work until the next restart and then vanish.
			writeError(w, http.StatusInternalServerError, errors.New("notification settings could not be saved"))
			return
		}
		s.notifyCfg.apply()
		writeJSON(w, http.StatusOK, s.notifyCfg.publicPagerDuty())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handlePagerDutyTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.PagerDuty
	s.notifyCfg.mu.RUnlock()
	if c.RoutingKey == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure a routing key first"))
		return
	}
	ch := buildPagerDutyChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
	if err := ch.Send(testAlert()); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func testAlert() models.Alert {
	return models.Alert{
		Rule:     "NotificationTest",
		Severity: "critical",
		Summary:  "NetOps test notification — your channel is configured correctly.",
	}
}
