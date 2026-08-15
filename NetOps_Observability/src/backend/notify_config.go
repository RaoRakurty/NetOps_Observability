package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"os"
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

type notifyConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  notify.ChannelConfig
	srv  *server
}

// defaultNotifyConfig is the shipped channel posture: push-class channels
// (Twilio/ntfy/PagerDuty) gate at critical, chatter-class (email/Slack) at
// warning. The #101 first-customer gate asserts ntfy's critical default.
func newNotifyConfigStore(path string, srv *server) *notifyConfigStore {
	s := &notifyConfigStore{path: path, srv: srv}
	s.cfg = notify.DefaultChannelConfig()
	if b, err := platformdb.Load(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg) // best-effort: corrupt state file starts from defaults
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
	if err := platformdb.Save(s.path, b); err != nil {
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
		s.srv.notifier.Replace(notify.BuildEmailChannel(s.cfg.SMTP))
	} else {
		s.srv.notifier.Remove("email")
	}
	// Twilio
	if s.cfg.Twilio.Enabled && s.cfg.Twilio.AccountSID != "" {
		s.srv.notifier.Replace(notify.BuildTwilioChannel(s.cfg.Twilio))
	} else {
		s.srv.notifier.Remove("twilio")
	}
	// ntfy
	if s.cfg.Ntfy.Enabled && s.cfg.Ntfy.Topic != "" {
		s.srv.notifier.Replace(notify.BuildNtfyChannel(s.cfg.Ntfy))
	} else {
		s.srv.notifier.Remove("ntfy")
	}
	// Slack
	if s.cfg.Slack.Enabled && s.cfg.Slack.WebhookURL != "" {
		s.srv.notifier.Replace(notify.BuildSlackChannel(s.cfg.Slack))
	} else {
		s.srv.notifier.Remove("slack")
	}
	// PagerDuty
	if s.cfg.PagerDuty.Enabled && s.cfg.PagerDuty.RoutingKey != "" {
		s.srv.notifier.Replace(notify.BuildPagerDutyChannel(s.cfg.PagerDuty, os.Getenv("PLATFORM_ENV"), os.Getenv("PLATFORM_REGION")))
	} else {
		s.srv.notifier.Remove("pagerduty")
	}
}

func (s *notifyConfigStore) emailSenderTo(recipients []string) (*notify.Email, bool) {
	s.mu.RLock()
	c := s.cfg.SMTP
	s.mu.RUnlock()
	if !c.Enabled || c.Host == "" || len(recipients) == 0 {
		return nil, false
	}
	e := notify.NewEmail(notify.HostPort(c.Host, c.Port), c.From).
		WithAuth(c.User, c.Pass).
		WithRecipients(strings.Join(recipients, ",")).
		WithTLSOnConnect(strings.EqualFold(c.Security, "tls"))
	return e, true
}

func (s *notifyConfigStore) publicSMTPView() notify.PublicSMTP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.SMTP
	return notify.PublicSMTP{
		Enabled: c.Enabled, Host: c.Host, Port: c.Port, From: c.From, User: c.User,
		PassSet: c.Pass != "", To: c.To, Security: c.Security, MinSeverity: c.MinSeverity,
	}
}

// handleChannelConfig is the generic GET/PUT admin surface every notification
// channel shares (#147 T4 — the decomposition plan's anticipated generic
// handler). GET returns the channel's redacted public view; PUT decodes the
// channel config, validates min_severity (plus any channel-specific
// preValidate), then under the store lock runs merge (preserve the write-only
// secret + apply channel defaults), assigns the channel's slot and persists.
//
// F-78: a PUT whose save failed must NOT apply or report success — it would
// work until the next restart and then vanish. The 500 is the contract.
func handleChannelConfig[T any](s *server, w http.ResponseWriter, r *http.Request,
	public func() any,
	minSeverity func(T) string,
	preValidate func(T) error,
	merge func(in T, cur notify.ChannelConfig) T,
	assign func(cfg *notify.ChannelConfig, in T)) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, public())
	case http.MethodPut:
		var in T
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !notify.ValidSeverity(minSeverity(in)) {
			writeError(w, http.StatusBadRequest, errors.New("invalid min_severity"))
			return
		}
		if preValidate != nil {
			if err := preValidate(in); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		s.notifyCfg.mu.Lock()
		in = merge(in, s.notifyCfg.cfg)
		assign(&s.notifyCfg.cfg, in)
		saveErr := s.notifyCfg.save()
		s.notifyCfg.mu.Unlock()
		if saveErr != nil {
			// F-78: do NOT apply or report success for a config that was not
			// written — it would work until the next restart and then vanish.
			writeError(w, http.StatusInternalServerError, errors.New("notification settings could not be saved"))
			return
		}
		s.notifyCfg.apply()
		writeJSON(w, http.StatusOK, public())
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSMTPConfig(w http.ResponseWriter, r *http.Request) {
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicSMTPView() },
		func(in notify.SMTPConfig) string { return in.MinSeverity },
		nil,
		func(in notify.SMTPConfig, cur notify.ChannelConfig) notify.SMTPConfig {
			if in.Pass == "" {
				in.Pass = cur.SMTP.Pass // preserve write-only secret
			}
			if in.Security == "" {
				in.Security = "starttls"
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "warning"
			}
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.SMTPConfig) { cfg.SMTP = in })
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
	ch := notify.BuildEmailChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
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
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicTwilio() },
		func(in notify.TwilioConfig) string { return in.MinSeverity },
		nil,
		func(in notify.TwilioConfig, cur notify.ChannelConfig) notify.TwilioConfig {
			if in.AuthToken == "" {
				in.AuthToken = cur.Twilio.AuthToken // preserve write-only secret
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "critical"
			}
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.TwilioConfig) { cfg.Twilio = in })
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
	ch := notify.BuildTwilioChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
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
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicNtfy() },
		func(in notify.NtfyConfig) string { return in.MinSeverity },
		func(in notify.NtfyConfig) error {
			// #101: the external stack watchdog's topic is off-limits for product
			// alerting — it must stay able to report the stack's own death, so the
			// two must never share a channel. Enforced when the deployment exports
			// WATCHDOG_NTFY_TOPIC; the first-customer gate script also checks
			// host-side against the watchdog's own env file.
			if wd := os.Getenv("WATCHDOG_NTFY_TOPIC"); wd != "" && in.Topic == wd {
				return errors.New("this topic is reserved for the stack watchdog — use a dedicated topic for platform alerts (watchdog independence)")
			}
			return nil
		},
		func(in notify.NtfyConfig, cur notify.ChannelConfig) notify.NtfyConfig {
			if in.Token == "" {
				in.Token = cur.Ntfy.Token // preserve write-only secret
			}
			if in.Server == "" {
				in.Server = "https://ntfy.sh"
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "critical"
			}
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.NtfyConfig) { cfg.Ntfy = in })
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
	ch := notify.BuildNtfyChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
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
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicSlack() },
		func(in notify.SlackConfig) string { return in.MinSeverity },
		nil,
		func(in notify.SlackConfig, cur notify.ChannelConfig) notify.SlackConfig {
			if in.WebhookURL == "" {
				in.WebhookURL = cur.Slack.WebhookURL // preserve write-only secret
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "warning"
			}
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.SlackConfig) { cfg.Slack = in })
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
	ch := notify.BuildSlackChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
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
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicPagerDuty() },
		func(in notify.PagerDutyConfig) string { return in.MinSeverity },
		nil,
		func(in notify.PagerDutyConfig, cur notify.ChannelConfig) notify.PagerDutyConfig {
			if in.RoutingKey == "" {
				in.RoutingKey = cur.PagerDuty.RoutingKey // preserve write-only secret
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "critical"
			}
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.PagerDutyConfig) { cfg.PagerDuty = in })
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
	ch := notify.BuildPagerDutyChannel(c, os.Getenv("PLATFORM_ENV"), os.Getenv("PLATFORM_REGION")).(interface{ Unguarded() notify.Channel }).Unguarded()
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
