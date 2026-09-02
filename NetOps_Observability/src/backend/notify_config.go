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
//
// G10 — Teams + SNS joined the managed set. Both were env-only: main.go
// registered them straight from TEAMS_WEBHOOK_URL / SNS_* with no admin
// surface and, worse, no severity gate — every alert at every severity went
// out, and nothing could change without a restart. They now go through the
// same store as the other five, and migrateEnvChannels() carries an existing
// env deployment across ONCE (latched in cfg.EnvSeeded), logging the env path
// as deprecated. The latch is what makes it once-and-only-once: an operator
// who then disables Teams in the UI is not overruled at the next boot by a
// TEAMS_WEBHOOK_URL still sitting in .env.

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
		// G10: an EXISTING deployment already has a stored config, so the
		// first-run seed below never runs for it. Carry the legacy env-only
		// channels (Teams/SNS) across here instead — once, latched, persisted.
		if s.migrateEnvChannels() {
			if err := s.save(); err != nil {
				// Not fatal: the channel is live in memory for this process. But
				// the latch did not persist, so say so rather than fail silently.
				logError("notify.config", "env channel migration persist failed (will retry next boot)", errf(err))
			}
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
	// G10: Teams/SNS use the same one-shot migration on a first run as they do
	// on an upgrade — one code path, so "seeded" means the same thing either way.
	s.migrateEnvChannels()
}

// migrateEnvChannels carries the deprecated env wiring for the channels that
// used to be registered directly in main.go into the managed config. Returns
// true if the config changed (the caller persists).
//
// Contract: ONCE. cfg.EnvSeeded latches each channel the first time it is
// migrated and is persisted with the config, so the env can never re-assert
// itself over a later admin decision. A channel whose env is not set is NOT
// latched — nothing was migrated, so there is nothing to protect against.
func (s *notifyConfigStore) migrateEnvChannels() bool {
	changed := false
	if s.migrateTeamsFromEnv() {
		changed = true
	}
	if s.migrateSNSFromEnv() {
		changed = true
	}
	return changed
}

// migrateTeamsFromEnv seeds Teams from TEAMS_WEBHOOK_URL /
// FEATURE_TEAMS_NOTIFICATIONS (the exact pair main.go registered from).
func (s *notifyConfigStore) migrateTeamsFromEnv() bool {
	if s.cfg.IsEnvSeeded("teams") {
		return false
	}
	url := strings.TrimSpace(os.Getenv("TEAMS_WEBHOOK_URL"))
	if url == "" {
		return false // nothing to migrate; leave the latch open
	}
	if s.cfg.Teams.WebhookURL != "" {
		// Already managed (admin-configured). Latch so the env stops being
		// consulted, but change nothing the operator set.
		s.cfg.MarkEnvSeeded("teams")
		return true
	}
	if err := notify.ValidateWebhookURL(url); err != nil {
		// Deliberately NOT latched: this is an operator-fixable env defect and
		// it must stay loud every boot until the channel is configured properly.
		logError("notify.config", "TEAMS_WEBHOOK_URL is not a usable webhook url — Teams not migrated", errf(err))
		return false
	}
	s.cfg.Teams.WebhookURL = url
	s.cfg.Teams.Enabled = os.Getenv("FEATURE_TEAMS_NOTIFICATIONS") == "true"
	if s.cfg.Teams.MinSeverity == "" {
		s.cfg.Teams.MinSeverity = "warning"
	}
	s.cfg.MarkEnvSeeded("teams")
	logWarn("notify.config", "migrated Teams from the deprecated TEAMS_WEBHOOK_URL env wiring into managed notification channels — the env vars are now ignored; manage this channel in Settings → Notification channels", map[string]any{
		"channel": "teams", "enabled": s.cfg.Teams.Enabled, "min_severity": s.cfg.Teams.MinSeverity,
	})
	return true
}

// migrateSNSFromEnv seeds SNS from SNS_TOPIC_ARN / SNS_PHONE_NUMBERS /
// AWS_REGION / FEATURE_SNS_NOTIFICATIONS. The AWS KEYS ARE NOT MIGRATED — they
// stay in the environment by design (notify.SNSConfig), so nothing secret is
// copied into the config file.
func (s *notifyConfigStore) migrateSNSFromEnv() bool {
	if s.cfg.IsEnvSeeded("sns") {
		return false
	}
	arn := strings.TrimSpace(os.Getenv("SNS_TOPIC_ARN"))
	numbers := strings.TrimSpace(os.Getenv("SNS_PHONE_NUMBERS"))
	if arn == "" && numbers == "" {
		return false
	}
	if s.cfg.SNS.TopicARN != "" || s.cfg.SNS.PhoneNumbers != "" {
		s.cfg.MarkEnvSeeded("sns")
		return true
	}
	in := notify.SNSConfig{
		Enabled:      os.Getenv("FEATURE_SNS_NOTIFICATIONS") == "true",
		TopicARN:     arn,
		Region:       strings.TrimSpace(os.Getenv("AWS_REGION")),
		PhoneNumbers: numbers,
		MinSeverity:  "critical",
		// The env channel had NO scope filter and NO severity gate: it received
		// every alert. Preserve the destination behavior operators actually have
		// today ("all") rather than silently narrowing their paging on upgrade;
		// teams.md documents switching to "platform".
		Scope: "all",
	}
	if in.Region == "" {
		in.Region = notify.SNSRegionFromARN(arn)
	}
	if err := notify.ValidateSNSConfig(in); err != nil {
		logError("notify.config", "SNS env wiring is not a usable configuration — SNS not migrated", errf(err))
		return false
	}
	s.cfg.SNS = in
	s.cfg.MarkEnvSeeded("sns")
	logWarn("notify.config", "migrated Amazon SNS from the deprecated SNS_*/FEATURE_SNS_NOTIFICATIONS env wiring into managed notification channels — the destination is now managed in Settings → Notification channels (AWS credentials stay in the environment)", map[string]any{
		"channel": "sns", "enabled": in.Enabled, "region": in.Region,
		"min_severity": in.MinSeverity, "scope": in.Scope,
	})
	return true
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
	// Teams (G10). Replace() keys on Channel.Name(), so this also SUPERSEDES the
	// legacy ungated channel main.go may still have registered from env — the
	// managed, severity-gated one wins, and disabling here removes it outright.
	if s.cfg.Teams.Enabled && s.cfg.Teams.WebhookURL != "" {
		s.srv.notifier.Replace(notify.BuildTeamsChannel(s.cfg.Teams))
	} else {
		s.srv.notifier.Remove("teams")
	}
	// SNS (G10). Credentials come from the TRUSTED process environment, never
	// from the stored config: without them there is no channel to register.
	if ak, sk := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); s.cfg.SNS.Enabled &&
		ak != "" && sk != "" && (s.cfg.SNS.TopicARN != "" || s.cfg.SNS.PhoneNumbers != "") {
		s.srv.notifier.Replace(notify.BuildSNSChannel(s.cfg.SNS, ak, sk))
	} else {
		s.srv.notifier.Remove("sns")
	}
}

// snsCredentials reads the AWS credential pair from the process environment —
// the ONE place the SNS credential is sourced. Returns false when either half
// is missing, so callers refuse rather than sign with a partial credential.
func snsCredentials() (accessKey, secretKey string, ok bool) {
	accessKey = strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	secretKey = strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	return accessKey, secretKey, accessKey != "" && secretKey != ""
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

// ---- Teams handlers (G10) --------------------------------------------------

type publicTeams struct {
	Enabled     bool   `json:"enabled"`
	WebhookSet  bool   `json:"webhook_set"`
	MinSeverity string `json:"min_severity"`
}

// publicTeams redacts exactly the way publicSlack does: a Teams Incoming
// Webhook URL embeds a bearer token, so the whole URL is the secret. The API
// returns a boolean, never the value — on GET, on PUT, and on the test hook.
func (s *notifyConfigStore) publicTeams() publicTeams {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.Teams
	return publicTeams{c.Enabled, c.WebhookURL != "", c.MinSeverity}
}

// storedTeamsWebhook returns the currently stored webhook URL. Used ONLY to
// validate a PUT that omits it (write-only preservation) — never rendered.
func (s *notifyConfigStore) storedTeamsWebhook() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Teams.WebhookURL
}

func (s *server) handleTeamsConfig(w http.ResponseWriter, r *http.Request) {
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicTeams() },
		func(in notify.TeamsConfig) string { return in.MinSeverity },
		func(in notify.TeamsConfig) error {
			// An omitted webhook means "keep the stored one" (write-only
			// preservation). Validate the EFFECTIVE config — the supplied URL
			// or, when omitted, the stored one — so "enabled with no webhook
			// anywhere" is a 400 rather than a channel that silently never fires.
			if in.WebhookURL == "" {
				in.WebhookURL = s.notifyCfg.storedTeamsWebhook()
			}
			return notify.ValidateTeamsConfig(in)
		},
		func(in notify.TeamsConfig, cur notify.ChannelConfig) notify.TeamsConfig {
			if in.WebhookURL == "" {
				in.WebhookURL = cur.Teams.WebhookURL // preserve write-only secret
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "warning"
			}
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.TeamsConfig) { cfg.Teams = in })
}

func (s *server) handleTeamsTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.Teams
	s.notifyCfg.mu.RUnlock()
	if c.WebhookURL == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure a webhook url first"))
		return
	}
	ch := notify.BuildTeamsChannel(c).(interface{ Unguarded() notify.Channel }).Unguarded()
	if err := ch.Send(testAlert()); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// ---- Amazon SNS handlers (G10) ---------------------------------------------

type publicSNS struct {
	Enabled      bool   `json:"enabled"`
	TopicARN     string `json:"topic_arn"`
	Region       string `json:"region"`
	PhoneNumbers string `json:"phone_numbers"`
	MinSeverity  string `json:"min_severity"`
	Scope        string `json:"scope"`
	// CredentialsSet reports whether the deployment's AWS credential pair is
	// present in the environment. It is the ONLY thing the API ever says about
	// the credential — the keys are not stored here and are never returned.
	CredentialsSet bool `json:"credentials_set"`
}

func (s *notifyConfigStore) publicSNS() publicSNS {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg.SNS
	_, _, credsOK := snsCredentials()
	return publicSNS{
		Enabled: c.Enabled, TopicARN: c.TopicARN, Region: c.Region,
		PhoneNumbers: c.PhoneNumbers, MinSeverity: c.MinSeverity,
		Scope: notify.NormalizeSNSScope(c.Scope), CredentialsSet: credsOK,
	}
}

func (s *server) handleSNSConfig(w http.ResponseWriter, r *http.Request) {
	handleChannelConfig(s, w, r,
		func() any { return s.notifyCfg.publicSNS() },
		func(in notify.SNSConfig) string { return in.MinSeverity },
		notify.ValidateSNSConfig,
		func(in notify.SNSConfig, cur notify.ChannelConfig) notify.SNSConfig {
			// SNS carries no write-only secret of its own (the AWS keys live in
			// the environment), so there is nothing to preserve here — only
			// defaults to fill in.
			if in.Region == "" {
				in.Region = notify.SNSRegionFromARN(in.TopicARN)
			}
			if in.MinSeverity == "" {
				in.MinSeverity = "critical"
			}
			in.Scope = notify.NormalizeSNSScope(in.Scope)
			return in
		},
		func(cfg *notify.ChannelConfig, in notify.SNSConfig) { cfg.SNS = in })
}

func (s *server) handleSNSTest(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	s.notifyCfg.mu.RLock()
	c := s.notifyCfg.cfg.SNS
	s.notifyCfg.mu.RUnlock()
	if c.TopicARN == "" && c.PhoneNumbers == "" {
		writeError(w, http.StatusBadRequest, errors.New("configure a topic ARN or phone numbers first"))
		return
	}
	ak, sk, ok := snsCredentials()
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in the deployment environment"))
		return
	}
	// The test send is explicit, so it bypasses the severity gate — but NOT the
	// platform scope filter, which BuildSNSChannel may have wrapped outside the
	// gate. Build the sender directly so a scope-restricted channel can still be
	// proven to work end to end.
	ch := notify.BuildSNSChannel(notify.SNSConfig{
		TopicARN: c.TopicARN, Region: c.Region, PhoneNumbers: c.PhoneNumbers,
		MinSeverity: c.MinSeverity, Scope: "all",
	}, ak, sk).(interface{ Unguarded() notify.Channel }).Unguarded()
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
