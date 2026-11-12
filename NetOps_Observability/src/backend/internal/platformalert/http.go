// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"netops/backend/internal/alertwebhook"
)

// http.go — GET/PUT /api/platform/alerting/host-route and
// POST /api/platform/alerting/host-route/test.
//
// Platform-global (CLAUDE.md §3a rule 3): the integrator's Authz is
// requirePlatformAdmin — never requireAdmin, because a tenant/org admin holds
// administration:admin. Secrets are WRITE-ONLY: a GET answers "set: true",
// never the value; a PUT that omits a secret keeps the stored one; clearing is
// an explicit flag. Every change is audited BEFORE it is made (a change the
// audit trail cannot record does not happen), and the audit detail names what
// changed without carrying a secret, the topic (a credential) or a phone
// number (PII).

// Route paths.
const (
	Path     = "/api/platform/alerting/host-route"
	TestPath = "/api/platform/alerting/host-route/test"
)

// maxBody bounds a request (§9 / LLM04-style DoS hygiene): the whole record
// is well under 2 KiB.
const maxBody = 16 << 10

// Caller is the authorized principal.
type Caller struct {
	Subject string
	APIKey  bool // an API-key principal: refused for changes and tests
}

// AuditEntry is one record the handler asks the integrator to write.
type AuditEntry struct {
	Subject string
	Method  string
	Path    string
	Status  int
	Outcome string // allow | error
	Detail  map[string]any
}

// Deps are the API's injected collaborators. All are required.
type Deps struct {
	// Authz authorizes the platform administrator and has written the error
	// response when ok is false.
	Authz       func(w http.ResponseWriter, r *http.Request) (Caller, bool)
	AuditStrict func(e AuditEntry) error
	Audit       func(e AuditEntry)
	WriteJSON   func(w http.ResponseWriter, status int, v any)
	WriteErr    func(w http.ResponseWriter, status int, err error)
	Log         LogFunc
	Now         func() time.Time
	// IgnoredEnv lists retired environment variables that are SET in this
	// process (RetiredEnvSet), so the page can say plainly that they do nothing.
	IgnoredEnv []string
}

// API serves the page.
type API struct {
	store  *Store
	router *Router
	d      Deps
}

// NewAPI wires the handlers.
func NewAPI(store *Store, router *Router, d Deps) *API {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &API{store: store, router: router, d: d}
}

// ── wire shapes ─────────────────────────────────────────────────────────────

// NtfyView / SMSView / View are the GET shape. No secret value appears in any
// of them — only *_set booleans.
type NtfyView struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	// Topic is shown to a signed-in platform administrator (who must subscribe
	// a phone to it) and MASKED for an API-key principal: the topic is a
	// credential, and a key is a long-lived bearer secret that can leak into
	// scripts and CI logs. TopicSet always says whether one is configured.
	Topic    string `json:"topic"`
	TopicSet bool   `json:"topic_set"`
	TokenSet bool   `json:"token_set"`
	Tiers    Tiers  `json:"tiers"`
}

type SMSView struct {
	Enabled      bool     `json:"enabled"`
	AccountSID   string   `json:"account_sid"`
	AuthTokenSet bool     `json:"auth_token_set"`
	From         string   `json:"from"`
	To           []string `json:"to"`
	Tiers        Tiers    `json:"tiers"`
	MaxPerHour   int      `json:"max_per_hour"`
}

type View struct {
	Ntfy NtfyView `json:"ntfy"`
	SMS  SMSView  `json:"sms"`
	// PageRouted false = pages reach NOBODY (the banner condition).
	PageRouted    bool `json:"page_routed"`
	WarningRouted bool `json:"warning_routed"`
	// StoreStatus: "ok" | "stale" (re-read failing; last good settings in
	// force) | "cached" (never read since start-up; the on-host last-good copy
	// is in force) | "unreadable" (never read since start-up; nothing in force).
	StoreStatus string    `json:"store_status"`
	IgnoredEnv  []string  `json:"ignored_env"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	// SMSBudgetRemaining is the SMS allowance left this hour (-1 = SMS off).
	SMSBudgetRemaining int `json:"sms_budget_remaining"`
}

// NtfyUpdate / SMSUpdate / Update are the PUT shape. A secret field left empty
// keeps the stored value; Clear* removes it.
type NtfyUpdate struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	Topic      string `json:"topic"`
	Token      string `json:"token"`
	ClearToken bool   `json:"clear_token"`
	Tiers      Tiers  `json:"tiers"`
}

type SMSUpdate struct {
	Enabled        bool     `json:"enabled"`
	AccountSID     string   `json:"account_sid"`
	AuthToken      string   `json:"auth_token"`
	ClearAuthToken bool     `json:"clear_auth_token"`
	From           string   `json:"from"`
	To             []string `json:"to"`
	Tiers          Tiers    `json:"tiers"`
	MaxPerHour     int      `json:"max_per_hour"`
}

type Update struct {
	Ntfy NtfyUpdate `json:"ntfy"`
	SMS  SMSUpdate  `json:"sms"`
	// ReplaceUnreadable is the administrator's explicit consent to overwrite
	// a stored record that could not be read (ErrStoreUnreadable).
	ReplaceUnreadable bool `json:"replace_unreadable"`
}

// view renders the record in force. maskTopic hides the topic (API-key
// principals).
func (a *API) view(maskTopic bool) View {
	c := a.store.Current()
	ok, everRead := a.store.Health()
	status := "ok"
	switch {
	case !ok && a.store.FromCache():
		status = "cached"
	case !ok && everRead:
		status = "stale"
	case !ok:
		status = "unreadable"
	}
	ignored := a.d.IgnoredEnv
	if ignored == nil {
		ignored = []string{}
	}
	to := c.SMS.To
	if to == nil {
		to = []string{}
	}
	topic := c.Ntfy.Topic
	if maskTopic {
		topic = ""
	}
	return View{
		Ntfy: NtfyView{Enabled: c.Ntfy.Enabled, Server: c.Ntfy.Server, Topic: topic, TopicSet: c.Ntfy.Topic != "",
			TokenSet: c.Ntfy.Token != "", Tiers: c.Ntfy.Tiers},
		SMS: SMSView{Enabled: c.SMS.Enabled, AccountSID: c.SMS.AccountSID, AuthTokenSet: c.SMS.AuthToken != "",
			From: c.SMS.From, To: to, Tiers: c.SMS.Tiers, MaxPerHour: c.SMS.MaxPerHour},
		PageRouted: c.PageRouted(), WarningRouted: c.WarningRouted(),
		StoreStatus: status, IgnoredEnv: ignored,
		UpdatedBy: c.UpdatedBy, UpdatedAt: c.UpdatedAt,
		SMSBudgetRemaining: a.router.SMSBudgetRemaining(),
	}
}

// merge applies an update onto the record in force. Pure: no IO.
func merge(cur Config, in Update, by string, at time.Time) Config {
	next := cur
	next.Ntfy.Enabled = in.Ntfy.Enabled
	next.Ntfy.Server = in.Ntfy.Server
	next.Ntfy.Topic = in.Ntfy.Topic
	next.Ntfy.Tiers = in.Ntfy.Tiers
	switch {
	case in.Ntfy.ClearToken:
		next.Ntfy.Token = ""
	case in.Ntfy.Token != "":
		next.Ntfy.Token = in.Ntfy.Token
	}
	next.SMS.Enabled = in.SMS.Enabled
	next.SMS.AccountSID = in.SMS.AccountSID
	next.SMS.From = in.SMS.From
	next.SMS.To = append([]string(nil), in.SMS.To...)
	next.SMS.Tiers = in.SMS.Tiers
	next.SMS.MaxPerHour = in.SMS.MaxPerHour
	switch {
	case in.SMS.ClearAuthToken:
		next.SMS.AuthToken = ""
	case in.SMS.AuthToken != "":
		next.SMS.AuthToken = in.SMS.AuthToken
	}
	next.UpdatedBy, next.UpdatedAt = by, at.UTC()
	return next
}

// changeSummary names what changed for the audit trail and the log — never a
// secret, the topic, or a phone number.
func changeSummary(before, after Config) map[string]any {
	return map[string]any{
		"action":            "platform_alert_route_set",
		"ntfy_enabled":      after.Ntfy.Enabled,
		"ntfy_server":       after.Ntfy.Server,
		"ntfy_topic_change": before.Ntfy.Topic != after.Ntfy.Topic,
		"ntfy_token_change": before.Ntfy.Token != after.Ntfy.Token,
		"ntfy_tiers":        after.Ntfy.Tiers,
		"sms_enabled":       after.SMS.Enabled,
		"sms_token_change":  before.SMS.AuthToken != after.SMS.AuthToken,
		"sms_recipients":    len(after.SMS.To),
		"sms_tiers":         after.SMS.Tiers,
		"sms_max_per_hour":  after.SMS.MaxPerHour,
		"page_routed":       after.PageRouted(),
		"warning_routed":    after.WarningRouted(),
	}
}

// ── handlers ────────────────────────────────────────────────────────────────

// HandleRoute serves GET and PUT on Path.
func (a *API) HandleRoute(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.d.Authz(w, r)
	if !ok {
		return
	}
	if a.store == nil || a.router == nil {
		a.d.WriteErr(w, http.StatusServiceUnavailable, errors.New("platform alert settings are not available on this server"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.d.WriteJSON(w, http.StatusOK, a.view(caller.APIKey))
	case http.MethodPut:
		a.put(w, r, caller)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.d.WriteErr(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

func (a *API) put(w http.ResponseWriter, r *http.Request, caller Caller) {
	if caller.APIKey {
		a.d.WriteErr(w, http.StatusForbidden, errors.New("platform alert settings can only be changed from a signed-in session"))
		return
	}
	var in Update
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		a.d.WriteErr(w, http.StatusBadRequest, errors.New("the settings could not be read; reload the page and try again"))
		return
	}
	now := a.d.Now()
	before := a.store.Current()
	// Validate BEFORE auditing: a refused input is not a change, and the
	// validation sentence is what the administrator needs to see.
	proposed := merge(before, in, caller.Subject, now)
	if err := proposed.Validate(); err != nil {
		a.d.WriteErr(w, http.StatusBadRequest, err)
		return
	}
	entry := AuditEntry{Subject: caller.Subject, Method: r.Method, Path: r.URL.Path, Status: http.StatusOK,
		Outcome: "allow", Detail: changeSummary(before, proposed)}
	if err := a.d.AuditStrict(entry); err != nil {
		a.d.WriteErr(w, http.StatusInternalServerError, errors.New("the change was not made: the audit trail could not record it"))
		return
	}
	after, err := a.store.Update(in.ReplaceUnreadable, func(cur Config) (Config, error) {
		return merge(cur, in, caller.Subject, now), nil
	})
	if err != nil {
		fail := entry
		fail.Status, fail.Outcome = http.StatusInternalServerError, "error"
		status := http.StatusInternalServerError
		msg := errors.New("the platform alert settings could not be saved; nothing was changed")
		switch {
		case errors.Is(err, ErrStoreUnreadable):
			status, msg = http.StatusConflict, ErrStoreUnreadable
		case isValidationErr(err):
			// The record changed under us between the pre-check and the save
			// (another administrator) and the merge no longer validates.
			status, msg = http.StatusBadRequest, err
		}
		fail.Status = status
		fail.Detail = map[string]any{"action": "platform_alert_route_set", "error": safeErr(err)}
		a.d.Audit(fail)
		a.log("error", "platform alert settings were NOT saved", map[string]any{"error": safeErr(err), "by": caller.Subject})
		a.d.WriteErr(w, status, msg)
		return
	}
	a.log("info", "platform alert settings changed", changeSummary(before, after))
	if !after.PageRouted() {
		a.log("warn", "platform alert settings saved with NO channel for pages: page-tier platform alerts now reach nobody",
			map[string]any{"by": caller.Subject, "where": alertwebhook.GUILocation})
	}
	a.d.WriteJSON(w, http.StatusOK, a.view(caller.APIKey))
}

// isValidationErr reports one of this package's validation sentences.
func isValidationErr(err error) bool {
	for _, v := range []error{ErrNtfyServer, ErrNtfyServerPrivate, ErrNtfyTopic, ErrNtfyToken, ErrNtfyIncomplete, ErrSMSSID,
		ErrSMSAuthToken, ErrSMSNumber, ErrSMSRecipients, ErrSMSIncomplete, ErrSMSCap, ErrNoTierSelected, ErrSMSFromIsTarget} {
		if errors.Is(err, v) {
			return true
		}
	}
	return false
}

// safeErr renders a store error for a log/audit line. Store errors wrap
// backend and vault failures, none of which carry a secret value; the cap
// keeps a pathological driver message from flooding the trail.
func safeErr(err error) string {
	s := err.Error()
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// HandleTest serves POST TestPath {"channel": "ntfy"|"sms"}.
func (a *API) HandleTest(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.d.Authz(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.d.WriteErr(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	if a.store == nil || a.router == nil {
		a.d.WriteErr(w, http.StatusServiceUnavailable, errors.New("platform alert settings are not available on this server"))
		return
	}
	if caller.APIKey {
		a.d.WriteErr(w, http.StatusForbidden, errors.New("a test message can only be sent from a signed-in session"))
		return
	}
	var in struct {
		Channel string `json:"channel"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil ||
		(in.Channel != alertwebhook.ChannelNtfy && in.Channel != alertwebhook.ChannelSMS) {
		a.d.WriteErr(w, http.StatusBadRequest, errors.New(`send {"channel": "ntfy"} or {"channel": "sms"}`))
		return
	}
	// A test sends a real message (and an SMS costs money): audited first.
	entry := AuditEntry{Subject: caller.Subject, Method: r.Method, Path: r.URL.Path, Status: http.StatusOK,
		Outcome: "allow", Detail: map[string]any{"action": "platform_alert_route_test", "channel": in.Channel}}
	if err := a.d.AuditStrict(entry); err != nil {
		a.d.WriteErr(w, http.StatusInternalServerError, errors.New("the test was not sent: the audit trail could not record it"))
		return
	}
	res := a.router.Test(in.Channel)
	a.log("info", "platform alert test message", map[string]any{"channel": res.Channel, "verdict": string(res.Verdict), "by": caller.Subject})
	// 200 with the verdict in the body: "the provider refused" is an answer to
	// show, not a failure of this request.
	a.d.WriteJSON(w, http.StatusOK, res)
}

func (a *API) log(level, msg string, f map[string]any) {
	if a.d.Log != nil {
		a.d.Log(level, msg, f)
	}
}
