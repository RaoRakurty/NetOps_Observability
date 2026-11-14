// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

// service.go — the inbound endpoints, the bounded answer queue and the admin /
// user API. The package owns the protocol and the state machine; the server
// injects everything that touches the rest of Correlix (Deps): who the caller
// is, the platform switch, the ask itself and the audit trail.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/ratelimit"
)

// Question is one approved chat user's question, handed to Deps.Asker.
type Question struct {
	Tenant         string
	UserID         string
	Platform       Platform
	Text           string
	ConversationID string // the thread's Iris conversation, "" = start one
}

// Refusal is an Asker error whose message is safe to show in the chat.
type Refusal struct{ Msg string }

func (r Refusal) Error() string { return r.Msg }

// Replier sends one reply on one platform.
type Replier interface {
	Reply(ctx context.Context, c Connection, in Inbound, text string) error
}

// Caller is the authenticated Correlix principal behind an API call.
type Caller struct {
	Tenant string
	Sub    string
	Cross  bool // platform owner's all-tenants view
	Person bool // a human session (not an API key)
	Admin  bool // workspace admin (administration:admin)
}

// Deps is everything the service needs from the server.
type Deps struct {
	Store   Store
	Enabled func() bool // the Features-page switch "Iris in Slack and Teams"
	Asker   func(ctx context.Context, q Question) (Answer, error)
	Teams   JWTVerifier
	Slack   Replier
	TeamsRe Replier
	// Authorize resolves the caller; admin=true requires a workspace admin. It
	// writes the refusal itself and returns false.
	Authorize  func(w http.ResponseWriter, r *http.Request, admin bool) (Caller, bool)
	Audit      func(tenant, actor, action string, detail map[string]any)
	Log        func(level, msg string, fields map[string]any)
	WriteJSON  func(w http.ResponseWriter, status int, v any)
	WriteError func(w http.ResponseWriter, status int, err error)
	Now        func() time.Time

	PerUserPerMin int // questions per chat user per minute (default 6)
	PerConnPerMin int // questions per connection per minute (default 60)
	QueueSize     int // answers waiting for a worker (default 64)
	AnswerTimeout time.Duration
}

// MaxQuestionChars bounds a chat question (LLM04).
const MaxQuestionChars = 2000

const maxInboundBody = 64 << 10

type job struct {
	conn Connection
	in   Inbound
}

// Service is Iris in chat.
type Service struct {
	d       Deps
	limiter *ratelimit.Limiter
	queue   chan job

	mu      sync.Mutex
	seen    map[string]time.Time // inbound event id → first seen (de-duplication)
	threads map[string]thread    // chat thread → Iris conversation
}

type thread struct {
	conv string
	at   time.Time
}

const (
	seenTTL    = 15 * time.Minute
	seenMax    = 8192
	threadTTL  = 8 * time.Hour
	threadsMax = 4096
)

// New builds the service. Run must be started for answers to be sent.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.PerUserPerMin <= 0 {
		d.PerUserPerMin = 6
	}
	if d.PerConnPerMin <= 0 {
		d.PerConnPerMin = 60
	}
	if d.QueueSize <= 0 {
		d.QueueSize = 64
	}
	if d.AnswerTimeout <= 0 {
		d.AnswerTimeout = 3 * time.Minute
	}
	if d.Log == nil {
		d.Log = func(string, string, map[string]any) {}
	}
	if d.Audit == nil {
		d.Audit = func(string, string, string, map[string]any) {}
	}
	return &Service{d: d, limiter: ratelimit.New(), queue: make(chan job, d.QueueSize),
		seen: map[string]time.Time{}, threads: map[string]thread{}}
}

// Run answers queued questions until ctx ends. Start one or more.
func (s *Service) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-s.queue:
			s.answer(ctx, j)
		}
	}
}

// ---- inbound ---------------------------------------------------------------

// HandleInbound serves POST /api/chatops/{slack|teams}/{token}.
func (s *Service) HandleInbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/chatops/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	p, ok := ParsePlatform(parts[0])
	if !ok || parts[0] != string(p) {
		http.NotFound(w, r)
		return
	}
	// The switch off, an unknown token, another platform's token and a
	// disabled connection are all the same 404: nothing is revealed.
	if s.d.Enabled == nil || !s.d.Enabled() {
		http.NotFound(w, r)
		return
	}
	conn, found, err := s.d.Store.ConnectionByToken(r.Context(), parts[1])
	if err != nil {
		s.d.Log("error", "connection lookup failed", map[string]any{"error": err.Error()})
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found || conn.Platform != p || !conn.Enabled {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInboundBody))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var in Inbound
	switch p {
	case Slack:
		if err := VerifySlack(r.Header, body, conn.SigningSecret, s.d.Now()); err != nil {
			s.reject(conn, "slack signature")
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		in, err = ParseSlack(r.Header.Get("Content-Type"), body)
	case Teams:
		var su string
		su, err = VerifyTeams(s.d.Teams, r.Header.Get("Authorization"), conn.AppID)
		if err != nil {
			s.reject(conn, "teams token")
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
		in, err = ParseTeams(body, su)
		if errors.Is(err, ErrSignature) {
			s.reject(conn, "teams service url")
			http.Error(w, "signature verification failed", http.StatusUnauthorized)
			return
		}
	}
	if err != nil {
		http.Error(w, "unreadable request", http.StatusBadRequest)
		return
	}
	switch in.Kind {
	case KindChallenge:
		s.d.WriteJSON(w, http.StatusOK, map[string]string{"challenge": in.Challenge})
		return
	case KindIgnore:
		w.WriteHeader(http.StatusOK)
		return
	}
	// The workspace (and, for Slack when set, the app) the admin connected — a
	// validly signed message from anywhere else is not this tenant's.
	if in.WorkspaceID != conn.WorkspaceID || (p == Slack && conn.AppID != "" && in.AppID != conn.AppID) || !ValidChatUser(in.ChatUserID) {
		s.reject(conn, "workspace mismatch")
		w.WriteHeader(http.StatusOK)
		return
	}
	if !s.firstSight(conn.TenantID + "|" + in.EventID) {
		w.WriteHeader(http.StatusOK) // a platform retry of something already queued
		return
	}
	select {
	case s.queue <- job{conn: conn, in: in}:
		if in.Slash {
			s.d.WriteJSON(w, http.StatusOK, map[string]string{"response_type": "ephemeral", "text": "Iris is looking into it…"})
			return
		}
	default:
		s.d.Log("warn", "answer queue full — question dropped", map[string]any{"tenant": conn.TenantID, "platform": string(p)})
		if in.Slash {
			s.d.WriteJSON(w, http.StatusOK, map[string]string{"response_type": "ephemeral", "text": "Iris is busy right now — try again in a minute."})
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Service) reject(c Connection, why string) {
	s.d.Log("warn", "inbound chat request refused", map[string]any{"tenant": c.TenantID, "platform": string(c.Platform), "reason": why})
}

func (s *Service) firstSight(key string) bool {
	if strings.HasSuffix(key, "|") {
		return true // no id to de-duplicate on
	}
	now := s.d.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if at, ok := s.seen[key]; ok && now.Sub(at) < seenTTL {
		return false
	}
	if len(s.seen) >= seenMax {
		for k, at := range s.seen {
			if now.Sub(at) >= seenTTL {
				delete(s.seen, k)
			}
		}
		if len(s.seen) >= seenMax {
			s.seen = map[string]time.Time{}
		}
	}
	s.seen[key] = now
	return true
}

// ---- answering ---------------------------------------------------------------

func (s *Service) answer(parent context.Context, j job) {
	ctx, cancel := context.WithTimeout(parent, s.d.AnswerTimeout)
	defer cancel()
	c, in := j.conn, j.in
	outcome := "answered"
	reply := func(text string) {
		var err error
		if c.Platform == Slack {
			err = s.d.Slack.Reply(ctx, c, in, text)
		} else {
			err = s.d.TeamsRe.Reply(ctx, c, in, text)
		}
		if err != nil {
			s.d.Log("error", "chat reply failed", map[string]any{"tenant": c.TenantID, "platform": string(c.Platform), "error": err.Error()})
		}
	}
	defer func() {
		// The audit line never carries the question or the answer.
		s.d.Audit(c.TenantID, string(c.Platform)+":"+in.ChatUserID, "chatops_question",
			map[string]any{"platform": string(c.Platform), "workspace_id": c.WorkspaceID, "chat_user_id": in.ChatUserID, "outcome": outcome})
	}()

	userKey := c.TenantID + "|" + string(c.Platform) + "|" + in.WorkspaceID + "|" + in.ChatUserID
	if !s.limiter.AllowN("u|"+userKey, s.d.PerUserPerMin) || !s.limiter.AllowN("c|"+c.TenantID+"|"+string(c.Platform), s.d.PerConnPerMin) {
		outcome = "rate_limited"
		reply(Plain(c.Platform, "Too many questions — wait a minute and ask again."))
		return
	}
	link, linked, err := s.d.Store.ActiveLink(ctx, c.TenantID, c.Platform, in.WorkspaceID, in.ChatUserID)
	if err != nil {
		outcome = "error"
		s.d.Log("error", "link lookup failed", map[string]any{"tenant": c.TenantID, "error": err.Error()})
		reply(Plain(c.Platform, "Iris could not check your chat account just now — try again shortly."))
		return
	}
	if !linked {
		outcome = "unlinked"
		reply(s.linkPrompt(ctx, c, in))
		return
	}
	if link.Status != LinkApproved {
		outcome = "pending"
		reply(Plain(c.Platform, "Your chat account's link to Correlix is waiting for a workspace admin to approve it."))
		return
	}
	if !in.Direct && !in.Slash && c.Platform == Teams && c.ChannelReplies != RepliesPublic {
		outcome = "private_only"
		reply(Plain(c.Platform, "To keep your network data private, ask me in a personal chat with Iris."))
		return
	}
	text := strings.TrimSpace(in.Text)
	if text == "" {
		outcome = "help"
		reply(Plain(c.Platform, "Ask me about your network — for example: what is going on right now?"))
		return
	}
	if len([]rune(text)) > MaxQuestionChars {
		outcome = "too_long"
		reply(Plain(c.Platform, "That question is too long — keep it under 2000 characters."))
		return
	}
	tkey := threadKey(link, in)
	ans, err := s.d.Asker(ctx, Question{Tenant: c.TenantID, UserID: link.UserID, Platform: c.Platform, Text: text, ConversationID: s.conversation(tkey)})
	var refusal Refusal
	switch {
	case errors.As(err, &refusal):
		outcome = "refused"
		reply(Plain(c.Platform, refusal.Msg))
		return
	case err != nil:
		outcome = "error"
		s.d.Log("error", "chat answer failed", map[string]any{"tenant": c.TenantID, "error": err.Error()})
		reply(Plain(c.Platform, "Iris could not answer that just now — try again shortly."))
		return
	}
	s.remember(tkey, ans.ConversationID)
	reply(Render(c.Platform, ans, c.PublicURL))
}

// linkPrompt issues a fresh code for an unlinked chat account.
func (s *Service) linkPrompt(ctx context.Context, c Connection, in Inbound) string {
	code, err := NewCode()
	if err == nil {
		err = s.d.Store.PutCode(ctx, c.TenantID, LinkCode{
			TenantID: c.TenantID, CodeHash: HashCode(c.TenantID, code), Platform: c.Platform,
			WorkspaceID: in.WorkspaceID, ChatUserID: in.ChatUserID, ChatName: CleanName(in.ChatName),
			ExpiresAt: s.d.Now().Add(CodeTTL),
		})
	}
	if err != nil {
		s.d.Log("error", "link code not issued", map[string]any{"tenant": c.TenantID, "error": err.Error()})
		return Plain(c.Platform, "Iris could not start linking your chat account just now — try again shortly.")
	}
	return Plain(c.Platform, "To ask Iris here, link this chat account to your Correlix account: in Correlix open Iris → Settings → "+
		"step 7, \"Iris in Slack and Teams\", and enter the code "+code+" within 15 minutes. A workspace admin then approves the link.")
}

func threadKey(l Link, in Inbound) string {
	switch {
	case in.ConversationID != "":
		return l.ID + "|" + in.ConversationID
	case in.Direct:
		return l.ID + "|" + in.ChannelID
	default:
		return l.ID + "|" + in.ChannelID + "|" + in.ThreadTS
	}
}

func (s *Service) conversation(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.threads[key]
	if !ok || s.d.Now().Sub(t.at) > threadTTL {
		return ""
	}
	return t.conv
}

func (s *Service) remember(key, conv string) {
	if conv == "" {
		return
	}
	now := s.d.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.threads) >= threadsMax {
		for k, t := range s.threads {
			if now.Sub(t.at) > threadTTL {
				delete(s.threads, k)
			}
		}
		if len(s.threads) >= threadsMax {
			s.threads = map[string]thread{}
		}
	}
	s.threads[key] = thread{conv: conv, at: now}
}

// ---- admin + user API --------------------------------------------------------

// connectionView is a connection as the admin page sees it: never a secret.
type connectionView struct {
	Platform         Platform       `json:"platform"`
	WorkspaceID      string         `json:"workspace_id"`
	AppID            string         `json:"app_id"`
	AppTenant        string         `json:"app_tenant,omitempty"`
	PublicURL        string         `json:"public_url"`
	ChannelReplies   ChannelReplies `json:"channel_replies"`
	Enabled          bool           `json:"enabled"`
	HasSigningSecret bool           `json:"has_signing_secret"`
	HasBotToken      bool           `json:"has_bot_token"`
	HasAppPassword   bool           `json:"has_app_password"`
	WebhookURL       string         `json:"webhook_url"`
	UpdatedBy        string         `json:"updated_by"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

func viewOf(c Connection) connectionView {
	return connectionView{
		Platform: c.Platform, WorkspaceID: c.WorkspaceID, AppID: c.AppID, AppTenant: c.AppTenant,
		PublicURL: c.PublicURL, ChannelReplies: c.ChannelReplies, Enabled: c.Enabled,
		HasSigningSecret: c.SigningSecret != "", HasBotToken: c.BotToken != "", HasAppPassword: c.AppPassword != "",
		WebhookURL: "/api/chatops/" + string(c.Platform) + "/" + c.WebhookToken,
		UpdatedBy:  c.UpdatedBy, UpdatedAt: c.UpdatedAt,
	}
}

// HandleAPI serves the admin and user endpoints:
//
//	GET    /api/chatops/connections            workspace admin
//	PUT    /api/chatops/connections/{platform} workspace admin
//	DELETE /api/chatops/connections/{platform} workspace admin
//	GET    /api/chatops/links                  workspace admin
//	POST   /api/chatops/links/{id}/approve     workspace admin (never for their own account)
//	POST   /api/chatops/links/{id}/revoke      workspace admin
//	POST   /api/chatops/link-code              any person in a workspace
//	GET    /api/chatops/me                     any person in a workspace
//	POST   /api/chatops/me/{id}/revoke         the linked person
func (s *Service) HandleAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/chatops/"), "/")
	seg := strings.Split(path, "/")
	switch {
	case seg[0] == "connections":
		s.apiConnections(w, r, seg)
	case seg[0] == "links":
		s.apiLinks(w, r, seg)
	case path == "link-code":
		s.apiLinkCode(w, r)
	case seg[0] == "me":
		s.apiMe(w, r, seg)
	default:
		http.NotFound(w, r)
	}
}

func (s *Service) caller(w http.ResponseWriter, r *http.Request, admin bool) (Caller, bool) {
	c, ok := s.d.Authorize(w, r, admin)
	if !ok {
		return Caller{}, false
	}
	if c.Cross || c.Tenant == "" {
		s.d.WriteError(w, http.StatusBadRequest, errors.New("chat connections belong to one workspace — choose a workspace first"))
		return Caller{}, false
	}
	return c, true
}

func (s *Service) apiConnections(w http.ResponseWriter, r *http.Request, seg []string) {
	c, ok := s.caller(w, r, true)
	if !ok {
		return
	}
	ctx := r.Context()
	if len(seg) == 1 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		conns, err := s.d.Store.Connections(ctx, c.Tenant)
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("the chat connections could not be read"))
			return
		}
		views := make([]connectionView, 0, len(conns))
		for _, cn := range conns {
			views = append(views, viewOf(cn))
		}
		s.d.WriteJSON(w, http.StatusOK, map[string]any{"switch_on": s.d.Enabled != nil && s.d.Enabled(), "connections": views})
		return
	}
	p, ok := ParsePlatform(seg[1])
	if !ok || len(seg) != 2 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var in Input
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
			s.d.WriteError(w, http.StatusBadRequest, errors.New("the connection could not be read"))
			return
		}
		prev, exists, err := s.d.Store.GetConnection(ctx, c.Tenant, p)
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("the chat connection could not be read"))
			return
		}
		next, err := Apply(p, prev, exists, in)
		if err != nil {
			s.d.WriteError(w, http.StatusBadRequest, err)
			return
		}
		next.TenantID, next.UpdatedBy, next.UpdatedAt = c.Tenant, c.Sub, s.d.Now().UTC()
		if err := s.d.Store.PutConnection(ctx, c.Tenant, next); err != nil {
			s.d.Log("error", "connection save failed", map[string]any{"tenant": c.Tenant, "error": err.Error()})
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("the chat connection could not be saved"))
			return
		}
		s.d.Audit(c.Tenant, c.Sub, "chatops_connection_saved", map[string]any{"platform": string(p), "enabled": next.Enabled,
			"secrets_changed": in.SigningSecret != "" || in.BotToken != "" || in.AppPassword != "", "token_rotated": in.RotateToken || !exists})
		s.d.WriteJSON(w, http.StatusOK, viewOf(next))
	case http.MethodDelete:
		gone, err := s.d.Store.DeleteConnection(ctx, c.Tenant, p)
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("the chat connection could not be removed"))
			return
		}
		if !gone {
			http.NotFound(w, r)
			return
		}
		s.d.Audit(c.Tenant, c.Sub, "chatops_connection_removed", map[string]any{"platform": string(p)})
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Service) apiLinks(w http.ResponseWriter, r *http.Request, seg []string) {
	c, ok := s.caller(w, r, true)
	if !ok {
		return
	}
	ctx := r.Context()
	if len(seg) == 1 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		links, err := s.d.Store.Links(ctx, c.Tenant)
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("the chat links could not be read"))
			return
		}
		s.d.WriteJSON(w, http.StatusOK, map[string]any{"links": links})
		return
	}
	if len(seg) != 3 || r.Method != http.MethodPost || (seg[2] != "approve" && seg[2] != "revoke") {
		http.NotFound(w, r)
		return
	}
	approve := seg[2] == "approve"
	if approve && !c.Person {
		s.d.WriteError(w, http.StatusForbidden, errors.New("a chat link is approved by a person, not an API key"))
		return
	}
	l, err := s.d.Store.DecideLink(ctx, c.Tenant, seg[1], c.Sub, approve, s.d.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, ErrSelf):
		s.d.WriteError(w, http.StatusForbidden, errors.New("another workspace admin approves a link to your own account"))
		return
	case err != nil:
		s.d.WriteError(w, http.StatusInternalServerError, errors.New("the chat link could not be updated"))
		return
	}
	s.d.Audit(c.Tenant, c.Sub, "chatops_link_"+seg[2], map[string]any{"link_id": l.ID, "platform": string(l.Platform), "linked_user": l.UserID})
	s.d.WriteJSON(w, http.StatusOK, l)
}

func (s *Service) apiLinkCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.caller(w, r, false)
	if !ok {
		return
	}
	if !c.Person {
		s.d.WriteError(w, http.StatusForbidden, errors.New("a chat account is linked by a person, not an API key"))
		return
	}
	// Guessing codes is bounded per person.
	if !s.limiter.AllowN("code|"+c.Tenant+"|"+c.Sub, 10) {
		s.d.WriteError(w, http.StatusTooManyRequests, errors.New("too many attempts — wait a minute"))
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil || len(strings.TrimSpace(body.Code)) > 16 {
		s.d.WriteError(w, http.StatusBadRequest, errors.New("enter the code Iris gave you in the chat"))
		return
	}
	l, err := s.d.Store.RedeemCode(r.Context(), c.Tenant, HashCode(c.Tenant, body.Code), c.Sub, s.d.Now())
	switch {
	case errors.Is(err, ErrNotFound):
		s.d.WriteError(w, http.StatusNotFound, errors.New("that code is unknown or has expired — ask Iris in the chat for a new one"))
		return
	case errors.Is(err, ErrLinked):
		s.d.WriteError(w, http.StatusConflict, errors.New("that chat account already has a link — a workspace admin can revoke it first"))
		return
	case err != nil:
		s.d.WriteError(w, http.StatusInternalServerError, errors.New("the link could not be created"))
		return
	}
	s.d.Audit(c.Tenant, c.Sub, "chatops_link_requested", map[string]any{"link_id": l.ID, "platform": string(l.Platform)})
	s.d.WriteJSON(w, http.StatusCreated, l)
}

func (s *Service) apiMe(w http.ResponseWriter, r *http.Request, seg []string) {
	c, ok := s.caller(w, r, false)
	if !ok {
		return
	}
	switch {
	case len(seg) == 1 && r.Method == http.MethodGet:
		links, err := s.d.Store.UserLinks(r.Context(), c.Tenant, c.Sub)
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("your chat links could not be read"))
			return
		}
		s.d.WriteJSON(w, http.StatusOK, map[string]any{"links": links})
	case len(seg) == 3 && seg[2] == "revoke" && r.Method == http.MethodPost:
		mine, err := s.d.Store.UserLinks(r.Context(), c.Tenant, c.Sub)
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("your chat links could not be read"))
			return
		}
		owned := false
		for _, l := range mine {
			owned = owned || l.ID == seg[1]
		}
		if !owned {
			http.NotFound(w, r)
			return
		}
		l, err := s.d.Store.DecideLink(r.Context(), c.Tenant, seg[1], c.Sub, false, s.d.Now())
		if errors.Is(err, ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.d.WriteError(w, http.StatusInternalServerError, errors.New("the link could not be revoked"))
			return
		}
		s.d.Audit(c.Tenant, c.Sub, "chatops_link_revoked_by_owner", map[string]any{"link_id": l.ID})
		s.d.WriteJSON(w, http.StatusOK, l)
	default:
		http.NotFound(w, r)
	}
}
