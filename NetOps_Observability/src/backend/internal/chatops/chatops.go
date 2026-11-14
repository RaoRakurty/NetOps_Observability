// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package chatops is Iris in Slack and Microsoft Teams (tracker 337 N-I6).
//
// A workspace admin connects the workspace's OWN chat app (a Slack app or a
// Teams bot registration). People then ask Iris in that chat; the answer is
// built by the same conversation engine as /api/ai/ask, AS the Correlix user
// the chat account is linked to — that user's tenant and permissions, never
// more. Nothing in this package can change anything: there is no write action
// from chat.
//
// The chain, end to end:
//
//  1. Inbound POST /api/chatops/{slack|teams}/{token}. The opaque token names
//     one connection, and with it the tenant — the request never chooses a
//     tenant. Unknown token, a disabled connection or the platform switch off
//     are the same 404.
//  2. The platform's own signature is verified BEFORE the body is read as
//     anything: Slack's v0 HMAC over the timestamp and body (5-minute replay
//     window), Teams' Bot Framework RS256 JWT (issuer, this bot as audience,
//     and the serviceurl claim equal to the activity's serviceUrl).
//  3. The chat user is looked up in the connection's tenant. An unlinked user
//     gets ONE reply: a short-lived link code and where to enter it. A pending
//     link says it is waiting; nothing else is answered.
//  4. A linked, approved user's question runs through Deps.Asker as that user.
//     The account is re-read on every question (disabled, moved or the
//     platform owner → refused): platform-admin powers never reach chat.
//  5. The reply carries the answer text and its citations as links into the
//     Correlix UI. In a channel it is visible only to the asker unless the
//     admin chose otherwise: a shared channel can hold people who may not see
//     the asker's data.
//
// Every step is audited without the question text.
package chatops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Platform is a chat service Iris can answer in.
type Platform string

const (
	Slack Platform = "slack"
	Teams Platform = "teams"
)

// ParsePlatform accepts exactly the two supported platforms.
func ParsePlatform(s string) (Platform, bool) {
	switch Platform(strings.ToLower(strings.TrimSpace(s))) {
	case Slack:
		return Slack, true
	case Teams:
		return Teams, true
	}
	return "", false
}

// ChannelReplies says who sees an answer asked in a shared channel.
type ChannelReplies string

const (
	// RepliesPrivate (the default): in a channel, only the asker sees the
	// answer (Slack ephemeral; Teams asks for a personal chat instead).
	RepliesPrivate ChannelReplies = "private"
	// RepliesPublic posts the answer in the channel thread for everyone in it.
	RepliesPublic ChannelReplies = "public"
)

// Connection is one tenant's chat app on one platform (at most one per
// platform per tenant). Secret fields hold PLAINTEXT only in memory; the
// Postgres store seals them and the API never returns them.
type Connection struct {
	TenantID string
	Platform Platform
	// WorkspaceID binds inbound messages to the workspace the admin connected:
	// Slack's team id (T… / E…), or the Microsoft Entra tenant id a Teams bot
	// serves (channelData.tenant.id). A message from another workspace is
	// refused even with a valid signature.
	WorkspaceID string
	// AppID: Teams — the bot's app id, the JWT audience (required). Slack — the
	// api_app_id, checked when set.
	AppID string
	// AppTenant: Teams only — the Entra tenant whose token endpoint issues the
	// bot's outbound token ("" = botframework.com, the multi-tenant default).
	AppTenant string
	// WebhookToken is the opaque path segment of this connection's inbound URL.
	WebhookToken string
	// PublicURL is the Correlix address citations link to ("" = labels only).
	PublicURL      string
	ChannelReplies ChannelReplies
	Enabled        bool

	SigningSecret string // Slack signing secret
	BotToken      string // Slack bot token (xoxb-…)
	AppPassword   string // Teams bot client secret

	UpdatedBy string
	UpdatedAt time.Time
}

// LinkStatus is a chat link's lifecycle.
type LinkStatus string

const (
	LinkPending  LinkStatus = "pending"
	LinkApproved LinkStatus = "approved"
	LinkRevoked  LinkStatus = "revoked"
)

// Link maps one chat account to one Correlix user in one tenant. Only an
// APPROVED link answers; approval is a workspace admin's, and never the linked
// user's own.
type Link struct {
	TenantID    string     `json:"tenant_id"`
	ID          string     `json:"id"`
	Platform    Platform   `json:"platform"`
	WorkspaceID string     `json:"workspace_id"`
	ChatUserID  string     `json:"chat_user_id"`
	ChatName    string     `json:"chat_name"`
	UserID      string     `json:"user_id"`
	Status      LinkStatus `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	DecidedAt   time.Time  `json:"decided_at,omitempty"`
}

// LinkCode is the one-time code an unlinked chat user is given. Only its hash
// is stored; the code itself exists in the chat reply and nowhere else.
type LinkCode struct {
	TenantID    string
	CodeHash    string
	Platform    Platform
	WorkspaceID string
	ChatUserID  string
	ChatName    string
	ExpiresAt   time.Time
}

// Errors the store and service share.
var (
	ErrNotFound  = errors.New("chatops: not found")
	ErrLinked    = errors.New("chatops: this chat account already has a link")
	ErrSelf      = errors.New("chatops: a link to your own account is approved by another admin")
	ErrNotLinked = errors.New("chatops: not linked")
)

// Store is where connections, links and codes live. tenant always comes from
// the server (the authenticated principal, or the connection a token named) —
// never from a request body. ConnectionByToken is the ONE cross-tenant read: an
// inbound request carries no tenant until its token is resolved.
type Store interface {
	ConnectionByToken(ctx context.Context, token string) (Connection, bool, error)
	Connections(ctx context.Context, tenant string) ([]Connection, error)
	GetConnection(ctx context.Context, tenant string, p Platform) (Connection, bool, error)
	PutConnection(ctx context.Context, tenant string, c Connection) error
	DeleteConnection(ctx context.Context, tenant string, p Platform) (bool, error)

	// ActiveLink returns the chat account's pending or approved link.
	ActiveLink(ctx context.Context, tenant string, p Platform, workspace, chatUser string) (Link, bool, error)
	Links(ctx context.Context, tenant string) ([]Link, error)
	UserLinks(ctx context.Context, tenant, userID string) ([]Link, error)
	// PutCode replaces the chat account's outstanding code.
	PutCode(ctx context.Context, tenant string, c LinkCode) error
	// RedeemCode turns an unexpired code into a PENDING link for userID and
	// spends the code. ErrNotFound for an unknown or expired code (one error:
	// which it was is not said), ErrLinked when the chat account already has a
	// pending or approved link.
	RedeemCode(ctx context.Context, tenant, codeHash, userID string, now time.Time) (Link, error)
	// DecideLink approves a pending link or revokes a pending/approved one.
	// ErrSelf when the decider is the linked user and approve is true.
	DecideLink(ctx context.Context, tenant, id, decidedBy string, approve bool, now time.Time) (Link, error)
}

// NormTenant is the one tenant normalisation every store path uses.
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// codeAlphabet has no 0/O, 1/I/L: a code is read off a chat screen and typed.
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// CodeTTL is how long a link code can be redeemed.
const CodeTTL = 15 * time.Minute

// NewCode returns a fresh 8-character link code formatted ABCD-EFGH.
func NewCode() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("chatops: code: %w", err)
	}
	out := make([]byte, 0, 9)
	for i, v := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(v)%len(codeAlphabet)])
	}
	return string(out), nil
}

// HashCode normalises a typed code (case, spaces, dashes) and hashes it, bound
// to the tenant so one tenant's hash never names another's code.
func HashCode(tenant, code string) string {
	norm := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r == '-' || r == ' ':
			return -1
		}
		return r
	}, strings.TrimSpace(code))
	sum := sha256.Sum256([]byte("chatops-link-code\x00" + NormTenant(tenant) + "\x00" + norm))
	return hex.EncodeToString(sum[:])
}

// NewToken returns an opaque webhook token (32 hex chars).
func NewToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("chatops: token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// NewID returns a random UUID v4 string.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("chatops: id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

var (
	reSlackTeam   = regexp.MustCompile(`^[TE][A-Z0-9]{2,20}$`)
	reSlackApp    = regexp.MustCompile(`^A[A-Z0-9]{2,20}$`)
	reSlackSecret = regexp.MustCompile(`^[a-f0-9]{16,128}$`)
	reSlackBot    = regexp.MustCompile(`^xoxb-[A-Za-z0-9-]{10,200}$`)
	reUUID        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reChatUser    = regexp.MustCompile(`^[A-Za-z0-9:._@-]{1,128}$`)
)

// Input is what an admin submits for a connection. Blank secrets keep the
// stored ones; on a NEW connection they are required.
type Input struct {
	WorkspaceID    string `json:"workspace_id"`
	AppID          string `json:"app_id"`
	AppTenant      string `json:"app_tenant"`
	PublicURL      string `json:"public_url"`
	ChannelReplies string `json:"channel_replies"`
	Enabled        bool   `json:"enabled"`
	SigningSecret  string `json:"signing_secret"`
	BotToken       string `json:"bot_token"`
	AppPassword    string `json:"app_password"`
	RotateToken    bool   `json:"rotate_token"`
}

// Apply validates in and merges it over prev (zero for a new connection),
// returning the connection to store. Every error is an operator sentence.
func Apply(p Platform, prev Connection, exists bool, in Input) (Connection, error) {
	c := prev
	c.Platform = p
	c.WorkspaceID = strings.TrimSpace(in.WorkspaceID)
	c.AppID = strings.TrimSpace(in.AppID)
	c.AppTenant = strings.TrimSpace(in.AppTenant)
	c.Enabled = in.Enabled
	switch ChannelReplies(strings.TrimSpace(in.ChannelReplies)) {
	case "", RepliesPrivate:
		c.ChannelReplies = RepliesPrivate
	case RepliesPublic:
		c.ChannelReplies = RepliesPublic
	default:
		return Connection{}, errors.New("channel replies must be private or public")
	}
	pub, err := cleanPublicURL(in.PublicURL)
	if err != nil {
		return Connection{}, err
	}
	c.PublicURL = pub
	sign, bot, pass := strings.TrimSpace(in.SigningSecret), strings.TrimSpace(in.BotToken), strings.TrimSpace(in.AppPassword)
	switch p {
	case Slack:
		if !reSlackTeam.MatchString(c.WorkspaceID) {
			return Connection{}, errors.New("the Slack workspace id starts with T or E, for example T0123ABCD")
		}
		if c.AppID != "" && !reSlackApp.MatchString(c.AppID) {
			return Connection{}, errors.New("the Slack app id starts with A, for example A0123ABCD")
		}
		if c.AppTenant != "" {
			return Connection{}, errors.New("the app tenant is for Teams only")
		}
		if sign != "" {
			if !reSlackSecret.MatchString(sign) {
				return Connection{}, errors.New("the signing secret is the hexadecimal value from the app's Basic Information page")
			}
			c.SigningSecret = sign
		}
		if bot != "" {
			if !reSlackBot.MatchString(bot) {
				return Connection{}, errors.New("the bot token starts with xoxb-")
			}
			c.BotToken = bot
		}
		if pass != "" {
			return Connection{}, errors.New("the app password is for Teams only")
		}
		if c.SigningSecret == "" || c.BotToken == "" {
			return Connection{}, errors.New("a Slack connection needs both the signing secret and the bot token")
		}
		c.AppPassword = ""
	case Teams:
		if !reUUID.MatchString(c.WorkspaceID) {
			return Connection{}, errors.New("the Microsoft tenant id is a GUID, for example 72f988bf-86f1-41af-91ab-2d7cd011db47")
		}
		if !reUUID.MatchString(c.AppID) {
			return Connection{}, errors.New("the bot's app id is a GUID from its Azure Bot registration")
		}
		if c.AppTenant != "" && !reUUID.MatchString(c.AppTenant) && c.AppTenant != "botframework.com" {
			return Connection{}, errors.New("the app tenant is empty (multi-tenant bot) or the bot's Microsoft tenant GUID")
		}
		if pass != "" {
			if len(pass) < 8 || len(pass) > 256 || strings.ContainsAny(pass, "\r\n\t") {
				return Connection{}, errors.New("the app password is the client secret value from the bot's registration")
			}
			c.AppPassword = pass
		}
		if sign != "" || bot != "" {
			return Connection{}, errors.New("the signing secret and bot token are for Slack only")
		}
		if c.AppPassword == "" {
			return Connection{}, errors.New("a Teams connection needs the bot's app password")
		}
		c.SigningSecret, c.BotToken = "", ""
	default:
		return Connection{}, errors.New("unknown chat platform")
	}
	if !exists || c.WebhookToken == "" || in.RotateToken {
		tok, err := NewToken()
		if err != nil {
			return Connection{}, err
		}
		c.WebhookToken = tok
	}
	return c, nil
}

func cleanPublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || len(raw) > 200 {
		return "", errors.New("the Correlix address is a plain http(s) address, for example https://correlix.example.com")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// ValidChatUser reports whether a platform user id is safe to store.
func ValidChatUser(id string) bool { return reChatUser.MatchString(id) }

// CleanName bounds a chat display name to printable text for the admin view.
func CleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}
