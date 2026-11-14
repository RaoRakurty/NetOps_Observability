// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

// teams.go — Microsoft Teams through the Bot Framework.
//
// Inbound: every activity carries "Authorization: Bearer <JWT>" signed by the
// Bot Framework. It is verified RS256 against the Bot Framework's published
// keys, with issuer https://api.botframework.com, THIS connection's bot app id
// as the audience, and its `serviceurl` claim equal to the activity's
// serviceUrl — the documented binding that stops a valid token for one
// conversation endpoint being replayed against another. The serviceUrl must
// also be a Microsoft Bot Framework host before anything is sent to it.
//
// Outbound: a client-credentials token for the bot (cached until shortly
// before it expires) and one POST to the conversation's reply endpoint.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/jwks"
)

// Bot Framework constants (Microsoft's published values).
const (
	BotFrameworkIssuer   = "https://api.botframework.com"
	BotFrameworkMetadata = "https://login.botframework.com/v1/.well-known/openidconfiguration"
	botFrameworkScope    = "https://api.botframework.com/.default"
	defaultAppTenant     = "botframework.com"
)

// JWTVerifier is the RS256 check against the Bot Framework's keys
// (*jwks.Cache in production).
type JWTVerifier interface {
	VerifyRS256(token, wantIssuer, wantAudience string) (jwks.Claims, error)
}

// AllowedServiceURL reports whether a Teams serviceUrl is a Microsoft Bot
// Framework endpoint (https, no credentials, a known host).
func AllowedServiceURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "smba.trafficmanager.net" || strings.HasSuffix(h, ".botframework.com") || h == "botframework.com"
}

// VerifyTeams checks the bearer token on a Teams activity and returns the
// verified service URL claim.
func VerifyTeams(v JWTVerifier, authHeader, appID string) (serviceURL string, err error) {
	if v == nil || appID == "" {
		return "", ErrSignature
	}
	tok, ok := strings.CutPrefix(strings.TrimSpace(authHeader), "Bearer ")
	if !ok || strings.TrimSpace(tok) == "" {
		return "", ErrSignature
	}
	claims, err := v.VerifyRS256(strings.TrimSpace(tok), BotFrameworkIssuer, appID)
	if err != nil {
		return "", ErrSignature
	}
	su, ok := claims.Claim("serviceurl")
	if !ok {
		return "", ErrSignature
	}
	return su, nil
}

var reTeamsAt = regexp.MustCompile(`(?s)<at[^>]*>.*?</at>`)
var reTags = regexp.MustCompile(`<[^>]{1,200}>`)

// ParseTeams reads a VERIFIED activity. verifiedServiceURL is the token's
// claim; an activity naming any other serviceUrl is refused.
func ParseTeams(body []byte, verifiedServiceURL string) (Inbound, error) {
	var a struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		ServiceURL string `json:"serviceUrl"`
		ChannelID  string `json:"channelId"`
		Text       string `json:"text"`
		From       struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			AADObjectID string `json:"aadObjectId"`
		} `json:"from"`
		Conversation struct {
			ID               string `json:"id"`
			ConversationType string `json:"conversationType"`
		} `json:"conversation"`
		ChannelData struct {
			Tenant struct {
				ID string `json:"id"`
			} `json:"tenant"`
		} `json:"channelData"`
	}
	if err := json.Unmarshal(body, &a); err != nil {
		return Inbound{}, fmt.Errorf("chatops: teams activity: %w", err)
	}
	if !strings.EqualFold(strings.TrimRight(a.ServiceURL, "/"), strings.TrimRight(verifiedServiceURL, "/")) {
		return Inbound{}, ErrSignature
	}
	if !AllowedServiceURL(a.ServiceURL) {
		return Inbound{}, ErrSignature
	}
	if a.Type != "message" || a.Conversation.ID == "" || a.ID == "" {
		return Inbound{Kind: KindIgnore}, nil // conversationUpdate, typing, reactions …
	}
	user := a.From.AADObjectID
	if user == "" {
		user = a.From.ID
	}
	text := reTeamsAt.ReplaceAllString(a.Text, "")
	text = strings.TrimSpace(reTags.ReplaceAllString(text, ""))
	return Inbound{
		Kind: KindQuestion, EventID: "teams:" + a.Conversation.ID + ":" + a.ID,
		WorkspaceID: a.ChannelData.Tenant.ID, ChatUserID: user, ChatName: a.From.Name,
		Text: text, Direct: a.Conversation.ConversationType == "" || a.Conversation.ConversationType == "personal",
		ServiceURL: a.ServiceURL, ConversationID: a.Conversation.ID, ActivityID: a.ID,
	}, nil
}

// TeamsPoster sends Teams replies with a cached bot token.
type TeamsPoster struct {
	Client *http.Client
	// TokenURL overrides the Entra token endpoint (tests only; "" = Microsoft).
	TokenURL string

	mu     sync.Mutex
	tokens map[string]cachedToken // tenant|appID → token
}

type cachedToken struct {
	value   string
	expires time.Time
}

func (p *TeamsPoster) token(ctx context.Context, c Connection) (string, error) {
	key := c.TenantID + "|" + c.AppID
	p.mu.Lock()
	if t, ok := p.tokens[key]; ok && time.Now().Before(t.expires) {
		p.mu.Unlock()
		return t.value, nil
	}
	p.mu.Unlock()
	tenant := c.AppTenant
	if tenant == "" {
		tenant = defaultAppTenant
	}
	endpoint := p.TokenURL
	if endpoint == "" {
		endpoint = "https://login.microsoftonline.com/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	}
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {c.AppID},
		"client_secret": {c.AppPassword}, "scope": {botFrameworkScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("chatops: teams token: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("chatops: teams token read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body can echo request details; only the status is reported.
		return "", fmt.Errorf("chatops: teams token refused (HTTP %d)", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("chatops: teams token unreadable")
	}
	life := time.Duration(tr.ExpiresIn)*time.Second - time.Minute
	if life < time.Minute {
		life = time.Minute
	}
	p.mu.Lock()
	if p.tokens == nil {
		p.tokens = map[string]cachedToken{}
	}
	p.tokens[key] = cachedToken{value: tr.AccessToken, expires: time.Now().Add(life)}
	p.mu.Unlock()
	return tr.AccessToken, nil
}

// Reply answers in, in its conversation.
func (p *TeamsPoster) Reply(ctx context.Context, c Connection, in Inbound, text string) error {
	if !AllowedServiceURL(in.ServiceURL) {
		return errors.New("chatops: teams serviceUrl is not a Bot Framework host")
	}
	tok, err := p.token(ctx, c)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(in.ServiceURL, "/") + "/v3/conversations/" + url.PathEscape(in.ConversationID) +
		"/activities/" + url.PathEscape(in.ActivityID)
	b, err := json.Marshal(map[string]any{"type": "message", "text": text, "textFormat": "markdown", "replyToId": in.ActivityID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("chatops: teams reply: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)); err != nil {
		return fmt.Errorf("chatops: teams reply read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("chatops: teams refused the reply (HTTP %d)", resp.StatusCode)
	}
	return nil
}
