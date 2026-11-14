// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

// slack.go — Slack inbound (Events API + slash command) and outbound replies.
//
// Inbound is signed with Slack's v0 scheme: HMAC-SHA256 over
// "v0:{timestamp}:{raw body}" keyed by the app's signing secret, compared in
// constant time, with a 5-minute window on the timestamp so a captured request
// cannot be replayed later. Event ids are additionally de-duplicated by the
// service (Slack retries a delivery it thinks failed).
//
// Outbound uses the app's bot token against slack.com/api only, and a slash
// command's response_url only when it is on hooks.slack.com.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SlackReplayWindow bounds how old a signed Slack request may be.
const SlackReplayWindow = 5 * time.Minute

// ErrSignature is every inbound authentication failure (one error: which check
// failed is logged, never told to the sender).
var ErrSignature = errors.New("chatops: request signature invalid")

// VerifySlack checks Slack's v0 signature over body at now.
func VerifySlack(h http.Header, body []byte, secret string, now time.Time) error {
	if secret == "" {
		return ErrSignature
	}
	tsHdr := h.Get("X-Slack-Request-Timestamp")
	ts, err := strconv.ParseInt(tsHdr, 10, 64)
	if err != nil {
		return ErrSignature
	}
	skew := now.Sub(time.Unix(ts, 0))
	if skew > SlackReplayWindow || skew < -SlackReplayWindow {
		return ErrSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + tsHdr + ":"))
	mac.Write(body)
	want := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(h.Get("X-Slack-Signature")), []byte(want)) {
		return ErrSignature
	}
	return nil
}

// InboundKind classifies a verified inbound request.
type InboundKind int

const (
	KindIgnore    InboundKind = iota // nothing to answer (bot message, edit, unknown event)
	KindChallenge                    // Slack url_verification
	KindQuestion                     // a person asked Iris something
)

// Inbound is one verified chat message, platform-neutral.
type Inbound struct {
	Kind        InboundKind
	Challenge   string
	EventID     string // de-duplication key ("" = none)
	WorkspaceID string
	AppID       string
	ChatUserID  string
	ChatName    string
	Text        string
	// Where to answer.
	ChannelID   string
	ThreadTS    string // Slack thread to reply in
	Direct      bool   // a one-to-one conversation with the bot
	ResponseURL string // Slack slash command
	Slash       bool
	// Teams
	ServiceURL     string
	ConversationID string
	ActivityID     string
}

var reSlackMention = regexp.MustCompile(`<@[A-Z0-9]+(?:\|[^>]*)?>`)

// ParseSlack reads a VERIFIED Slack body: a slash command (form-encoded) or an
// Events API envelope (JSON).
func ParseSlack(contentType string, body []byte) (Inbound, error) {
	if strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		v, err := url.ParseQuery(string(body))
		if err != nil {
			return Inbound{}, fmt.Errorf("chatops: slack form: %w", err)
		}
		if v.Get("command") == "" {
			return Inbound{Kind: KindIgnore}, nil // interactivity payloads are not ChatOps
		}
		return Inbound{
			Kind: KindQuestion, Slash: true,
			WorkspaceID: v.Get("team_id"), AppID: v.Get("api_app_id"),
			ChatUserID: v.Get("user_id"), ChatName: v.Get("user_name"),
			ChannelID: v.Get("channel_id"), Text: strings.TrimSpace(v.Get("text")),
			ResponseURL: v.Get("response_url"), EventID: "cmd:" + v.Get("trigger_id"),
			Direct: strings.HasPrefix(v.Get("channel_id"), "D"),
		}, nil
	}
	var env struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		TeamID    string `json:"team_id"`
		APIAppID  string `json:"api_app_id"`
		EventID   string `json:"event_id"`
		Event     struct {
			Type        string `json:"type"`
			Subtype     string `json:"subtype"`
			User        string `json:"user"`
			BotID       string `json:"bot_id"`
			Text        string `json:"text"`
			Channel     string `json:"channel"`
			ChannelType string `json:"channel_type"`
			TS          string `json:"ts"`
			ThreadTS    string `json:"thread_ts"`
		} `json:"event"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return Inbound{}, fmt.Errorf("chatops: slack event: %w", err)
	}
	switch env.Type {
	case "url_verification":
		return Inbound{Kind: KindChallenge, Challenge: env.Challenge}, nil
	case "event_callback":
	default:
		return Inbound{Kind: KindIgnore}, nil
	}
	ev := env.Event
	// Never answer a bot (ourselves included) or an edit/join/system message:
	// that is how chat bots loop.
	if ev.BotID != "" || ev.Subtype != "" || ev.User == "" {
		return Inbound{Kind: KindIgnore}, nil
	}
	direct := ev.Type == "message" && ev.ChannelType == "im"
	if ev.Type != "app_mention" && !direct {
		return Inbound{Kind: KindIgnore}, nil
	}
	thread := ev.ThreadTS
	if thread == "" {
		thread = ev.TS
	}
	return Inbound{
		Kind: KindQuestion, EventID: env.EventID,
		WorkspaceID: env.TeamID, AppID: env.APIAppID,
		ChatUserID: ev.User, ChannelID: ev.Channel, ThreadTS: thread, Direct: direct,
		Text: strings.TrimSpace(reSlackMention.ReplaceAllString(ev.Text, "")),
	}, nil
}

// slackAPIBase is where every bot-token call goes (overridable in tests only).
const slackAPIBase = "https://slack.com/api"

// SlackPoster sends Slack replies.
type SlackPoster struct {
	Client  *http.Client
	APIBase string // "" = slackAPIBase
}

// AllowedResponseURL reports whether a slash command's response_url is Slack's.
func AllowedResponseURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "hooks.slack.com" && u.User == nil
}

// Reply answers in.
func (p SlackPoster) Reply(ctx context.Context, c Connection, in Inbound, text string) error {
	if in.Slash {
		if !AllowedResponseURL(in.ResponseURL) {
			return errors.New("chatops: slack response_url is not hooks.slack.com")
		}
		// A slash command's answer is ephemeral: only the asker sees it.
		return p.post(ctx, in.ResponseURL, "", map[string]any{"response_type": "ephemeral", "text": text})
	}
	base := p.APIBase
	if base == "" {
		base = slackAPIBase
	}
	payload := map[string]any{"channel": in.ChannelID, "text": text, "unfurl_links": false, "unfurl_media": false}
	method := "chat.postMessage"
	if !in.Direct {
		payload["thread_ts"] = in.ThreadTS
		if c.ChannelReplies != RepliesPublic {
			// Private by default: in a channel only the asker sees the answer.
			method = "chat.postEphemeral"
			payload["user"] = in.ChatUserID
		}
	}
	return p.post(ctx, base+"/"+method, c.BotToken, payload)
}

func (p SlackPoster) post(ctx context.Context, endpoint, bearer string, payload map[string]any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return fmt.Errorf("chatops: slack post: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("chatops: slack read: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("chatops: slack answered HTTP %d", resp.StatusCode)
	}
	if bearer == "" {
		return nil // response_url answers "ok" as plain text
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("chatops: slack reply unreadable: %w", err)
	}
	if !out.OK {
		return fmt.Errorf("chatops: slack refused the reply: %s", out.Error)
	}
	return nil
}
