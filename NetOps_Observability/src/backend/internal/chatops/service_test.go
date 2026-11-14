// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chatops

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/jwks"
)

const (
	testSecret = "8f742231b10e8888abcd99yyyzzz85a5"
	testBot    = "xoxb-1111-2222-SECRETBOTTOKEN"
	tenantA    = "t-alpha"
	tenantB    = "t-beta"
)

// harness wires a Service over a MemStore with recording fakes.
type harness struct {
	t       *testing.T
	store   *MemStore
	svc     *Service
	on      bool
	now     time.Time
	mu      sync.Mutex
	replies []string
	asked   []Question
	logs    []string
	audits  []string
	askErr  error
}

type recReplier struct{ h *harness }

func (r recReplier) Reply(_ context.Context, _ Connection, _ Inbound, text string) error {
	r.h.mu.Lock()
	defer r.h.mu.Unlock()
	r.h.replies = append(r.h.replies, text)
	return nil
}

type fakeVerifier struct {
	serviceURL string
	err        error
	gotAud     string
}

func (f *fakeVerifier) VerifyRS256(_, iss, aud string) (jwks.Claims, error) {
	f.gotAud = aud
	if f.err != nil {
		return jwks.Claims{}, f.err
	}
	if iss != BotFrameworkIssuer {
		return jwks.Claims{}, errors.New("issuer")
	}
	raw, _ := json.Marshal(map[string]string{"serviceurl": f.serviceURL})
	return jwks.Claims{Raw: raw}, nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, store: NewMemStore(), on: true, now: time.Unix(1_800_000_000, 0)}
	h.svc = New(Deps{
		Store:   h.store,
		Enabled: func() bool { return h.on },
		Asker: func(_ context.Context, q Question) (Answer, error) {
			h.mu.Lock()
			h.asked = append(h.asked, q)
			h.mu.Unlock()
			if h.askErr != nil {
				return Answer{}, h.askErr
			}
			return Answer{Text: "All quiet on " + q.Tenant, ConversationID: "conv-" + q.UserID,
				Citations: []Citation{{Label: "Incident 7", Href: "/app/incidents/7"}}}, nil
		},
		Teams:   &fakeVerifier{serviceURL: "https://smba.trafficmanager.net/emea/"},
		Slack:   recReplier{h},
		TeamsRe: recReplier{h},
		Authorize: func(w http.ResponseWriter, r *http.Request, admin bool) (Caller, bool) {
			c := Caller{Tenant: r.Header.Get("X-T"), Sub: r.Header.Get("X-Sub"), Person: r.Header.Get("X-Key") == "",
				Admin: r.Header.Get("X-Admin") == "1", Cross: r.Header.Get("X-Cross") == "1"}
			if admin && !c.Admin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Caller{}, false
			}
			return c, true
		},
		Audit: func(tenant, actor, action string, d map[string]any) {
			b, _ := json.Marshal(d)
			h.mu.Lock()
			h.audits = append(h.audits, tenant+" "+actor+" "+action+" "+string(b))
			h.mu.Unlock()
		},
		Log: func(level, msg string, f map[string]any) {
			b, _ := json.Marshal(f)
			h.mu.Lock()
			h.logs = append(h.logs, level+" "+msg+" "+string(b))
			h.mu.Unlock()
		},
		WriteJSON: func(w http.ResponseWriter, status int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v) // test helper
		},
		WriteError: func(w http.ResponseWriter, status int, err error) { http.Error(w, err.Error(), status) },
		Now:        func() time.Time { return h.now },
		QueueSize:  16,
	})
	return h
}

func (h *harness) connect(tenant string, p Platform, enabled bool) Connection {
	h.t.Helper()
	var in Input
	if p == Slack {
		in = Input{WorkspaceID: "T0ALPHA", SigningSecret: strings.Repeat("ab", 16), BotToken: testBot, Enabled: enabled, PublicURL: "https://correlix.example.com/"}
	} else {
		in = Input{WorkspaceID: "72f988bf-86f1-41af-91ab-2d7cd011db47", AppID: "11111111-2222-3333-4444-555555555555", AppPassword: "s3cret-app-password", Enabled: enabled}
	}
	c, err := Apply(p, Connection{}, false, in)
	if err != nil {
		h.t.Fatalf("apply: %v", err)
	}
	c.TenantID = tenant
	if err := h.store.PutConnection(context.Background(), tenant, c); err != nil {
		h.t.Fatalf("put: %v", err)
	}
	return c
}

// drain answers everything queued, synchronously.
func (h *harness) drain() {
	for {
		select {
		case j := <-h.svc.queue:
			h.svc.answer(context.Background(), j)
		default:
			return
		}
	}
}

func signSlack(body []byte, secret string, ts int64) http.Header {
	hd := http.Header{}
	tsS := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + tsS + ":"))
	mac.Write(body)
	hd.Set("X-Slack-Request-Timestamp", tsS)
	hd.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	hd.Set("Content-Type", "application/json")
	return hd
}

func slackMention(team, user, text, eventID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"type": "event_callback", "team_id": team, "event_id": eventID,
		"event": map[string]any{"type": "app_mention", "user": user, "text": "<@UBOT> " + text, "channel": "C1", "ts": "1.2"},
	})
	return b
}

func (h *harness) postSlack(c Connection, body []byte, hd http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/chatops/slack/"+c.WebhookToken, strings.NewReader(string(body)))
	for k, v := range hd {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	h.svc.HandleInbound(w, r)
	return w
}

func TestVerifySlack(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"type":"event_callback"}`)
	if err := VerifySlack(signSlack(body, testSecret, now.Unix()), body, testSecret, now); err != nil {
		t.Fatalf("a correctly signed request must verify: %v", err)
	}
	cases := map[string]http.Header{
		"wrong secret":     signSlack(body, "deadbeefdeadbeefdeadbeefdeadbeef", now.Unix()),
		"stale (replayed)": signSlack(body, testSecret, now.Add(-6*time.Minute).Unix()),
		"from the future":  signSlack(body, testSecret, now.Add(6*time.Minute).Unix()),
	}
	for name, hd := range cases {
		if err := VerifySlack(hd, body, testSecret, now); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: want ErrSignature, got %v", name, err)
		}
	}
	tampered := signSlack(body, testSecret, now.Unix())
	if err := VerifySlack(tampered, []byte(`{"type":"other"}`), testSecret, now); !errors.Is(err, ErrSignature) {
		t.Error("a body changed after signing must be refused")
	}
	if err := VerifySlack(signSlack(body, testSecret, now.Unix()), body, "", now); !errors.Is(err, ErrSignature) {
		t.Error("no stored secret must refuse, never accept")
	}
	noTS := http.Header{}
	noTS.Set("X-Slack-Signature", "v0=00")
	if err := VerifySlack(noTS, body, testSecret, now); !errors.Is(err, ErrSignature) {
		t.Error("a missing timestamp must be refused")
	}
}

func TestParseSlackPayloads(t *testing.T) {
	in, err := ParseSlack("application/json", slackMention("T0ALPHA", "U1", "what is going on?", "Ev1"))
	if err != nil || in.Kind != KindQuestion || in.Text != "what is going on?" || in.ThreadTS != "1.2" || in.Direct {
		t.Fatalf("mention: %+v %v", in, err)
	}
	bot, _ := json.Marshal(map[string]any{"type": "event_callback", "team_id": "T0ALPHA",
		"event": map[string]any{"type": "app_mention", "user": "U1", "bot_id": "B1", "text": "loop"}})
	if in, _ := ParseSlack("application/json", bot); in.Kind != KindIgnore {
		t.Error("a bot's own message must never be answered (loop guard)")
	}
	edit, _ := json.Marshal(map[string]any{"type": "event_callback", "team_id": "T0ALPHA",
		"event": map[string]any{"type": "message", "subtype": "message_changed", "user": "U1", "channel_type": "im"}})
	if in, _ := ParseSlack("application/json", edit); in.Kind != KindIgnore {
		t.Error("an edit must not be re-answered")
	}
	dm, _ := json.Marshal(map[string]any{"type": "event_callback", "team_id": "T0ALPHA", "event_id": "Ev2",
		"event": map[string]any{"type": "message", "user": "U1", "channel_type": "im", "channel": "D1", "text": "hi", "ts": "9.9"}})
	if in, _ := ParseSlack("application/json", dm); in.Kind != KindQuestion || !in.Direct {
		t.Errorf("a direct message is a question: %+v", in)
	}
	ch, _ := json.Marshal(map[string]any{"type": "url_verification", "challenge": "abc"})
	if in, _ := ParseSlack("application/json", ch); in.Kind != KindChallenge || in.Challenge != "abc" {
		t.Error("url_verification echoes the challenge")
	}
	form := url.Values{"command": {"/iris"}, "text": {"status"}, "team_id": {"T0ALPHA"}, "user_id": {"U1"},
		"channel_id": {"C1"}, "response_url": {"https://hooks.slack.com/commands/1/2"}, "trigger_id": {"tr1"}}
	in, err = ParseSlack("application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil || !in.Slash || in.Text != "status" || in.EventID != "cmd:tr1" {
		t.Fatalf("slash: %+v %v", in, err)
	}
	if AllowedResponseURL("https://evil.example.com/hook") || !AllowedResponseURL("https://hooks.slack.com/x") {
		t.Error("response_url must be hooks.slack.com only")
	}
}

// TestInboundIsClosedUnlessEverythingIsOn: the switch, the token, the platform
// and the connection's own toggle are each enough to answer 404 — and a bad
// signature is 401 with nothing queued.
func TestInboundIsClosedUnlessEverythingIsOn(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	body := slackMention("T0ALPHA", "U1", "hello", "Ev1")
	good := signSlack(body, c.SigningSecret, h.now.Unix())

	h.on = false
	if w := h.postSlack(c, body, good); w.Code != http.StatusNotFound {
		t.Errorf("switch off: want 404, got %d", w.Code)
	}
	h.on = true
	bad := c
	bad.WebhookToken = "0000000000000000"
	if w := h.postSlack(bad, body, good); w.Code != http.StatusNotFound {
		t.Errorf("unknown token: want 404, got %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/chatops/teams/"+c.WebhookToken, strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.svc.HandleInbound(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("a Slack token on the Teams path: want 404, got %d", w.Code)
	}
	if w := h.postSlack(c, body, signSlack(body, "deadbeefdeadbeefdeadbeefdeadbeef", h.now.Unix())); w.Code != http.StatusUnauthorized {
		t.Errorf("bad signature: want 401, got %d", w.Code)
	}
	if w := h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Add(-10*time.Minute).Unix())); w.Code != http.StatusUnauthorized {
		t.Errorf("replayed request: want 401, got %d", w.Code)
	}
	if len(h.svc.queue) != 0 {
		t.Fatal("nothing may be queued from a refused request")
	}
	off := h.connect(tenantB, Slack, false)
	if w := h.postSlack(off, body, signSlack(body, off.SigningSecret, h.now.Unix())); w.Code != http.StatusNotFound {
		t.Errorf("disabled connection: want 404, got %d", w.Code)
	}
}

func TestSlackChallengeAndWorkspaceBinding(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	ch, _ := json.Marshal(map[string]any{"type": "url_verification", "challenge": "c-123"})
	w := h.postSlack(c, ch, signSlack(ch, c.SigningSecret, h.now.Unix()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "c-123") {
		t.Fatalf("challenge: %d %s", w.Code, w.Body.String())
	}
	other := slackMention("T0OTHER", "U1", "hello", "Ev9")
	if w := h.postSlack(c, other, signSlack(other, c.SigningSecret, h.now.Unix())); w.Code != http.StatusOK || len(h.svc.queue) != 0 {
		t.Fatal("a message from another Slack workspace must not be answered")
	}
}

// TestUnlinkedUserGetsOnlyTheLinkPrompt: an unlinked chat account gets a link
// code and nothing else — the Asker is never called.
func TestUnlinkedUserGetsOnlyTheLinkPrompt(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	body := slackMention("T0ALPHA", "U1", "show me every incident", "Ev1")
	h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	h.drain()
	if len(h.asked) != 0 {
		t.Fatal("an unlinked chat user's question must never reach Iris")
	}
	if len(h.replies) != 1 || !strings.Contains(h.replies[0], "link this chat account") {
		t.Fatalf("want one link prompt, got %q", h.replies)
	}
	code := extractCode(t, h.replies[0])
	// The code redeems in tenant A only.
	if w := apiCall(h, http.MethodPost, "/api/chatops/link-code", `{"code":"`+code+`"}`, tenantB, "bob", false); w.Code != http.StatusNotFound {
		t.Errorf("a code from tenant A redeemed in tenant B: want 404, got %d", w.Code)
	}
	// The failed try did not spend it in A (B never saw it).
	if w := apiCall(h, http.MethodPost, "/api/chatops/link-code", `{"code":"`+strings.ToLower(code)+`"}`, tenantA, "alice", false); w.Code != http.StatusCreated {
		t.Fatalf("redeem in tenant A: %d %s", w.Code, w.Body.String())
	}
	// Pending: still not answered.
	body2 := slackMention("T0ALPHA", "U1", "now?", "Ev2")
	h.postSlack(c, body2, signSlack(body2, c.SigningSecret, h.now.Unix()))
	h.drain()
	if len(h.asked) != 0 || !strings.Contains(h.replies[len(h.replies)-1], "waiting for a workspace admin") {
		t.Fatalf("a pending link must not answer: asked=%d last=%q", len(h.asked), h.replies[len(h.replies)-1])
	}
}

func extractCode(t *testing.T, s string) string {
	t.Helper()
	i := strings.Index(s, "the code ")
	if i < 0 {
		t.Fatalf("no code in %q", s)
	}
	return s[i+9 : i+18]
}

func apiCall(h *harness, method, path, body, tenant, sub string, admin bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("X-T", tenant)
	r.Header.Set("X-Sub", sub)
	if admin {
		r.Header.Set("X-Admin", "1")
	}
	w := httptest.NewRecorder()
	h.svc.HandleAPI(w, r)
	return w
}

// linkApproved runs the whole flow: prompt → redeem by userSub → approve by admin.
func linkApproved(t *testing.T, h *harness, c Connection, chatUser, userSub, adminSub string) Link {
	t.Helper()
	body := slackMention(c.WorkspaceID, chatUser, "hi", "Ev-link-"+chatUser)
	h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	h.drain()
	code := extractCode(t, h.replies[len(h.replies)-1])
	w := apiCall(h, http.MethodPost, "/api/chatops/link-code", `{"code":"`+code+`"}`, c.TenantID, userSub, false)
	if w.Code != http.StatusCreated {
		t.Fatalf("redeem: %d %s", w.Code, w.Body.String())
	}
	var l Link
	_ = json.Unmarshal(w.Body.Bytes(), &l) // test decode
	if w := apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", c.TenantID, adminSub, true); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	return l
}

func TestApprovalRules(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	body := slackMention("T0ALPHA", "U1", "hi", "Ev1")
	h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	h.drain()
	code := extractCode(t, h.replies[0])
	w := apiCall(h, http.MethodPost, "/api/chatops/link-code", `{"code":"`+code+`"}`, tenantA, "alice", false)
	var l Link
	_ = json.Unmarshal(w.Body.Bytes(), &l) // test decode
	if w := apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", tenantA, "alice", false); w.Code != http.StatusForbidden {
		t.Errorf("a non-admin approving: want 403, got %d", w.Code)
	}
	if w := apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", tenantA, "alice", true); w.Code != http.StatusForbidden {
		t.Errorf("an admin approving a link to their OWN account: want 403, got %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", nil)
	r.Header.Set("X-T", tenantA)
	r.Header.Set("X-Sub", "apikey:ci")
	r.Header.Set("X-Admin", "1")
	r.Header.Set("X-Key", "1")
	kw := httptest.NewRecorder()
	h.svc.HandleAPI(kw, r)
	if kw.Code != http.StatusForbidden {
		t.Errorf("an API key approving: want 403, got %d", kw.Code)
	}
	if w := apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", tenantB, "root-b", true); w.Code != http.StatusNotFound {
		t.Errorf("another tenant's admin approving: want 404, got %d", w.Code)
	}
	if w := apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", tenantA, "carol", true); w.Code != http.StatusOK {
		t.Fatalf("another admin approving: %d %s", w.Code, w.Body.String())
	}
	if w := apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", tenantA, "carol", true); w.Code != http.StatusNotFound {
		t.Error("an approved link is not approved twice")
	}
	// The owner revokes their own link; a stranger cannot.
	if w := apiCall(h, http.MethodPost, "/api/chatops/me/"+l.ID+"/revoke", "", tenantA, "mallory", false); w.Code != http.StatusNotFound {
		t.Errorf("revoking someone else's link: want 404, got %d", w.Code)
	}
	if w := apiCall(h, http.MethodPost, "/api/chatops/me/"+l.ID+"/revoke", "", tenantA, "alice", false); w.Code != http.StatusOK {
		t.Errorf("revoking your own link: %d", w.Code)
	}
}

// TestLinkedUserIsAnsweredAsThemselvesInTheirTenant is the §3a core: the ask
// runs for the LINKED user in the CONNECTION's tenant — nothing from the
// request chooses either.
func TestLinkedUserIsAnsweredAsThemselvesInTheirTenant(t *testing.T) {
	h := newHarness(t)
	ca := h.connect(tenantA, Slack, true)
	cb := h.connect(tenantB, Slack, true) // same Slack workspace id, another tenant's app
	linkApproved(t, h, ca, "U1", "alice", "carol")
	linkApproved(t, h, cb, "U1", "bob", "dave")
	h.asked, h.replies = nil, nil

	body := slackMention("T0ALPHA", "U1", "what is going on?", "Ev-a")
	h.postSlack(ca, body, signSlack(body, ca.SigningSecret, h.now.Unix()))
	h.drain()
	if len(h.asked) != 1 || h.asked[0].Tenant != tenantA || h.asked[0].UserID != "alice" {
		t.Fatalf("tenant A's connection must ask as alice in A: %+v", h.asked)
	}
	if !strings.Contains(h.replies[0], "All quiet on "+tenantA) || strings.Contains(h.replies[0], tenantB) {
		t.Fatalf("reply carries another tenant: %q", h.replies[0])
	}
	if !strings.Contains(h.replies[0], "<https://correlix.example.com/app/incidents/7|Incident 7>") {
		t.Fatalf("citation must link into Correlix: %q", h.replies[0])
	}
	// The same chat user through tenant B's app is bob in B; B's answer never
	// mentions A.
	body = slackMention("T0ALPHA", "U1", "what is going on?", "Ev-b")
	h.postSlack(cb, body, signSlack(body, cb.SigningSecret, h.now.Unix()))
	h.drain()
	if h.asked[1].Tenant != tenantB || h.asked[1].UserID != "bob" {
		t.Fatalf("tenant B's connection must ask as bob in B: %+v", h.asked[1])
	}
	// A follow-up in the same thread carries the thread's conversation.
	body = slackMention("T0ALPHA", "U1", "and the second one?", "Ev-a2")
	h.postSlack(ca, body, signSlack(body, ca.SigningSecret, h.now.Unix()))
	h.drain()
	if h.asked[2].ConversationID != "conv-alice" {
		t.Errorf("follow-up should continue the thread's conversation, got %q", h.asked[2].ConversationID)
	}
	// Admin views are tenant-scoped.
	w := apiCall(h, http.MethodGet, "/api/chatops/links", "", tenantB, "dave", true)
	if strings.Contains(w.Body.String(), "alice") {
		t.Fatal("tenant B's admin sees tenant A's link")
	}
}

func TestDuplicateDeliveryIsAnsweredOnce(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	linkApproved(t, h, c, "U1", "alice", "carol")
	h.asked = nil
	body := slackMention("T0ALPHA", "U1", "status", "Ev-dup")
	hd := signSlack(body, c.SigningSecret, h.now.Unix())
	h.postSlack(c, body, hd)
	hd.Set("X-Slack-Retry-Num", "1")
	h.postSlack(c, body, hd)
	h.drain()
	if len(h.asked) != 1 {
		t.Fatalf("a retried delivery must be answered once, got %d", len(h.asked))
	}
}

func TestRateLimitsAndBounds(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	linkApproved(t, h, c, "U1", "alice", "carol")
	h.asked, h.replies = nil, nil
	for i := 0; i < 8; i++ {
		body := slackMention("T0ALPHA", "U1", "q", fmt.Sprintf("Ev-r%d", i))
		h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	}
	h.drain()
	// The link flow above used one of U1's six; five questions get through.
	if len(h.asked) != 5 {
		t.Errorf("per-user limit: %d asks reached Iris, want 5", len(h.asked))
	}
	if !strings.Contains(h.replies[len(h.replies)-1], "Too many questions") {
		t.Errorf("the over-limit reply says so: %q", h.replies[len(h.replies)-1])
	}
	h2 := newHarness(t)
	c2 := h2.connect(tenantA, Slack, true)
	linkApproved(t, h2, c2, "U2", "alice", "carol")
	h2.asked, h2.replies = nil, nil
	long := strings.Repeat("x", MaxQuestionChars+1)
	body := slackMention("T0ALPHA", "U2", long, "Ev-long")
	h2.postSlack(c2, body, signSlack(body, c2.SigningSecret, h2.now.Unix()))
	h2.drain()
	if len(h2.asked) != 0 || !strings.Contains(h2.replies[0], "too long") {
		t.Errorf("an oversized question must be refused before Iris: %q", h2.replies)
	}
}

func TestRefusalIsShownAndNotAnAnswer(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	linkApproved(t, h, c, "U1", "alice", "carol")
	h.replies = nil
	h.askErr = Refusal{Msg: "Your Correlix account can't use Iris from chat right now."}
	body := slackMention("T0ALPHA", "U1", "q", "Ev-ref")
	h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	h.drain()
	if len(h.replies) != 1 || !strings.Contains(h.replies[0], "can't use Iris from chat") {
		t.Fatalf("refusal: %q", h.replies)
	}
	h.askErr = errors.New("db: connection reset by peer at 10.1.2.3")
	body = slackMention("T0ALPHA", "U1", "q2", "Ev-err")
	h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	h.drain()
	if strings.Contains(h.replies[1], "10.1.2.3") || !strings.Contains(h.replies[1], "could not answer") {
		t.Fatalf("an internal error must not reach the chat: %q", h.replies[1])
	}
}

// TestSecretsAndQuestionsNeverReachLogsOrAudit drives every path and checks the
// signing secret, the bot token, the app password and the question text never
// appear in a log line or an audit record.
func TestSecretsAndQuestionsNeverReachLogsOrAudit(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Slack, true)
	tc := h.connect(tenantB, Teams, true)
	linkApproved(t, h, c, "U1", "alice", "carol")
	const q = "TOPSECRETQUESTION about payroll"
	body := slackMention("T0ALPHA", "U1", q, "Ev-s")
	h.postSlack(c, body, signSlack(body, c.SigningSecret, h.now.Unix()))
	h.postSlack(c, body, signSlack(body, "deadbeefdeadbeefdeadbeefdeadbeef", h.now.Unix())) // refused
	h.drain()
	w := apiCall(h, http.MethodPut, "/api/chatops/connections/slack",
		`{"workspace_id":"T0ALPHA","signing_secret":"`+strings.Repeat("cd", 16)+`","bot_token":"xoxb-9999-NEWSECRETTOKEN","enabled":true}`, tenantA, "carol", true)
	if w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	get := apiCall(h, http.MethodGet, "/api/chatops/connections", "", tenantA, "carol", true)
	all := strings.Join(h.logs, "\n") + strings.Join(h.audits, "\n") + w.Body.String() + get.Body.String()
	for _, secret := range []string{c.SigningSecret, testBot, strings.Repeat("cd", 16), "xoxb-9999-NEWSECRETTOKEN", tc.AppPassword, q} {
		if strings.Contains(all, secret) {
			t.Errorf("%q leaked into logs, audit or the API response", secret)
		}
	}
	if !strings.Contains(get.Body.String(), `"has_bot_token":true`) {
		t.Errorf("the admin view says a token is set without showing it: %s", get.Body.String())
	}
}

func TestConnectionAPIIsTenantScopedAndValidated(t *testing.T) {
	h := newHarness(t)
	h.connect(tenantA, Slack, true)
	if w := apiCall(h, http.MethodGet, "/api/chatops/connections", "", tenantB, "dave", true); strings.Contains(w.Body.String(), "T0ALPHA") {
		t.Fatal("tenant B sees tenant A's connection")
	}
	if w := apiCall(h, http.MethodDelete, "/api/chatops/connections/slack", "", tenantB, "dave", true); w.Code != http.StatusNotFound {
		t.Errorf("tenant B deleting A's connection: want 404, got %d", w.Code)
	}
	if w := apiCall(h, http.MethodGet, "/api/chatops/connections", "", tenantA, "alice", false); w.Code != http.StatusForbidden {
		t.Errorf("a non-admin reading connections: want 403, got %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/chatops/connections", nil)
	r.Header.Set("X-T", "")
	r.Header.Set("X-Admin", "1")
	r.Header.Set("X-Cross", "1")
	w := httptest.NewRecorder()
	h.svc.HandleAPI(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("the platform owner's all-tenants view must choose a workspace: got %d", w.Code)
	}
	bad := []string{
		`{"workspace_id":"nope","signing_secret":"` + strings.Repeat("ab", 16) + `","bot_token":"xoxb-1111-AAAAAAAAAA"}`,
		`{"workspace_id":"T0NEW","signing_secret":"not-hex!","bot_token":"xoxb-1111-AAAAAAAAAA"}`,
		`{"workspace_id":"T0NEW","signing_secret":"` + strings.Repeat("ab", 16) + `","bot_token":"xoxp-user-token"}`,
		`{"workspace_id":"T0NEW"}`,
		`{"workspace_id":"T0NEW","signing_secret":"` + strings.Repeat("ab", 16) + `","bot_token":"xoxb-1111-AAAAAAAAAA","public_url":"javascript:alert(1)"}`,
	}
	for _, b := range bad {
		if w := apiCall(h, http.MethodPut, "/api/chatops/connections/slack", b, tenantB, "dave", true); w.Code != http.StatusBadRequest {
			t.Errorf("want 400 for %s, got %d", b, w.Code)
		}
	}
	// Blank secrets on an update keep the stored ones.
	if w := apiCall(h, http.MethodPut, "/api/chatops/connections/slack", `{"workspace_id":"T0ALPHA","enabled":false}`, tenantA, "carol", true); w.Code != http.StatusOK {
		t.Fatalf("update keeping secrets: %d %s", w.Code, w.Body.String())
	}
	got, _, _ := h.store.GetConnection(context.Background(), tenantA, Slack)
	if got.BotToken != testBot || got.Enabled {
		t.Errorf("update must keep the token and apply the toggle: %+v", got)
	}
}

func TestTeamsInbound(t *testing.T) {
	h := newHarness(t)
	c := h.connect(tenantA, Teams, true)
	v := h.svc.d.Teams.(*fakeVerifier)
	activity := func(serviceURL, convType, user, id string) []byte {
		b, _ := json.Marshal(map[string]any{
			"type": "message", "id": id, "serviceUrl": serviceURL, "text": "<at>Iris</at> what changed?",
			"from":         map[string]any{"id": "29:abc", "aadObjectId": user, "name": "Alice"},
			"conversation": map[string]any{"id": "a:conv1", "conversationType": convType},
			"channelData":  map[string]any{"tenant": map[string]any{"id": c.WorkspaceID}},
		})
		return b
	}
	post := func(body []byte, auth string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/chatops/teams/"+c.WebhookToken, strings.NewReader(string(body)))
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		h.svc.HandleInbound(w, r)
		return w.Code
	}
	const su = "https://smba.trafficmanager.net/emea/"
	if code := post(activity(su, "personal", "aad-1", "m1"), ""); code != http.StatusUnauthorized {
		t.Errorf("no token: want 401, got %d", code)
	}
	if v.gotAud != "" {
		t.Error("the verifier must not even run without a bearer token")
	}
	if code := post(activity("https://smba.trafficmanager.net/other/", "personal", "aad-1", "m2"), "Bearer x"); code != http.StatusUnauthorized {
		t.Errorf("serviceUrl differing from the token's claim: want 401, got %d", code)
	}
	if v.gotAud != c.AppID {
		t.Errorf("the token's audience must be this bot (%s), checked %q", c.AppID, v.gotAud)
	}
	v.serviceURL = "https://evil.example.com/"
	if code := post(activity("https://evil.example.com/", "personal", "aad-1", "m3"), "Bearer x"); code != http.StatusUnauthorized {
		t.Errorf("a non-Bot-Framework serviceUrl: want 401, got %d", code)
	}
	v.serviceURL = su
	v.err = errors.New("expired")
	if code := post(activity(su, "personal", "aad-1", "m4"), "Bearer x"); code != http.StatusUnauthorized {
		t.Errorf("an invalid token: want 401, got %d", code)
	}
	v.err = nil
	if code := post(activity(su, "personal", "aad-1", "m5"), "Bearer x"); code != http.StatusOK {
		t.Fatalf("a valid activity: got %d", code)
	}
	h.drain()
	if len(h.asked) != 0 || !strings.Contains(h.replies[0], "link this chat account") {
		t.Fatalf("unlinked Teams user gets the prompt only: %q", h.replies)
	}
	// Link aad-1 → alice, approved by carol.
	code := extractCode(t, h.replies[0])
	w := apiCall(h, http.MethodPost, "/api/chatops/link-code", `{"code":"`+code+`"}`, tenantA, "alice", false)
	var l Link
	_ = json.Unmarshal(w.Body.Bytes(), &l) // test decode
	apiCall(h, http.MethodPost, "/api/chatops/links/"+l.ID+"/approve", "", tenantA, "carol", true)
	h.replies = nil
	post(activity(su, "channel", "aad-1", "m6"), "Bearer x")
	h.drain()
	if len(h.asked) != 0 || !strings.Contains(h.replies[0], "personal chat") {
		t.Fatalf("a channel question is redirected to a personal chat by default: %q", h.replies)
	}
	post(activity(su, "personal", "aad-1", "m7"), "Bearer x")
	h.drain()
	if len(h.asked) != 1 || h.asked[0].UserID != "alice" || h.asked[0].Text != "what changed?" {
		t.Fatalf("personal chat question: %+v", h.asked)
	}
}

func TestSlackPosterPrivacyDefault(t *testing.T) {
	var got []map[string]any
	var paths, auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m) // test server
		got = append(got, m)
		paths = append(paths, r.URL.Path)
		auths = append(auths, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"ok":true}`)) // test server
	}))
	defer srv.Close()
	p := SlackPoster{Client: srv.Client(), APIBase: srv.URL}
	c := Connection{Platform: Slack, BotToken: testBot, ChannelReplies: RepliesPrivate}
	in := Inbound{ChannelID: "C1", ThreadTS: "1.2", ChatUserID: "U1"}
	if err := p.Reply(context.Background(), c, in, "answer"); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/chat.postEphemeral" || got[0]["user"] != "U1" || got[0]["thread_ts"] != "1.2" {
		t.Errorf("a channel answer is ephemeral to the asker by default: %s %+v", paths[0], got[0])
	}
	if auths[0] != "Bearer "+testBot {
		t.Error("the bot token authenticates the call")
	}
	c.ChannelReplies = RepliesPublic
	_ = p.Reply(context.Background(), c, in, "answer") // checked below
	if paths[1] != "/chat.postMessage" || got[1]["thread_ts"] != "1.2" {
		t.Errorf("public replies go in the thread: %s %+v", paths[1], got[1])
	}
	in.Direct, c.ChannelReplies = true, RepliesPrivate
	_ = p.Reply(context.Background(), c, in, "answer") // checked below
	if paths[2] != "/chat.postMessage" {
		t.Errorf("a direct message is answered normally: %s", paths[2])
	}
	if err := p.Reply(context.Background(), c, Inbound{Slash: true, ResponseURL: "https://evil.example.com/x"}, "a"); err == nil {
		t.Error("a response_url off hooks.slack.com must be refused")
	}
}

func TestTeamsPosterTokenAndHostGuard(t *testing.T) {
	calls := 0
	tokSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil || r.Form.Get("scope") != "https://api.botframework.com/.default" || r.Form.Get("client_secret") != "pw" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`)) // test server
	}))
	defer tokSrv.Close()
	p := &TeamsPoster{Client: tokSrv.Client(), TokenURL: tokSrv.URL}
	c := Connection{TenantID: tenantA, AppID: "app", AppPassword: "pw"}
	for i := 0; i < 2; i++ {
		if tok, err := p.token(context.Background(), c); err != nil || tok != "tok-1" {
			t.Fatalf("token: %q %v", tok, err)
		}
	}
	if calls != 1 {
		t.Errorf("the bot token must be cached, fetched %d times", calls)
	}
	if err := p.Reply(context.Background(), c, Inbound{ServiceURL: "https://evil.example.com/"}, "x"); err == nil {
		t.Error("a reply to a non-Bot-Framework host must be refused")
	}
	for raw, want := range map[string]bool{
		"https://smba.trafficmanager.net/emea/": true, "https://europe.webchat.botframework.com/": true,
		"http://smba.trafficmanager.net/": false, "https://botframework.com.evil.io/": false,
		"https://user@smba.trafficmanager.net/": false, "https://smba.trafficmanager.net:8443/": false,
	} {
		if AllowedServiceURL(raw) != want {
			t.Errorf("AllowedServiceURL(%s) = %v", raw, !want)
		}
	}
}
