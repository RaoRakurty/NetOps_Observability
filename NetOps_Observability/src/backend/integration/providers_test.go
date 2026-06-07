package integration

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func req(headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhook", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestRegistry_Defaults(t *testing.T) {
	r := DefaultRegistry()
	for _, typ := range []string{"servicenow", "jira", "pagerduty", "slack"} {
		p, ok := r.Get(typ)
		if !ok || p.Type() != typ {
			t.Fatalf("provider %q not registered", typ)
		}
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unknown provider should not resolve")
	}
	if len(r.Types()) != 4 {
		t.Fatalf("expected 4 providers, got %d", len(r.Types()))
	}
}

func TestServiceNow_VerifyAndNormalize(t *testing.T) {
	p := NewServiceNowProvider()
	body := []byte(`{"number":"INC0010","sys_id":"abc","state":"6","sys_mod_count":5,"assigned_to":"jdoe","sys_updated_by":"jdoe","sys_updated_on":"2026-06-03 21:00:00","event_id":"d1"}`)
	if err := p.VerifyWebhook(req(map[string]string{headerWebhookSecret: "s3cret"}), body, "s3cret"); err != nil {
		t.Fatalf("valid secret should pass: %v", err)
	}
	if err := p.VerifyWebhook(req(map[string]string{headerWebhookSecret: "wrong"}), body, "s3cret"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong secret must fail, got %v", err)
	}
	evs, err := p.Normalize("acme", body)
	if err != nil || len(evs) != 1 {
		t.Fatalf("normalize: err=%v n=%d", err, len(evs))
	}
	e := evs[0]
	if e.ExternalID != "INC0010" || e.ExternalSeq != 5 || e.ExternalState != "resolved" || e.Type != EventResolved || e.ProviderEvtID != "d1" || e.Assignee != "jdoe" {
		t.Fatalf("unexpected SN event: %+v", e)
	}
}

func TestJira_VerifyAndNormalize(t *testing.T) {
	p := NewJiraProvider()
	body := []byte(`{"webhookEvent":"jira:issue_updated","timestamp":1700000000000,"issue":{"id":"10001","key":"NOC-1","fields":{"status":{"name":"In Progress"},"assignee":{"displayName":"Jane"}}},"changelog":{"id":"99999"}}`)
	// SR-020: pin "now" near the body's event timestamp so the replay window passes.
	timeNow = func() time.Time { return time.Unix(1700000000, 0) }
	defer func() { timeNow = time.Now }()
	sig := "sha256=" + hmacSHA256Hex([]byte("whk"), body)
	if err := p.VerifyWebhook(req(map[string]string{"X-Hub-Signature": sig}), body, "whk"); err != nil {
		t.Fatalf("valid jira sig should pass: %v", err)
	}
	if err := p.VerifyWebhook(req(map[string]string{"X-Hub-Signature": sig + "00"}), body, "whk"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("tampered jira sig must fail")
	}
	// SR-020: a validly-signed request replayed long after its event time is rejected.
	timeNow = func() time.Time { return time.Unix(1700000000, 0).Add(2 * time.Hour) }
	if err := p.VerifyWebhook(req(map[string]string{"X-Hub-Signature": sig}), body, "whk"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("replayed (stale) jira request must be rejected")
	}
	timeNow = func() time.Time { return time.Unix(1700000000, 0) }
	evs, _ := p.Normalize("acme", body)
	e := evs[0]
	if e.ExternalID != "NOC-1" || e.ExternalSeq != 99999 || e.ExternalState != "In Progress" || e.Assignee != "Jane" || e.Type != EventAcknowledged {
		t.Fatalf("unexpected Jira event: %+v", e)
	}
	// Comment webhook → distinct type.
	cbody := []byte(`{"webhookEvent":"comment_created","timestamp":1700000005000,"issue":{"id":"10001","key":"NOC-1","fields":{"status":{"name":"In Progress"}}},"comment":{"id":"55","body":"on it","author":{"displayName":"Jane"}}}`)
	cevs, _ := p.Normalize("acme", cbody)
	if cevs[0].Type != EventCommentAdded || cevs[0].Comment != "on it" {
		t.Fatalf("expected comment event, got %+v", cevs[0])
	}
}

func TestPagerDuty_VerifyAndNormalize(t *testing.T) {
	p := NewPagerDutyProvider()
	body := []byte(`{"event":{"id":"ev-1","event_type":"incident.acknowledged","occurred_at":"2026-06-03T21:00:00Z","agent":{"summary":"Jane"},"data":{"id":"PINC1","status":"acknowledged","assignees":[{"summary":"Jane"}]}}}`)
	// SR-020: pin "now" near occurred_at so the replay window passes.
	occurred, _ := time.Parse(time.RFC3339, "2026-06-03T21:00:00Z")
	timeNow = func() time.Time { return occurred }
	defer func() { timeNow = time.Now }()
	good := "v1=" + hmacSHA256Hex([]byte("pdk"), body)
	// Multi-value header (key rotation) — one valid token among others must pass.
	if err := p.VerifyWebhook(req(map[string]string{"X-PagerDuty-Signature": "v1=deadbeef, " + good}), body, "pdk"); err != nil {
		t.Fatalf("valid PD sig should pass: %v", err)
	}
	if err := p.VerifyWebhook(req(map[string]string{"X-PagerDuty-Signature": "v1=deadbeef"}), body, "pdk"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("no matching PD sig must fail")
	}
	// SR-020: validly-signed but replayed long after occurred_at → rejected.
	timeNow = func() time.Time { return occurred.Add(2 * time.Hour) }
	if err := p.VerifyWebhook(req(map[string]string{"X-PagerDuty-Signature": good}), body, "pdk"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("replayed (stale) PD request must be rejected")
	}
	timeNow = func() time.Time { return occurred }
	evs, _ := p.Normalize("acme", body)
	e := evs[0]
	if e.ProviderEvtID != "ev-1" || e.ExternalID != "PINC1" || e.Type != EventAcknowledged || e.Assignee != "Jane" {
		t.Fatalf("unexpected PD event: %+v", e)
	}
}

func TestSlack_VerifyReplayAndNormalize(t *testing.T) {
	p := NewSlackProvider()
	secret := "slacksign"
	now := time.Date(2026, 6, 3, 21, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	defer func() { timeNow = time.Now }()

	payload := `{"type":"block_actions","user":{"username":"jane"},"trigger_id":"tg1","actions":[{"action_id":"ack_incident","value":"inc-123"}]}`
	body := []byte("payload=" + url.QueryEscape(payload))

	mkReq := func(ts int64, sig string) *http.Request {
		return req(map[string]string{
			"X-Slack-Request-Timestamp": strconv.FormatInt(ts, 10),
			"X-Slack-Signature":         sig,
		})
	}
	validTs := now.Unix()
	base := append([]byte("v0:"+strconv.FormatInt(validTs, 10)+":"), body...)
	validSig := "v0=" + hmacSHA256Hex([]byte(secret), base)

	if err := p.VerifyWebhook(mkReq(validTs, validSig), body, secret); err != nil {
		t.Fatalf("valid slack sig should pass: %v", err)
	}
	// Replay: a validly-signed-but-old request (>5min) is rejected.
	oldTs := now.Add(-10 * time.Minute).Unix()
	oldBase := append([]byte("v0:"+strconv.FormatInt(oldTs, 10)+":"), body...)
	oldSig := "v0=" + hmacSHA256Hex([]byte(secret), oldBase)
	if err := p.VerifyWebhook(mkReq(oldTs, oldSig), body, secret); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("stale (replayed) slack request must be rejected")
	}
	// Tampered signature.
	if err := p.VerifyWebhook(mkReq(validTs, validSig+"00"), body, secret); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatal("tampered slack sig must fail")
	}

	evs, err := p.Normalize("acme", body)
	if err != nil || len(evs) != 1 {
		t.Fatalf("normalize: err=%v n=%d", err, len(evs))
	}
	e := evs[0]
	if e.Type != EventAcknowledged || e.AlertID != "inc-123" || e.Actor != "jane" || e.ExternalState != "acknowledged" {
		t.Fatalf("unexpected slack event: %+v", e)
	}
}
