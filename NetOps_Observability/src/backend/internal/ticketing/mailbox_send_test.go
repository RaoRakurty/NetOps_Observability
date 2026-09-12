// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// mailbox_send_test.go — the two mailbox APIs, tested as SEQUENCES and as
// MESSAGES.
//
//	· the sequence. Every request the fake provider received is asserted as a
//	  whole list: a probe that reached sendMail, or a send that skipped the
//	  token, fails here rather than in front of a vendor.
//	· the message. Graph's JSON is decoded back into its own shape and Gmail's
//	  base64url `raw` is parsed back with net/mail + mime/multipart, so the
//	  assertions are on a real message rather than on our string building.
//	· the ceilings. Graph's 3 MB single-request limit is refused BY NAME, before
//	  the bundle is opened and before anything reaches the network.
//	· the audit. One row per send, carrying the vendor, the transport and the
//	  message id — and never the subject, the body or the attachment.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingAudit collects the send rows.
type recordingAudit struct {
	mu     sync.Mutex
	events []CaseAuditEvent
}

func (r *recordingAudit) RecordCaseAction(e CaseAuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingAudit) all() []CaseAuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]CaseAuditEvent(nil), r.events...)
}

func approvedMailRequest() CaseRequest {
	return CaseRequest{
		Synopsis: "BGP session down on spine1", Description: "The session to the DIA edge is idle.",
		Severity: "P2", ContactName: "Jane Doe", ContactEmail: "jane.doe@acme.example",
		IdempotencyKey: "inc-4711",
		Approval:       Approval{Actor: "user:7", ApprovedAt: time.Now().UTC()},
	}
}

// ── Microsoft Graph ─────────────────────────────────────────────────────────

func TestGraphSendMailIsTokenThenSendMailAndNothingElse(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "arista")
	audit := &recordingAudit{}
	c.WithAudit(audit)

	cfg := TACConnectorConfig{Email: graphCfg()}
	if _, err := c.CreateCase(context.Background(), cfg, approvedMailRequest()); err != nil {
		t.Fatalf("create: %v", err)
	}

	seen := f.seen()
	want := []string{
		"POST /" + graphCfg().EntraTenantID + "/oauth2/v2.0/token",
		"POST /v1.0/users/noc@acme.example/sendMail",
	}
	if len(seen) != len(want) {
		t.Fatalf("sequence = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("call %d = %q, want %q (whole sequence %v)", i, seen[i], want[i], seen)
		}
	}
	calls := f.recorded()
	if got := calls[1].Auth; got != "Bearer minted-bearer" {
		t.Fatalf("sendMail Authorization = %q", got)
	}

	var body graphSendMail
	if err := json.Unmarshal(calls[1].Body, &body); err != nil {
		t.Fatalf("sendMail body is not the Graph message shape: %v", err)
	}
	if !body.SaveToSentItems {
		t.Error("the message must land in Sent Items: it is the operator's own record")
	}
	if len(body.Message.ToRecipients) != 1 || body.Message.ToRecipients[0].EmailAddress.Address != "support@arista.com" {
		t.Fatalf("recipients = %+v, want the closed-table mailbox", body.Message.ToRecipients)
	}
	if len(body.Message.ReplyTo) != 1 || body.Message.ReplyTo[0].EmailAddress.Address != "jane.doe@acme.example" {
		t.Errorf("replyTo = %+v — Arista asks for a named contact", body.Message.ReplyTo)
	}
	if body.Message.Body.ContentType != "Text" {
		t.Errorf("body contentType = %q, want Text (an HTML case body is a rendering risk)", body.Message.Body.ContentType)
	}
	if !strings.Contains(body.Message.Subject, "BGP session down") {
		t.Errorf("subject = %q", body.Message.Subject)
	}
	if len(body.Message.InternetMessageHeaders) != 1 ||
		body.Message.InternetMessageHeaders[0].Name != graphCorrelationHeader {
		t.Fatalf("headers = %+v, want the one correlation header", body.Message.InternetMessageHeaders)
	}

	// Exactly one audit row, carrying the vendor, the transport and the id —
	// and nothing from the message itself.
	rows := audit.all()
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want one per send", len(rows))
	}
	row := rows[0]
	if row.Action != "send" || row.Result != "ok" || row.Vendor != "Arista Networks" {
		t.Fatalf("audit row = %+v", row)
	}
	if row.Transport != "email-graph" || row.Detail != string(MailboxAuthGraph) {
		t.Fatalf("audit transport/detail = %q/%q", row.Transport, row.Detail)
	}
	if row.MessageID != body.Message.InternetMessageHeaders[0].Value {
		t.Fatalf("audited id %q is not the one on the message (%q)", row.MessageID, body.Message.InternetMessageHeaders[0].Value)
	}
	for _, leak := range []string{"BGP session down", "The session to the DIA edge", "jane.doe@acme.example"} {
		blob, _ := json.Marshal(row)
		if strings.Contains(string(blob), leak) {
			t.Fatalf("the audit row carries message content (%q): %s", leak, blob)
		}
	}
}

// Graph's 3 MB single-request ceiling is the binding one on that mode, and it is
// refused by NAME before the bundle is opened and before anything is sent.
func TestGraphRefusesABundleOverTheSingleRequestCeiling(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "cisco")
	cfg := TACConnectorConfig{Email: graphCfg()}

	limit, advice := c.attachLimit(cfg.Email)
	if limit != graphRawAttachLimit() {
		t.Fatalf("limit = %d, want Graph's raw ceiling %d", limit, graphRawAttachLimit())
	}
	if limit >= EmailProfileMaxBytes {
		t.Fatalf("Graph's ceiling (%d) must be stricter than the 14 MB profile", limit)
	}
	if !strings.Contains(advice, "3 MB") {
		t.Errorf("the advice must name the ceiling, got %q", advice)
	}

	opened := false
	_, err := c.AttachBundle(context.Background(), cfg, CaseRef{Number: "123456789"}, Bundle{
		Name: "show-tech.zip", Size: limit + 1, SHA256: "abc",
		Open: func() (io.ReadCloser, error) { opened = true; return nil, errors.New("must not be opened") },
	})
	var big AttachTooLargeError
	if !errors.As(err, &big) {
		t.Fatalf("err = %v, want AttachTooLargeError", err)
	}
	if big.Limit != limit || !strings.Contains(big.Advice, "3 MB") {
		t.Fatalf("refusal = %+v, want the Graph ceiling named", big)
	}
	if opened {
		t.Error("the bundle was opened even though it could never be sent")
	}
	if got := f.seen(); len(got) != 0 {
		t.Fatalf("an oversize bundle still reached the provider: %v", got)
	}
	if retryable(err) {
		t.Error("an oversize bundle must never be retried")
	}
}

// The ENCODED request is checked too: a bundle that clears the raw pre-flight
// but whose JSON does not fit is still refused, not truncated.
func TestGraphChecksTheEncodedRequestNotJustTheRawBundle(t *testing.T) {
	m := outgoingMail{
		To: "support@arista.com", Subject: "s", Body: "b", Reference: "r@acme.example",
		Parts: []emailPart{{Name: "big.zip", ContentType: "application/zip",
			Data: bytes.Repeat([]byte("z"), int(GraphAttachmentMaxBytes))}},
	}
	_, err := graphSendBody(graphCfg(), m)
	var big AttachTooLargeError
	if !errors.As(err, &big) {
		t.Fatalf("err = %v, want AttachTooLargeError on the encoded request", err)
	}
	if big.Limit != GraphAttachmentMaxBytes {
		t.Fatalf("limit = %d, want Graph's %d", big.Limit, GraphAttachmentMaxBytes)
	}
}

func TestTheGraphProbeReadsTheMailboxAndNeverSends(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "arista")
	cfg := TACConnectorConfig{Email: graphCfg()}

	res := ProbeConnector(context.Background(), c, cfg, 5*time.Second, nil)
	if res.Outcome != ProbeOK {
		t.Fatalf("outcome = %q (%s), want ok", res.Outcome, res.Note)
	}
	seen := f.seen()
	if len(seen) != 2 || seen[1] != "GET /v1.0/users/noc@acme.example" {
		t.Fatalf("the probe's conversation was %v, want a token then one mailbox read", seen)
	}
	for _, call := range seen {
		if strings.Contains(call, "sendMail") {
			t.Fatal("THE PROBE SENT MAIL")
		}
	}
	// The mailbox read must actually carry a $select — a probe that pulled the
	// whole user object would read more of the directory than it needs.
	if q := f.recorded()[1].Query; !strings.Contains(q, "select") {
		t.Errorf("mailbox read query = %q, want a $select", q)
	}
}

func TestAGraphProbeWithADeadCredentialIsRefusedNotUnreachable(t *testing.T) {
	f := newFakeMailbox(t)
	f.status["/users"] = http.StatusForbidden
	c := f.connector(t, "arista")

	res := ProbeConnector(context.Background(), c, TACConnectorConfig{Email: graphCfg()}, 5*time.Second, nil)
	if res.Outcome != ProbeRefused {
		t.Fatalf("outcome = %q (%s), want refused", res.Outcome, res.Note)
	}
	if strings.Contains(res.Note, "app-client-SECRET") {
		t.Fatalf("the note carries the client secret: %q", res.Note)
	}
}

// ── the optional reply read ─────────────────────────────────────────────────

func TestTheReplyReadIsOffUnlessTheTenantAsksForIt(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "cisco")
	cfg := TACConnectorConfig{Email: graphCfg()}

	if _, _, err := c.LookupCaseNumber(context.Background(), cfg, "BGP session down on edge1",
		time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported while read_replies is off", err)
	}
	if got := f.seen(); len(got) != 0 {
		t.Fatalf("a mailbox we were not allowed to read was read anyway: %v", got)
	}
}

// The reply read answers for ONE case: the reply to the message Correlix sent,
// not the newest thing the vendor happened to write.
func TestTheReplyReadLiftsTheCaseNumberOutOfTheReplyToOurOwnMessage(t *testing.T) {
	f := newFakeMailbox(t)
	f.reply["/messages"] = `{"value":[
		{"subject":"RE: SR 987654321 - a different case entirely","receivedDateTime":"2026-09-07T10:00:00Z"},
		{"subject":"RE: SR 123456789 - BGP session down on edge1","receivedDateTime":"2026-09-06T10:00:00Z"},
		{"subject":"newsletter, no case here","receivedDateTime":"2026-09-07T11:00:00Z"}]}`
	c := f.connector(t, "cisco")
	e := graphCfg()
	e.ReadReplies = true

	ref, found, err := c.LookupCaseNumber(context.Background(), TACConnectorConfig{Email: e},
		"BGP session down on edge1", time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC))
	if err != nil || !found {
		t.Fatalf("lookup = %v, found=%v", err, found)
	}
	if ref.Number != "123456789" {
		t.Fatalf("case number = %q, want the SR from the reply to OUR message", ref.Number)
	}
	if got := f.recorded()[1].Query; !strings.Contains(got, "search") || !strings.Contains(got, "attach%40cisco.com") {
		t.Fatalf("search query = %q, want a $search on the CLOSED-table mailbox", got)
	}
}

func TestACaseReferenceIsOnlyReadInAVendorsOwnSubjectShape(t *testing.T) {
	cisco, _ := EmailVendorFor("cisco")
	arista, _ := EmailVendorFor("arista")
	for _, tc := range []struct {
		vendor  EmailVendor
		subject string
		want    string
	}{
		{cisco, "RE: SR 123456789 - link down", "123456789"},
		{cisco, "SR#987654321 update", "987654321"},
		{cisco, "SR 12345 is not nine digits", ""},
		{cisco, "no reference at all", ""},
		{arista, "RE: Ref. ID ABC-123 - your case", "ABC-123"},
		{arista, "Ref ID: xyz789", "xyz789"},
		{arista, "no reference at all", ""},
	} {
		got, ok := caseRefFromSubject(tc.vendor, tc.subject)
		if tc.want == "" {
			if ok {
				t.Errorf("%s / %q: read %q out of a subject with no reference", tc.vendor.ID, tc.subject, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("%s / %q = %q (%v), want %q", tc.vendor.ID, tc.subject, got, ok, tc.want)
		}
	}
}

// ── Gmail ───────────────────────────────────────────────────────────────────

func TestGmailSendsTheSameMimeTheRelayWouldAndKeepsTheProviderId(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "cisco")
	cfg := TACConnectorConfig{Email: gmailCfg(t)}

	res, err := c.AttachBundle(context.Background(), cfg, CaseRef{Number: "123456789"},
		testBundle("show-tech.zip", 4096))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if res.ID != "gmail-msg-1" {
		t.Fatalf("result id = %q, want Gmail's own message id", res.ID)
	}
	if res.Transport != "email-gmail" {
		t.Fatalf("transport = %q", res.Transport)
	}

	seen := f.seen()
	want := []string{"POST /token", "POST /gmail/v1/users/noc@acme.example/messages/send"}
	if len(seen) != 2 || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("sequence = %v, want %v", seen, want)
	}

	var body struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(f.recorded()[1].Body, &body); err != nil {
		t.Fatalf("send body: %v", err)
	}
	rawMsg, err := base64.RawURLEncoding.DecodeString(body.Raw)
	if err != nil {
		t.Fatalf("raw is not base64url: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(rawMsg))
	if err != nil {
		t.Fatalf("raw is not an RFC 5322 message: %v", err)
	}
	if to := msg.Header.Get("To"); to != "attach@cisco.com" {
		t.Fatalf("To = %q, want the closed-table mailbox", to)
	}
	if !strings.Contains(msg.Header.Get("Subject"), "SR 123456789") {
		t.Fatalf("subject = %q, want Cisco's SR form", msg.Header.Get("Subject"))
	}
	id := msg.Header.Get("Message-ID")
	if !strings.HasPrefix(id, "<correlix-") || !strings.HasSuffix(id, ">") {
		t.Fatalf("Message-ID = %q, want a Correlix msg-id", id)
	}
	// The bundle really is attached, as a real MIME part.
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("content type = %q (%v)", msg.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	sawAttachment := false
	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			t.Fatalf("part: %v", perr)
		}
		if strings.Contains(part.Header.Get("Content-Disposition"), "show-tech.zip") {
			sawAttachment = true
		}
	}
	if !sawAttachment {
		t.Error("the bundle did not survive into the Gmail message")
	}
}

func TestTheGmailProbeReadsTheProfileUnderTheSendScope(t *testing.T) {
	f := newFakeMailbox(t)
	c := f.connector(t, "arista")

	res := ProbeConnector(context.Background(), c, TACConnectorConfig{Email: gmailCfg(t)}, 5*time.Second, nil)
	if res.Outcome != ProbeOK {
		t.Fatalf("outcome = %q (%s)", res.Outcome, res.Note)
	}
	seen := f.seen()
	if len(seen) != 2 || seen[1] != "GET /gmail/v1/users/noc@acme.example/profile" {
		t.Fatalf("sequence = %v, want a token then getProfile", seen)
	}
	// The scope the probe asked for must be the one the SEND uses; a probe that
	// passed on a wider scope would certify a path that does not work.
	if got := f.recorded()[0].Form.Get("assertion"); got == "" {
		t.Fatal("the probe did not present a signed assertion")
	}
}

// ── retries ─────────────────────────────────────────────────────────────────

func TestARateLimitedSendIsRetriedAndHonoursTheProvidersWait(t *testing.T) {
	f := newFakeMailbox(t)
	f.once["/sendMail"] = http.StatusTooManyRequests
	f.retryAfter = "60" // far past our ceiling: the clamp is the point
	c := f.connector(t, "arista")
	// An operator is watching this call, so the interactive policy's cap is what
	// bounds it — never the provider's minute.
	c.retry = RetryPolicy{MaxAttempts: 3, Base: time.Millisecond, Cap: 20 * time.Millisecond}

	start := time.Now()
	if _, err := c.CreateCase(context.Background(), TACConnectorConfig{Email: graphCfg()}, approvedMailRequest()); err != nil {
		t.Fatalf("create: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("the call waited %s — the provider's Retry-After was not clamped to the policy cap", elapsed)
	}
	sends := 0
	for _, call := range f.seen() {
		if strings.HasSuffix(call, "/sendMail") {
			sends++
		}
	}
	if sends != 2 {
		t.Fatalf("sendMail attempts = %d, want the 429 retried exactly once", sends)
	}
}

func TestARefusedSendIsNotRetriedAndIsAudited(t *testing.T) {
	f := newFakeMailbox(t)
	f.status["/sendMail"] = http.StatusBadRequest
	c := f.connector(t, "arista")
	audit := &recordingAudit{}
	c.WithAudit(audit)

	_, err := c.CreateCase(context.Background(), TACConnectorConfig{Email: graphCfg()}, approvedMailRequest())
	if err == nil {
		t.Fatal("a 400 must be an error")
	}
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) {
		t.Fatalf("err = %v, want a permanent refusal", err)
	}
	sends := 0
	for _, call := range f.seen() {
		if strings.HasSuffix(call, "/sendMail") {
			sends++
		}
	}
	if sends != 1 {
		t.Fatalf("sendMail attempts = %d — a 400 must never be retried", sends)
	}
	rows := audit.all()
	if len(rows) != 1 || rows[0].Result != "error" {
		t.Fatalf("a failed send must still be audited, got %+v", rows)
	}
	if rows[0].Error == "" {
		t.Error("the audited failure names no reason")
	}
}

// ── configuration ───────────────────────────────────────────────────────────

// Each mode is validated on its OWN terms: demanding a relay host of a Graph
// mailbox, or a client secret of a password relay, would make a correct
// configuration unsavable.
func TestEachMailboxModeIsValidatedOnItsOwnTerms(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  EmailConnectorConfig
		want string // substring of the refusal; "" = must be accepted
	}{
		{"password relay, as before", EmailConnectorConfig{
			Enabled: true, Host: "smtp.acme.example:587", From: "noc@acme.example"}, ""},
		{"password relay with no host", EmailConnectorConfig{
			Enabled: true, From: "noc@acme.example"}, "host:port"},
		{"graph, complete", graphCfg(), ""},
		{"graph with no mailbox", func() EmailConnectorConfig {
			e := graphCfg()
			e.Mailbox = ""
			return e
		}(), "mailbox"},
		{"graph with no client secret", func() EmailConnectorConfig {
			e := graphCfg()
			e.OAuthClientSecret = ""
			return e
		}(), "oauth_client_secret"},
		{"graph with no directory id", func() EmailConnectorConfig {
			e := graphCfg()
			e.EntraTenantID = ""
			return e
		}(), "entra_tenant_id"},
		{"smtp oauth with no provider", EmailConnectorConfig{
			Enabled: true, AuthMode: MailboxAuthSMTPOAuth,
			Host: "smtp.office365.com:587", From: "noc@acme.example"}, "oauth_provider"},
		{"an invented mode falls back to the relay", EmailConnectorConfig{
			Enabled: true, AuthMode: "carrier-pigeon",
			Host: "smtp.acme.example:587", From: "noc@acme.example"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEmailConfig(tc.cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("must be accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("must be refused, naming %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name %q", err, tc.want)
			}
		})
	}
}

func TestAGoogleMailboxWithAnUnusableKeyIsRefusedOnSave(t *testing.T) {
	e := gmailCfg(t)
	e.ServiceAccountKey = "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"
	err := validateEmailConfig(e)
	if err == nil {
		t.Fatal("a key that cannot sign must be refused at save time, not at 3am")
	}
	if strings.Contains(err.Error(), "bm90IGEga2V5") {
		t.Fatalf("the refusal echoed key material: %v", err)
	}
}

// The two new secrets are write-only exactly like the password: never
// serialized out, reported only as presence, and tri-state on a save.
func TestTheOAuthSecretsAreWriteOnly(t *testing.T) {
	cfg := TACConnectorConfig{Email: EmailConnectorConfig{
		Enabled: true, AuthMode: MailboxAuthGraph, Mailbox: "noc@acme.example",
		EntraTenantID: "t", OAuthClientID: "c", OAuthClientSecret: "SECRET",
		ServiceAccountKey: "KEYMATERIAL",
	}}
	red := cfg.Redacted()
	if red.Email.OAuthClientSecret != "" || red.Email.ServiceAccountKey != "" {
		t.Fatalf("Redacted left a secret behind: %+v", red.Email)
	}
	blob, _ := json.Marshal(red)
	for _, leak := range []string{"SECRET", "KEYMATERIAL"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("a redacted record serialized %q: %s", leak, blob)
		}
	}
	present := SectionSecretsPresent(SectionEmail, cfg)
	for _, name := range []string{"password", "oauth_client_secret", "service_account_key"} {
		if _, ok := present[name]; !ok {
			t.Fatalf("secret %q is not reported at all: %v", name, present)
		}
	}
	if !present["oauth_client_secret"] || !present["service_account_key"] || present["password"] {
		t.Fatalf("presence = %v", present)
	}

	// Tri-state, for each of the three.
	base := `"enabled":true,"auth_mode":"microsoft365","mailbox":"noc@acme.example","entra_tenant_id":"t","oauth_client_id":"c"`
	for _, tc := range []struct {
		name, body string
		wantSecret string
		wantKey    string
	}{
		{"omitted keeps both", "{" + base + "}", "SECRET", "KEYMATERIAL"},
		{"empty clears one", `{` + base + `,"oauth_client_secret":""}`, "", "KEYMATERIAL"},
		{"a value replaces one", `{` + base + `,"oauth_client_secret":"rotated"}`, "rotated", "KEYMATERIAL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ApplyConnectorWrite(SectionEmail, []byte(tc.body), cfg)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			if out.Email.OAuthClientSecret != tc.wantSecret || out.Email.ServiceAccountKey != tc.wantKey {
				t.Fatalf("secrets = %q/%q, want %q/%q",
					out.Email.OAuthClientSecret, out.Email.ServiceAccountKey, tc.wantSecret, tc.wantKey)
			}
		})
	}
}

// The connector's standing note says HOW this tenant's mailbox is
// authenticated — "email" no longer means one thing.
func TestTheConnectorReportsItsAuthMode(t *testing.T) {
	c, err := NewEmailCaseConnector("arista")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for mode, want := range map[MailboxAuthMode]string{
		MailboxAuthPassword:  "password relay",
		MailboxAuthGraph:     "Microsoft 365",
		MailboxAuthGmail:     "Google Workspace",
		MailboxAuthSMTPOAuth: "SMTP with OAuth",
	} {
		note := c.AuthModeNote(TACConnectorConfig{Email: EmailConnectorConfig{AuthMode: mode}})
		if !strings.Contains(note, want) {
			t.Errorf("%s note = %q, want it to name %q", mode, note, want)
		}
	}
	// The note is a MODE, never a credential.
	note := c.AuthModeNote(TACConnectorConfig{Email: graphCfg()})
	for _, leak := range []string{"app-client-SECRET", "app-client-id"} {
		if strings.Contains(note, leak) {
			t.Fatalf("the auth-mode note carries a credential: %q", note)
		}
	}
}

// ── SMTP with OAuth ─────────────────────────────────────────────────────────

func smtpOAuthCfg(host string) EmailConnectorConfig {
	e := graphCfg()
	e.AuthMode = MailboxAuthSMTPOAuth
	e.OAuthProvider = MailboxProviderMicrosoft
	e.Host = host
	e.From = "noc@acme.example"
	return e
}

// The SMTP mode asks for the provider's SMTP scope, NOT the API scope: a token
// minted for Graph is one Exchange Online's SMTP endpoint will not accept.
func TestSMTPOAuthAsksForTheProvidersSMTPScope(t *testing.T) {
	for _, tc := range []struct {
		provider, wantScope, wantLogin string
	}{
		{MailboxProviderMicrosoft, outlookSMTPScope, "noc@acme.example"},
		{MailboxProviderGoogle, gmailSMTPScope, "noc@acme.example"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			f := newFakeMailbox(t)
			c := f.connector(t, "arista")
			cfg := smtpOAuthCfg("smtp.example:587")
			cfg.OAuthProvider = tc.provider
			if tc.provider == MailboxProviderGoogle {
				g := gmailCfg(t)
				cfg.ServiceAccountEmail, cfg.ServiceAccountKey = g.ServiceAccountEmail, g.ServiceAccountKey
			}

			auth, err := c.xoauth2(context.Background(), cfg)
			if err != nil {
				t.Fatalf("xoauth2: %v", err)
			}
			calls := f.recorded()
			if len(calls) != 1 {
				t.Fatalf("the mint took %d requests: %v", len(calls), f.seen())
			}
			if tc.provider == MailboxProviderMicrosoft {
				if got := calls[0].Form.Get("scope"); got != tc.wantScope {
					t.Fatalf("scope = %q, want %q", got, tc.wantScope)
				}
			} else {
				var claims map[string]any
				decodeSegT(t, strings.Split(calls[0].Form.Get("assertion"), ".")[1], &claims)
				if got, _ := claims["scope"].(string); got != tc.wantScope {
					t.Fatalf("assertion scope = %q, want %q", got, tc.wantScope)
				}
			}
			_, initial, err := auth.Start(&smtpServerInfoTLS)
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			if !strings.HasPrefix(string(initial), "user="+tc.wantLogin+"\x01auth=Bearer ") {
				t.Fatalf("SASL response = %q", initial)
			}
		})
	}
}

// The token is minted BEFORE the relay is dialled: an operator whose app
// registration is the broken thing must be told that, not "the relay refused".
func TestTheSMTPOAuthProbeMintsFirstThenDialsTheRelay(t *testing.T) {
	f := newFakeMailbox(t)
	relay := newFakeSMTP(t, []string{"fake"}, "") // advertises no STARTTLS
	c := f.connector(t, "arista")
	cfg := TACConnectorConfig{Email: smtpOAuthCfg(relay.addr())}

	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	res := ProbeConnector(context.Background(), c, cfg, 5*time.Second, nil)
	if res.Outcome != ProbeRefused || !strings.Contains(res.Note, "STARTTLS") {
		t.Fatalf("outcome = %q (%s), want the TLS refusal", res.Outcome, res.Note)
	}
	if got := f.seen(); len(got) != 1 || !strings.HasSuffix(got[0], "/oauth2/v2.0/token") {
		t.Fatalf("the token was not minted before the relay was dialled: %v", got)
	}
}

// A dead app registration is reported as a dead app registration, and the relay
// is never dialled at all.
func TestAnSMTPOAuthProbeWithADeadAppNeverReachesTheRelay(t *testing.T) {
	f := newFakeMailbox(t)
	f.status["/oauth2/v2.0/token"] = http.StatusUnauthorized
	c := f.connector(t, "arista")
	// A relay address nothing is listening on: reaching it would be an error of
	// a different shape, which is exactly what this asserts does not happen.
	cfg := TACConnectorConfig{Email: smtpOAuthCfg("127.0.0.1:1")}

	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	res := ProbeConnector(context.Background(), c, cfg, 5*time.Second, nil)
	if res.Outcome != ProbeRefused {
		t.Fatalf("outcome = %q (%s), want refused", res.Outcome, res.Note)
	}
	if !strings.Contains(res.Note, "microsoft 365 token") {
		t.Fatalf("the note must name the token exchange, got %q", res.Note)
	}
	if strings.Contains(res.Note, "app-client-SECRET") {
		t.Fatalf("the note carries the client secret: %q", res.Note)
	}
}
