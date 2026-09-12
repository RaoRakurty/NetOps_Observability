// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// mailbox_send.go — the two mailbox APIs the email connector can send through
// when SMTP is not on offer, plus their read-only probes.
//
//	Microsoft Graph  POST /v1.0/users/{mailbox}/sendMail
//	                 the message is JSON, attachments are base64 fileAttachments,
//	                 and the WHOLE request must clear Graph's 3 MB single-request
//	                 ceiling. Above it Microsoft's only answer is the
//	                 upload-session flow, which exists on a DRAFT message and is
//	                 therefore not a send-in-one-call path at all — so Correlix
//	                 refuses BY NAME with the ceiling rather than silently
//	                 truncating an evidence bundle.
//	Gmail            POST /gmail/v1/users/{mailbox}/messages/send
//	                 the message is an RFC 5322 MIME blob, base64url in `raw`,
//	                 under Gmail's 25 MB total ceiling. That is the SAME MIME the
//	                 SMTP path builds — one builder, already parsed back by its
//	                 own tests, rather than a second one that could drift.
//
// THE PROBES READ. /users/{mailbox} on Graph and users.getProfile on Gmail are
// the cheapest calls that prove the token mints AND that it is authorized for
// this exact mailbox. Neither sends, drafts or stores anything, which is the
// whole contract of caseconn_probe.go.
//
// EVERY CALL IS BOUNDED (§9) and every response body is read under a limit. A
// bearer never leaves this file: it is set on the request and nothing that can
// be logged or returned is derived from it (§8).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The two published ceilings, and the RAW bundle sizes that still fit once
// base64 has expanded them (RFC 2045, ~37%).
const (
	// GraphAttachmentMaxBytes is Graph's single-request sendMail ceiling.
	GraphAttachmentMaxBytes int64 = 3 << 20
	// GmailMessageMaxBytes is Gmail's total message ceiling.
	GmailMessageMaxBytes int64 = 25 << 20
)

func graphRawAttachLimit() int64 { return rawUnderEncodedCeiling(GraphAttachmentMaxBytes) }
func gmailRawAttachLimit() int64 { return rawUnderEncodedCeiling(GmailMessageMaxBytes) }

// rawUnderEncodedCeiling is the largest RAW payload that still fits under an
// ENCODED ceiling once base64 has expanded it.
func rawUnderEncodedCeiling(encoded int64) int64 {
	room := float64(encoded) / base64Overhead
	return int64(room)
}

// graphOversizeAdvice is what an operator does about a refusal. It names the
// ceiling and the two real ways out; it never suggests retrying the same bytes.
const graphOversizeAdvice = "Microsoft Graph accepts a sendMail request of at most 3 MB in one call, and the larger-file path is an upload session on a draft message rather than a send. Use the link-only case description, or send this bundle through an SMTP relay."

const gmailOversizeAdvice = "Gmail accepts a message of at most 25 MB. Use the link-only case description."

// ── Microsoft Graph sendMail ────────────────────────────────────────────────

type graphAddress struct {
	Address string `json:"address"`
}

type graphRecipient struct {
	EmailAddress graphAddress `json:"emailAddress"`
}

type graphItemBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type graphHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type graphAttachment struct {
	ODataType    string `json:"@odata.type"`
	Name         string `json:"name"`
	ContentType  string `json:"contentType"`
	ContentBytes string `json:"contentBytes"`
}

type graphMessage struct {
	Subject                string            `json:"subject"`
	Body                   graphItemBody     `json:"body"`
	ToRecipients           []graphRecipient  `json:"toRecipients"`
	ReplyTo                []graphRecipient  `json:"replyTo,omitempty"`
	InternetMessageHeaders []graphHeader     `json:"internetMessageHeaders,omitempty"`
	Attachments            []graphAttachment `json:"attachments,omitempty"`
}

type graphSendMail struct {
	Message         graphMessage `json:"message"`
	SaveToSentItems bool         `json:"saveToSentItems"`
}

// graphCorrelationHeader is the ONE custom header the message carries. Graph
// assigns its own internetMessageId and returns nothing from sendMail, so this
// is how a message in the operator's Sent Items is tied back to the audit row.
// Graph only accepts custom headers whose name begins with "x-".
const graphCorrelationHeader = "x-correlix-reference"

// graphSendBody renders the outgoing mail as Graph's JSON and enforces the
// single-request ceiling on the ENCODED request — the number Microsoft actually
// measures — in addition to the raw pre-flight the caller already ran.
func graphSendBody(cfg EmailConnectorConfig, m outgoingMail) ([]byte, error) {
	msg := graphMessage{
		Subject:      m.Subject,
		Body:         graphItemBody{ContentType: "Text", Content: m.Body},
		ToRecipients: []graphRecipient{{EmailAddress: graphAddress{Address: m.To}}},
	}
	if r := strings.TrimSpace(cfg.ReplyTo); r != "" {
		msg.ReplyTo = []graphRecipient{{EmailAddress: graphAddress{Address: r}}}
	}
	if m.Reference != "" {
		msg.InternetMessageHeaders = []graphHeader{{Name: graphCorrelationHeader, Value: m.Reference}}
	}
	for _, p := range m.Parts {
		msg.Attachments = append(msg.Attachments, graphAttachment{
			ODataType:    "#microsoft.graph.fileAttachment",
			Name:         sanitizeFileName(p.Name),
			ContentType:  orDefault(p.ContentType, "application/octet-stream"),
			ContentBytes: base64.StdEncoding.EncodeToString(p.Data),
		})
	}
	raw, err := json.Marshal(graphSendMail{Message: msg, SaveToSentItems: true})
	if err != nil {
		return nil, fmt.Errorf("microsoft 365: building the message failed: %w", err)
	}
	if int64(len(raw)) > GraphAttachmentMaxBytes {
		return nil, AttachTooLargeError{
			Transport: "email-graph", Size: int64(len(raw)),
			Limit: GraphAttachmentMaxBytes, Advice: graphOversizeAdvice,
		}
	}
	return raw, nil
}

// sendGraph posts one message. Graph answers 202 with an empty body, so the
// audited message id is the reference Correlix generated and stamped as a
// header — the id that is actually common to all three transports.
func (c *EmailCaseConnector) sendGraph(ctx context.Context, cfg EmailConnectorConfig, m outgoingMail) (string, error) {
	mailbox := strings.TrimSpace(cfg.Mailbox)
	if mailbox == "" {
		return "", PermanentDeliveryError{errors.New("microsoft 365: the sending mailbox is required")}
	}
	body, err := graphSendBody(cfg, m)
	if err != nil {
		return "", err
	}
	tok, err := c.tokens().Token(ctx, cfg, graphDefaultScope)
	if err != nil {
		return "", err
	}
	endpoint := strings.TrimSuffix(c.endpoints().Graph, "/") + "/users/" + url.PathEscape(mailbox) + "/sendMail"
	if _, err := c.mailboxJSON(ctx, "microsoft 365 sendMail", http.MethodPost, endpoint, tok, body); err != nil {
		return "", err
	}
	return m.Reference, nil
}

// probeGraph READS one mailbox. It proves three things at once: the app's
// credentials mint a token, the token is accepted by Graph, and the mailbox this
// tenant named is a real one the app can address. It sends nothing.
func (c *EmailCaseConnector) probeGraph(ctx context.Context, cfg EmailConnectorConfig) error {
	mailbox := strings.TrimSpace(cfg.Mailbox)
	if mailbox == "" {
		return PermanentDeliveryError{errors.New("microsoft 365: the sending mailbox is required")}
	}
	tok, err := c.tokens().Token(ctx, cfg, graphDefaultScope)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(c.endpoints().Graph, "/") + "/users/" + url.PathEscape(mailbox) +
		"?$select=id,mail,userPrincipalName"
	raw, err := c.mailboxJSON(ctx, "microsoft 365 mailbox read", http.MethodGet, endpoint, tok, nil)
	if err != nil {
		return err
	}
	var out struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &out) != nil || strings.TrimSpace(out.ID) == "" {
		return PermanentDeliveryError{errors.New(
			"microsoft 365: the directory answered but named no mailbox — check the address, and that the app registration has the Mail.Send application permission with admin consent")}
	}
	return nil
}

// ── the optional reply read ─────────────────────────────────────────────────

// caseRefFromSubject lifts a vendor's case reference out of a reply subject. The
// shapes are the vendors' OWN published subject conventions, the same ones
// emailSubject writes — nothing is guessed.
var (
	ciscoSubjectRef  = regexp.MustCompile(`(?i)\bSR\s*#?\s*([0-9]{9})\b`)
	aristaSubjectRef = regexp.MustCompile(`(?i)\bRef\.?\s*ID\s*[:#]?\s*([A-Za-z0-9._-]{1,64})\b`)
)

// vendorSubjectRef is the vendor's own subject-reference pattern, or nil for a
// vendor that publishes none.
func vendorSubjectRef(v EmailVendor) *regexp.Regexp {
	switch v.ID {
	case "cisco":
		return ciscoSubjectRef
	case "arista":
		return aristaSubjectRef
	}
	return nil
}

func caseRefFromSubject(v EmailVendor, subject string) (string, bool) {
	re := vendorSubjectRef(v)
	if re == nil {
		return "", false
	}
	m := re.FindStringSubmatch(subject)
	if len(m) != 2 {
		return "", false
	}
	return m[1], true
}

// LookupCaseNumber reads the REPLY to ONE sent case in the tenant's own mailbox
// and lifts the vendor's case reference out of the subject line.
//
// IT IS NOT A POLL, and that is why it is not the Poll capability. It reads OUR
// mailbox, never the vendor's case system, so it can learn a case NUMBER — the
// one thing an email create cannot know at send time — and it can never learn a
// case STATUS. Declaring Poll here would promise a status surface that does not
// exist (research §6, the "explicit honesty rule").
//
// IT ANSWERS FOR ONE CASE, NOT FOR THE MAILBOX. sentSubject is the exact subject
// the create put on the wire and sentAt is when it went; a reply is accepted
// ONLY when it answers that message. Returning the newest reply from the vendor
// instead — which is all a mailbox-wide read can do — hands the same number to
// every unnumbered case the tenant has open with them, and files one vendor's
// case number against another operator's incident.
//
// WHY THE SUBJECT AND NOT A MESSAGE ID. Graph's sendMail returns 202 and an
// empty body: it assigns the message's internetMessageId itself and never tells
// us what it chose. So the id the vendor's reply threads against is an id this
// process has never seen, and the subject Correlix composed — which the vendor's
// mail system quotes back, decorated with their own case reference — is the
// strongest handle that actually exists on this path.
//
// It is opt-in per tenant (read_replies) because it needs a second, wider
// permission — Mail.Read — that a tenant may reasonably refuse to grant.
func (c *EmailCaseConnector) LookupCaseNumber(ctx context.Context, cfg TACConnectorConfig,
	sentSubject string, sentAt time.Time) (CaseRef, bool, error) {
	e := cfg.Email
	if err := c.ValidateConfig(cfg); err != nil {
		return CaseRef{}, false, err
	}
	if strings.TrimSpace(sentSubject) == "" {
		// With nothing to match against, the only available answer would be a
		// guess. Refuse instead of guessing (§3, §10).
		return CaseRef{}, false, PermanentDeliveryError{errors.New(
			"the reply read needs the subject the case was opened with; this case carries none")}
	}
	if !e.ReadReplies {
		return CaseRef{}, false, fmt.Errorf("%w: reading the reply thread is off for this tenant", ErrUnsupported)
	}
	if e.authMode() != MailboxAuthGraph {
		return CaseRef{}, false, fmt.Errorf("%w: the reply read is a Microsoft Graph capability", ErrUnsupported)
	}
	tok, err := c.tokens().Token(ctx, e, graphDefaultScope)
	if err != nil {
		return CaseRef{}, false, err
	}
	// $search is Graph's own mailbox search; the term is the vendor's published
	// mailbox, which comes from the CLOSED table and never from a request.
	q := url.Values{}
	q.Set("$search", `"from:`+c.vendor.Mailbox+`"`)
	q.Set("$select", "subject,receivedDateTime")
	q.Set("$top", "25")
	endpoint := strings.TrimSuffix(c.endpoints().Graph, "/") + "/users/" +
		url.PathEscape(strings.TrimSpace(e.Mailbox)) + "/messages?" + q.Encode()
	raw, err := c.mailboxJSON(ctx, "microsoft 365 reply read", http.MethodGet, endpoint, tok, nil)
	if err != nil {
		return CaseRef{}, false, err
	}
	var out struct {
		Value []struct {
			Subject  string    `json:"subject"`
			Received time.Time `json:"receivedDateTime"`
		} `json:"value"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return CaseRef{}, false, PermanentDeliveryError{errors.New("microsoft 365: the reply search returned something this connector does not understand")}
	}
	// Only replies to THIS message, and only ones carrying a reference in the
	// vendor's own published subject shape.
	refs := map[string]bool{}
	for _, msg := range out.Value {
		if !replyAnswers(c.vendor, sentSubject, sentAt, msg.Subject, msg.Received) {
			continue
		}
		if ref, ok := caseRefFromSubject(c.vendor, msg.Subject); ok {
			refs[ref] = true
		}
	}
	switch len(refs) {
	case 0:
		return CaseRef{}, false, nil
	case 1:
		for ref := range refs {
			return CaseRef{ID: ref, Number: ref}, true, nil
		}
	}
	// Two different case numbers answering one message. That is a mailbox this
	// connector cannot read honestly — picking either would file a number
	// against a case it may not belong to — so it says so and files none.
	return CaseRef{}, false, PermanentDeliveryError{errors.New(
		"the vendor's mailbox holds replies naming more than one case number for this message; read the thread and record the number by hand")}
}

// replyAnswers reports that one mailbox message is a reply to the message
// Correlix sent for this case.
//
// The rule is deliberately TIGHT: too tight costs a lookup that answers "not
// yet" and is retried on schedule, while too loose costs one vendor's case
// number filed against another operator's incident. Two things must hold — the
// reply cannot predate the message it answers, and once the mail client's reply
// markers and the vendor's own case reference are taken off the front, what is
// left must be EXACTLY the subject we sent.
func replyAnswers(v EmailVendor, sentSubject string, sentAt time.Time, replySubject string, received time.Time) bool {
	if !sentAt.IsZero() && !received.IsZero() && received.Before(sentAt.Add(-replyClockSkew)) {
		return false
	}
	want := normalizeSubject(sentSubject)
	if want == "" {
		return false
	}
	got := normalizeSubject(replySubject)
	if got == want {
		return true
	}
	// "SR 123456789 - <our subject>": the vendor's own reference, then ours.
	rest, ok := stripVendorReference(v, got)
	return ok && rest == want
}

// stripVendorReference removes a vendor case reference that stands at the FRONT
// of a subject, with whatever separator follows it. A reference found anywhere
// else is left alone: it belongs to the text, not to the prefix.
func stripVendorReference(v EmailVendor, subject string) (string, bool) {
	re := vendorSubjectRef(v)
	if re == nil {
		return subject, false
	}
	loc := re.FindStringIndex(subject)
	if loc == nil || loc[0] != 0 {
		return subject, false
	}
	rest := strings.TrimSpace(subject[loc[1]:])
	rest = strings.TrimSpace(strings.TrimLeft(rest, "-:|"))
	return rest, true
}

// replyClockSkew is how much earlier than our own send timestamp a reply may be
// stamped before it stops being credible. Two clocks are involved — this host's
// and the mail service's — and neither is disciplined to the other.
const replyClockSkew = 10 * time.Minute

// replyMarkers are the prefixes a mail client puts in front of a quoted subject.
// They are stripped repeatedly: a thread three answers deep carries three.
var replyMarkers = []string{"re:", "re :", "fw:", "fwd:", "fw :", "fwd :", "aw:", "sv:", "tr:", "vs:"}

// normalizeSubject reduces a subject line to what can be compared: lower case,
// single spaces, no reply markers and no leading [TAG] a mail gateway stamped on
// the front. It never removes anything from the MIDDLE of a subject, so two
// different cases cannot normalise to the same string.
func normalizeSubject(s string) string {
	out := strings.ToLower(strings.Join(strings.Fields(s), " "))
	for changed := true; changed; {
		changed = false
		for _, m := range replyMarkers {
			if rest, ok := strings.CutPrefix(out, m); ok {
				out = strings.TrimSpace(rest)
				changed = true
			}
		}
		if strings.HasPrefix(out, "[") {
			if i := strings.Index(out, "]"); i > 0 {
				out = strings.TrimSpace(out[i+1:])
				changed = true
			}
		}
	}
	return out
}

// ── Gmail users.messages.send ───────────────────────────────────────────────

// sendGmail posts the SAME RFC 5322 message the SMTP path builds, base64url in
// `raw`. Gmail answers with its own message id, which is what gets audited.
func (c *EmailCaseConnector) sendGmail(ctx context.Context, cfg EmailConnectorConfig, msg []byte) (string, error) {
	mailbox := strings.TrimSpace(cfg.Mailbox)
	if mailbox == "" {
		return "", PermanentDeliveryError{errors.New("google workspace: the sending mailbox is required")}
	}
	if int64(len(msg)) > GmailMessageMaxBytes {
		return "", AttachTooLargeError{
			Transport: "email-gmail", Size: int64(len(msg)),
			Limit: GmailMessageMaxBytes, Advice: gmailOversizeAdvice,
		}
	}
	body, err := json.Marshal(map[string]string{"raw": base64.RawURLEncoding.EncodeToString(msg)})
	if err != nil {
		return "", fmt.Errorf("google workspace: building the request failed: %w", err)
	}
	tok, err := c.tokens().Token(ctx, cfg, gmailSendScope)
	if err != nil {
		return "", err
	}
	endpoint := strings.TrimSuffix(c.endpoints().Gmail, "/") + "/users/" + url.PathEscape(mailbox) + "/messages/send"
	raw, err := c.mailboxJSON(ctx, "gmail send", http.MethodPost, endpoint, tok, body)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	// The send has already succeeded, so a response we cannot parse costs the
	// audit its provider-side id and nothing else — best-effort by design.
	_ = json.Unmarshal(raw, &out)
	return strings.TrimSpace(out.ID), nil
}

// probeGmail READS the mailbox profile: the cheapest call proving the assertion
// signs, the delegation is granted for this mailbox, and the scope is live.
func (c *EmailCaseConnector) probeGmail(ctx context.Context, cfg EmailConnectorConfig) error {
	mailbox := strings.TrimSpace(cfg.Mailbox)
	if mailbox == "" {
		return PermanentDeliveryError{errors.New("google workspace: the sending mailbox is required")}
	}
	// getProfile is readable under the send scope, so the probe asks for exactly
	// what the send path asks for — a test that passed on a wider scope than the
	// send uses would certify a path that does not work.
	tok, err := c.tokens().Token(ctx, cfg, gmailSendScope)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(c.endpoints().Gmail, "/") + "/users/" + url.PathEscape(mailbox) + "/profile"
	raw, err := c.mailboxJSON(ctx, "gmail profile read", http.MethodGet, endpoint, tok, nil)
	if err != nil {
		return err
	}
	var out struct {
		EmailAddress string `json:"emailAddress"`
	}
	if json.Unmarshal(raw, &out) != nil || strings.TrimSpace(out.EmailAddress) == "" {
		return PermanentDeliveryError{errors.New(
			"google workspace: Gmail answered but named no mailbox — check the domain-wide delegation grant for this client id and the gmail.send scope")}
	}
	return nil
}

// ── the shared JSON call ────────────────────────────────────────────────────

// mailboxJSON runs one bounded, bearer-authenticated call against a mailbox API.
// The bearer is set on the request and appears nowhere else; the response body
// is read under a limit and only ever quoted through classifyMailboxStatus.
func (c *EmailCaseConnector) mailboxJSON(ctx context.Context, op, method, endpoint, bearer string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, mailboxCallTimeout)
	defer cancel()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return nil, PermanentDeliveryError{fmt.Errorf("%s: the endpoint is not a usable URL", op)}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := c.tokens().client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: the mailbox API did not answer", op)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on a close failure
	// raw is a diagnostic snippet only; the STATUS is what decides the outcome,
	// so a short read cannot change the answer — best-effort by design.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxMailboxRespBytes))
	if cerr := classifyMailboxStatus(op, resp, raw); cerr != nil {
		return nil, cerr
	}
	return raw, nil
}
