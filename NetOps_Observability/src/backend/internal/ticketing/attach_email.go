// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// attach_email.go — the universal fallback: open a case, or attach to one, by
// email with the bundle as a MIME attachment.
//
// It is the ONLY mechanism for five of seven vendors (research §4.3) and it
// fully serves Arista, so it is Tier 1 alongside the two ITSM connectors.
//
// THE 14 MB NUMBER (research §3). Base64 costs ~37% (RFC 2045 §6.8: 3 octets →
// 4 characters, plus CRLF every 76 characters). The binding ceilings are:
//
//	Cisco attach@cisco.com           20 MB message  → ~14.6 MB raw
//	ServiceNow inbound email action  18 MiB total   → ~13.8 MB raw
//	Exchange Online default send     35 MB          → ~25.5 MB raw
//
// 14 000 000 raw bytes encode to ~19.2 MB, which clears all three at once
// without per-customer tuning. That is the profile ceiling enforced here.
//
// RFC 1870 sets no universal limit and defines 552 as the over-size reply, so
// the sender READS the receiving MTA's advertised SIZE at EHLO and treats 552
// as a first-class outcome (degrade to link-only), never as a transport error
// to retry.
//
// TLS IS REQUIRED. An evidence bundle is customer network data; it does not
// leave in the clear. If the relay offers neither implicit TLS nor STARTTLS the
// send is refused. This is why the transport is built here on stdlib net/smtp
// rather than reusing notify.Email, whose STARTTLS is opportunistic by design
// (an alert that cannot be encrypted is still better delivered than dropped —
// the opposite trade to this one).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"net/textproto"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// EmailProfileMaxBytes is the ≤14 MB raw bundle profile (research §3).
	EmailProfileMaxBytes int64 = 14_000_000
	// base64Overhead is the RFC 2045 expansion factor used to predict the
	// on-the-wire message size against an MTA's advertised SIZE.
	base64Overhead = 1.37
	// emailSMTPDialTimeout / emailSMTPDeadline bound the conversation (§9).
	emailSMTPDialTimeout = 15 * time.Second
	emailSMTPDeadline    = 10 * time.Minute
)

// ── the closed per-vendor mailbox table ─────────────────────────────────────

// EmailVendorMode says what a mailbox can actually do, so the UI never offers
// "Open case" on a mailbox that only accepts attachments to an existing one.
type EmailVendorMode string

const (
	// EmailModeCreateAndAttach: a mail to this address OPENS a case.
	EmailModeCreateAndAttach EmailVendorMode = "create_and_attach"
	// EmailModeAttachOnly: the mailbox attaches to an EXISTING case identified
	// in the subject. Not a degraded create — a first-class mode (research §6).
	EmailModeAttachOnly EmailVendorMode = "attach_only"
)

// EmailVendor is one row of the CLOSED table. Adding a row is a code change on
// purpose: an address that files a support case with a real vendor is not
// tenant-configurable input.
type EmailVendor struct {
	ID      string
	Vendor  string
	Mailbox string
	Mode    EmailVendorMode
	// CaseRefPattern, when set, is the shape of the case reference this vendor
	// requires in the SUBJECT for the mail to be filed against the right case.
	CaseRefPattern *regexp.Regexp
	// SubjectTemplate documents how the subject is built. Rendered by
	// emailSubject; never taken from a request.
	SubjectHint string
	// MaxMessageBytes is the vendor's own message ceiling (0 = not published).
	MaxMessageBytes int64
	Source          string
	Notes           string
}

var (
	// ciscoSRPattern is Cisco's SR number as the attach mailbox expects it in
	// the subject: "SR " + 9 digits (research §1, Cisco row, SCM guide).
	ciscoSRPattern = regexp.MustCompile(`^[0-9]{9}$`)
	// aristaRefPattern is deliberately permissive: Arista publishes that the
	// case Ref. ID goes in the subject or body and auto-attaches, but does NOT
	// publish the id's format. We require a non-empty token with no whitespace
	// rather than inventing a shape.
	aristaRefPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// emailVendors is the whole table. Only vendors whose case mailbox is PUBLISHED
// in the research appear. Nokia's reply-to-case address is per-case and never
// published, so Nokia is intentionally absent — see caseconn_portal.go.
var emailVendors = map[string]EmailVendor{
	"arista": {
		ID: "arista", Vendor: "Arista Networks",
		Mailbox: "support@arista.com", Mode: EmailModeCreateAndAttach,
		CaseRefPattern: aristaRefPattern,
		SubjectHint:    "priority is set by stating it in the subject or body; the default is P3",
		Source:         "https://www.arista.com/en/support/customer-support",
		Notes:          "wants the problem description, a compressed show tech-support, network diagrams, and a name + contact; attaching to an existing case auto-files on the case Ref. ID in the subject",
	},
	"cisco": {
		ID: "cisco", Vendor: "Cisco",
		Mailbox: "attach@cisco.com", Mode: EmailModeAttachOnly,
		CaseRefPattern: ciscoSRPattern,
		SubjectHint:    `the subject must carry "SR xxxxxxxxx"`,
		// The mailbox's own hard limit (research §3). The profile ceiling is
		// lower still; both are enforced, the stricter wins.
		MaxMessageBytes: 20 << 20,
		Source:          "https://www.cisco.com/c/en/us/support/web/tac/tac-customer-file-uploads.html",
		Notes:           "attaches to an existing SR only; CXD is the unlimited path for the same SR",
	},
}

// EmailVendorFor returns the closed-table row for a vendor id.
func EmailVendorFor(id string) (EmailVendor, bool) {
	v, ok := emailVendors[strings.ToLower(strings.TrimSpace(id))]
	return v, ok
}

// EmailVendorIDs lists the vendors the email connector can address, sorted.
func EmailVendorIDs() []string {
	out := make([]string, 0, len(emailVendors))
	for k := range emailVendors {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// emailSubject composes the subject line the vendor mailbox parses. It is
// SERVER-BUILT from the closed table plus a validated case reference — a client
// never supplies a raw subject, so it cannot smuggle a header (CRLF is stripped
// by sanitizeHeaderValue in any case).
func emailSubject(v EmailVendor, caseRef, synopsis string) (string, error) {
	ref := strings.TrimSpace(caseRef)
	switch v.ID {
	case "cisco":
		if !ciscoSRPattern.MatchString(ref) {
			return "", PermanentDeliveryError{errors.New("cisco email attach: the 9-digit SR number is required in the subject")}
		}
		return sanitizeHeaderValue("SR " + ref + " - " + synopsis), nil
	case "arista":
		if ref == "" {
			return sanitizeHeaderValue(synopsis), nil
		}
		if !aristaRefPattern.MatchString(ref) {
			return "", PermanentDeliveryError{errors.New("arista email attach: the case Ref. ID must be a plain token")}
		}
		return sanitizeHeaderValue("Ref. ID " + ref + " - " + synopsis), nil
	}
	return sanitizeHeaderValue(synopsis), nil
}

// sanitizeHeaderValue strips CR/LF and control characters so no field composed
// into an RFC 5322 header can inject one (§3: validate at every boundary).
func sanitizeHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 250 {
		out = out[:250]
	}
	return out
}

// ── the connector ───────────────────────────────────────────────────────────

// EmailCaseConnector opens or attaches to a vendor case by email.
// sendFn is injectable so tests drive a fake SMTP conversation.
type EmailCaseConnector struct {
	vendor EmailVendor
	sendFn func(ctx context.Context, cfg EmailConnectorConfig, to string, msg []byte) error
	retry  RetryPolicy
}

// NewEmailCaseConnector builds the connector for one closed-table vendor.
func NewEmailCaseConnector(vendorID string) (*EmailCaseConnector, error) {
	v, ok := EmailVendorFor(vendorID)
	if !ok {
		return nil, fmt.Errorf("email connector: %q is not in the closed vendor mailbox table", vendorID)
	}
	return &EmailCaseConnector{vendor: v, retry: DefaultCaseRetry()}, nil
}

// NewEmailCaseConnectorWithSender injects the transport (tests).
func NewEmailCaseConnectorWithSender(vendorID string, send func(ctx context.Context, cfg EmailConnectorConfig, to string, msg []byte) error) (*EmailCaseConnector, error) {
	c, err := NewEmailCaseConnector(vendorID)
	if err != nil {
		return nil, err
	}
	c.sendFn = send
	return c, nil
}

func (c *EmailCaseConnector) Name() string { return "email-" + c.vendor.ID }

// Vendor exposes the closed-table row (the UI renders the mailbox + notes).
func (c *EmailCaseConnector) Vendor() EmailVendor { return c.vendor }

func (c *EmailCaseConnector) Capabilities() Caps {
	limit := EmailProfileMaxBytes
	if c.vendor.MaxMessageBytes > 0 {
		// The raw bundle that fits inside the vendor's MESSAGE ceiling.
		if raw := int64(float64(c.vendor.MaxMessageBytes) / base64Overhead); raw < limit {
			limit = raw
		}
	}
	return Caps{
		Create:               c.vendor.Mode == EmailModeCreateAndAttach,
		Attach:               true,
		Poll:                 false, // no machine-readable status: the case link is the only surface
		Note:                 false,
		AttachToExistingOnly: c.vendor.Mode == EmailModeAttachOnly,
		MaxAttachBytes:       limit,
		RequiresEntitlement:  false,
		Notes:                c.vendor.Vendor + " — " + c.vendor.Mailbox + "; " + c.vendor.Notes,
	}
}

func (c *EmailCaseConnector) ValidateConfig(cfg TACConnectorConfig) error {
	if !cfg.Email.Enabled {
		return ErrNotConfigured
	}
	return validateEmailConfig(cfg.Email)
}

// CreateCase sends the opening mail. Only vendors whose mailbox OPENS a case
// declare Create; everyone else gets ErrUnsupported rather than a mail that
// silently lands nowhere.
func (c *EmailCaseConnector) CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error) {
	if !c.Capabilities().Create {
		return CaseRef{}, fmt.Errorf("%w: %s accepts attachments to an existing case only (%s)",
			ErrUnsupported, c.vendor.Vendor, c.vendor.SubjectHint)
	}
	if err := c.ValidateConfig(cfg); err != nil {
		return CaseRef{}, err
	}
	if !req.Approval.Valid() {
		return CaseRef{}, ErrNotApproved
	}
	subject, err := emailSubject(c.vendor, "", req.Synopsis)
	if err != nil {
		return CaseRef{}, err
	}
	msg, err := buildCaseEmail(cfg.Email, c.vendor.Mailbox, subject, caseEmailBody(req), nil)
	if err != nil {
		return CaseRef{}, err
	}
	if err := c.send(ctx, cfg.Email, req.IdempotencyKey, msg); err != nil {
		return CaseRef{}, err
	}
	// There is no case id yet: the vendor assigns one and replies. Saying so is
	// the honest answer — a fabricated ref would be worse than none.
	return CaseRef{Number: "", URL: "", ID: ""}, nil
}

// AttachBundle sends the bundle as a MIME attachment against a case reference.
func (c *EmailCaseConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return AttachResult{}, err
	}
	caps := c.Capabilities()
	if err := checkBundle("email", b, caps.AttachLimit(),
		"the email profile is capped so the message clears Cisco's 20 MB mailbox, ServiceNow's 18 MiB inbound cap and the Exchange Online default; use an API path or a link-only case description"); err != nil {
		return AttachResult{}, err
	}
	subject, err := emailSubject(c.vendor, orDefault(ref.Number, ref.ID), b.Name)
	if err != nil {
		return AttachResult{}, err
	}
	// Read the bundle once: the message is assembled whole because SMTP DATA is
	// not restartable, and the profile ceiling keeps that bounded at ~14 MB.
	rc, err := b.Open()
	if err != nil {
		return AttachResult{}, fmt.Errorf("email: open bundle: %w", err)
	}
	payload, err := io.ReadAll(io.LimitReader(rc, b.Size))
	closeErr := rc.Close()
	if err != nil {
		return AttachResult{}, fmt.Errorf("email: read bundle: %w", err)
	}
	if closeErr != nil {
		return AttachResult{}, fmt.Errorf("email: close bundle: %w", closeErr)
	}
	if int64(len(payload)) != b.Size {
		return AttachResult{}, fmt.Errorf("email: bundle is %d bytes but declared %d", len(payload), b.Size)
	}
	msg, err := buildCaseEmail(cfg.Email, c.vendor.Mailbox, subject,
		attachEmailBody(c.vendor, ref, b), []emailPart{{
			Name: sanitizeFileName(b.Name), ContentType: orDefault(b.ContentType, "application/zip"), Data: payload,
		}})
	if err != nil {
		return AttachResult{}, err
	}
	if err := c.send(ctx, cfg.Email, orDefault(ref.Number, b.SHA256), msg); err != nil {
		return AttachResult{}, err
	}
	return AttachResult{
		Name: b.Name, Size: b.Size, SHA256: b.SHA256,
		At: time.Now().UTC(), Transport: "email",
	}, nil
}

// FetchCase is honestly unsupported: an email mailbox has no status surface.
func (c *EmailCaseConnector) FetchCase(context.Context, TACConnectorConfig, CaseRef) (RemoteCase, bool, error) {
	return RemoteCase{}, false, fmt.Errorf("%w: email has no machine-readable case status", ErrUnsupported)
}

// AddNote is unsupported: a note without a case id cannot be threaded reliably.
func (c *EmailCaseConnector) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	return fmt.Errorf("%w: email cannot add a note to a case", ErrUnsupported)
}

// send applies the bounded retry around one SMTP conversation.
func (c *EmailCaseConnector) send(ctx context.Context, cfg EmailConnectorConfig, key string, msg []byte) error {
	sender := c.sendFn
	if sender == nil {
		sender = sendSMTP
	}
	_, err := withRetry(ctx, c.retry, orDefault(key, c.vendor.ID), func(ctx context.Context) (struct{}, error) {
		return struct{}{}, sender(ctx, cfg, c.vendor.Mailbox, msg)
	})
	return err
}

var _ CaseConnector = (*EmailCaseConnector)(nil)

// ── message assembly (hand-built MIME, stdlib only) ─────────────────────────

type emailPart struct {
	Name        string
	ContentType string
	Data        []byte
}

// buildCaseEmail assembles an RFC 5322 message: a text/plain body plus
// base64 attachment parts under multipart/mixed. The boundary is random, not
// derived from content, so it can never collide with the payload.
func buildCaseEmail(cfg EmailConnectorConfig, to, subject, body string, parts []emailPart) ([]byte, error) {
	from := sanitizeHeaderValue(cfg.From)
	if from == "" || to == "" {
		return nil, PermanentDeliveryError{errors.New("email: sender and recipient are required")}
	}
	var buf bytes.Buffer
	writeHeader := func(k, v string) {
		buf.WriteString(k + ": " + sanitizeHeaderValue(v) + "\r\n")
	}
	writeHeader("From", from)
	writeHeader("To", to)
	if cfg.ReplyTo != "" {
		writeHeader("Reply-To", cfg.ReplyTo)
	}
	// Encoded-word the subject ONLY when it is not pure ASCII (RFC 2047):
	// mime.QEncoding leaves ASCII untouched, which matters because the vendor
	// mailboxes parse the SR number / case Ref. ID out of the RAW subject line
	// and would not see it through an encoded word.
	writeHeader("Subject", mime.QEncoding.Encode("UTF-8", subject))
	writeHeader("Date", time.Now().UTC().Format(time.RFC1123Z))
	buf.WriteString("MIME-Version: 1.0\r\n")

	if len(parts) == 0 {
		buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		buf.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
		buf.WriteString(body)
		return buf.Bytes(), nil
	}

	boundary, err := mimeBoundary()
	if err != nil {
		return nil, err
	}
	buf.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	buf.WriteString(body)
	buf.WriteString("\r\n")
	for _, p := range parts {
		buf.WriteString("--" + boundary + "\r\n")
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", orDefault(p.ContentType, "application/octet-stream"))
		h.Set("Content-Transfer-Encoding", "base64")
		h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", sanitizeFileName(p.Name)))
		for _, k := range []string{"Content-Type", "Content-Transfer-Encoding", "Content-Disposition"} {
			buf.WriteString(k + ": " + h.Get(k) + "\r\n")
		}
		buf.WriteString("\r\n")
		enc := base64.StdEncoding.EncodeToString(p.Data)
		for i := 0; i < len(enc); i += 76 {
			end := i + 76
			if end > len(enc) {
				end = len(enc)
			}
			buf.WriteString(enc[i:end] + "\r\n")
		}
	}
	buf.WriteString("--" + boundary + "--\r\n")
	return buf.Bytes(), nil
}

// mimeBoundary mints a random multipart boundary.
func mimeBoundary() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("email: boundary: %w", err)
	}
	return "correlix-" + hex.EncodeToString(b[:]), nil
}

// caseEmailBody is the opening mail's body: the problem statement plus the
// entitlement and contact facts the vendor asks for. Every value comes from the
// server-side case request, never from raw model or client text.
func caseEmailBody(req CaseRequest) string {
	var b strings.Builder
	b.WriteString(req.Description)
	b.WriteString("\r\n\r\n--- case details ---\r\n")
	for _, kv := range [][2]string{
		{"Severity", req.Severity},
		{"Device", req.DeviceID},
		{"Serial number", req.SerialNumber},
		{"Contact", req.ContactName},
		{"Contact email", req.ContactEmail},
		{"Contact phone", req.ContactPhone},
		{"Reference", req.IdempotencyKey},
	} {
		if strings.TrimSpace(kv[1]) != "" {
			b.WriteString(kv[0] + ": " + sanitizeHeaderValue(kv[1]) + "\r\n")
		}
	}
	return b.String()
}

// attachEmailBody is the attach mail's body: what is attached, its digest, and
// which case it belongs to. The SHA256 is the link between what Correlix
// collected and what the vendor received (research §5.6).
func attachEmailBody(v EmailVendor, ref CaseRef, b Bundle) string {
	var s strings.Builder
	s.WriteString("Diagnostic bundle collected by Correlix.\r\n\r\n")
	if r := orDefault(ref.Number, ref.ID); r != "" {
		s.WriteString("Case reference: " + sanitizeHeaderValue(r) + "\r\n")
	}
	s.WriteString("File: " + sanitizeFileName(b.Name) + "\r\n")
	s.WriteString("Size: " + strconv.FormatInt(b.Size, 10) + " bytes\r\n")
	if b.SHA256 != "" {
		s.WriteString("SHA256: " + sanitizeHeaderValue(b.SHA256) + "\r\n")
	}
	s.WriteString("Vendor mailbox: " + v.Mailbox + "\r\n")
	return s.String()
}

// ── SMTP transport (stdlib net/smtp, TLS required) ──────────────────────────

// ErrSizeRejected is the RFC 1870 552 outcome, or a pre-flight refusal against
// the MTA's advertised SIZE: the message does not fit. The caller degrades to a
// link-only case description; it never retries the same bytes.
type ErrSizeRejected struct {
	Advertised int64
	Message    int64
	Reply      string
}

func (e ErrSizeRejected) Error() string {
	if e.Advertised > 0 {
		return fmt.Sprintf("smtp: message of %d bytes exceeds the relay's advertised SIZE of %d: %s",
			e.Message, e.Advertised, Truncate(e.Reply, 200))
	}
	return fmt.Sprintf("smtp: relay rejected the message size (%d bytes): %s", e.Message, Truncate(e.Reply, 200))
}

// checkAdvertisedSize implements the RFC 1870 pre-flight: a relay that
// advertises SIZE=n cannot accept a message longer than n, so refusing here
// saves a doomed DATA phase and produces the same first-class outcome as a 552.
// An unparseable or zero parameter means "no stated limit" and is not an error.
func checkAdvertisedSize(param string, msgLen int64) error {
	adv, err := strconv.ParseInt(strings.TrimSpace(param), 10, 64)
	if err != nil || adv <= 0 || msgLen <= adv {
		return nil
	}
	return ErrSizeRejected{Advertised: adv, Message: msgLen,
		Reply: "refused before DATA against the relay's advertised SIZE"}
}

// sendSMTP runs one bounded, TLS-required SMTP conversation.
func sendSMTP(ctx context.Context, cfg EmailConnectorConfig, to string, msg []byte) error {
	host, _, err := net.SplitHostPort(cfg.Host)
	if err != nil {
		return PermanentDeliveryError{fmt.Errorf("smtp: host must be host:port")}
	}
	deadline := time.Now().Add(emailSMTPDeadline)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	d := &net.Dialer{Timeout: emailSMTPDialTimeout}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	if cfg.TLSOnConnect {
		// Implicit TLS (port 465): the handshake happens inside the dial, so it
		// is covered by both the dialer timeout and the caller's context.
		conn, err = (&tls.Dialer{NetDialer: d, Config: tlsCfg}).DialContext(ctx, "tcp", cfg.Host)
	} else {
		conn, err = d.DialContext(ctx, "tcp", cfg.Host)
	}
	if err != nil {
		return fmt.Errorf("smtp: connect to relay failed")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close() // best-effort: nothing actionable on a close failure
		return fmt.Errorf("smtp: set deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close() // best-effort: nothing actionable on a close failure
		return fmt.Errorf("smtp: greeting failed")
	}
	defer func() { _ = c.Close() }() // Quit is attempted below; a double close is harmless

	if !cfg.TLSOnConnect {
		ok, _ := c.Extension("STARTTLS")
		if !ok {
			// TLS is REQUIRED here, unlike the alert channel: a bundle carries
			// customer network state and must not cross the wire in the clear.
			return PermanentDeliveryError{errors.New("smtp: relay does not offer STARTTLS and the TAC bundle transport requires TLS")}
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: STARTTLS failed")
		}
	}
	// RFC 1870: refuse before DATA when the relay advertises a SIZE we exceed.
	if _, param := c.Extension("SIZE"); param != "" {
		if err := checkAdvertisedSize(param, int64(len(msg))); err != nil {
			return err
		}
	}
	if cfg.User != "" {
		ok, _ := c.Extension("AUTH")
		if !ok {
			return PermanentDeliveryError{errors.New("smtp: credentials configured but the relay advertises no AUTH")}
		}
		// PlainAuth itself refuses to send credentials over an unencrypted
		// connection; that check is deliberately left to it.
		if err := c.Auth(smtp.PlainAuth("", cfg.User, cfg.Password, host)); err != nil {
			// The error can quote the server's reply but never the password.
			return PermanentDeliveryError{errors.New("smtp: authentication rejected by the relay")}
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return classifySMTPError(err, int64(len(msg)))
	}
	if err := c.Rcpt(to); err != nil {
		return classifySMTPError(err, int64(len(msg)))
	}
	w, err := c.Data()
	if err != nil {
		return classifySMTPError(err, int64(len(msg)))
	}
	if _, err := w.Write(msg); err != nil {
		return classifySMTPError(err, int64(len(msg)))
	}
	if err := w.Close(); err != nil {
		return classifySMTPError(err, int64(len(msg)))
	}
	return c.Quit()
}

// classifySMTPError turns a 552 (RFC 1870's over-size reply) into the
// first-class size outcome and 5xx into a permanent rejection.
func classifySMTPError(err error, msgSize int64) error {
	if err == nil {
		return nil
	}
	var tp *textproto.Error
	if errors.As(err, &tp) {
		switch {
		case tp.Code == 552 || tp.Code == 523:
			return ErrSizeRejected{Message: msgSize, Reply: Truncate(tp.Msg, 200)}
		case tp.Code >= 500:
			return PermanentDeliveryError{fmt.Errorf("smtp: relay refused: %d %s", tp.Code, Truncate(tp.Msg, 200))}
		}
		return fmt.Errorf("smtp: relay replied %d %s", tp.Code, Truncate(tp.Msg, 200))
	}
	return fmt.Errorf("smtp: conversation failed")
}
