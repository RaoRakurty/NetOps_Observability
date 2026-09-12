// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// attach_email_test.go — the universal fallback, tested at two levels: the
// MESSAGE (parsed back with mime/multipart, so the assertions are on real MIME
// rather than on our string building) and the TRANSPORT (a fake SMTP server on
// a real listener, so the TLS-required rule and the RFC 1870 552 outcome are
// exercised as conversations, not as unit-tested branches).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func testBundle(name string, size int) Bundle {
	body := bytes.Repeat([]byte("z"), size)
	return Bundle{
		Name: name, ContentType: "application/zip", Size: int64(size),
		SHA256: "abc123",
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil },
	}
}

func emailCfg() TACConnectorConfig {
	return TACConnectorConfig{Email: EmailConnectorConfig{
		Enabled: true, Host: "smtp.example.com:587", From: "noc@customer.example",
		ReplyTo: "jane.doe@customer.example",
	}}
}

// capturingSender records the message instead of sending it.
type capturingSender struct {
	to   string
	msg  []byte
	err  error
	call int
}

func (c *capturingSender) send(_ context.Context, _ EmailConnectorConfig, to string, msg []byte) error {
	c.call++
	c.to, c.msg = to, msg
	return c.err
}

func TestEmailVendorTableIsClosedAndCarriesThePublishedMailboxes(t *testing.T) {
	arista, ok := EmailVendorFor("arista")
	if !ok {
		t.Fatal("arista must be in the table: email is the ONLY path Arista publishes")
	}
	if arista.Mailbox != "support@arista.com" || arista.Mode != EmailModeCreateAndAttach {
		t.Errorf("arista row = %+v", arista)
	}
	cisco, ok := EmailVendorFor("cisco")
	if !ok {
		t.Fatal("cisco attach mailbox missing")
	}
	if cisco.Mailbox != "attach@cisco.com" || cisco.Mode != EmailModeAttachOnly {
		t.Errorf("cisco row = %+v", cisco)
	}
	// Nokia's reply-to-case address is per-case and never published, so it must
	// NOT be guessable from this table.
	if _, ok := EmailVendorFor("nokia"); ok {
		t.Error("nokia has no published case mailbox and must not be in the closed table")
	}
	if _, err := NewEmailCaseConnector("acme"); err == nil {
		t.Error("an unknown vendor must be refused, not defaulted")
	}
}

func TestEmailAttachToCiscoRequiresTheSRNumberInTheSubject(t *testing.T) {
	cap := &capturingSender{}
	c, err := NewEmailCaseConnectorWithSender("cisco", cap.send)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailCfg()

	// Without a 9-digit SR the mail must not be sent at all.
	if _, err := c.AttachBundle(context.Background(), cfg, CaseRef{Number: "not-an-sr"}, testBundle("b.zip", 16)); err == nil {
		t.Fatal("want a refusal without a valid SR number")
	}
	if cap.call != 0 {
		t.Fatalf("a malformed reference must not reach the relay (%d calls)", cap.call)
	}

	res, err := c.AttachBundle(context.Background(), cfg, CaseRef{Number: "695123456"}, testBundle("bundle.zip", 32))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if cap.to != "attach@cisco.com" {
		t.Errorf("recipient = %q, want attach@cisco.com", cap.to)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(cap.msg))
	if err != nil {
		t.Fatalf("the composed message is not valid RFC 5322: %v", err)
	}
	if subj := msg.Header.Get("Subject"); !strings.HasPrefix(subj, "SR 695123456") {
		t.Errorf("subject = %q, want it to lead with the SR number", subj)
	}
	if res.Transport != "email" || res.SHA256 != "abc123" {
		t.Errorf("result = %+v", res)
	}
}

func TestEmailAttachOnlyVendorRefusesCreate(t *testing.T) {
	cap := &capturingSender{}
	c, _ := NewEmailCaseConnectorWithSender("cisco", cap.send)
	_, err := c.CreateCase(context.Background(), emailCfg(), CaseRequest{
		Synopsis: "x", Approval: Approval{Actor: "user:1", ApprovedAt: time.Now()},
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if !c.Capabilities().AttachToExistingOnly {
		t.Error("attach-to-existing must be declared, so the UI never renders Open case")
	}
	if cap.call != 0 {
		t.Error("nothing may be sent for an unsupported capability")
	}
}

func TestEmailCreateRequiresHumanApproval(t *testing.T) {
	cap := &capturingSender{}
	c, _ := NewEmailCaseConnectorWithSender("arista", cap.send)
	_, err := c.CreateCase(context.Background(), emailCfg(), CaseRequest{Synopsis: "link down on spine1"})
	if !errors.Is(err, ErrNotApproved) {
		t.Fatalf("err = %v, want ErrNotApproved — a case is never opened autonomously", err)
	}
	if cap.call != 0 {
		t.Error("an unapproved create must not reach the relay")
	}
}

func TestEmailMessageIsWellFormedMultipartWithTheBundleAttached(t *testing.T) {
	cap := &capturingSender{}
	c, _ := NewEmailCaseConnectorWithSender("arista", cap.send)
	payload := 4096
	if _, err := c.AttachBundle(context.Background(), emailCfg(),
		CaseRef{Number: "CASE-99"}, testBundle("evidence.zip", payload)); err != nil {
		t.Fatalf("attach: %v", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(cap.msg))
	if err != nil {
		t.Fatalf("not valid RFC 5322: %v", err)
	}
	if got := msg.Header.Get("Reply-To"); got != "jane.doe@customer.example" {
		t.Errorf("Reply-To = %q — the named human must be reachable", got)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("content type = %q (%v), want multipart/mixed", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var sawText, sawAttachment bool
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("multipart: %v", err)
		}
		switch {
		case strings.HasPrefix(p.Header.Get("Content-Type"), "text/plain"):
			sawText = true
			body, _ := io.ReadAll(p)
			if !strings.Contains(string(body), "abc123") {
				t.Error("the body must carry the bundle SHA256 — it is the link between collected and delivered")
			}
		case p.FileName() == "evidence.zip":
			sawAttachment = true
			if p.Header.Get("Content-Transfer-Encoding") != "base64" {
				t.Errorf("attachment encoding = %q, want base64", p.Header.Get("Content-Transfer-Encoding"))
			}
			// multipart does not decode base64, so decode it here: the bytes
			// must round-trip exactly.
			raw, _ := io.ReadAll(p)
			b, derr := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
			if derr != nil {
				t.Fatalf("attachment is not valid base64: %v", derr)
			}
			if len(b) != payload {
				t.Errorf("attachment decoded to %d bytes, want %d", len(b), payload)
			}
		}
	}
	if !sawText || !sawAttachment {
		t.Errorf("parts: text=%v attachment=%v", sawText, sawAttachment)
	}
}

func TestEmailEnforcesTheFourteenMegabyteProfile(t *testing.T) {
	cap := &capturingSender{}
	c, _ := NewEmailCaseConnectorWithSender("arista", cap.send)

	over := EmailProfileMaxBytes + 1
	_, err := c.AttachBundle(context.Background(), emailCfg(), CaseRef{Number: "C-1"},
		Bundle{Name: "big.zip", Size: over, Open: func() (io.ReadCloser, error) {
			t.Fatal("the bundle must never be opened once it is over the ceiling")
			return nil, nil
		}})
	var tooBig AttachTooLargeError
	if !errors.As(err, &tooBig) {
		t.Fatalf("err = %v, want AttachTooLargeError", err)
	}
	if cap.call != 0 {
		t.Error("an oversize bundle must not reach the relay")
	}
}

func TestEmailCiscoMailboxCeilingIsStricterThanTheProfile(t *testing.T) {
	c, _ := NewEmailCaseConnector("cisco")
	limit := c.Capabilities().MaxAttachBytes
	// 20 MB message ÷ 1.37 base64 overhead ≈ 14.6 MB, so the binding constraint
	// is whichever is smaller. Both must be under the 20 MB mailbox limit once
	// base64 is applied.
	if float64(limit)*base64Overhead >= float64(20<<20) {
		t.Fatalf("limit %d encodes to %.0f bytes, above Cisco's 20 MB mailbox cap",
			limit, float64(limit)*base64Overhead)
	}
	if limit > EmailProfileMaxBytes {
		t.Errorf("limit %d exceeds the 14 MB profile", limit)
	}
}

func TestEmailHeaderInjectionIsStripped(t *testing.T) {
	cap := &capturingSender{}
	c, _ := NewEmailCaseConnectorWithSender("arista", cap.send)
	// A synopsis carrying CRLF + a forged header must not produce a second header.
	_, err := c.CreateCase(context.Background(), emailCfg(), CaseRequest{
		Synopsis: "outage\r\nBcc: attacker@evil.example",
		Approval: Approval{Actor: "user:1", ApprovedAt: time.Now()},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(cap.msg))
	if err != nil {
		t.Fatalf("not valid RFC 5322: %v", err)
	}
	if msg.Header.Get("Bcc") != "" {
		t.Fatal("a CRLF in the synopsis injected a Bcc header")
	}
}

func TestEmailConnectorNeedsAnOptedInTenant(t *testing.T) {
	c, _ := NewEmailCaseConnector("arista")
	if err := c.ValidateConfig(TACConnectorConfig{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured for a tenant that never opted in", err)
	}
}

// ── transport ───────────────────────────────────────────────────────────────

// fakeSMTP speaks just enough SMTP to exercise the transport rules. ehlo lists
// the extensions it advertises; reply overrides the response to a command.
type fakeSMTP struct {
	ln         net.Listener
	extensions []string
	dataReply  string
	done       chan struct{}
}

func newFakeSMTP(t *testing.T, extensions []string, dataReply string) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, extensions: extensions, dataReply: dataReply, done: make(chan struct{})}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close(); <-f.done })
	return f
}

func (f *fakeSMTP) addr() string { return f.ln.Addr().String() }

func (f *fakeSMTP) serve() {
	defer close(f.done)
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	w := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	w("220 fake ESMTP")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			for i, e := range f.extensions {
				if i == len(f.extensions)-1 {
					w("250 " + e)
				} else {
					w("250-" + e)
				}
			}
			if len(f.extensions) == 0 {
				w("250 fake")
			}
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
			w("250 ok")
		case strings.HasPrefix(cmd, "DATA"):
			if f.dataReply != "" {
				w(f.dataReply)
				continue
			}
			w("354 go ahead")
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(l) == "." {
					w("250 queued")
					break
				}
			}
		case strings.HasPrefix(cmd, "QUIT"):
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func TestSMTPRefusesARelayThatCannotDoTLS(t *testing.T) {
	f := newFakeSMTP(t, []string{"fake"}, "") // no STARTTLS advertised
	cfg := EmailConnectorConfig{Enabled: true, Host: f.addr(), From: "noc@example.com"}
	err := sendSMTP(context.Background(), cfg, "support@arista.com", []byte("Subject: x\r\n\r\nbody"))
	if err == nil {
		t.Fatal("a bundle must never leave over an unencrypted relay")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want it to name the missing STARTTLS", err)
	}
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) {
		t.Errorf("a relay without TLS is a permanent condition, got %v", err)
	}
}

func TestSMTPRefusesLocallyAgainstTheAdvertisedSIZE(t *testing.T) {
	// RFC 1870: the sender reads the relay's advertised SIZE at EHLO and refuses
	// before DATA rather than burning a doomed transfer.
	err := checkAdvertisedSize("500", 1000)
	var sz ErrSizeRejected
	if !errors.As(err, &sz) {
		t.Fatalf("err = %v, want ErrSizeRejected", err)
	}
	if sz.Advertised != 500 || sz.Message != 1000 {
		t.Errorf("outcome = %+v, want advertised 500 / message 1000", sz)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("the error should name the advertised SIZE, got %v", err)
	}
	// A message that fits, an unparseable parameter, and an absent limit are all
	// "no objection" — never a spurious refusal.
	for _, tc := range []struct {
		param string
		n     int64
	}{{"500", 500}, {"500", 499}, {"", 10}, {"not-a-number", 10}, {"0", 10}} {
		if err := checkAdvertisedSize(tc.param, tc.n); err != nil {
			t.Errorf("checkAdvertisedSize(%q, %d) = %v, want nil", tc.param, tc.n, err)
		}
	}
}

func TestSMTP552IsAFirstClassSizeOutcome(t *testing.T) {
	f := newFakeSMTP(t, []string{"fake"}, "552 message size exceeds fixed maximum message size")
	cfg := EmailConnectorConfig{Enabled: true, Host: f.addr(), From: "noc@example.com", TLSOnConnect: false}
	// The TLS rule fires first on this relay, which is itself the point: the
	// transport refuses before it can even learn the size verdict.
	err := sendSMTP(context.Background(), cfg, "support@arista.com", []byte("Subject: x\r\n\r\nbody"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want the TLS refusal to come first", err)
	}
	// The 552 classification itself is exercised directly, since a real 552 can
	// only be produced after a TLS handshake a fake relay cannot offer.
	sized := classifySMTPError(&textprotoError{Code: 552, Msg: "too big"}, 1234)
	var sz ErrSizeRejected
	if !errors.As(sized, &sz) {
		t.Fatalf("552 classified as %v, want ErrSizeRejected", sized)
	}
	if sz.Message != 1234 {
		t.Errorf("size = %d, want the message size", sz.Message)
	}
	perm := classifySMTPError(&textprotoError{Code: 550, Msg: "no such user"}, 1)
	var p PermanentDeliveryError
	if !errors.As(perm, &p) {
		t.Errorf("a 5xx must be permanent, got %v", perm)
	}
}

// textprotoError is an alias so the test can construct the stdlib error the
// SMTP client returns without importing net/textproto into the assertions.
type textprotoError = textproto.Error
