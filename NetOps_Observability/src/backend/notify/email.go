package notify

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"

	"netops/backend/models"
)

// Email sends alerts via SMTP. Configure with SMTP_HOST (host:port),
// SMTP_FROM, SMTP_USER, SMTP_PASS, and SMTP_TO (comma-separated list of
// destination addresses). Auth is PLAIN over STARTTLS — for providers
// that demand SSL-on-connect (port 465), set SMTP_TLS_ON_CONNECT=true
// and the dialer will wrap the conn before HELO.
type Email struct {
	host         string // "smtp.example.com:587"
	from         string
	user         string
	password     string
	to           []string
	tlsOnConnect bool // true for SSL-on-connect (port 465)
}

func NewEmail(host, from string) *Email {
	return &Email{host: host, from: from}
}

// WithTLSOnConnect enables implicit TLS (SSL-on-connect, typically port 465)
// instead of STARTTLS. Required by Gmail:465, Office365 SSL, etc.
func (e *Email) WithTLSOnConnect(on bool) *Email {
	e.tlsOnConnect = on
	return e
}

// WithAuth sets PLAIN credentials. Safe to call after NewEmail.
func (e *Email) WithAuth(user, pass string) *Email {
	e.user, e.password = user, pass
	return e
}

// WithRecipients accepts either []string or a comma-separated string.
func (e *Email) WithRecipients(recipients string) *Email {
	for _, r := range strings.Split(recipients, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			e.to = append(e.to, r)
		}
	}
	return e
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(a models.Alert) error {
	if e.host == "" || e.from == "" {
		return errors.New("smtp host or sender not configured")
	}
	if len(e.to) == 0 {
		return errors.New("no recipients configured (SMTP_TO)")
	}

	subject := fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Rule)
	body := buildEmailBody(a)
	msg := buildRFC5322(e.from, e.to, subject, body, "text/plain; charset=UTF-8")
	return e.sendRaw([]byte(msg))
}

// SendDocument delivers a one-off message with an explicit subject and a body of
// the given MIME content type (e.g. "text/html; charset=UTF-8") to the configured
// recipients, reusing the same SMTP transport as Send. The reporting pipeline
// uses it to deliver a rendered HTML artifact as the email body; the alert Send
// path is unchanged.
func (e *Email) SendDocument(subject, contentType, body string) error {
	if e.host == "" || e.from == "" {
		return errors.New("smtp host or sender not configured")
	}
	if len(e.to) == 0 {
		return errors.New("no recipients configured")
	}
	if contentType == "" {
		contentType = "text/plain; charset=UTF-8"
	}
	msg := buildRFC5322(e.from, e.to, subject, body, contentType)
	return e.sendRaw([]byte(msg))
}

// Attachment is a file attached to a report email (e.g. an Excel or PDF export).
type Attachment struct {
	Filename    string
	ContentType string
	Bytes       []byte
}

// SendReport delivers an HTML-bodied email with optional file attachments
// (multipart/mixed), to the configured recipients via the shared transport. With
// no attachments it degrades to a plain HTML send. The reporting pipeline uses it
// so an Excel/PDF export rides along with the rendered report.
func (e *Email) SendReport(subject, htmlBody string, attachments []Attachment) error {
	if e.host == "" || e.from == "" {
		return errors.New("smtp host or sender not configured")
	}
	if len(e.to) == 0 {
		return errors.New("no recipients configured")
	}
	if len(attachments) == 0 {
		return e.SendDocument(subject, "text/html; charset=UTF-8", htmlBody)
	}
	msg, err := buildMixed(e.from, e.to, subject, htmlBody, attachments)
	if err != nil {
		return err
	}
	return e.sendRaw(msg)
}

// buildMixed assembles an RFC 5322 multipart/mixed message: an HTML body part
// plus base64-encoded attachment parts.
func buildMixed(from string, to []string, subject, htmlBody string, atts []Attachment) ([]byte, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	htmlHdr := textproto.MIMEHeader{}
	htmlHdr.Set("Content-Type", "text/html; charset=UTF-8")
	htmlHdr.Set("Content-Transfer-Encoding", "8bit")
	pw, err := mw.CreatePart(htmlHdr)
	if err != nil {
		return nil, err
	}
	if _, err := pw.Write([]byte(htmlBody)); err != nil {
		return nil, err
	}

	for _, a := range atts {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		ah := textproto.MIMEHeader{}
		ah.Set("Content-Type", ct)
		ah.Set("Content-Transfer-Encoding", "base64")
		ah.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", a.Filename))
		aw, err := mw.CreatePart(ah)
		if err != nil {
			return nil, err
		}
		enc := base64.StdEncoding.EncodeToString(a.Bytes)
		for i := 0; i < len(enc); i += 76 {
			end := i + 76
			if end > len(enc) {
				end = len(enc)
			}
			if _, err := aw.Write([]byte(enc[i:end] + "\r\n")); err != nil {
				return nil, err
			}
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	headers := "From: " + from + "\r\n" +
		"To: " + strings.Join(to, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"" + mw.Boundary() + "\"\r\n\r\n"
	return append([]byte(headers), body.Bytes()...), nil
}

// sendRaw applies auth and the STARTTLS / TLS-on-connect transport choice shared
// by Send and SendDocument.
func (e *Email) sendRaw(msg []byte) error {
	host, _, _ := net.SplitHostPort(e.host)
	var auth smtp.Auth
	if e.user != "" {
		auth = smtp.PlainAuth("", e.user, e.password, host)
	}
	if e.tlsOnConnect {
		return e.sendTLSOnConnect(host, auth, msg)
	}
	// STARTTLS path (port 587/25).
	return smtp.SendMail(e.host, auth, e.from, e.to, msg)
}

// sendTLSOnConnect dials an implicit-TLS connection (port 465) before HELO,
// which smtp.SendMail can't do on its own.
func (e *Email) sendTLSOnConnect(host string, auth smtp.Auth, msg []byte) error {
	conn, err := tls.Dial("tcp", e.host, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(e.from); err != nil {
		return err
	}
	for _, rcpt := range e.to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func buildEmailBody(a models.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Rule:     %s\n", a.Rule)
	fmt.Fprintf(&b, "Severity: %s\n", a.Severity)
	if a.DeviceID != "" {
		fmt.Fprintf(&b, "Device:   %s\n", a.DeviceID)
	}
	fmt.Fprintf(&b, "Fired:    %s\n", a.FiredAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintln(&b)
	if a.Summary != "" {
		fmt.Fprintln(&b, a.Summary)
	}
	if a.Description != "" {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, a.Description)
	}
	if len(a.Labels) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Labels:")
		for k, v := range a.Labels {
			fmt.Fprintf(&b, "  %s=%s\n", k, v)
		}
	}
	return b.String()
}

func buildRFC5322(from string, to []string, subject, body, contentType string) string {
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: " + contentType,
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}
