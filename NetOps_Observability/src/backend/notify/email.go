package notify

import (
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"netops/backend/models"
)

// Email sends alerts via SMTP. Configure with SMTP_HOST (host:port),
// SMTP_FROM, SMTP_USER, SMTP_PASS, and SMTP_TO (comma-separated list of
// destination addresses). Auth is PLAIN over STARTTLS — for providers
// that demand SSL-on-connect (port 465), set SMTP_TLS_ON_CONNECT=true
// and the dialer will wrap the conn before HELO.
type Email struct {
	host     string // "smtp.example.com:587"
	from     string
	user     string
	password string
	to       []string
}

func NewEmail(host, from string) *Email {
	return &Email{host: host, from: from}
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

	msg := buildRFC5322(e.from, e.to, subject, body)

	var auth smtp.Auth
	if e.user != "" {
		host, _, _ := net.SplitHostPort(e.host)
		auth = smtp.PlainAuth("", e.user, e.password, host)
	}
	return smtp.SendMail(e.host, auth, e.from, e.to, []byte(msg))
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

func buildRFC5322(from string, to []string, subject, body string) string {
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body
}
