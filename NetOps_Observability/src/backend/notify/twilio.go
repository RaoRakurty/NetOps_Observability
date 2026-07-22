package notify

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netops/backend/models"
)

// Twilio sends SMS via the REST API. Requires an Account SID, an Auth
// Token, a Twilio phone number to send from, and at least one
// destination number. Numbers must be in E.164 format ("+15551234567").
//
// API: POST https://api.twilio.com/2010-04-01/Accounts/{SID}/Messages.json
// Auth: HTTP Basic — username = Account SID, password = Auth Token
type Twilio struct {
	accountSID string
	authToken  string
	from       string
	to         []string
	client     *http.Client
}

func NewTwilio(accountSID, authToken, from, recipients string) *Twilio {
	t := &Twilio{
		accountSID: accountSID,
		authToken:  authToken,
		from:       from,
		client:     &http.Client{Timeout: 15 * time.Second},
	}
	for _, r := range strings.Split(recipients, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			t.to = append(t.to, r)
		}
	}
	return t
}

func (t *Twilio) Name() string { return "twilio" }

func (t *Twilio) Send(a models.Alert) error {
	if t.accountSID == "" || t.authToken == "" || t.from == "" {
		return errors.New("twilio not fully configured (need SID, token, from)")
	}
	if len(t.to) == 0 {
		return errors.New("no twilio recipients configured")
	}

	body := smsBody(a)

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.accountSID)
	var firstErr error
	for _, dst := range t.to {
		form := url.Values{}
		form.Set("From", t.from)
		form.Set("To", dst)
		form.Set("Body", body)

		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(t.accountSID, t.authToken)

		resp, err := t.client.Do(req)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if resp.StatusCode >= 300 {
			// F-27 class: bounded error-body read (see sns.go).
			b, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyMaxBytes))
			resp.Body.Close()
			if firstErr == nil {
				firstErr = fmt.Errorf("twilio %d: %s", resp.StatusCode, string(b))
			}
			continue
		}
		resp.Body.Close()
	}
	return firstErr
}

// smsBody compresses the alert into ~140 chars so it lands as a single
// SMS segment when possible.
func smsBody(a models.Alert) string {
	prefix := fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), a.Rule)
	if a.DeviceID != "" {
		prefix += " @ " + a.DeviceID
	}
	if a.Summary == "" {
		return prefix
	}
	const max = 140
	full := prefix + ": " + a.Summary
	if len(full) <= max {
		return full
	}
	return full[:max-1] + "…"
}
