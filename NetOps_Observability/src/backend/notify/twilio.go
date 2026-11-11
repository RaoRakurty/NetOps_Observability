// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	// base is the REST API origin. Always DefaultTwilioAPIBase in production;
	// WithEndpoint exists so the senders can be driven against an httptest
	// server — a test must never send a real, billable SMS.
	base string
}

// DefaultTwilioAPIBase is Twilio's REST API origin.
const DefaultTwilioAPIBase = "https://api.twilio.com"

// maxSMSText bounds one message (§9). 160 characters is ONE billable GSM-7
// segment; Text() never sends more than that, so a pathological alert title
// cannot multiply the cost of a page.
const maxSMSText = 160

func NewTwilio(accountSID, authToken, from, recipients string) *Twilio {
	t := &Twilio{
		accountSID: accountSID,
		authToken:  authToken,
		from:       from,
		client:     &http.Client{Timeout: 15 * time.Second},
		base:       DefaultTwilioAPIBase,
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

// WithEndpoint points the sender at another REST origin (an httptest server).
// Returns the receiver so it composes with the constructor.
func (t *Twilio) WithEndpoint(base string) *Twilio {
	if b := strings.TrimRight(strings.TrimSpace(base), "/"); b != "" {
		t.base = b
	}
	return t
}

// messagesURL is the Messages resource for this account. The SID is
// path-escaped: it is operator input and must not be able to re-shape the path.
func (t *Twilio) messagesURL() string {
	return t.base + "/2010-04-01/Accounts/" + url.PathEscape(t.accountSID) + "/Messages.json"
}

// TwilioStatusError is a non-2xx answer from the Twilio API, carried as a TYPE
// so a caller with a retry policy (internal/alertwebhook) can tell "slow down"
// from "you are wrong" without parsing a message. Like NtfyStatusError it never
// carries the provider's response body: that body can echo the destination
// number and account detail, and a caller that logs or shows err.Error() must
// leak neither (§8).
type TwilioStatusError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *TwilioStatusError) Error() string { return fmt.Sprintf("twilio: status %d", e.Status) }

// RateLimited reports a refusal for budget reasons (429).
func (e *TwilioStatusError) RateLimited() bool { return e.Status == http.StatusTooManyRequests }

// Retryable reports whether re-sending the same message can succeed: 429 and
// 5xx only. A 4xx about the request (bad number, bad credential) never fixes
// itself, and retrying it only spends money and budget.
func (e *TwilioStatusError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// AuthRejected reports that Twilio refused the credentials.
func (e *TwilioStatusError) AuthRejected() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// RetryDelay is the server's own Retry-After, already clamped.
func (e *TwilioStatusError) RetryDelay() time.Duration { return e.RetryAfter }

// Text sends one already-composed message to every configured recipient. It
// is the platform self-health route's sender (internal/platformalert), which
// composes its own text from the alert tier; Send stays the product path.
//
// Differences from Send, all deliberate: the text is bounded to ONE segment,
// a failure is a typed *TwilioStatusError with no provider body in it, and a
// transport error never carries the request URL.
func (t *Twilio) Text(body string) error {
	if t.accountSID == "" || t.authToken == "" || t.from == "" {
		return errors.New("twilio not fully configured (need SID, token, from)")
	}
	if len(t.to) == 0 {
		return errors.New("no twilio recipients configured")
	}
	body = strings.TrimSpace(body)
	if body == "" {
		body = "Correlix platform alert"
	}
	if r := []rune(body); len(r) > maxSMSText {
		body = string(r[:maxSMSText-1]) + "…"
	}
	var firstErr error
	for _, dst := range t.to {
		if err := t.post(dst, body); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *Twilio) post(dst, body string) error {
	form := url.Values{}
	form.Set("From", t.from)
	form.Set("To", dst)
	form.Set("Body", body)
	req, err := http.NewRequest(http.MethodPost, t.messagesURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("twilio: could not build the request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.accountSID, t.authToken)
	resp, err := t.client.Do(req)
	if err != nil {
		// Never the *url.Error's own text: it embeds the request URL.
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			return fmt.Errorf("twilio: request failed: %w", ue.Err)
		}
		return errors.New("twilio: request failed")
	}
	// Drain a bounded amount so the connection can be reused; the content is
	// deliberately discarded (see TwilioStatusError).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errBodyMaxBytes)) // best-effort: connection reuse only
	_ = resp.Body.Close()                                                  // best-effort: nothing actionable on close failure
	if resp.StatusCode >= 300 {
		return &TwilioStatusError{Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	return nil
}

func (t *Twilio) Send(a models.Alert) error {
	if t.accountSID == "" || t.authToken == "" || t.from == "" {
		return errors.New("twilio not fully configured (need SID, token, from)")
	}
	if len(t.to) == 0 {
		return errors.New("no twilio recipients configured")
	}

	body := smsBody(a)

	endpoint := t.messagesURL()
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
			b, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyMaxBytes)) // best-effort: diagnostic snippet; a read error just leaves it empty
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
