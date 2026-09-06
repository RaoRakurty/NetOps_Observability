// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package cisco is the wire client for Cisco's two case-facing services: CXD
// (attach a file to an existing SR) and Smart Bonding (open an SR).
//
// It is a PROTOCOL client only — no Correlix domain types, no config store, no
// audit. internal/ticketing wraps it as a CaseConnector. Keeping the dependency
// one-way means this package can be exercised against a fake Cisco without
// dragging the ticketing domain in, and internal/ticketing never imports a
// vendor's error vocabulary (CLAUDE.md §2, no cross-domain calls).
//
// THE CORRECTION THAT MADE THIS PACKAGE NECESSARY
// (docs/design/TAC_CASE_OPENING_RESEARCH_2026-09-05.md §1, Cisco row): the
// Support Case API v3 is READ-ONLY (GET only) and scoped to PSS partners. It
// does not open cases. Creation is Smart Bonding; attachment is CXD.
//
// SOURCES
//   - CXD: https://www.cisco.com/c/en/us/support/web/tac/tac-customer-file-uploads.html
//     PUT https://cxd.cisco.com/home/<file>, Basic auth = SR number / per-case
//     token, no size limit. The token is valid 72 days and is refreshable.
//   - Smart Bonding endpoints:
//     https://developer.cisco.com/docs/smart-bonding-customer-api/self-onboarding-guidance/
//   - Smart Bonding entitlement:
//     https://developer.cisco.com/docs/smart-bonding-customer-api/entitlement-information/
//     serial number (hardware) OR contract id + PID (software), plus the CCO-ID.
//   - Smart Bonding attachments (the create response carries the CXD host and
//     token as Field80 / Field81):
//     https://developer.cisco.com/docs/smart-bonding-customer-api/attachment-information/
//   - OAuth2 client_credentials token endpoint:
//     https://developer.cisco.com/docs/support-apis/authentication/
package cisco

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Pinned hosts. A tenant has no legitimate reason to point the Cisco connector
// at an arbitrary host, so these are constants, not configuration
// (research §5.5).
const (
	// CXDHost is the file-upload service.
	CXDHost = "cxd.cisco.com"
	// SmartBondingHost is the production Smart Bonding endpoint.
	SmartBondingHost = "sb.xylem.cisco.com"
	// TokenHost serves the OAuth2 client_credentials token (1 h TTL).
	TokenHost = "id.cisco.com" // #nosec G101 -- a published hostname, not a credential
	// DefaultTokenURL is the published token endpoint.
	DefaultTokenURL = "https://" + TokenHost + "/oauth2/default/v1/token"
	// PushPath is the Smart Bonding create/update call.
	PushPath = "/rest/v1/push/call"
	// PullPath is the customer-side status poll.
	PullPath = "/rest/v1/pull/call"
)

const (
	maxRespBytes  = 1 << 20
	callTimeout   = 30 * time.Second
	uploadTimeout = 30 * time.Minute // CXD publishes no size limit; the clock still bounds it
)

// Client is the Cisco wire client. baseOverride and cxdOverride exist ONLY so a
// test can point at an httptest server; production leaves them empty and the
// pinned hosts apply.
type Client struct {
	HTTP *http.Client
	// StagingHost, when set, replaces SmartBondingHost. Cisco does not publish
	// the staging hostname — it comes from the customer's onboarding project —
	// so the CALLER validates it against the cisco.com suffix before setting it.
	StagingHost string
	// baseOverride / cxdOverride: full scheme+host for tests.
	baseOverride string
	cxdOverride  string
}

// NewForTest points the client at fake Smart Bonding and CXD servers.
func NewForTest(httpc *http.Client, smartBondingBase, cxdBase string) *Client {
	return &Client{HTTP: httpc, baseOverride: smartBondingBase, cxdOverride: cxdBase}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: callTimeout}
}

func (c *Client) sbBase() string {
	if c.baseOverride != "" {
		return strings.TrimRight(c.baseOverride, "/")
	}
	if h := strings.TrimSpace(c.StagingHost); h != "" {
		return "https://" + strings.ToLower(h)
	}
	return "https://" + SmartBondingHost
}

func (c *Client) cxdBase(host string) string {
	if c.cxdOverride != "" {
		return strings.TrimRight(c.cxdOverride, "/")
	}
	// A create response may hand back its own CXD host (Field80). It is still
	// pinned: anything other than the published host is refused rather than
	// followed, so a compromised or spoofed response cannot redirect an upload.
	if h := strings.ToLower(strings.TrimSpace(host)); h != "" && h != CXDHost {
		return ""
	}
	return "https://" + CXDHost
}

// ── CXD attach ──────────────────────────────────────────────────────────────

// UploadCXD PUTs one file to an existing SR's upload area.
//
//	PUT https://cxd.cisco.com/home/<file>
//	Authorization: Basic base64(<SR number>:<token>)
//
// srNumber and token together ARE the credential; the token is per-SR, valid 72
// days, and must never be persisted or logged. size must be known so a
// Content-Length is sent and the local guard can bound the stream.
func (c *Client) UploadCXD(ctx context.Context, host, srNumber, token, fileName string, r io.Reader, size int64) error {
	if strings.TrimSpace(srNumber) == "" || strings.TrimSpace(token) == "" {
		return fmt.Errorf("%w: cisco cxd: the SR number and the per-case upload token are both required", ErrRequestInvalid)
	}
	if strings.TrimSpace(fileName) == "" {
		return fmt.Errorf("%w: cisco cxd: a file name is required", ErrRequestInvalid)
	}
	if r == nil || size <= 0 {
		return fmt.Errorf("%w: cisco cxd: a reader and a known size are required", ErrRequestInvalid)
	}
	base := c.cxdBase(host)
	if base == "" {
		return fmt.Errorf("%w: cisco cxd: upload host %q is not the pinned %s", ErrRequestInvalid, host, CXDHost)
	}
	u, err := url.Parse(base + "/home/" + url.PathEscape(fileName))
	if err != nil {
		return fmt.Errorf("%w: cisco cxd: bad upload url", ErrRequestInvalid)
	}

	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), io.LimitReader(r, size))
	if err != nil {
		return fmt.Errorf("cisco cxd: build request: %w", err)
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.SetBasicAuth(srNumber, token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		// Never echo err: it can embed the URL, and the credential rides the
		// Authorization header only. Say what failed, not how.
		return errors.New("cisco cxd: PUT /home/<file>: request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Op: "cxd upload", Status: resp.StatusCode, Body: truncate(string(body), 240),
			RetryAfter: resp.Header.Get("Retry-After")}
	}
	return nil
}

// ── Smart Bonding ───────────────────────────────────────────────────────────

// Entitlement is the create-time proof of support coverage. Cisco accepts a
// serial number for hardware OR a contract id + PID for software, and requires
// the CCO-ID in both cases.
type Entitlement struct {
	CCOID        string
	SerialNumber string
	ContractID   string
	PID          string
}

// Validate enforces the documented rule BEFORE a call is made, so an
// unentitled create fails locally with a message the operator can act on
// instead of a vendor round-trip (research §8.1).
func (e Entitlement) Validate() error {
	if strings.TrimSpace(e.CCOID) == "" {
		return errors.New("cisco: the CCO-ID is required on every case")
	}
	hasSerial := strings.TrimSpace(e.SerialNumber) != ""
	hasContract := strings.TrimSpace(e.ContractID) != "" && strings.TrimSpace(e.PID) != ""
	if !hasSerial && !hasContract {
		return errors.New("cisco: entitlement needs a serial number (hardware) or a contract id + PID (software)")
	}
	return nil
}

// CreateRequest is what the connector hands the client. Fields carries the
// case body keyed by the field names the TENANT's onboarding project issued —
// Cisco does not publish the push/call request schema, so nothing here invents
// one (see FieldMap in the connector config).
type CreateRequest struct {
	Entitlement Entitlement
	// CustomerCaseNumber and CustomerUniqueTransactionID are the two request
	// field names the research does cite (§7, Cisco). The transaction id is the
	// idempotency key: Cisco treats a repeat as an update, not a new case.
	CustomerCaseNumber          string
	CustomerUniqueTransactionID string
	Fields                      map[string]string
}

// CreateResponse is the create result. Field80/Field81 are Cisco's own names
// for the CXD host and per-case upload token returned with a new SR, which is
// what closes the create → attach loop.
type CreateResponse struct {
	SRNumber  string
	CXDHost   string
	CXDToken  string
	RawStatus string
}

// createEnvelope is the JSON shape we parse back. Only the cited names are
// bound; anything else the tenant's onboarding defines rides in Extra and is
// never interpreted here.
type createEnvelope struct {
	SRNumber     string `json:"srNumber"`
	ServiceReqID string `json:"serviceRequestId"`
	Field80      string `json:"Field80"`
	Field81      string `json:"Field81"`
	Status       string `json:"status"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// CreateCase POSTs the Smart Bonding push/call. bearer is the OAuth token the
// caller already obtained (Token below); the auth model for the Smart Bonding
// proxy is not published on the public pages, so the token is passed through
// as a bearer exactly as issued and nothing about it is guessed.
func (c *Client) CreateCase(ctx context.Context, bearer string, req CreateRequest) (CreateResponse, error) {
	if err := req.Entitlement.Validate(); err != nil {
		return CreateResponse{}, err
	}
	if strings.TrimSpace(req.CustomerUniqueTransactionID) == "" {
		return CreateResponse{}, fmt.Errorf("%w: cisco: customerUniqueTransactionID is required (Cisco treats a repeat as an update, not a new case)", ErrRequestInvalid)
	}
	body := map[string]any{
		"customerUniqueTransactionID": req.CustomerUniqueTransactionID,
	}
	if req.CustomerCaseNumber != "" {
		body["customerCaseNumber"] = req.CustomerCaseNumber
	}
	for k, v := range req.Fields {
		if k == "" {
			continue
		}
		body[k] = v
	}
	raw, status, err := c.call(ctx, bearer, PushPath, body)
	if err != nil {
		return CreateResponse{}, err
	}
	var env createEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return CreateResponse{}, fmt.Errorf("cisco: push/call returned %d with a body that is not the documented envelope", status)
	}
	if env.ErrorCode != "" || env.ErrorMessage != "" {
		return CreateResponse{}, &VendorError{Code: env.ErrorCode, Message: truncate(env.ErrorMessage, 400)}
	}
	sr := firstNonEmpty(env.SRNumber, env.ServiceReqID)
	if sr == "" {
		return CreateResponse{}, errors.New("cisco: push/call succeeded but returned no SR number")
	}
	return CreateResponse{SRNumber: sr, CXDHost: env.Field80, CXDToken: env.Field81, RawStatus: env.Status}, nil
}

// pullEnvelope is the status poll's answer.
type pullEnvelope struct {
	SRNumber  string `json:"srNumber"`
	Status    string `json:"status"`
	UpdatedAt string `json:"lastModifiedDate"`
}

// CaseStatus polls pull/call for one SR. Smart Bonding is a PULL model — there
// is no webhook (research §6).
type CaseStatus struct {
	SRNumber  string
	Status    string
	UpdatedAt time.Time
}

// FetchCase polls one SR's status.
func (c *Client) FetchCase(ctx context.Context, bearer, srNumber string) (CaseStatus, bool, error) {
	if strings.TrimSpace(srNumber) == "" {
		return CaseStatus{}, false, fmt.Errorf("%w: cisco: a SR number is required", ErrRequestInvalid)
	}
	raw, _, err := c.call(ctx, bearer, PullPath, map[string]any{"srNumber": srNumber})
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return CaseStatus{}, false, nil
		}
		return CaseStatus{}, false, err
	}
	var env pullEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return CaseStatus{}, false, errors.New("cisco: pull/call returned an unexpected body")
	}
	if env.SRNumber == "" && env.Status == "" {
		return CaseStatus{}, false, nil
	}
	st := CaseStatus{SRNumber: firstNonEmpty(env.SRNumber, srNumber), Status: env.Status}
	if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(env.UpdatedAt)); perr == nil {
		st.UpdatedAt = t.UTC()
	}
	return st, true, nil
}

// call performs one bounded, authenticated Smart Bonding request.
func (c *Client) call(ctx context.Context, bearer, path string, body map[string]any) ([]byte, int, error) {
	if strings.TrimSpace(bearer) == "" {
		return nil, 0, fmt.Errorf("%w: cisco: a Smart Bonding access token is required", ErrRequestInvalid)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("cisco: encode request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sbBase()+path, bytes.NewReader(b))
	if err != nil {
		return nil, 0, fmt.Errorf("cisco: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("cisco: POST %s: request failed", path)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return raw, resp.StatusCode, &StatusError{Op: "POST " + path, Status: resp.StatusCode,
			Body: truncate(string(raw), 240), RetryAfter: resp.Header.Get("Retry-After")}
	}
	return raw, resp.StatusCode, nil
}

// ── OAuth2 ──────────────────────────────────────────────────────────────────

// Token obtains an access token with the client_credentials grant. tokenURL
// must already be validated against the pinned host allowlist by the caller;
// the default is DefaultTokenURL. The token TTL is 1 hour.
func (c *Client) Token(ctx context.Context, tokenURL, clientID, clientSecret string) (string, time.Duration, error) {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return "", 0, fmt.Errorf("%w: cisco: client_id and client_secret are required", ErrRequestInvalid)
	}
	if strings.TrimSpace(tokenURL) == "" {
		tokenURL = DefaultTokenURL
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("cisco: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		// The form body carries the client secret; never let an error quote it.
		return "", 0, errors.New("cisco: token request failed")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, &StatusError{Op: "oauth token", Status: resp.StatusCode, Body: truncate(string(raw), 240)}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" {
		return "", 0, errors.New("cisco: token response carried no access_token")
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour // the documented TTL
	}
	return tok.AccessToken, ttl, nil
}

// ── errors ──────────────────────────────────────────────────────────────────

// ErrRequestInvalid marks a refusal made LOCALLY, before anything was sent:
// a missing credential, an unknown upload host, a malformed argument. It is
// wrapped so the caller can classify it as permanent — retrying identical bad
// input cannot succeed, and a retry loop around it just makes an operator wait.
var ErrRequestInvalid = errors.New("cisco: request refused before it was sent")

// StatusError is a non-2xx from Cisco. Body is a bounded snippet; no request
// header, and therefore no credential, is ever in it.
type StatusError struct {
	Op         string
	Status     int
	Body       string
	RetryAfter string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("cisco: %s returned %d: %s", e.Op, e.Status, e.Body)
}

// VendorError is Cisco's own in-band refusal (entitlement, validation). The
// message is surfaced VERBATIM to the operator (research §8.1).
type VendorError struct {
	Code    string
	Message string
}

func (e *VendorError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("cisco: %s: %s", e.Code, e.Message)
	}
	return "cisco: " + e.Message
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
