// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package juniper is the wire client for Juniper's Service Case API
// (css-caseapi): open a service request, attach a file through the S3 token
// flow, and poll status.
//
// Like the cisco package this is a PROTOCOL client only; internal/ticketing
// wraps it as a CaseConnector.
//
// MATURITY: the API is marked **Beta** and its portal is a webMethods URL, not
// a stable *.juniper.net developer domain. Junos Space Service Now — the
// historical auto-open-a-JTAC-case mechanism — is EOL and must not be built on.
// The connector therefore fails CLOSED on schema drift rather than mis-filing a
// case (research §8.4).
//
// SOURCES (docs/design/TAC_CASE_OPENING_RESEARCH_2026-09-05.md §1, Juniper row)
//   - API catalog: https://jnprprod.devportal-aw-us.webmethods.io/portal/apis
//   - OpenAPI spec: https://jnprprod.devportal-aw-us.webmethods.io/portal/rest/v1/files/ea71e0db-1f98-4c24-a817-9f9648e64b20
//   - onboarding (issues appId + customerSourceID): https://onboarding-form-app.juniper.net
//   - JTAC user guide: https://support.juniper.net/sites/support/pdf/guidelines/jtac-user-guide.pdf
//
// DOCUMENTED CONSTRAINTS honoured here:
//   - OAuth2 client_credentials at
//     https://apigw.juniper.net/invoke/pub.apigateway.oauth2/getAccessToken
//     with scopes css-api-scope and css-phase2-scope; an API key in the
//     Authorization header is the alternative.
//   - problemDescription ≤ 15000 characters, synopsis ≤ 250.
//   - priority's legal values come from the API's own /getlov — never hard-coded.
//   - contactEmail must be a real person, not an alias (enforced by the caller).
//   - errors 600–614 are the ENTITLEMENT class (expired contract, no contract,
//     warranty-only, missing serial) and are surfaced verbatim.
//   - 1000 invocations per hour, hard.
//   - querysrlist covers the last 90 days only.
package juniper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pinned host and published paths.
const (
	// APIHost is the only host this client will talk to.
	APIHost = "apigw.juniper.net"
	// TokenPath is the published OAuth2 token endpoint.
	TokenPath = "/invoke/pub.apigateway.oauth2/getAccessToken" // #nosec G101 -- a published URL path, not a credential
	// ScopeCSSAPI / ScopeCSSPhase2 are the published scopes.
	ScopeCSSAPI    = "css-api-scope"
	ScopeCSSPhase2 = "css-phase2-scope"

	PathCreateSR           = "/createsr"
	PathAttachFile         = "/attachfile"
	PathGetFileUploadToken = "/getfileuploadtoken"
	PathQuerySRDetails     = "/querysrdetails"
	PathGetLOV             = "/getlov"
)

// Documented text caps.
const (
	MaxProblemDescription = 15000
	MaxSynopsis           = 250
)

// HourlyInvocationLimit is Juniper's hard block. The client refuses locally at
// the limit rather than burning the tenant's budget on a call it knows will be
// rejected (research §8.5).
const HourlyInvocationLimit = 1000

const (
	maxRespBytes  = 1 << 20
	callTimeout   = 45 * time.Second
	uploadTimeout = 30 * time.Minute
)

// Client is the Juniper wire client.
type Client struct {
	HTTP *http.Client
	// BasePath prefixes the published endpoint paths. The research cites the
	// endpoints as /createsr etc.; if a tenant's onboarding places them under a
	// prefix, it is configured rather than guessed. Must stay on APIHost.
	BasePath string

	baseOverride string // scheme+host for tests

	mu      sync.Mutex
	window  time.Time
	callsIn int
}

// NewForTest points the client at a fake gateway.
func NewForTest(httpc *http.Client, base string) *Client {
	return &Client{HTTP: httpc, baseOverride: base}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: callTimeout}
}

func (c *Client) base() string {
	if c.baseOverride != "" {
		return strings.TrimRight(c.baseOverride, "/")
	}
	return "https://" + APIHost + strings.TrimRight(c.BasePath, "/")
}

// budget enforces the documented 1000-invocations-per-hour ceiling.
func (c *Client) budget() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Sub(c.window) >= time.Hour {
		c.window, c.callsIn = now, 0
	}
	if c.callsIn >= HourlyInvocationLimit {
		return &RateLimitError{Until: c.window.Add(time.Hour)}
	}
	c.callsIn++
	return nil
}

// Auth is the per-request credential. Exactly one of Bearer / APIKey is set.
type Auth struct {
	Bearer string
	APIKey string
}

func (a Auth) apply(req *http.Request) error {
	switch {
	case strings.TrimSpace(a.Bearer) != "":
		req.Header.Set("Authorization", "Bearer "+a.Bearer)
	case strings.TrimSpace(a.APIKey) != "":
		// The published alternative: the API key travels in Authorization.
		req.Header.Set("Authorization", a.APIKey)
	default:
		return fmt.Errorf("%w: juniper: no credential supplied", ErrRequestInvalid)
	}
	return nil
}

// ── create ──────────────────────────────────────────────────────────────────

// CreateSRRequest carries ONLY field names cited in the research. Anything not
// cited is absent rather than invented.
type CreateSRRequest struct {
	AppID                       string `json:"appId"`
	CustomerSourceID            string `json:"customerSourceID"`
	UserID                      string `json:"userId"`
	AccountID                   string `json:"accountID"`
	Synopsis                    string `json:"synopsis"`
	ProblemDescription          string `json:"problemDescription"`
	Priority                    string `json:"priority"`
	ContactEmail                string `json:"contactEmail"`
	CaseTypeCode                string `json:"caseTypeCode,omitempty"`
	FollowUpMethod              string `json:"followUpMethod,omitempty"`
	SoftwareVersion             string `json:"softwareVersion"`
	SerialNumber                string `json:"serialNumber,omitempty"`
	NetworkOutage               *bool  `json:"networkOutage,omitempty"`
	CustomerUniqueTransactionID string `json:"customerUniqueTransactionID"`
}

// Validate applies the documented caps and required fields before a call.
func (r CreateSRRequest) Validate() error {
	// Ordered so the reported field is stable across runs.
	for _, f := range []struct{ name, value string }{
		{"appId", r.AppID},
		{"customerSourceID", r.CustomerSourceID},
		{"userId", r.UserID},
		{"accountID", r.AccountID},
		{"synopsis", r.Synopsis},
		{"problemDescription", r.ProblemDescription},
		{"priority", r.Priority},
		{"contactEmail", r.ContactEmail},
		{"customerUniqueTransactionID", r.CustomerUniqueTransactionID},
	} {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("%w: juniper: %s is required", ErrRequestInvalid, f.name)
		}
	}
	// Mandatory since 2024-05-16.
	if strings.TrimSpace(r.SoftwareVersion) == "" {
		return fmt.Errorf("%w: juniper: softwareVersion has been mandatory since 2024-05-16", ErrRequestInvalid)
	}
	if len([]rune(r.Synopsis)) > MaxSynopsis {
		return fmt.Errorf("%w: juniper: synopsis is %d characters, above the documented %d", ErrRequestInvalid, len([]rune(r.Synopsis)), MaxSynopsis)
	}
	if len([]rune(r.ProblemDescription)) > MaxProblemDescription {
		return fmt.Errorf("%w: juniper: problemDescription is %d characters, above the documented %d",
			ErrRequestInvalid, len([]rune(r.ProblemDescription)), MaxProblemDescription)
	}
	return nil
}

// CreateSRResponse is the create result.
type CreateSRResponse struct {
	SRNumber string `json:"srNumber"`
}

type srEnvelope struct {
	SRNumber     string `json:"srNumber"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// CreateSR opens a service request.
func (c *Client) CreateSR(ctx context.Context, auth Auth, req CreateSRRequest) (CreateSRResponse, error) {
	if err := req.Validate(); err != nil {
		return CreateSRResponse{}, err
	}
	raw, err := c.post(ctx, auth, PathCreateSR, req)
	if err != nil {
		return CreateSRResponse{}, err
	}
	var env srEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return CreateSRResponse{}, fmt.Errorf("%w: juniper: createsr returned a body that is not the documented envelope (the API is Beta — failing closed rather than mis-filing)", ErrRequestInvalid)
	}
	if err := vendorError(env.ErrorCode, env.ErrorMessage); err != nil {
		return CreateSRResponse{}, err
	}
	if strings.TrimSpace(env.SRNumber) == "" {
		return CreateSRResponse{}, errors.New("juniper: createsr succeeded but returned no srNumber")
	}
	return CreateSRResponse{SRNumber: env.SRNumber}, nil
}

// ── attach: getfileuploadtoken → S3 PUT → attachfile ────────────────────────

// UploadToken is the STS credential set /getfileuploadtoken hands back. The
// research documents the FLOW ("AWS S3 STS creds → client PUTs to S3 →
// /attachfile with documentPath") but not the JSON field names, so the parse
// accepts AWS's OWN published credential names in both casings and fails
// closed, naming the missing field, if the shape differs.
//
// These credentials are short-lived and per-upload: never persisted, never
// logged (research §8.6).
type UploadToken struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Bucket          string
	ObjectKey       string
	DocumentPath    string
}

// uploadTokenEnvelope binds both the camelCase and the AWS PascalCase spellings.
type uploadTokenEnvelope struct {
	AccessKeyID1     string `json:"accessKeyId"`
	AccessKeyID2     string `json:"AccessKeyId"`
	SecretAccessKey1 string `json:"secretAccessKey"`
	SecretAccessKey2 string `json:"SecretAccessKey"`
	SessionToken1    string `json:"sessionToken"`
	SessionToken2    string `json:"SessionToken"`
	Region1          string `json:"region"`
	Region2          string `json:"Region"`
	Bucket1          string `json:"bucket"`
	Bucket2          string `json:"Bucket"`
	Key1             string `json:"key"`
	Key2             string `json:"objectKey"`
	DocumentPath     string `json:"documentPath"`
	ErrorCode        string `json:"errorCode"`
	ErrorMessage     string `json:"errorMessage"`
}

// GetFileUploadToken requests the per-upload S3 credentials.
func (c *Client) GetFileUploadToken(ctx context.Context, auth Auth, srNumber, fileName string, sizeInBytes int64) (UploadToken, error) {
	if strings.TrimSpace(srNumber) == "" || strings.TrimSpace(fileName) == "" {
		return UploadToken{}, fmt.Errorf("%w: juniper: srNumber and fileName are required for an upload token", ErrRequestInvalid)
	}
	raw, err := c.post(ctx, auth, PathGetFileUploadToken, map[string]any{
		"srNumber": srNumber, "fileName": fileName, "sizeInBytes": sizeInBytes,
	})
	if err != nil {
		return UploadToken{}, err
	}
	var env uploadTokenEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return UploadToken{}, errors.New("juniper: getfileuploadtoken returned an unparseable body")
	}
	if err := vendorError(env.ErrorCode, env.ErrorMessage); err != nil {
		return UploadToken{}, err
	}
	t := UploadToken{
		AccessKeyID:     firstNonEmpty(env.AccessKeyID1, env.AccessKeyID2),
		SecretAccessKey: firstNonEmpty(env.SecretAccessKey1, env.SecretAccessKey2),
		SessionToken:    firstNonEmpty(env.SessionToken1, env.SessionToken2),
		Region:          firstNonEmpty(env.Region1, env.Region2),
		Bucket:          firstNonEmpty(env.Bucket1, env.Bucket2),
		ObjectKey:       firstNonEmpty(env.Key1, env.Key2, env.DocumentPath),
		DocumentPath:    firstNonEmpty(env.DocumentPath, env.Key1, env.Key2),
	}
	// Ordered, not a map range: the FIRST missing field must be named the same
	// way on every run, or an operator chasing a Beta-API schema change gets a
	// different error each time they retry.
	for _, f := range []struct{ name, value string }{
		{"access key id", t.AccessKeyID},
		{"secret access key", t.SecretAccessKey},
		{"region", t.Region},
		{"bucket", t.Bucket},
		{"object key", t.ObjectKey},
	} {
		if f.value == "" {
			// Fail closed and SAY WHICH field is missing: on a Beta API a silent
			// partial parse would upload nowhere and report success.
			return UploadToken{}, fmt.Errorf("%w: juniper: getfileuploadtoken response carried no %s — the upload flow cannot proceed",
				ErrRequestInvalid, f.name)
		}
	}
	return t, nil
}

// AttachFileRequest registers an uploaded object against the SR. documentPath
// and sizeInBytes are the two cited field names.
type AttachFileRequest struct {
	AppID                       string `json:"appId"`
	CustomerSourceID            string `json:"customerSourceID"`
	UserID                      string `json:"userId"`
	SRNumber                    string `json:"srNumber"`
	FileName                    string `json:"fileName"`
	DocumentPath                string `json:"documentPath"`
	SizeInBytes                 int64  `json:"sizeInBytes"`
	CustomerUniqueTransactionID string `json:"customerUniqueTransactionID"`
}

// AttachFile registers the uploaded object with the SR.
func (c *Client) AttachFile(ctx context.Context, auth Auth, req AttachFileRequest) error {
	if strings.TrimSpace(req.SRNumber) == "" || strings.TrimSpace(req.DocumentPath) == "" {
		return fmt.Errorf("%w: juniper: srNumber and documentPath are required", ErrRequestInvalid)
	}
	raw, err := c.post(ctx, auth, PathAttachFile, req)
	if err != nil {
		return err
	}
	var env srEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return errors.New("juniper: attachfile returned an unparseable body")
	}
	return vendorError(env.ErrorCode, env.ErrorMessage)
}

// ── status ──────────────────────────────────────────────────────────────────

// SRDetails is the poll result. querysrlist covers the last 90 days only; a
// case older than that simply is not returned, which the caller reports as
// "not found" rather than "closed".
type SRDetails struct {
	SRNumber  string
	Status    string
	UpdatedAt time.Time
}

type srDetailsEnvelope struct {
	SRNumber     string `json:"srNumber"`
	Status       string `json:"status"`
	LastUpdated  string `json:"lastUpdatedDate"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// QuerySRDetails polls one SR.
func (c *Client) QuerySRDetails(ctx context.Context, auth Auth, appID, customerSourceID, userID, srNumber string) (SRDetails, bool, error) {
	if strings.TrimSpace(srNumber) == "" {
		return SRDetails{}, false, fmt.Errorf("%w: juniper: srNumber is required", ErrRequestInvalid)
	}
	raw, err := c.post(ctx, auth, PathQuerySRDetails, map[string]any{
		"appId": appID, "customerSourceID": customerSourceID, "userId": userID, "srNumber": srNumber,
	})
	if err != nil {
		var se *StatusError
		if errors.As(err, &se) && se.Status == http.StatusNotFound {
			return SRDetails{}, false, nil
		}
		return SRDetails{}, false, err
	}
	var env srDetailsEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return SRDetails{}, false, errors.New("juniper: querysrdetails returned an unparseable body")
	}
	if err := vendorError(env.ErrorCode, env.ErrorMessage); err != nil {
		return SRDetails{}, false, err
	}
	if strings.TrimSpace(env.SRNumber) == "" && strings.TrimSpace(env.Status) == "" {
		return SRDetails{}, false, nil
	}
	d := SRDetails{SRNumber: firstNonEmpty(env.SRNumber, srNumber), Status: env.Status}
	if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(env.LastUpdated)); perr == nil {
		d.UpdatedAt = t.UTC()
	}
	return d, true, nil
}

// GetLOV fetches a list of values (e.g. the legal `priority` values). The
// research is explicit: FETCH it, never hard-code it.
func (c *Client) GetLOV(ctx context.Context, auth Auth, lovType string) ([]string, error) {
	raw, err := c.post(ctx, auth, PathGetLOV, map[string]any{"lovType": lovType})
	if err != nil {
		return nil, err
	}
	var env struct {
		Values       []string `json:"values"`
		ErrorCode    string   `json:"errorCode"`
		ErrorMessage string   `json:"errorMessage"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return nil, errors.New("juniper: getlov returned an unparseable body")
	}
	if err := vendorError(env.ErrorCode, env.ErrorMessage); err != nil {
		return nil, err
	}
	return env.Values, nil
}

// ── OAuth ───────────────────────────────────────────────────────────────────

// Token obtains an access token with the client_credentials grant and the two
// published scopes.
func (c *Client) Token(ctx context.Context, clientID, clientSecret string) (string, time.Duration, error) {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return "", 0, fmt.Errorf("%w: juniper: client_id and client_secret are required", ErrRequestInvalid)
	}
	body := map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"scope":         ScopeCSSAPI + " " + ScopeCSSPhase2,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return "", 0, fmt.Errorf("juniper: encode token request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+TokenPath, bytes.NewReader(b))
	if err != nil {
		return "", 0, fmt.Errorf("juniper: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		// The body carries the client secret; never let an error quote it.
		return "", 0, errors.New("juniper: token request failed")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, &StatusError{Op: "oauth token", Status: resp.StatusCode, Body: truncate(string(raw), 240)}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   any    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" {
		return "", 0, errors.New("juniper: token response carried no access_token")
	}
	return tok.AccessToken, expiresIn(tok.ExpiresIn), nil
}

func expiresIn(v any) time.Duration {
	switch t := v.(type) {
	case float64:
		if t > 0 {
			return time.Duration(t) * time.Second
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Hour
}

// ── plumbing ────────────────────────────────────────────────────────────────

func (c *Client) post(ctx context.Context, auth Auth, path string, body any) ([]byte, error) {
	if err := c.budget(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("juniper: encode request: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+path, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("juniper: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := auth.apply(req); err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("juniper: POST %s: request failed", path)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return raw, &StatusError{Op: "POST " + path, Status: resp.StatusCode,
			Body: truncate(string(raw), 240), RetryAfter: resp.Header.Get("Retry-After")}
	}
	return raw, nil
}

// ── errors ──────────────────────────────────────────────────────────────────

// ErrRequestInvalid marks a refusal made LOCALLY, before anything was sent —
// a documented cap exceeded, a required field missing, a response shape that
// does not match the pinned contract. Wrapped so the caller classifies it as
// permanent rather than retrying identical bad input.
var ErrRequestInvalid = errors.New("juniper: request refused before it was sent")

// StatusError is a non-2xx from the gateway.
type StatusError struct {
	Op         string
	Status     int
	Body       string
	RetryAfter string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("juniper: %s returned %d: %s", e.Op, e.Status, e.Body)
}

// EntitlementError is the 600–614 class: expired contract, no contract,
// warranty-only ("open a Technical SR via other channels"), missing serial.
// The vendor's own words are carried through untouched.
type EntitlementError struct {
	Code    string
	Message string
}

func (e *EntitlementError) Error() string {
	return fmt.Sprintf("juniper entitlement check failed (%s): %s", e.Code, e.Message)
}

// VendorError is any other in-band refusal.
type VendorError struct {
	Code    string
	Message string
}

func (e *VendorError) Error() string { return fmt.Sprintf("juniper: %s: %s", e.Code, e.Message) }

// RateLimitError is the local guard against the documented 1000/hour ceiling.
type RateLimitError struct{ Until time.Time }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("juniper: the documented 1000 invocations/hour budget is spent; it resets at %s",
		e.Until.UTC().Format(time.RFC3339))
}

// IsEntitlementCode reports whether a Juniper error code is in the documented
// entitlement class (600–614).
func IsEntitlementCode(code string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(code))
	return err == nil && n >= 600 && n <= 614
}

// vendorError turns an in-band {errorCode,errorMessage} into the right type.
func vendorError(code, msg string) error {
	code, msg = strings.TrimSpace(code), truncate(msg, 400)
	if code == "" && msg == "" {
		return nil
	}
	if IsEntitlementCode(code) {
		return &EntitlementError{Code: code, Message: msg}
	}
	return &VendorError{Code: orUnknown(code), Message: msg}
}

func orUnknown(s string) string {
	if s == "" {
		return "unspecified"
	}
	return s
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
