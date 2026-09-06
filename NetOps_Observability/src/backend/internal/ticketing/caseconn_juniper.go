// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_juniper.go — Juniper Service Case API as a CaseConnector.
//
// Technically the best-designed target in the study: OAuth2 client_credentials,
// POST /createsr, a three-step attachment flow with no documented byte cap, and
// a real status poll. It is ranked below Cisco only because it is marked Beta,
// its onboarding is a form-and-email process, and it hard-fails on entitlement
// (errors 600–614) — which is precisely why EntitlementError carries Juniper's
// verbatim message to the operator instead of a generic failure.
//
// THE NAMED-HUMAN RULE is enforced here, not left to the UI: Juniper's own doc
// requires contactEmail to be "a real person and not an alias", so a create
// with a shared mailbox is refused locally rather than filed and bounced.
//
// The `publishSR` webhook receiver is W3's; this connector polls.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/ticketing/vendors/juniper"
	"netops/backend/safehttp"
)

// juniperHostAllowlist is the PINNED host set (research §5.5).
func juniperHostAllowlist() []string { return []string{juniper.APIHost} }

// JuniperConnector implements create + attach + poll.
type JuniperConnector struct {
	client *juniper.Client
	retry  RetryPolicy

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewJuniperConnector builds the connector. Pass a test client to drive it
// against a fake gateway.
func NewJuniperConnector(c *juniper.Client) *JuniperConnector {
	if c == nil {
		c = &juniper.Client{HTTP: safehttp.Client(45 * time.Second)}
	}
	return &JuniperConnector{client: c, retry: DefaultCaseRetry()}
}

func (c *JuniperConnector) Name() string { return "juniper" }

func (c *JuniperConnector) Capabilities() Caps {
	return Caps{
		Create: true, Attach: true, Poll: true, Note: false,
		// publishSR is a real webhook, but the receiver route is W3's; declaring
		// it here would promise a surface that does not exist yet.
		Webhook:             false,
		MaxAttachBytes:      0, // sizeInBytes is unvalidated and no cap is published
		RequiresEntitlement: true,
		// SeverityValues is deliberately EMPTY: priority's legal values come from
		// the API's own /getlov and must be fetched, never hard-coded. Use
		// FetchSeverityValues.
		SeverityValues: nil,
		Notes:          "Beta API. Per-customer onboarding issues appId + customerSourceID, and userId must be a registered Customer Service Portal user. contactEmail must be a named human, not an alias. Entitlement is hard-checked at create (errors 600–614). Hard limit of 1000 invocations per hour. querysrlist covers the last 90 days only; priority values come from /getlov",
	}
}

func (c *JuniperConnector) ValidateConfig(cfg TACConnectorConfig) error {
	if !cfg.Juniper.Enabled {
		return ErrNotConfigured
	}
	return validateJuniperConfig(cfg.Juniper)
}

// FetchSeverityValues fetches the legal `priority` values from /getlov. The
// research is explicit that this list must be fetched, never hard-coded.
func (c *JuniperConnector) FetchSeverityValues(ctx context.Context, cfg TACConnectorConfig) ([]string, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return nil, err
	}
	auth, err := c.auth(ctx, cfg)
	if err != nil {
		return nil, err
	}
	vals, err := c.client.GetLOV(ctx, auth, "priority")
	return vals, translateJuniperError(err)
}

func (c *JuniperConnector) CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return CaseRef{}, err
	}
	if !req.Approval.Valid() {
		return CaseRef{}, ErrNotApproved
	}
	contact := orDefault(req.ContactEmail, cfg.Juniper.DefaultContactEmail)
	if !isNamedHumanEmail(contact) {
		return CaseRef{}, PermanentDeliveryError{errors.New(
			"juniper: contactEmail must be a real person, not a shared alias — Juniper's API requires a named human on the case")}
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		return CaseRef{}, PermanentDeliveryError{errors.New("juniper: an idempotency key is required (it becomes customerUniqueTransactionID)")}
	}
	// softwareVersion has been mandatory since 2024-05-16.
	sw := strings.TrimSpace(req.Fields["software_version"])
	if sw == "" {
		return CaseRef{}, PermanentDeliveryError{errors.New(
			"juniper: softwareVersion is mandatory (since 2024-05-16) — supply the device's Junos version")}
	}
	create := juniper.CreateSRRequest{
		AppID:                       cfg.Juniper.AppID,
		CustomerSourceID:            cfg.Juniper.CustomerSourceID,
		UserID:                      cfg.Juniper.UserID,
		AccountID:                   cfg.Juniper.AccountID,
		Synopsis:                    req.Synopsis,
		ProblemDescription:          req.Description,
		Priority:                    req.Severity,
		ContactEmail:                contact,
		CaseTypeCode:                req.Fields["case_type_code"],
		FollowUpMethod:              req.Fields["follow_up_method"],
		SoftwareVersion:             sw,
		SerialNumber:                req.SerialNumber,
		CustomerUniqueTransactionID: req.IdempotencyKey,
	}
	// networkOutage applies to P1 technical SRs only, so it is sent only when
	// the operator set it — an unset optional stays absent, not false.
	if v, ok := req.Fields["network_outage"]; ok {
		outage := strings.EqualFold(strings.TrimSpace(v), "true")
		create.NetworkOutage = &outage
	}

	out, err := withRetry(ctx, c.retry, req.IdempotencyKey, func(ctx context.Context) (juniper.CreateSRResponse, error) {
		auth, aerr := c.auth(ctx, cfg)
		if aerr != nil {
			return juniper.CreateSRResponse{}, aerr
		}
		res, cerr := c.client.CreateSR(ctx, auth, create)
		return res, translateJuniperError(cerr)
	})
	if err != nil {
		return CaseRef{}, err
	}
	return CaseRef{ID: out.SRNumber, Number: out.SRNumber,
		URL: "https://support.juniper.net/support/requests/" + out.SRNumber}, nil
}

// AttachBundle runs the documented three-step flow: getfileuploadtoken → S3 PUT
// (SigV4, with the STS credentials the token carried) → attachfile with the
// documentPath. The STS credentials are per-upload and never persisted.
func (c *JuniperConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return AttachResult{}, err
	}
	sr := strings.TrimSpace(orDefault(ref.Number, ref.ID))
	if sr == "" {
		return AttachResult{}, PermanentDeliveryError{errors.New("juniper: the SR number is required")}
	}
	caps := c.Capabilities()
	if err := checkBundle("juniper", b, caps.AttachLimit(),
		"Juniper publishes no attachment size cap; this is Correlix's own runaway guard"); err != nil {
		return AttachResult{}, err
	}
	name := sanitizeFileName(b.Name)

	res, err := withRetry(ctx, c.retry, sr+":"+b.SHA256, func(ctx context.Context) (AttachResult, error) {
		auth, aerr := c.auth(ctx, cfg)
		if aerr != nil {
			return AttachResult{}, aerr
		}
		tok, terr := c.client.GetFileUploadToken(ctx, auth, sr, name, b.Size)
		if terr != nil {
			return AttachResult{}, translateJuniperError(terr)
		}
		if perr := c.client.PutObject(ctx, tok, orDefault(b.ContentType, "application/zip"), b.Open, b.Size); perr != nil {
			return AttachResult{}, translateJuniperError(perr)
		}
		if aerr := c.client.AttachFile(ctx, auth, juniper.AttachFileRequest{
			AppID:                       cfg.Juniper.AppID,
			CustomerSourceID:            cfg.Juniper.CustomerSourceID,
			UserID:                      cfg.Juniper.UserID,
			SRNumber:                    sr,
			FileName:                    name,
			DocumentPath:                tok.DocumentPath,
			SizeInBytes:                 b.Size,
			CustomerUniqueTransactionID: b.SHA256,
		}); aerr != nil {
			return AttachResult{}, translateJuniperError(aerr)
		}
		return AttachResult{ID: sr, Name: name, Size: b.Size, SHA256: b.SHA256,
			At: time.Now().UTC(), Transport: "juniper-s3"}, nil
	})
	if err != nil {
		return AttachResult{}, err
	}
	return res, nil
}

func (c *JuniperConnector) FetchCase(ctx context.Context, cfg TACConnectorConfig, ref CaseRef) (RemoteCase, bool, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return RemoteCase{}, false, err
	}
	auth, err := c.auth(ctx, cfg)
	if err != nil {
		return RemoteCase{}, false, err
	}
	sr := orDefault(ref.Number, ref.ID)
	d, found, err := c.client.QuerySRDetails(ctx, auth, cfg.Juniper.AppID, cfg.Juniper.CustomerSourceID, cfg.Juniper.UserID, sr)
	if err != nil {
		return RemoteCase{}, false, translateJuniperError(err)
	}
	if !found {
		// querysrlist covers the last 90 days; older is absent, not closed.
		return RemoteCase{}, false, nil
	}
	return RemoteCase{ID: d.SRNumber, Number: d.SRNumber, Status: d.Status, UpdatedAt: d.UpdatedAt, URL: ref.URL}, true, nil
}

func (c *JuniperConnector) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	// /updatesr exists but its request schema is not cited in the research, and
	// a mis-shaped update on a live support case is worse than no note.
	return fmt.Errorf("%w: adding a note maps to /updatesr, whose request schema is not in the pinned contract", ErrUnsupported)
}

// auth resolves the per-request credential: a cached OAuth token, or the API key.
func (c *JuniperConnector) auth(ctx context.Context, cfg TACConnectorConfig) (juniper.Auth, error) {
	if strings.EqualFold(strings.TrimSpace(cfg.Juniper.AuthMode), "apikey") {
		return juniper.Auth{APIKey: cfg.Juniper.APIKey}, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires.Add(-time.Minute)) {
		return juniper.Auth{Bearer: c.token}, nil
	}
	// The token endpoint is on the pinned host by construction; assert it.
	if err := validatePinnedURL("https://"+juniper.APIHost+juniper.TokenPath, juniperHostAllowlist()); err != nil {
		return juniper.Auth{}, PermanentDeliveryError{err}
	}
	tok, ttl, err := c.client.Token(ctx, cfg.Juniper.ClientID, cfg.Juniper.ClientSecret)
	if err != nil {
		return juniper.Auth{}, translateJuniperError(err)
	}
	c.token, c.expires = tok, time.Now().Add(ttl)
	return juniper.Auth{Bearer: tok}, nil
}

var _ CaseConnector = (*JuniperConnector)(nil)

// translateJuniperError maps the vendor client's vocabulary onto the
// connector's retry semantics, keeping Juniper's own words.
func translateJuniperError(err error) error {
	if err == nil {
		return nil
	}
	// A refusal made locally, before anything was sent, is permanent: retrying
	// identical bad input only makes the operator wait.
	if errors.Is(err, juniper.ErrRequestInvalid) {
		return PermanentDeliveryError{err}
	}
	var ent *juniper.EntitlementError
	if errors.As(err, &ent) {
		return EntitlementError{Vendor: "juniper", Code: ent.Code, VendorMsg: ent.Message}
	}
	var ve *juniper.VendorError
	if errors.As(err, &ve) {
		return PermanentDeliveryError{err}
	}
	var rl *juniper.RateLimitError
	if errors.As(err, &rl) {
		return RateLimitedError{After: time.Until(rl.Until)}
	}
	var se *juniper.StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case http.StatusTooManyRequests:
			return RateLimitedError{After: parseRetryAfterSeconds(se.RetryAfter, 60*time.Second)}
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			return PermanentDeliveryError{err}
		}
	}
	return err
}
