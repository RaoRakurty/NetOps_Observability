package ticketing

// caseconn_cisco.go — Cisco in two halves, attach FIRST (research §4.4).
//
//	CiscoCXDConnector          attach-to-existing-SR, no size limit, needs only
//	                           the SR number + the per-case token the admin
//	                           copies out of SCM. The low-friction Cisco entry
//	                           point; ship-able without any onboarding project.
//	CiscoSmartBondingConnector open an SR. Requires a completed per-customer
//	                           onboarding project; the create response carries
//	                           the CXD host + token (Field80/Field81) so
//	                           create → attach closes the loop.
//
// WHAT IS DELIBERATELY NOT BUILT: Cisco does not publish the Smart Bonding
// push/call REQUEST SCHEMA on its public pages — only the entitlement inputs,
// two request field names (customerCaseNumber, customerUniqueTransactionID) and
// the two response fields. Rather than guess field names for the case body,
// the connector requires a FieldMap issued by the tenant's onboarding project
// and fails closed with ErrNotOnboarded when it is missing. Guessing here would
// mis-file a real support case against a real contract.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/ticketing/vendors/cisco"
	"netops/backend/safehttp"
)

// ciscoHostAllowlist is the PINNED set of hosts the Cisco connector may reach.
// A tenant cannot point it anywhere else (research §5.5). staging, when the
// tenant's onboarding issued one, is admitted only after the cisco.com-suffix
// check in validateCiscoConfig.
func ciscoHostAllowlist(staging string) []string {
	hosts := []string{cisco.CXDHost, cisco.SmartBondingHost, cisco.TokenHost}
	if s := strings.ToLower(strings.TrimSpace(staging)); s != "" {
		hosts = append(hosts, s)
	}
	return hosts
}

// ciscoCanonicalFields are the case-body fields a Smart Bonding create needs
// from us. Each must be bound to the tenant's own request field name through
// FieldMap; an unmapped one is a hard, honest refusal.
var ciscoCanonicalFields = []string{
	"synopsis", "description", "severity", "contact_email", "contact_name",
	"cco_id", "serial_number", "contract_id", "pid",
}

// ── CXD attach ──────────────────────────────────────────────────────────────

// CiscoCXDConnector uploads a bundle to an existing SR.
type CiscoCXDConnector struct {
	client *cisco.Client
	retry  RetryPolicy
}

// NewCiscoCXDConnector builds the CXD connector. Pass a test client to drive it
// against a fake CXD.
func NewCiscoCXDConnector(c *cisco.Client) *CiscoCXDConnector {
	if c == nil {
		c = &cisco.Client{HTTP: safehttp.Client(30 * time.Second)}
	}
	return &CiscoCXDConnector{client: c, retry: DefaultCaseRetry()}
}

func (c *CiscoCXDConnector) Name() string { return "cisco-cxd" }

func (c *CiscoCXDConnector) Capabilities() Caps {
	return Caps{
		Create: false, Attach: true, Poll: false, Note: false,
		AttachToExistingOnly: true,
		// Cisco documents NO size limit on CXD (the SCM browser upload says "No
		// limit" too). 0 means exactly that; AttachLimit() still applies the
		// local runaway guard.
		MaxAttachBytes:      0,
		RequiresEntitlement: false,
		SeverityValues:      ciscoSeverities(),
		Notes:               "attach-to-existing-SR only. The admin supplies the SR number and the per-case upload token from Support Case Manager; the token is valid 72 days, is never persisted by Correlix, and is the only path in this study with no file-size limit at all",
	}
}

// ciscoSeverities is Cisco's own published S1–S4 vocabulary (research §2). It
// is a DISPLAY vocabulary: the operator picks, Correlix never translates.
func ciscoSeverities() []string {
	return []string{
		"S1 — Critical impact (system down)",
		"S2 — Substantial impact (degradation)",
		"S3 — Minimal impact (partial degradation)",
		"S4 — No impact (informational)",
	}
}

func (c *CiscoCXDConnector) ValidateConfig(cfg TACConnectorConfig) error {
	if !cfg.Cisco.Enabled {
		return ErrNotConfigured
	}
	// CXD needs NO stored credential: the SR number and token are per-case and
	// arrive on the request. That is what makes it the low-friction entry point.
	return nil
}

func (c *CiscoCXDConnector) CreateCase(context.Context, TACConnectorConfig, CaseRequest) (CaseRef, error) {
	return CaseRef{}, fmt.Errorf("%w: CXD attaches to an existing SR; open the case in Support Case Manager or through Smart Bonding first", ErrUnsupported)
}

// AttachBundle PUTs the bundle. ref.Number is the SR number and
// ref.UploadToken the per-case CXD token — both ephemeral, neither logged.
func (c *CiscoCXDConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return AttachResult{}, err
	}
	sr := strings.TrimSpace(orDefault(ref.Number, ref.ID))
	if sr == "" {
		return AttachResult{}, PermanentDeliveryError{errors.New("cisco cxd: the SR number is required")}
	}
	if strings.TrimSpace(ref.UploadToken) == "" {
		return AttachResult{}, PermanentDeliveryError{errors.New("cisco cxd: the per-case upload token from Support Case Manager is required")}
	}
	caps := c.Capabilities()
	if err := checkBundle("cisco-cxd", b, caps.AttachLimit(),
		"Cisco documents no CXD size limit; this is Correlix's own runaway guard"); err != nil {
		return AttachResult{}, err
	}
	name := sanitizeFileName(b.Name)
	res, err := attachWithRetry(ctx, c.retry, b, func(ctx context.Context, rc readCloser) (AttachResult, error) {
		if err := c.client.UploadCXD(ctx, ref.UploadHost, sr, ref.UploadToken, name, rc, b.Size); err != nil {
			return AttachResult{}, translateCiscoError(err)
		}
		return AttachResult{Name: name, Size: b.Size, Transport: "cisco-cxd"}, nil
	}, b.SHA256)
	if err != nil {
		return AttachResult{}, err
	}
	res.ID = sr
	return res, nil
}

func (c *CiscoCXDConnector) FetchCase(context.Context, TACConnectorConfig, CaseRef) (RemoteCase, bool, error) {
	return RemoteCase{}, false, fmt.Errorf("%w: CXD is an upload service with no case-status surface", ErrUnsupported)
}

func (c *CiscoCXDConnector) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	return fmt.Errorf("%w: CXD cannot add a note to an SR", ErrUnsupported)
}

var _ CaseConnector = (*CiscoCXDConnector)(nil)

// ── Smart Bonding create ────────────────────────────────────────────────────

// CiscoSmartBondingConnector opens an SR and, when the create response carries
// them, hands the CXD host and token straight back on the CaseRef so the caller
// can attach without a second credential prompt.
type CiscoSmartBondingConnector struct {
	client *cisco.Client
	cxd    *CiscoCXDConnector
	retry  RetryPolicy

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewCiscoSmartBondingConnector builds the create connector.
func NewCiscoSmartBondingConnector(c *cisco.Client) *CiscoSmartBondingConnector {
	if c == nil {
		c = &cisco.Client{HTTP: safehttp.Client(30 * time.Second)}
	}
	return &CiscoSmartBondingConnector{client: c, cxd: NewCiscoCXDConnector(c), retry: DefaultCaseRetry()}
}

func (c *CiscoSmartBondingConnector) Name() string { return "cisco-smart-bonding" }

func (c *CiscoSmartBondingConnector) Capabilities() Caps {
	return Caps{
		Create: true, Attach: true, Poll: true, Note: false,
		// Smart Bonding is a PULL model: the customer polls pull/call. There is
		// no webhook, and saying otherwise would be a promise we cannot keep.
		Webhook:             false,
		MaxAttachBytes:      0, // attaches through CXD, which has no documented limit
		RequiresEntitlement: true,
		SeverityValues:      ciscoSeverities(),
		Notes:               "requires a completed per-customer Smart Bonding onboarding project (analysis → implementation → test → go-live). Entitlement is checked at create: a serial number for hardware, or a contract id + PID for software, plus the CCO-ID in every case. The create response carries the CXD host and token (Field80/Field81), so create → attach is closed-loop",
	}
}

func (c *CiscoSmartBondingConnector) ValidateConfig(cfg TACConnectorConfig) error {
	if !cfg.Cisco.Enabled || !cfg.Cisco.SmartBondingEnabled {
		return ErrNotConfigured
	}
	if err := validateCiscoConfig(cfg.Cisco); err != nil {
		return err
	}
	if missing := missingCiscoFieldBindings(cfg.Cisco.FieldMap); len(missing) > 0 {
		return fmt.Errorf("%w: Cisco does not publish the Smart Bonding push/call request schema, so these case fields must be bound to the field names your onboarding project issued: %s",
			ErrNotOnboarded, strings.Join(missing, ", "))
	}
	return nil
}

// missingCiscoFieldBindings names the canonical fields with no binding.
func missingCiscoFieldBindings(m map[string]string) []string {
	var missing []string
	for _, f := range ciscoCanonicalFields {
		if strings.TrimSpace(m[f]) == "" {
			missing = append(missing, f)
		}
	}
	return missing
}

func (c *CiscoSmartBondingConnector) CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return CaseRef{}, err
	}
	if !req.Approval.Valid() {
		return CaseRef{}, ErrNotApproved
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" {
		return CaseRef{}, PermanentDeliveryError{errors.New("cisco: an idempotency key is required (it becomes customerUniqueTransactionID)")}
	}
	ent := cisco.Entitlement{
		CCOID:        cfg.Cisco.CCOID,
		SerialNumber: req.SerialNumber,
		ContractID:   req.Fields["contract_id"],
		PID:          req.Fields["pid"],
	}
	if err := ent.Validate(); err != nil {
		return CaseRef{}, EntitlementError{Vendor: "cisco", VendorMsg: err.Error()}
	}
	c.client.StagingHost = cfg.Cisco.StagingHost

	fields := map[string]string{}
	bind := func(canonical, value string) {
		if k := strings.TrimSpace(cfg.Cisco.FieldMap[canonical]); k != "" && strings.TrimSpace(value) != "" {
			fields[k] = value
		}
	}
	bind("synopsis", Truncate(req.Synopsis, 250))
	bind("description", req.Description)
	bind("severity", req.Severity)
	bind("contact_email", req.ContactEmail)
	bind("contact_name", req.ContactName)
	bind("cco_id", cfg.Cisco.CCOID)
	bind("serial_number", req.SerialNumber)
	bind("contract_id", ent.ContractID)
	bind("pid", ent.PID)

	out, err := withRetry(ctx, c.retry, req.IdempotencyKey, func(ctx context.Context) (cisco.CreateResponse, error) {
		bearer, terr := c.bearer(ctx, cfg)
		if terr != nil {
			return cisco.CreateResponse{}, terr
		}
		res, cerr := c.client.CreateCase(ctx, bearer, cisco.CreateRequest{
			Entitlement:                 ent,
			CustomerCaseNumber:          req.Fields["customer_case_number"],
			CustomerUniqueTransactionID: req.IdempotencyKey,
			Fields:                      fields,
		})
		return res, translateCiscoError(cerr)
	})
	if err != nil {
		return CaseRef{}, err
	}
	return CaseRef{
		ID: out.SRNumber, Number: out.SRNumber,
		URL:         "https://mycase.cloudapps.cisco.com/case?swtId=" + out.SRNumber,
		UploadHost:  out.CXDHost,
		UploadToken: out.CXDToken, // ephemeral, per-SR: used immediately, never stored
	}, nil
}

// AttachBundle delegates to CXD: Smart Bonding's own attachment path IS CXD.
func (c *CiscoSmartBondingConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return AttachResult{}, err
	}
	return c.cxd.AttachBundle(ctx, cfg, ref, b)
}

func (c *CiscoSmartBondingConnector) FetchCase(ctx context.Context, cfg TACConnectorConfig, ref CaseRef) (RemoteCase, bool, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return RemoteCase{}, false, err
	}
	c.client.StagingHost = cfg.Cisco.StagingHost
	bearer, err := c.bearer(ctx, cfg)
	if err != nil {
		return RemoteCase{}, false, err
	}
	st, found, err := c.client.FetchCase(ctx, bearer, orDefault(ref.Number, ref.ID))
	if err != nil {
		return RemoteCase{}, false, translateCiscoError(err)
	}
	if !found {
		// The API answered and knows no such case: "not found" is a fact, not a
		// failure, so the caller sees found=false with a nil error.
		return RemoteCase{}, false, nil
	}
	return RemoteCase{ID: st.SRNumber, Number: st.SRNumber, Status: st.Status, UpdatedAt: st.UpdatedAt, URL: ref.URL}, true, nil
}

func (c *CiscoSmartBondingConnector) AddNote(context.Context, TACConnectorConfig, CaseRef, string) error {
	return fmt.Errorf("%w: the public Smart Bonding pages document no note endpoint for the customer API", ErrUnsupported)
}

// bearer returns a cached OAuth token, refreshing a minute before expiry. The
// token itself never reaches a log or an error.
func (c *CiscoSmartBondingConnector) bearer(ctx context.Context, cfg TACConnectorConfig) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	tokenURL := orDefault(cfg.Cisco.TokenURL, cisco.DefaultTokenURL)
	if err := validatePinnedURL(tokenURL, ciscoHostAllowlist(cfg.Cisco.StagingHost)); err != nil {
		return "", PermanentDeliveryError{err}
	}
	tok, ttl, err := c.client.Token(ctx, tokenURL, cfg.Cisco.ClientID, cfg.Cisco.ClientSecret)
	if err != nil {
		return "", translateCiscoError(err)
	}
	c.token, c.expires = tok, time.Now().Add(ttl)
	return tok, nil
}

var _ CaseConnector = (*CiscoSmartBondingConnector)(nil)

// translateCiscoError maps the vendor client's error vocabulary onto the
// connector's retry semantics, keeping Cisco's own words for the operator.
func translateCiscoError(err error) error {
	if err == nil {
		return nil
	}
	// A refusal made locally, before anything was sent, is permanent: retrying
	// identical bad input only makes the operator wait.
	if errors.Is(err, cisco.ErrRequestInvalid) {
		return PermanentDeliveryError{err}
	}
	var ve *cisco.VendorError
	if errors.As(err, &ve) {
		return EntitlementError{Vendor: "cisco", Code: ve.Code, VendorMsg: ve.Message}
	}
	var se *cisco.StatusError
	if errors.As(err, &se) {
		switch se.Status {
		case http.StatusTooManyRequests:
			return RateLimitedError{After: parseRetryAfterSeconds(se.RetryAfter, 30*time.Second)}
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return PermanentDeliveryError{err}
		}
	}
	return err
}

// parseRetryAfterSeconds reads a delta-seconds Retry-After, bounded.
func parseRetryAfterSeconds(v string, def time.Duration) time.Duration {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil && n > 0 && n <= 3600 {
		return time.Duration(n) * time.Second
	}
	return def
}
