package ticketing

// caseconn_itsm.go — the Tier-1 ITSM connectors: ServiceNow and Jira as
// CaseConnectors.
//
// They are thin: the adapters already do create, update, note, resolve and
// fetch against a per-tenant, SSRF-validated, write-only-secret connection.
// This file adds the case-opening SHAPE on top of them — capability
// declaration, the bounded retry, the bundle attach, and the human-approval
// rule — and nothing else. The tenant's CONNECTION (instance URL, credentials)
// arrives in cfg.ITSM, resolved by the caller from ITSMConfigStore, and is
// never persisted in the TAC record.
//
// Research §4.1: this is where most enterprises actually escalate first. The
// NOC opens its own incident and the vendor case is opened FROM it; Cisco's own
// create path (Smart Bonding) is literally an ITSM-to-TAC bridge.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── ServiceNow ──────────────────────────────────────────────────────────────

// ServiceNowCaseConnector adapts the ServiceNow adapter to CaseConnector.
type ServiceNowCaseConnector struct {
	adapter *ServiceNowAdapter
	retry   RetryPolicy
}

// NewServiceNowCaseConnector builds the connector over an adapter (inject one
// with a fake client in tests).
func NewServiceNowCaseConnector(a *ServiceNowAdapter) *ServiceNowCaseConnector {
	if a == nil {
		a = NewServiceNowAdapter()
	}
	return &ServiceNowCaseConnector{adapter: a, retry: DefaultCaseRetry()}
}

func (c *ServiceNowCaseConnector) Name() string { return "servicenow" }

func (c *ServiceNowCaseConnector) Capabilities() Caps {
	return Caps{
		Create: true, Attach: true, Poll: true, Note: true, Close: true,
		// Webhook is FALSE on purpose: ServiceNow can push, but only through an
		// Outbound REST message the CUSTOMER builds. Declaring it would promise
		// something Correlix does not provision.
		Webhook:        false,
		MaxAttachBytes: SnowDefaultMaxAttachBytes,
		Notes:          "attachment ceiling is the instance property com.glide.attachment.max_size (default 1024 MB); no chunked or resumable upload exists, and the inbound EMAIL path is far stricter at 18 MiB total",
	}
}

func (c *ServiceNowCaseConnector) ValidateConfig(cfg TACConnectorConfig) error {
	if !cfg.ServiceNow.Enabled {
		return ErrNotConfigured
	}
	if cfg.ITSM.InstanceURL == "" {
		return fmt.Errorf("%w: the tenant has no ServiceNow connection configured", ErrNotConfigured)
	}
	return c.adapter.ValidateConfig(cfg.ITSM)
}

func (c *ServiceNowCaseConnector) CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return CaseRef{}, err
	}
	if !req.Approval.Valid() {
		return CaseRef{}, ErrNotApproved
	}
	p := caseRequestToPayload(req)
	ref, err := withRetry(ctx, c.retry, req.IdempotencyKey, func(ctx context.Context) (Ref, error) {
		return c.adapter.CreateIncident(ctx, cfg.ITSM, p)
	})
	if err != nil {
		return CaseRef{}, err
	}
	return CaseRef{ID: ref.SysID, Number: ref.Number, URL: ref.URL}, nil
}

func (c *ServiceNowCaseConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return AttachResult{}, err
	}
	limit := cfg.ServiceNow.MaxAttachBytes
	if limit <= 0 {
		limit = SnowDefaultMaxAttachBytes
	}
	if err := checkBundle("servicenow", b, limit,
		"ServiceNow publishes no chunked or resumable upload; use the smaller bundle profile or a link-only case description"); err != nil {
		return AttachResult{}, err
	}
	return attachWithRetry(ctx, c.retry, b, func(ctx context.Context, rc readCloser) (AttachResult, error) {
		return c.adapter.attachFile(ctx, cfg.ITSM, ref.ID, sanitizeFileName(b.Name), rc, b.Size, limit,
			orDefault(b.ContentType, "application/zip"))
	}, b.SHA256)
}

func (c *ServiceNowCaseConnector) FetchCase(ctx context.Context, cfg TACConnectorConfig, ref CaseRef) (RemoteCase, bool, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return RemoteCase{}, false, err
	}
	inc, found, err := c.adapter.FetchIncident(ctx, cfg.ITSM, Ref{SysID: ref.ID, Number: ref.Number})
	if err != nil || !found {
		return RemoteCase{}, found, err
	}
	return RemoteCase{
		ID: inc.SysID, Number: inc.Number,
		Status: snowStateName(inc.State), UpdatedAt: inc.UpdatedAt, URL: ref.URL,
	}, true, nil
}

func (c *ServiceNowCaseConnector) AddNote(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, note string) error {
	if err := c.ValidateConfig(cfg); err != nil {
		return err
	}
	_, err := withRetry(ctx, c.retry, ref.ID+":note", func(ctx context.Context) (struct{}, error) {
		return struct{}{}, c.adapter.AddWorkNote(ctx, cfg.ITSM, Ref{SysID: ref.ID}, note)
	})
	return err
}

// snowStateName maps the numeric incident state onto the operator's word.
func snowStateName(state int) string {
	switch state {
	case 1:
		return "new"
	case SnowStateInProgress:
		return "in_progress"
	case 3:
		return "on_hold"
	case SnowStateResolved:
		return "resolved"
	case SnowStateClosed:
		return "closed"
	case 0:
		return "unknown"
	}
	return fmt.Sprintf("state_%d", state)
}

var _ CaseConnector = (*ServiceNowCaseConnector)(nil)

// ── Jira ────────────────────────────────────────────────────────────────────

// JiraCaseConnector adapts the Jira adapter to CaseConnector.
type JiraCaseConnector struct {
	adapter *JiraAdapter
	retry   RetryPolicy
	// deployment defaults the capability declaration when no tenant config is
	// in hand (the registry renders capabilities before a tenant is chosen).
	deployment string
}

// NewJiraCaseConnector builds the connector over an adapter.
func NewJiraCaseConnector(a *JiraAdapter) *JiraCaseConnector {
	if a == nil {
		a = NewJiraAdapter()
	}
	return &JiraCaseConnector{adapter: a, retry: DefaultCaseRetry(), deployment: jiraCloud}
}

func (c *JiraCaseConnector) Name() string { return "jira" }

func (c *JiraCaseConnector) Capabilities() Caps {
	_, _, limit := jiraAttachDefaults(c.deployment)
	return Caps{
		Create: true, Attach: true, Poll: true, Note: true, Close: true,
		// jira:issue_updated is a real webhook, but Cloud's dynamic webhooks
		// EXPIRE after 30 days and must be refreshed — W3 owns that receiver.
		Webhook:        false,
		MaxAttachBytes: limit,
		Notes:          "Cloud defaults to 1 GB per attachment on /rest/api/3, Data Center to 10 MB on /rest/api/2; both are instance properties, so the tenant's configured value wins. Jira Cloud rate-limits 20 writes per 2 s PER ISSUE — exactly the create-then-attach pattern",
	}
}

func (c *JiraCaseConnector) ValidateConfig(cfg TACConnectorConfig) error {
	if !cfg.Jira.Enabled {
		return ErrNotConfigured
	}
	if cfg.ITSM.InstanceURL == "" {
		return fmt.Errorf("%w: the tenant has no Jira connection configured", ErrNotConfigured)
	}
	return c.adapter.ValidateConfig(cfg.ITSM)
}

func (c *JiraCaseConnector) CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return CaseRef{}, err
	}
	if !req.Approval.Valid() {
		return CaseRef{}, ErrNotApproved
	}
	p := caseRequestToPayload(req)
	ref, err := withRetry(ctx, c.retry, req.IdempotencyKey, func(ctx context.Context) (Ref, error) {
		return c.adapter.CreateIncident(ctx, cfg.ITSM, p)
	})
	if err != nil {
		return CaseRef{}, err
	}
	// The Jira adapter's canonical ref is the numeric id; the KEY is what the
	// attachment endpoint and the operator both use.
	return CaseRef{ID: orDefault(ref.Number, ref.SysID), Number: ref.Number, URL: ref.URL}, nil
}

func (c *JiraCaseConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return AttachResult{}, err
	}
	_, _, limit := jiraAttachDefaults(cfg.Jira.Deployment)
	if cfg.Jira.MaxAttachBytes > 0 {
		limit = cfg.Jira.MaxAttachBytes
	}
	if err := checkBundle("jira", b, limit,
		"raise the instance's attachment size property, use the smaller bundle profile, or attach a link-only case description"); err != nil {
		return AttachResult{}, err
	}
	key := orDefault(ref.Number, ref.ID)
	return attachWithRetry(ctx, c.retry, b, func(ctx context.Context, rc readCloser) (AttachResult, error) {
		return c.adapter.AttachFileWithConfig(ctx, cfg.ITSM, cfg.Jira, key, b.Name, rc, b.Size)
	}, b.SHA256)
}

func (c *JiraCaseConnector) FetchCase(ctx context.Context, cfg TACConnectorConfig, ref CaseRef) (RemoteCase, bool, error) {
	if err := c.ValidateConfig(cfg); err != nil {
		return RemoteCase{}, false, err
	}
	key := orDefault(ref.Number, ref.ID)
	if strings.TrimSpace(key) == "" {
		return RemoteCase{}, false, PermanentDeliveryError{fmt.Errorf("jira: poll requires the issue key")}
	}
	// GET /rest/api/{2,3}/issue/{key}?fields=status,updated — the documented
	// poll surface (fields.status + fields.updated).
	prefix, _, _ := jiraAttachDefaults(cfg.Jira.Deployment)
	raw, status, err := c.adapter.do(ctx, cfg.ITSM, http.MethodGet,
		prefix+"/issue/"+url.PathEscape(key)+"?fields=status,updated", nil)
	if err != nil {
		if status == http.StatusNotFound {
			return RemoteCase{}, false, nil // the issue is gone: not an error
		}
		return RemoteCase{}, false, err
	}
	var resp struct {
		Key    string `json:"key"`
		Fields struct {
			Status struct {
				Name string `json:"name"`
			} `json:"status"`
			Updated string `json:"updated"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return RemoteCase{}, false, fmt.Errorf("jira: decode issue: %w", err)
	}
	if resp.Key == "" {
		return RemoteCase{}, false, nil
	}
	out := RemoteCase{
		ID: resp.Key, Number: resp.Key,
		Status: strings.ToLower(strings.TrimSpace(resp.Fields.Status.Name)),
		URL:    jiraBrowseURL(cfg.ITSM.InstanceURL, resp.Key),
	}
	// Jira timestamps are RFC3339 with a numeric offset and no colon.
	for _, layout := range []string{"2006-01-02T15:04:05.999-0700", time.RFC3339} {
		if t, perr := time.Parse(layout, strings.TrimSpace(resp.Fields.Updated)); perr == nil {
			out.UpdatedAt = t.UTC()
			break
		}
	}
	return out, true, nil
}

func (c *JiraCaseConnector) AddNote(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, note string) error {
	if err := c.ValidateConfig(cfg); err != nil {
		return err
	}
	_, err := withRetry(ctx, c.retry, ref.ID+":note", func(ctx context.Context) (struct{}, error) {
		return struct{}{}, c.adapter.AddWorkNote(ctx, cfg.ITSM, Ref{SysID: ref.ID, Number: ref.Number}, note)
	})
	return err
}

var _ CaseConnector = (*JiraCaseConnector)(nil)

// ── shared ──────────────────────────────────────────────────────────────────

// readCloser is the alias the attach callbacks take, so a caller cannot forget
// that the reader it is handed is owned by attachWithRetry.
type readCloser = interface {
	Read(p []byte) (int, error)
}

// attachWithRetry re-OPENS the bundle on every attempt: an io.Reader cannot be
// replayed, so a retry that reused it would upload a truncated file. The reader
// is closed on every path, including the failing ones.
func attachWithRetry(ctx context.Context, p RetryPolicy, b Bundle, do func(context.Context, readCloser) (AttachResult, error), key string) (AttachResult, error) {
	res, err := withRetry(ctx, p, key, func(ctx context.Context) (AttachResult, error) {
		rc, err := b.Open()
		if err != nil {
			return AttachResult{}, PermanentDeliveryError{fmt.Errorf("open bundle: %w", err)}
		}
		out, err := do(ctx, rc)
		if cerr := rc.Close(); cerr != nil && err == nil {
			return AttachResult{}, fmt.Errorf("close bundle: %w", cerr)
		}
		return out, err
	})
	if err != nil {
		return AttachResult{}, err
	}
	if res.SHA256 == "" {
		res.SHA256 = b.SHA256
	}
	if res.At.IsZero() {
		res.At = time.Now().UTC()
	}
	return res, nil
}

// caseRequestToPayload maps the connector-neutral case request onto the ITSM
// Payload the existing adapters already speak. Nothing is invented: the case
// body is title + description + the identifiers the operator confirmed.
func caseRequestToPayload(req CaseRequest) Payload {
	return Payload{
		CorrObjectID:      req.IdempotencyKey,
		Title:             Truncate(req.Synopsis, 250),
		Summary:           req.Description,
		Verdict:           "confirmed", // a human approved this escalation
		AffectedScope:     req.DeviceID,
		RecommendedAction: "Escalated to vendor TAC by " + req.Approval.Actor,
	}
}
