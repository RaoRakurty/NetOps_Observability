// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_audit.go — the structured audit trail for TAC case actions.
//
// Research §5.6: case create, attach, status poll and credential change are all
// audited, carrying tenant, incident, device, bundle digest and case id. The
// bundle's SHA256 is the link between "what we collected" and "what the vendor
// received".
//
// CLAUDE.md §8/§10: the event NEVER carries a credential, a token, an S3 STS
// key or a bundle's contents — only identifiers and digests. The sink is
// injectable so the HTTP layer can persist it; the default writes one
// structured applog line so an unwired deployment is still observable rather
// than silent.

import (
	"context"
	"strings"
	"time"

	"netops/backend/internal/applog"
)

// CaseAuditEvent is one auditable TAC connector action.
type CaseAuditEvent struct {
	At        time.Time `json:"at"`
	TenantID  string    `json:"tenant_id"`
	Actor     string    `json:"actor"`     // user:<id> — never "system" for a create
	Action    string    `json:"action"`    // create|attach|poll|note|config_change
	Connector string    `json:"connector"` // registry id
	Vendor    string    `json:"vendor"`
	// IncidentID / DeviceID tie the case back to what caused it.
	IncidentID string `json:"incident_id,omitempty"`
	DeviceID   string `json:"device_id,omitempty"`
	CaseID     string `json:"case_id,omitempty"`
	CaseNumber string `json:"case_number,omitempty"`
	// BundleSHA256 / BundleBytes prove which artifact left the platform.
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
	BundleBytes  int64  `json:"bundle_bytes,omitempty"`
	Transport    string `json:"transport,omitempty"`
	Result       string `json:"result"` // ok|error
	Error        string `json:"error,omitempty"`
	// ApprovedBy / ApprovedAt record the human-in-the-loop proof on a create.
	ApprovedBy string    `json:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`
}

// CaseAuditSink receives events. Implementations must not block the caller for
// long: a slow audit store must never stall an operator's escalation.
type CaseAuditSink interface {
	RecordCaseAction(e CaseAuditEvent)
}

// applogCaseAudit is the default sink: one structured line per action.
type applogCaseAudit struct{}

// DefaultCaseAuditSink writes structured applog lines.
func DefaultCaseAuditSink() CaseAuditSink { return applogCaseAudit{} }

func (applogCaseAudit) RecordCaseAction(e CaseAuditEvent) {
	fields := map[string]any{
		"tenant": e.TenantID, "actor": e.Actor, "action": e.Action,
		"connector": e.Connector, "vendor": e.Vendor, "result": e.Result,
	}
	for k, v := range map[string]string{
		"incident": e.IncidentID, "device": e.DeviceID, "case_id": e.CaseID,
		"case_number": e.CaseNumber, "bundle_sha256": e.BundleSHA256,
		"transport": e.Transport, "approved_by": e.ApprovedBy,
	} {
		if strings.TrimSpace(v) != "" {
			fields[k] = v
		}
	}
	if e.BundleBytes > 0 {
		fields["bundle_bytes"] = e.BundleBytes
	}
	if e.Error != "" {
		fields["error"] = Truncate(e.Error, 480)
	}
	if e.Result == "error" {
		applog.Error("tac-case", "TAC case action failed", fields)
		return
	}
	applog.Info("tac-case", "TAC case action", fields)
}

// AuditedConnector wraps any CaseConnector and emits one audit event per
// action. Wrapping rather than threading the sink through every connector keeps
// each connector a pure protocol adapter (§2: no hidden coupling).
type AuditedConnector struct {
	Inner CaseConnector
	Sink  CaseAuditSink
	// Ctx carries the who/what that the connector itself has no business
	// knowing. Set per request by the caller.
	TenantID   string
	Actor      string
	IncidentID string
	DeviceID   string
	Vendor     string
}

func (a AuditedConnector) sink() CaseAuditSink {
	if a.Sink != nil {
		return a.Sink
	}
	return DefaultCaseAuditSink()
}

func (a AuditedConnector) event(action, result string) CaseAuditEvent {
	return CaseAuditEvent{
		At: time.Now().UTC(), TenantID: a.TenantID, Actor: a.Actor, Action: action,
		Connector: a.Inner.Name(), Vendor: a.Vendor, IncidentID: a.IncidentID,
		DeviceID: a.DeviceID, Result: result,
	}
}

func (a AuditedConnector) Name() string       { return a.Inner.Name() }
func (a AuditedConnector) Capabilities() Caps { return a.Inner.Capabilities() }
func (a AuditedConnector) ValidateConfig(c TACConnectorConfig) error {
	return a.Inner.ValidateConfig(c)
}

func (a AuditedConnector) CreateCase(ctx context.Context, cfg TACConnectorConfig, req CaseRequest) (CaseRef, error) {
	ref, err := a.Inner.CreateCase(ctx, cfg, req)
	e := a.event("create", "ok")
	e.ApprovedBy, e.ApprovedAt = req.Approval.Actor, req.Approval.ApprovedAt
	if err != nil {
		e.Result, e.Error = "error", err.Error()
	} else {
		e.CaseID, e.CaseNumber = ref.ID, ref.Number
	}
	a.sink().RecordCaseAction(e)
	return ref, err
}

func (a AuditedConnector) AttachBundle(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, b Bundle) (AttachResult, error) {
	res, err := a.Inner.AttachBundle(ctx, cfg, ref, b)
	e := a.event("attach", "ok")
	e.CaseID, e.CaseNumber = ref.ID, ref.Number
	e.BundleSHA256, e.BundleBytes = b.SHA256, b.Size
	if err != nil {
		e.Result, e.Error = "error", err.Error()
	} else {
		e.Transport = res.Transport
	}
	a.sink().RecordCaseAction(e)
	return res, err
}

func (a AuditedConnector) FetchCase(ctx context.Context, cfg TACConnectorConfig, ref CaseRef) (RemoteCase, bool, error) {
	rc, found, err := a.Inner.FetchCase(ctx, cfg, ref)
	e := a.event("poll", "ok")
	e.CaseID, e.CaseNumber = ref.ID, ref.Number
	if err != nil {
		e.Result, e.Error = "error", err.Error()
	}
	a.sink().RecordCaseAction(e)
	return rc, found, err
}

func (a AuditedConnector) AddNote(ctx context.Context, cfg TACConnectorConfig, ref CaseRef, note string) error {
	err := a.Inner.AddNote(ctx, cfg, ref, note)
	e := a.event("note", "ok")
	e.CaseID, e.CaseNumber = ref.ID, ref.Number
	if err != nil {
		e.Result, e.Error = "error", err.Error()
	}
	a.sink().RecordCaseAction(e)
	return err
}

var _ CaseConnector = AuditedConnector{}
