// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_tac.go — THE ADAPTER POINT. It makes every connector in this package
// satisfy internal/tac.CaseOpener, W1's published seam.
//
// The dependency runs ONE WAY, which is what keeps this legal under CLAUDE.md §2:
// internal/ticketing imports internal/tac (for the seam's types), and
// internal/tac never imports internal/ticketing — its own doc comment says the
// implementations "live in internal/ticketing and are injected". The wiring
// layer builds these adapters and passes them to tac.WithOpeners.
//
// The two vocabularies differ in shape, not in meaning, and the mapping is
// mechanical:
//
//	ticketing.Caps{Create,Attach,Poll}      → tac []CaseCapability{create,attach,poll_status}
//	Caps.MaxAttachBytes / AttachLimit()     → ConnectorInfo.MaxAttachmentBytes
//	ValidateConfig(cfg) == nil              → ConnectorInfo.Configured
//	Caps.Notes / PortalURL / RequiredFields → ConnectorInfo.Note / CaseForm.Portal*
//	CaseConnector.CreateCase + AttachBundle → SubmitCase (one human-approved act)
//	CaseConnector.FetchCase                 → PollStatus
//
// CapLink is claimed when the connector produces a case URL, which every
// creating connector does and no attach-only one does.
//
// HUMAN APPROVAL crosses the seam here: tac.CaseRequest.Actor is the
// authenticated principal who pressed submit, so SubmitCase — and ONLY
// SubmitCase — mints the Approval that CreateCase requires. There is no path
// from PrepareCase (which performs no remote write) to a created case.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netops/backend/internal/tac"
)

// TenantConfigResolver hands the adapter one tenant's connector configuration,
// INCLUDING the ITSM connection resolved from ITSMConfigStore. It is injected
// so this package does not reach for ambient state, and so a caller cannot
// smuggle a foreign tenant's credentials in through a request body: the adapter
// only ever passes the tenant id it was given by the seam.
type TenantConfigResolver func(ctx context.Context, tenantID string) (TACConnectorConfig, error)

// BundleOpener resolves a bundle path to its bytes, size and digest, refusing
// any path outside the tenant's own bundle directory. It is injected because
// internal/tac owns the bundle store's layout, and because a connector must
// never accept a path from anywhere else (W1's CaseRequest doc).
type BundleOpener func(ctx context.Context, tenantID, path string) (Bundle, error)

// TACOpener adapts one CaseConnector to tac.CaseOpener.
type TACOpener struct {
	Connector CaseConnector
	// Display is the operator-facing name; falls back to the connector id.
	Display string
	// Vendor groups connectors in the UI ("cisco", "juniper", "arista", …).
	Vendor string
	// Resolve and OpenBundle are required; without them the adapter reports the
	// connector as unconfigured rather than guessing at credentials or paths.
	Resolve    TenantConfigResolver
	OpenBundle BundleOpener
	// Audit receives one event per create/attach/poll. Defaults to applog.
	Audit CaseAuditSink
	// Now is injected for deterministic tests.
	Now func() time.Time
}

// NewTACOpener builds an adapter for one connector.
func NewTACOpener(c CaseConnector, vendor, display string, resolve TenantConfigResolver, open BundleOpener) *TACOpener {
	return &TACOpener{Connector: c, Vendor: vendor, Display: display, Resolve: resolve, OpenBundle: open}
}

// TACOpenersFromRegistry adapts every connector in a registry, in matrix order
// (cheapest tier first), so the wiring layer can hand the whole set to
// tac.WithOpeners in one call.
func TACOpenersFromRegistry(r *CaseConnectorRegistry, resolve TenantConfigResolver, open BundleOpener) []tac.CaseOpener {
	entries := r.Matrix()
	out := make([]tac.CaseOpener, 0, len(entries))
	for _, e := range entries {
		out = append(out, NewTACOpener(e.Connector, e.Vendor, connectorDisplayName(e), resolve, open))
	}
	return out
}

// connectorDisplayName is the operator-facing label for a registry row.
func connectorDisplayName(e ConnectorEntry) string {
	switch e.ID {
	case "servicenow":
		return "ServiceNow incident"
	case "jira":
		return "Jira issue"
	case "cisco-cxd":
		return "Cisco CXD (attach to an existing SR)"
	case "cisco-smart-bonding":
		return "Cisco Smart Bonding (open an SR)"
	case "juniper":
		return "Juniper Service Case"
	}
	if strings.HasPrefix(e.ID, "email-") {
		return strings.ToUpper(e.Vendor[:1]) + e.Vendor[1:] + " support email"
	}
	if strings.HasPrefix(e.ID, "portal-") {
		return strings.ToUpper(e.Vendor[:1]) + e.Vendor[1:] + " portal (copy & paste)"
	}
	return e.ID
}

func (o *TACOpener) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

func (o *TACOpener) audit() CaseAuditSink {
	if o.Audit != nil {
		return o.Audit
	}
	return DefaultCaseAuditSink()
}

// Info declares the connector for ONE tenant. Configured is tenant-specific:
// the same connector is configured for one tenant and not another, and an
// unconfigured one is SHOWN with the reason rather than hidden.
func (o *TACOpener) Info(ctx context.Context, tenantID string) tac.ConnectorInfo {
	caps := o.Connector.Capabilities()
	info := tac.ConnectorInfo{
		ID:                 o.Connector.Name(),
		Display:            orDefault(o.Display, o.Connector.Name()),
		Vendor:             o.Vendor,
		Capabilities:       tacCapabilities(caps),
		MaxAttachmentBytes: tacMaxAttachment(caps),
		Note:               caps.Notes,
		// Which settings form brings credentials for this path, if any.
		ConfigSection: string(SectionForConnector(o.Connector.Name())),
	}
	info.Profile = tac.ProfileForConnector(info)

	cfg, err := o.tenantConfig(ctx, tenantID)
	switch {
	case errors.Is(err, ErrNotConfigured), errors.Is(err, ErrTenantNotFound):
		// A TENANT WITH NO ROW IS NOT A FAILED READ. This is the normal state of
		// every fresh install: nobody has brought credentials yet. It used to
		// fall into the error arm below and print "connector configuration could
		// not be read for this tenant" on all twelve connectors — including the
		// portal-only ones, which have nothing to configure at all.
		info.Configured = false
		info.StatusNote = NotConfiguredStatusNote
	case err != nil:
		// A REAL read failure. It is named, it is flagged for the UI, and the
		// service logs it (§10) — it is never dressed up as a state.
		info.Configured = false
		info.Unavailable = true
		info.StatusNote = "the stored connector configuration could not be read: " + Truncate(err.Error(), 160)
	default:
		verr := o.Connector.ValidateConfig(cfg)
		info.Configured = verr == nil
		if verr != nil {
			// The reason is what the operator needs: "not onboarded" and "no
			// credentials" are different problems with different next steps.
			info.StatusNote = verr.Error()
		}
	}
	return info
}

// NotConfiguredStatusNote is the state a tenant with no stored credentials is
// in. It is a sentence about what to do next, not a report of a failure.
const NotConfiguredStatusNote = "No credentials for this tenant yet — bring your own to use it."

// tacCapabilities maps the declared Caps onto the seam's closed verb set.
func tacCapabilities(c Caps) []tac.CaseCapability {
	var out []tac.CaseCapability
	if c.Create {
		out = append(out, tac.CapCreate)
	}
	if c.Attach {
		out = append(out, tac.CapAttach)
	}
	if c.Poll {
		out = append(out, tac.CapPollStatus)
	}
	// A connector produces a case link exactly when it can create the case it
	// would link to; an attach-only one has no id of its own to link.
	if c.Create {
		out = append(out, tac.CapLink)
	}
	if out == nil {
		out = []tac.CaseCapability{}
	}
	return out
}

// tacMaxAttachment translates the ceiling. The seam's contract is that 0 means
// "cannot attach at all", whereas ours means "no DOCUMENTED vendor limit" — so
// a connector that can attach without a published cap reports our local
// runaway guard rather than 0, which would read as "cannot attach".
func tacMaxAttachment(c Caps) int64 {
	if !c.Attach {
		return 0
	}
	return c.AttachLimit()
}

// PrepareCase fills in what THIS connector knows and names what it still needs.
// It performs no remote write of any kind.
func (o *TACOpener) PrepareCase(ctx context.Context, req tac.CaseRequest) (tac.CaseForm, error) {
	caps := o.Connector.Capabilities()
	form := req.Form
	form.ConnectorID = o.Connector.Name()
	info := o.Info(ctx, req.TenantID)
	form.Profile = info.Profile
	if caps.PortalURL != "" {
		form.PortalURL = caps.PortalURL
	}
	if form.BundleName == "" && req.BundlePath != "" {
		form.BundleName = filepath.Base(req.BundlePath)
	}
	if form.BundleBytes == 0 && o.OpenBundle != nil && req.BundlePath != "" {
		if b, err := o.OpenBundle(ctx, req.TenantID, req.BundlePath); err == nil {
			form.BundleBytes = b.Size
		}
		// A bundle we cannot size yet is not an error at PREPARE time: the form
		// is still worth showing, and SubmitCase fails loudly if it is unreadable.
	}
	form.MissingFields = o.missingFields(ctx, req, form)
	return form, nil
}

// missingFields names what the operator must still supply for THIS connector.
// Correlix never guesses an entitlement identifier or a contact.
func (o *TACOpener) missingFields(ctx context.Context, req tac.CaseRequest, form tac.CaseForm) []string {
	caps := o.Connector.Capabilities()
	miss := []string{}
	add := func(f string) {
		for _, have := range miss {
			if have == f {
				return
			}
		}
		miss = append(miss, f)
	}
	// Carry forward anything the caller already determined.
	for _, f := range form.MissingFields {
		add(f)
	}
	if caps.AttachToExistingOnly {
		// An attach-to-existing connector needs the case it is attaching TO and
		// the per-case upload credential. Both now cross the seam, so this
		// reports what is still BLANK rather than refusing the path outright.
		for _, f := range attachOnlyMissingFields(req) {
			add(f)
		}
		return miss
	}
	if !caps.Create {
		// A portal-only connector opens nothing, so it demands no entitlement
		// fields of its own.
		return miss
	}
	if strings.TrimSpace(form.ContactEmail) == "" {
		add("contact_email")
	}
	if caps.RequiresEntitlement {
		if strings.TrimSpace(form.SerialNumber) == "" && strings.TrimSpace(form.ContractID) == "" {
			// Cisco takes a serial OR a contract; Juniper takes the serial.
			add("serial_number")
		}
	}
	switch o.Connector.Name() {
	case "juniper":
		// softwareVersion has been mandatory since 2024-05-16, and contactEmail
		// must be a named human — both refuse at the vendor, so refuse here.
		if strings.TrimSpace(req.Form.Product) == "" && strings.TrimSpace(req.Platform) == "" {
			add("software_version")
		}
		if e := strings.TrimSpace(form.ContactEmail); e != "" && !isNamedHumanEmail(e) {
			add("contact_email (must be a named human, not a shared alias)")
		}
	case "cisco-smart-bonding":
		cfg, err := o.tenantConfig(ctx, req.TenantID)
		if err == nil {
			for _, f := range missingCiscoFieldBindings(cfg.Cisco.FieldMap) {
				add("cisco field mapping: " + f)
			}
		}
	}
	return miss
}

// SubmitCase is the human-approved action: create where the connector can, then
// attach where it can and the bundle fits. A connector without CapCreate
// returns a successful result carrying the portal text and no case id.
func (o *TACOpener) SubmitCase(ctx context.Context, req tac.CaseRequest) (tac.CaseResult, error) {
	caps := o.Connector.Capabilities()
	res := tac.CaseResult{ConnectorID: o.Connector.Name(), SubmittedAt: o.now(), PortalText: req.Form.PortalText}

	// The approving human. tac.CaseRequest.Actor is the authenticated principal
	// who pressed submit — without one there is no approval and nothing is sent.
	if strings.TrimSpace(req.Actor) == "" {
		return res, fmt.Errorf("%w: no authenticated actor — a case is opened by a person, never by an engine", tac.ErrFormIncomplete)
	}
	if miss := o.missingFields(ctx, req, req.Form); len(miss) > 0 && caps.Create {
		return res, fmt.Errorf("%w: %s", tac.ErrFormIncomplete, strings.Join(miss, ", "))
	}

	cfg, err := o.tenantConfig(ctx, req.TenantID)
	if err != nil {
		return res, translateToTAC(err)
	}
	if verr := o.Connector.ValidateConfig(cfg); verr != nil {
		return res, translateToTAC(verr)
	}

	audited := AuditedConnector{
		Inner: o.Connector, Sink: o.audit(), TenantID: req.TenantID, Actor: req.Actor,
		IncidentID: req.IncidentID, DeviceID: req.DeviceID, Vendor: o.Vendor,
	}

	var ref CaseRef
	switch {
	case caps.Create:
		ref, err = audited.CreateCase(ctx, cfg, tacToCaseRequest(req, o.now()))
		if err != nil {
			return res, translateToTAC(err)
		}
		res.CaseID = orDefault(ref.Number, ref.ID)
		res.CaseURL = ref.URL
		res.Status = "created"
	case caps.AttachToExistingOnly:
		// Attach-to-existing needs two values a create path does not: the
		// EXISTING case reference, and — for Cisco CXD — the per-case upload
		// token the admin copies out of the vendor's portal. The seam now
		// carries both, and carries them SEPARATELY on purpose: the case number
		// is a form field (rendered, echoed, logged), the token is
		// tac.CaseSecrets (redacted under every rendering Go has). Neither is
		// smuggled through a field meant for something else.
		if miss := attachOnlyMissingFields(req); len(miss) > 0 {
			return res, fmt.Errorf("%w: %s", tac.ErrFormIncomplete, strings.Join(miss, ", "))
		}
		ref = CaseRef{
			Number:      strings.TrimSpace(req.Form.ExistingCaseNumber),
			UploadToken: req.Secrets.UploadToken,
			UploadHost:  strings.TrimSpace(req.Secrets.UploadHost),
		}
		res.CaseID = ref.Number
		res.Status = "existing"
	default:
		res.AttachNote = "this connector cannot open a case; use the portal text and the downloaded bundle"
		return res, nil
	}

	if !caps.Attach {
		res.AttachNote = "this connector cannot attach a file; download the bundle and attach it yourself"
		return res, nil
	}
	if req.Form.Profile == tac.ProfileLinkOnly || strings.TrimSpace(req.BundlePath) == "" {
		res.AttachNote = "no attachment for this path: the case text references the bundle, which stays in Correlix for download"
		return res, nil
	}
	if o.OpenBundle == nil {
		res.AttachNote = "no bundle store is wired; download the bundle and attach it yourself"
		return res, nil
	}
	b, err := o.OpenBundle(ctx, req.TenantID, req.BundlePath)
	if err != nil {
		// The case IS created; say the attach failed rather than losing the case.
		res.AttachNote = "the bundle could not be read: " + Truncate(err.Error(), 200)
		return res, nil
	}
	if _, err := audited.AttachBundle(ctx, cfg, ref, b); err != nil {
		var tooBig AttachTooLargeError
		if errors.As(err, &tooBig) {
			res.AttachNote = fmt.Sprintf("the bundle is %d bytes, above this connector's %d-byte limit: %s",
				tooBig.Size, tooBig.Limit, tooBig.Advice)
			return res, nil
		}
		res.AttachNote = "the attachment failed: " + Truncate(err.Error(), 200)
		return res, nil
	}
	res.Attached = true
	return res, nil
}

// attachOnlyMissingFields names what an attach-to-existing connector still needs
// from the operator. Naming a missing field makes the UI disable submit WITH A
// REASON, which is the honesty rule: a capability we cannot reach is displayed,
// never silently degraded to a download.
//
// It reads the request rather than returning a constant list, so a form the
// operator HAS completed submits instead of being refused on principle.
func attachOnlyMissingFields(req tac.CaseRequest) []string {
	var miss []string
	if strings.TrimSpace(req.Form.ExistingCaseNumber) == "" {
		miss = append(miss, "existing_case_number (the SR or case this bundle attaches to)")
	}
	if strings.TrimSpace(req.Secrets.UploadToken) == "" {
		miss = append(miss, "upload_token (the per-case credential from the vendor's portal)")
	}
	return miss
}

// PollStatus reads a case's status back.
func (o *TACOpener) PollStatus(ctx context.Context, tenantID, caseID string) (tac.CaseResult, error) {
	res := tac.CaseResult{ConnectorID: o.Connector.Name(), CaseID: caseID, SubmittedAt: o.now()}
	if !o.Connector.Capabilities().Poll {
		return res, tac.ErrCapabilityUnsupported
	}
	cfg, err := o.tenantConfig(ctx, tenantID)
	if err != nil {
		return res, translateToTAC(err)
	}
	audited := AuditedConnector{Inner: o.Connector, Sink: o.audit(), TenantID: tenantID,
		Actor: "system:poll", Vendor: o.Vendor}
	rc, found, err := audited.FetchCase(ctx, cfg, CaseRef{ID: caseID, Number: caseID})
	if err != nil {
		return res, translateToTAC(err)
	}
	if !found {
		res.Status = "not_found"
		return res, nil
	}
	res.Status, res.CaseURL = rc.Status, rc.URL
	if rc.Number != "" {
		res.CaseID = rc.Number
	}
	return res, nil
}

// tenantConfig resolves one tenant's configuration. A nil resolver is not a
// crash and not a silent success: it is "unconfigured", which is exactly what
// an unwired deployment is.
func (o *TACOpener) tenantConfig(ctx context.Context, tenantID string) (TACConnectorConfig, error) {
	if o.Resolve == nil {
		return TACConnectorConfig{}, ErrNotConfigured
	}
	cfg, err := o.Resolve(ctx, tenantID)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			return TACConnectorConfig{}, ErrNotConfigured
		}
		return TACConnectorConfig{}, err
	}
	return cfg, nil
}

// tacToCaseRequest maps the seam's human-reviewed form onto our case request,
// stamping the approval from the authenticated actor.
func tacToCaseRequest(req tac.CaseRequest, now time.Time) CaseRequest {
	return CaseRequest{
		Synopsis:     req.Form.Title,
		Description:  req.Form.Description,
		Severity:     req.Form.Severity,
		ContactName:  req.Form.ContactName,
		ContactEmail: req.Form.ContactEmail,
		DeviceID:     orDefault(req.Hostname, req.DeviceID),
		SerialNumber: req.Form.SerialNumber,
		// The incident id is the idempotency key: Cisco and Juniper both treat a
		// repeat transaction id as an UPDATE, so a retried submit for one
		// incident can never open a second case.
		IdempotencyKey: orDefault(req.IncidentID, req.Form.Title),
		Fields: map[string]string{
			"contract_id":      req.Form.ContractID,
			"software_version": orDefault(req.Form.Product, req.Platform),
			"product":          req.Form.Product,
		},
		Approval: Approval{Actor: req.Actor, ApprovedAt: now},
	}
}

// translateToTAC maps our error vocabulary onto the seam's typed sentinels, so
// the route layer classifies without matching on strings. The underlying error
// is wrapped, not replaced: the vendor's verbatim entitlement text survives.
func translateToTAC(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotConfigured), errors.Is(err, ErrNotOnboarded):
		return fmt.Errorf("%w: %w", tac.ErrConnectorNotConfigured, err)
	case errors.Is(err, ErrUnsupported):
		return fmt.Errorf("%w: %w", tac.ErrCapabilityUnsupported, err)
	case errors.Is(err, ErrNotApproved):
		return fmt.Errorf("%w: %w", tac.ErrFormIncomplete, err)
	}
	var tooBig AttachTooLargeError
	if errors.As(err, &tooBig) {
		return fmt.Errorf("%w: %w", tac.ErrAttachmentTooLarge, err)
	}
	return err
}

// FileBundleOpener builds a BundleOpener over a tenant-keyed bundle directory.
// It is the guard the seam's contract demands: a connector must not accept a
// path from anywhere else, so the resolved path must stay inside THIS tenant's
// own directory after symlinks are followed.
func FileBundleOpener(rootFor func(tenantID string) string, sha256For func(path string) string) BundleOpener {
	return func(_ context.Context, tenantID, path string) (Bundle, error) {
		if rootFor == nil {
			return Bundle{}, errors.New("bundle store: no tenant bundle root configured")
		}
		root, err := filepath.EvalSymlinks(filepath.Clean(rootFor(tenantID)))
		if err != nil {
			return Bundle{}, fmt.Errorf("bundle store: tenant bundle directory is unavailable: %w", err)
		}
		full, err := filepath.EvalSymlinks(filepath.Clean(path))
		if err != nil {
			return Bundle{}, fmt.Errorf("bundle store: bundle is unavailable: %w", err)
		}
		rel, err := filepath.Rel(root, full)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			// Refuse without echoing the path: a traversal attempt is not a
			// reason to print an arbitrary filesystem location into a log.
			return Bundle{}, errors.New("bundle store: the bundle path is outside this tenant's bundle directory")
		}
		st, err := os.Stat(full)
		if err != nil {
			return Bundle{}, fmt.Errorf("bundle store: cannot stat the bundle: %w", err)
		}
		if st.IsDir() || st.Size() <= 0 {
			return Bundle{}, errors.New("bundle store: the bundle is not a readable file")
		}
		digest := ""
		if sha256For != nil {
			digest = sha256For(full)
		}
		return Bundle{
			Name:        filepath.Base(full),
			ContentType: "application/zip",
			Size:        st.Size(),
			SHA256:      digest,
			Open: func() (io.ReadCloser, error) {
				return os.Open(full) // #nosec G304 -- full is confined to the tenant's own bundle directory above
			},
		}, nil
	}
}

var _ tac.CaseOpener = (*TACOpener)(nil)
