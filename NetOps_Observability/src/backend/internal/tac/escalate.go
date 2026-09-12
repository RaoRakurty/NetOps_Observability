// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// escalate.go — ONE ACTION.
//
// Owner's goal, verbatim (2026-09-06): "We are just trying to close that initial
// time lag, so ease of collecting data and open the case with one or two clicks,
// that's the goal."
//
// So this file is the whole escalation expressed as two calls a person makes and
// nothing in between:
//
//	Escalate  — classify, plan, choose the capture, choose the connector, and
//	            start collecting. NOTHING leaves the platform.
//	Prepare   — build the redacted bundle and the pre-filled case form. Still
//	            nothing leaves the platform; this is what the confirmation
//	            screen renders.
//	Confirm   — the human presses the button. THIS is the only call that opens a
//	            case, and it is the only one that can.
//
// "Correlix never opens a case on its own" is not a slogan here, it is the
// shape of the API: Escalate and Prepare have no path to a vendor, and Confirm
// requires an authenticated actor the connector layer turns into an Approval.
//
// WHY THE ROUTE IS DECIDED HERE AND NOT IN THE UI. Which connector carries a
// vendor's cases is a TENANT SETTING with a fallback ladder — the tenant's own
// choice, then the vendor's configured native path, then email, then portal
// text — and every rung has to be explained on the confirmation screen ("this
// is going to Cisco Smart Bonding because your team routed Cisco there"). A
// client that computed it would have to hold the ladder, the connector
// capabilities and the tenant's settings, and would get it subtly different from
// the server that then acts on it.
//
// WHAT IS NEVER GUESSED. A missing entitlement identifier is a REFUSAL BY NAME
// with a link to where it is set, never a case filed with a blank field and
// never a silently-substituted default. That is the whole reason
// ConnectorInfo.Required crosses the seam.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/vendorprofile"
)

// EscalationSettings is the tenant's TAC routing, resolved for ONE device.
//
// It crosses into this package as plain data rather than as a store, because
// internal/tac must not import internal/ticketing (§2, no circular or
// cross-domain imports). The wiring layer resolves it and hands it in; this
// package neither reads nor writes any tenant configuration of its own.
type EscalationSettings struct {
	// Contact is the named human the vendor calls back.
	ContactName  string
	ContactEmail string
	ContactPhone string
	// RouteByVendor maps a device vendor id onto the connector id the tenant
	// chose for it.
	RouteByVendor map[string]string
	// CaptureByDialect maps a dialect slug onto the tenant capture/template id
	// that replaces the Correlix default.
	CaptureByDialect map[string]string
	// Contract is the support agreement covering THIS device, already resolved
	// through the per-serial override.
	ContractID      string
	AccountID       string
	SiteID          string
	SupportLevel    string
	ContractExpires string
	// ContractExpired is set when the coverage end date has passed. It is a
	// WARNING on the confirmation screen, never a refusal: a vendor may still
	// take the case, and Correlix does not get to decide that.
	ContractExpired bool
}

// RouteReason says WHY a connector was chosen. It is a closed set because it is
// rendered as a sentence on the confirmation screen and an operator has to be
// able to trust that the words mean the same thing every time.
type RouteReason string

const (
	// RouteTenantChoice — the tenant routed this vendor here explicitly.
	RouteTenantChoice RouteReason = "tenant_route"
	// RouteRequested — the operator picked this connector for this case.
	RouteRequested RouteReason = "requested"
	// RouteVendorNative — the vendor's own API path, configured for this tenant.
	RouteVendorNative RouteReason = "vendor_native"
	// RouteVendorEmail — the vendor's support mailbox, configured for this tenant.
	RouteVendorEmail RouteReason = "vendor_email"
	// RoutePortalFallback — no configured path; the operator gets the pre-filled
	// text, the bundle and the portal link, which is the minimum they can have.
	RoutePortalFallback RouteReason = "portal_fallback"
)

// EscalationRoute is the chosen path and the reason, for the screen.
type EscalationRoute struct {
	ConnectorID string      `json:"connector_id"`
	Display     string      `json:"display"`
	Vendor      string      `json:"vendor,omitempty"`
	Reason      RouteReason `json:"reason"`
	// Note is the operator-facing sentence: "your team routed Cisco here", "no
	// Cisco path is configured, so this is the portal text and the bundle".
	Note string `json:"note"`
	// Configured reports whether the chosen connector actually has credentials.
	// A tenant route naming an unconfigured connector is HONOURED and then
	// refused by name — silently rerouting a deliberate choice would teach an
	// operator that the setting does nothing.
	Configured bool `json:"configured"`
	// Portal marks a path that opens nothing: the operator gets text, a bundle
	// and a link. It is a complete outcome, not a failure.
	Portal bool `json:"portal"`
	// AuthMode is how the connector authenticates, so the case chip can say so.
	AuthMode string `json:"auth_mode,omitempty"`
	// Alternatives are the other connectors that could carry this vendor, for
	// the "send it somewhere else" control. Each is a ConnectorInfo id.
	Alternatives []string `json:"alternatives,omitempty"`
}

// EscalateRequest is what the ONE action carries. Everything else — the
// evidence, the tenant, the device's ownership — is server-derived.
type EscalateRequest struct {
	// ClassID overrides the classification. Empty means "use what Correlix
	// decided", which is the one-click path.
	ClassID string
	// ConnectorID overrides the routed connector for this case only.
	ConnectorID string
	// CaptureID overrides the capture for this case only. Empty means the
	// tenant's preferred capture for this dialect, then the Correlix default.
	CaptureID string
	// Severity is the incident severity, mapped by the caller into the vendor's
	// own vocabulary before it reaches a connector.
	Severity string
	// Title is the case title. Empty means the class title plus the hostname,
	// which is what a TAC engineer wants to read in a queue.
	Title string
	// Target scopes the plan (peer, interface, prefix…).
	Target Target
	// Topology is Correlix's own neighbourhood for the device.
	Topology []TopologyNote
	// IncludeOptional adds the dialect's opt-in captures.
	IncludeOptional bool
	// Consent names the intents the operator explicitly approved.
	Consent []string
}

// Proposal is the ONE CONFIRMATION SCREEN: exactly what will be sent, and to
// whom, and nothing has been sent yet.
type Proposal struct {
	IncidentID string          `json:"incident_id"`
	Route      EscalationRoute `json:"route"`
	Form       CaseForm        `json:"form"`
	// Bundle is the artifact that will be attached (or referenced), already
	// built and already redacted.
	Bundle StoredBundle `json:"bundle"`
	// Ready reports that Confirm would succeed. When it is false, Blockers says
	// what is missing, BY NAME, and where each one is set.
	Ready    bool            `json:"ready"`
	Blockers []RequiredField `json:"blockers,omitempty"`
	// BlockerNote is the same refusal as one sentence in the vendor's terms.
	BlockerNote string `json:"blocker_note,omitempty"`
	// Warnings are things an operator should see but that do not block: an
	// expired support contract, a capture that ran partially, a bundle trimmed
	// to fit a mailbox.
	Warnings []string `json:"warnings,omitempty"`
	// Redaction is the standing promise, restated on the screen that sends.
	Redaction string `json:"redaction"`
	// Approval is the sentence the screen carries above the button.
	Approval   string    `json:"approval"`
	PreparedAt time.Time `json:"prepared_at"`
}

// ApprovalSentence is the claim the confirmation screen makes, in one line. It
// is a constant because it is a PROMISE: if it ever stops being true, this
// string has to be deleted along with the code that made it false.
const ApprovalSentence = "Correlix never opens a case on its own. Nothing above has been sent — " +
	"pressing Open case is what sends it, from you, with your name on it."

// ── the route ladder ────────────────────────────────────────────────────────

// ChooseRoute picks the connector that will carry this case.
//
// The ladder, in order, and each rung is reported rather than assumed:
//
//  1. the operator's explicit choice for this case;
//  2. the tenant's configured route for this device's vendor — honoured even
//     when the named connector is unconfigured, because a deliberate setting
//     that silently does something else is worse than one that says no;
//  3. the vendor's own configured native path that can CREATE a case;
//  4. the vendor's configured mailbox;
//  5. portal text — always available, never a failure.
func ChooseRoute(infos []ConnectorInfo, vendor string, settings EscalationSettings, requested string) EscalationRoute {
	byID := map[string]ConnectorInfo{}
	for _, in := range infos {
		byID[in.ID] = in
	}
	vendorKey := strings.ToLower(strings.TrimSpace(vendor))

	alternatives := []string{}
	for _, in := range infos {
		if strings.EqualFold(in.Vendor, vendorKey) || in.ID == PortalTextConnectorID {
			alternatives = append(alternatives, in.ID)
		}
	}
	sort.Strings(alternatives)

	route := func(in ConnectorInfo, reason RouteReason, note string) EscalationRoute {
		return EscalationRoute{
			ConnectorID: in.ID, Display: in.Display, Vendor: in.Vendor, Reason: reason,
			Note: note, Configured: in.Configured, AuthMode: in.AuthMode,
			Portal:       !in.Can(CapCreate) && !in.Can(CapAttach),
			Alternatives: alternatives,
		}
	}

	if id := strings.TrimSpace(requested); id != "" {
		if in, ok := byID[id]; ok {
			return route(in, RouteRequested, "you chose this path for this case.")
		}
	}
	if id, ok := settings.RouteByVendor[vendorKey]; ok && strings.TrimSpace(id) != "" {
		if in, found := byID[strings.TrimSpace(id)]; found {
			note := "your team routed " + displayVendor(vendorKey) + " cases here."
			if !in.Configured {
				note += " It has no credentials for this tenant yet, so this case cannot be opened through it until they are brought."
			}
			return route(in, RouteTenantChoice, note)
		}
		// A route naming a connector this platform no longer has is a real
		// misconfiguration. It falls through to the ladder, and the note that
		// eventually renders says which rung was used — the operator is never
		// told their setting was honoured when it was not.
	}
	// The vendor's own configured paths, best capability first.
	for _, want := range []func(ConnectorInfo) bool{
		func(in ConnectorInfo) bool { return in.Can(CapCreate) && in.Can(CapAttach) },
		func(in ConnectorInfo) bool { return in.Can(CapCreate) },
		func(in ConnectorInfo) bool { return in.Can(CapAttach) },
	} {
		for _, in := range infos {
			if !strings.EqualFold(in.Vendor, vendorKey) || !in.Configured || !want(in) {
				continue
			}
			reason := RouteVendorNative
			note := displayVendor(vendorKey) + "'s own support integration, configured for your tenant."
			if strings.HasPrefix(in.ID, "email-") {
				reason = RouteVendorEmail
				note = displayVendor(vendorKey) + "'s support mailbox, configured for your tenant."
			}
			return route(in, reason, note)
		}
	}
	// Portal text: the honest floor. It is always present because the service
	// appends it, and it is a complete outcome — pre-filled text, the bundle and
	// the vendor's own link.
	for _, in := range infos {
		if in.ID != PortalTextConnectorID {
			continue
		}
		note := "no support integration is configured for " + displayVendor(vendorKey) +
			", so Correlix has prepared the case text, the redacted bundle and the vendor's portal link for you to submit."
		return route(in, RoutePortalFallback, note)
	}
	return EscalationRoute{
		ConnectorID: PortalTextConnectorID, Display: "Portal text", Reason: RoutePortalFallback,
		Note:   "no case connector is available on this deployment; download the bundle and use the case text.",
		Portal: true, Alternatives: alternatives,
	}
}

// displayVendor renders a vendor id for a sentence.
//
// The name comes from the VENDOR REGISTRY (internal/vendorprofile), which is
// where this platform's vendor vocabulary lives — this file must not carry a
// second copy of it, and the vocabulary guard enforces that. A vendor the
// registry does not know is title-cased rather than replaced: inventing a vendor
// name would be worse than showing the id the inventory actually holds.
func displayVendor(v string) string {
	id := strings.ToLower(strings.TrimSpace(v))
	if id == "" {
		return "this vendor"
	}
	if rec, ok := vendorprofile.Default().Vendor(id); ok && strings.TrimSpace(rec.DisplayName) != "" {
		return rec.DisplayName
	}
	return strings.ToUpper(id[:1]) + id[1:]
}

// ── the one action ──────────────────────────────────────────────────────────

// Escalate is CLICK ONE: classify, plan, pick the capture, pick the route and
// start collecting. It performs no remote write of any kind.
//
// It returns the chosen route so the panel can name it while the collection
// runs, and the job so the Captures rows have something to show. A deployment
// with no capture transport is not a failure: the escalation still classifies,
// still plans, still routes, and the operator pastes outputs in — which is
// exactly what CollectNote has always said.
func (s *Service) Escalate(ctx context.Context, tenant, incident string, dev Device, ev Evidence,
	req EscalateRequest, settings EscalationSettings, infos []ConnectorInfo) (*State, EscalationRoute, error) {
	classID := strings.TrimSpace(req.ClassID)
	if classID == "" {
		classID = s.Classify(tenant, incident, ev).ClassID
	}
	plan, err := s.Plan(tenant, incident, classID, dev, PlanOptions{
		IncludeOptional: req.IncludeOptional,
		Target:          req.Target,
		Topology:        req.Topology,
		Consent:         ConsentSet(req.Consent),
	})
	if err != nil {
		return nil, EscalationRoute{}, err
	}
	route := ChooseRoute(infos, dev.Vendor, settings, req.ConnectorID)

	s.mu.Lock()
	st := s.stateLocked(tenant, incident)
	r := route
	st.Route = &r
	st.Settings = &settings
	st.Proposal = nil
	st.UpdatedAt = s.now().UTC()
	s.mu.Unlock()

	// A collection is started only when there is a transport for it. Without
	// one the escalation is still real — the plan, the route and the paste path
	// are all there — and the panel says so in the server's own words.
	if s.collector != nil {
		if _, cerr := s.StartCollect(tenant, incident, nil); cerr != nil && !errors.Is(cerr, ErrCollectBusy) {
			return s.Get(tenant, incident), route, cerr
		}
	}
	_ = plan
	_ = ctx
	return s.Get(tenant, incident), route, nil
}

// PreparedCapture reports which capture the escalation should run for a device's
// dialect: the tenant's preferred one when they set one for this platform,
// otherwise the Correlix default derived from the plan.
//
// It returns the template id and an honest note. A preferred id the tenant
// cannot resolve is NOT silently ignored: the caller applies it, fails, and the
// escalation says the default was used instead.
func PreferredCaptureID(settings EscalationSettings, dialect string) (string, bool) {
	id := strings.TrimSpace(settings.CaptureByDialect[strings.ToLower(strings.TrimSpace(dialect))])
	return id, id != ""
}

// Prepare is the step between the two clicks: build the redacted bundle and the
// pre-filled form for the chosen route, and work out whether Confirm could
// succeed. It performs no remote write.
func (s *Service) Prepare(ctx context.Context, tenant, incident string, in BundleInput,
	req EscalateRequest, actor string, infos []ConnectorInfo) (*Proposal, error) {
	s.mu.Lock()
	st := s.states[tenant][incident]
	if st == nil {
		s.mu.Unlock()
		return nil, errors.New("tac: this incident has not been escalated in this api process")
	}
	if st.Capture == nil {
		s.mu.Unlock()
		return nil, errors.New("tac: nothing has been collected for this escalation yet")
	}
	route := EscalationRoute{}
	if st.Route != nil {
		route = *st.Route
	}
	settings := EscalationSettings{}
	if st.Settings != nil {
		settings = *st.Settings
	}
	capture := st.Capture
	class := Classification{}
	if st.Classification != nil {
		class = *st.Classification
	}
	s.mu.Unlock()

	if id := strings.TrimSpace(req.ConnectorID); id != "" && id != route.ConnectorID {
		route = ChooseRoute(infos, capture.Vendor(), settings, id)
	}
	if route.ConnectorID == "" {
		route = ChooseRoute(infos, capture.Vendor(), settings, "")
	}

	info, found := ConnectorByID(infos, route.ConnectorID)
	if !found {
		return nil, fmt.Errorf("tac: the routed case connector %q is not available", route.ConnectorID)
	}
	in.Profile = ProfileForConnector(info)
	in.MaxBytes = info.MaxAttachmentBytes
	b, meta, err := s.Bundle(ctx, tenant, incident, in)
	if err != nil {
		return nil, err
	}

	form := CaseForm{
		ConnectorID:  route.ConnectorID,
		Title:        caseTitle(req.Title, class, capture),
		Description:  b.Statement.Text,
		Severity:     strings.TrimSpace(req.Severity),
		Product:      firstFilled(capture.Model, capture.Platform),
		SerialNumber: capture.Serial,
		ContractID:   settings.ContractID,
		ContactName:  settings.ContactName,
		ContactEmail: settings.ContactEmail,
		BundleName:   meta.Name,
		BundleBytes:  meta.Bytes,
		Profile:      in.Profile,
	}
	caseReq := CaseRequest{
		TenantID: tenant, IncidentID: incident, ClassID: class.ClassID,
		DeviceID: capture.DeviceID, Hostname: capture.Hostname, Platform: capture.Platform,
		Form: form, BundlePath: incident + "/" + meta.Name, Actor: actor,
	}
	prepared, ferr := s.PrepareCaseWith(ctx, tenant, route.ConnectorID, caseReq)
	if ferr != nil && !errors.Is(ferr, ErrConnectorNotConfigured) {
		return nil, ferr
	}
	if ferr == nil {
		form = prepared
	}

	p := &Proposal{
		IncidentID: incident, Route: route, Form: form, Bundle: meta,
		Redaction:  RedactionNoteText,
		Approval:   ApprovalSentence,
		PreparedAt: s.now().UTC(),
	}
	p.Blockers = append(p.Blockers, form.MissingRequired...)
	p.BlockerNote = form.MissingNote
	if !info.Configured && !route.Portal {
		p.BlockerNote = strings.TrimSpace(info.StatusNote + " " + p.BlockerNote)
	}
	p.Ready = len(p.Blockers) == 0 && (route.Portal || info.Configured)
	p.Warnings = escalationWarnings(settings, capture, b)

	s.mu.Lock()
	if st2 := s.states[tenant][incident]; st2 != nil {
		st2.Proposal = p
		st2.Route = &route
		st2.UpdatedAt = s.now().UTC()
	}
	s.mu.Unlock()
	return p, nil
}

// PrepareCaseWith is PrepareCase without the "unknown connector" ambiguity: it
// is the form-filling half the proposal needs, and it returns the connector's
// own refusal rather than swallowing it.
func (s *Service) PrepareCaseWith(ctx context.Context, tenant, connectorID string, req CaseRequest) (CaseForm, error) {
	o, info, ok := s.opener(ctx, tenant, connectorID)
	if !ok {
		return CaseForm{}, errors.New("tac: unknown case connector")
	}
	req.Form.Profile = ProfileForConnector(info)
	f, err := o.PrepareCase(ctx, req)
	if err != nil {
		return CaseForm{}, err
	}
	if !info.Configured {
		return f, ErrConnectorNotConfigured
	}
	return f, nil
}

// escalationWarnings gathers what an operator should SEE without being stopped.
func escalationWarnings(settings EscalationSettings, capt *Capture, b *Bundle) []string {
	var out []string
	if settings.ContractExpired {
		out = append(out, "your support contract for this vendor shows an end date of "+
			settings.ContractExpires+". The vendor may refuse the case; Correlix will still send it if you do.")
	}
	if capt != nil {
		failed := 0
		for _, cc := range capt.Commands {
			if cc.Err != "" {
				failed++
			}
		}
		if failed > 0 {
			out = append(out, fmt.Sprintf("%d of %d commands did not come back. The bundle carries what was collected and names the rest.",
				failed, len(capt.Commands)))
		}
		if capt.Stopped != "" {
			out = append(out, capt.Stopped)
		}
	}
	if b != nil && len(b.Manifest.Trimmed) > 0 {
		out = append(out, fmt.Sprintf("%d output(s) were left out to fit this path's attachment limit. The manifest names every one, and the full bundle stays here to download.",
			len(b.Manifest.Trimmed)))
	}
	return out
}

// caseTitle builds the case title a TAC engineer reads in a queue: what broke,
// on which box. An operator-supplied title always wins.
func caseTitle(supplied string, class Classification, capt *Capture) string {
	if t := strings.TrimSpace(supplied); t != "" {
		return clip(t, 200)
	}
	title := strings.TrimSpace(class.Title)
	if title == "" {
		title = strings.TrimSpace(capt.ClassTitle)
	}
	if title == "" {
		title = "Network issue"
	}
	if h := strings.TrimSpace(capt.Hostname); h != "" {
		title += " on " + h
	}
	return clip(title, 200)
}

func firstFilled(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// ConnectorByID finds a connector's declared info in a list.
func ConnectorByID(infos []ConnectorInfo, id string) (ConnectorInfo, bool) {
	for _, in := range infos {
		if in.ID == id {
			return in, true
		}
	}
	return ConnectorInfo{}, false
}

// Confirm is CLICK TWO: the human-approved submit.
//
// It is the ONLY method in this package that can cause a case to exist. It
// refuses when the proposal was not ready — by name, with the same blockers the
// screen showed — so a client that skipped the screen cannot open a case with a
// blank entitlement field.
func (s *Service) Confirm(ctx context.Context, tenant, incident, actor string, form CaseForm,
	secrets CaseSecrets) (CaseResult, error) {
	s.mu.Lock()
	st := s.states[tenant][incident]
	if st == nil || st.Proposal == nil {
		s.mu.Unlock()
		return CaseResult{}, errors.New("tac: nothing has been prepared for this escalation — review the case before sending it")
	}
	p := st.Proposal
	capture := st.Capture
	s.mu.Unlock()

	if strings.TrimSpace(actor) == "" {
		return CaseResult{}, fmt.Errorf("%w: a case is opened by a person, never by an engine", ErrFormIncomplete)
	}
	// The operator may complete a blocked field on the screen; the check is
	// re-run against what they actually submitted, not against what was
	// prepared, so filling it in works and leaving it blank still refuses.
	merged := mergeCaseForm(p.Form, form)
	if note := missingNoteFor(p.Blockers, merged); note != "" {
		return CaseResult{}, fmt.Errorf("%w: %s", ErrFormIncomplete, note)
	}

	req := CaseRequest{
		TenantID: tenant, IncidentID: incident, ClassID: p.Form.ConnectorID,
		Form: merged, BundlePath: incident + "/" + p.Bundle.Name, Actor: actor, Secrets: secrets,
	}
	if capture != nil {
		req.ClassID = capture.ClassID
		req.DeviceID, req.Hostname, req.Platform = capture.DeviceID, capture.Hostname, capture.Platform
	}
	return s.SubmitCase(ctx, tenant, incident, p.Route.ConnectorID, req)
}

// mergeCaseForm folds the operator's edits onto the prepared form. The
// connector id, the bundle and the problem statement are NOT editable: they are
// what the server built and what the screen showed.
func mergeCaseForm(prepared, edited CaseForm) CaseForm {
	out := prepared
	if v := strings.TrimSpace(edited.Title); v != "" {
		out.Title = clip(v, 200)
	}
	if v := strings.TrimSpace(edited.Severity); v != "" {
		out.Severity = clip(v, 64)
	}
	if v := strings.TrimSpace(edited.Product); v != "" {
		out.Product = clip(v, 128)
	}
	if v := strings.TrimSpace(edited.SerialNumber); v != "" {
		out.SerialNumber = clip(v, 64)
	}
	if v := strings.TrimSpace(edited.ContractID); v != "" {
		out.ContractID = clip(v, 64)
	}
	if v := strings.TrimSpace(edited.ContactName); v != "" {
		out.ContactName = clip(v, 128)
	}
	if v := strings.TrimSpace(edited.ContactEmail); v != "" {
		out.ContactEmail = clip(v, 200)
	}
	if v := strings.TrimSpace(edited.ExistingCaseNumber); v != "" {
		out.ExistingCaseNumber = clip(v, 64)
	}
	return out
}

// missingNoteFor re-applies the proposal's blockers to the SUBMITTED form and
// renders what is still missing, by name.
func missingNoteFor(blockers []RequiredField, form CaseForm) string {
	if len(blockers) == 0 {
		return ""
	}
	have := formValues(form)
	// An AnyOf group is satisfied by one complete alternative.
	groups := map[string]bool{}
	for _, f := range blockers {
		if f.AnyOf == "" {
			continue
		}
		if _, seen := groups[f.AnyOf]; !seen {
			groups[f.AnyOf] = anyOfSatisfied(blockers, f.AnyOf, have)
		}
	}
	var still []string
	seen := map[string]bool{}
	for _, f := range blockers {
		if f.AnyOf != "" {
			if groups[f.AnyOf] || seen["group:"+f.AnyOf] {
				continue
			}
			seen["group:"+f.AnyOf] = true
			still = append(still, anyOfPhrase(blockers, f.AnyOf))
			continue
		}
		if strings.TrimSpace(have[f.Key]) != "" || seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		still = append(still, f.Label+" ("+f.SettingsHint+")")
	}
	if len(still) == 0 {
		return ""
	}
	return "this case still needs " + strings.Join(still, "; ")
}

// anyOfSatisfied reports whether ONE complete alternative of a group is present.
func anyOfSatisfied(fields []RequiredField, group string, have map[string]string) bool {
	alts := map[string][]RequiredField{}
	for _, f := range fields {
		if f.AnyOf != group {
			continue
		}
		alt := f.Alt
		if alt == "" {
			alt = f.Key
		}
		alts[alt] = append(alts[alt], f)
	}
	for _, members := range alts {
		complete := true
		for _, m := range members {
			if strings.TrimSpace(have[m.Key]) == "" {
				complete = false
				break
			}
		}
		if complete {
			return true
		}
	}
	return false
}

// anyOfPhrase renders one unsatisfied group as "a serial number, or a contract
// id and a PID (Administration → Ticket delivery → Vendor contracts)".
func anyOfPhrase(fields []RequiredField, group string) string {
	order := []string{}
	byAlt := map[string][]string{}
	hint := ""
	for _, f := range fields {
		if f.AnyOf != group {
			continue
		}
		alt := f.Alt
		if alt == "" {
			alt = f.Key
		}
		if _, seen := byAlt[alt]; !seen {
			order = append(order, alt)
		}
		byAlt[alt] = append(byAlt[alt], f.Label)
		if hint == "" {
			hint = f.SettingsHint
		}
	}
	parts := make([]string, 0, len(order))
	for _, alt := range order {
		parts = append(parts, strings.Join(byAlt[alt], " and "))
	}
	phrase := strings.Join(parts, ", or ")
	if hint != "" {
		phrase += " (" + hint + ")"
	}
	return phrase
}

// formValues renders a form as the key→value map the required-field check reads.
func formValues(f CaseForm) map[string]string {
	return map[string]string{
		"title":                f.Title,
		"description":          f.Description,
		"severity":             f.Severity,
		"product":              f.Product,
		"pid":                  f.Product,
		"serial_number":        f.SerialNumber,
		"contract_id":          f.ContractID,
		"contact_name":         f.ContactName,
		"contact_email":        f.ContactEmail,
		"existing_case_number": f.ExistingCaseNumber,
	}
}
