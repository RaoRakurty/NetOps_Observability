// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// escalatehttp.go — the HTTP surface over the ONE ACTION, as an injectable
// module in the same shape TemplateAPI and LearningAPI already have.
//
// It lives here rather than in the api's adapter block because everything in it
// is a DECISION: which route was chosen and how it is described, what the
// confirmation screen carries, what Confirm re-checks, how a case becomes a
// tracked link with a cadence, when a manual refresh is too soon. The api keeps
// what only the api can do — resolving the caller's own incident and device
// through the principal-scoped stores — and hands it in.
//
// THE SPLIT IS THE SAFETY PROPERTY. escalate and prepare have no path to a
// vendor; confirm is the only method here that can cause a case to exist, and it
// goes through Service.Confirm, which needs a proposal and a named human. A
// reader checking "Correlix never opens a case on its own" has three functions
// to read, not a thousand-line adapter block.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// escalateMaxBody bounds every request this surface accepts (§3/§9).
const escalateMaxBody = 1 << 20

// Subject is the resolved escalation subject: one incident, in the caller's own
// scope, with the tenant already stamped from the records that authorised it.
type Subject struct {
	IncidentID string
	Ref        string
	Title      string
	Tenant     string
	Cross      bool
	// Devices are the affected device ids from the correlation object, offered
	// as the escalation's device picker.
	Devices []string
	// Actor is the authenticated principal. It is what becomes the vendor's
	// named human, so it is carried explicitly rather than re-derived.
	Actor string
}

// EscalateAPIDeps are the surface's injected collaborators. Every one is
// required: a surface built from incomplete deps could act unscoped, so the
// constructor fails closed rather than defaulting a gap.
type EscalateAPIDeps struct {
	// Service is the escalation engine.
	Service *Service
	// Resolve authorises the caller and resolves {id} in their OWN scope. It has
	// already written the response (404 for a cross-tenant or unknown id) when
	// ok is false. level is the platform's own permission level.
	Resolve func(w http.ResponseWriter, r *http.Request, write bool) (Subject, bool)
	// ResolveDevice resolves the subject device through the principal-scoped
	// inventory, having written the response when ok is false.
	ResolveDevice func(w http.ResponseWriter, r *http.Request, subj Subject, deviceID string) (Device, bool)
	// Evidence assembles the CLOSED classification input from stores the caller
	// can already read, and reports which answered and which did not.
	Evidence func(r *http.Request, subj Subject) (Evidence, []string, []string)
	// Topology is Correlix's own neighbourhood for a device.
	Topology func(r *http.Request, deviceID string) []TopologyNote
	// BundleInput gathers the evidence the bundle carries.
	BundleInput func(r *http.Request, subj Subject) BundleInput
	// Settings resolves the tenant's TAC routing for ONE device.
	Settings func(r *http.Request, subj Subject, vendor, serial string) EscalationSettings
	// Tracker holds open cases and their refresh schedule.
	Tracker *CaseTracker
	// Poller re-reads one case's status. It is also what "Refresh now" uses, so
	// the manual path and the scheduled one cannot diverge.
	Poller *CasePoller
	// Templates resolves the per-tenant command-template store at REQUEST time —
	// a function rather than a value because the store is built after the routes
	// are registered. It may be nil on a build without one; a reviewed
	// collection then answers 503 rather than running an unresolved list.
	Templates func() TemplateStore
	// PersistCase writes a case link onto the incident record.
	PersistCase func(ctx context.Context, tenant, incident string, link CaseLink)
	// Remember writes the escalation into the investigation memory Iris recalls
	// from. Best-effort by contract: it must never fail a case a human opened.
	Remember func(r *http.Request, subj Subject, b *Bundle, res CaseResult)
	// Audit records every action, on both outcomes.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)
	// WriteJSON / WriteError are the platform's response writers.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// Now is the clock.
	Now func() time.Time
}

func (d EscalateAPIDeps) validate() error {
	missing := make([]string, 0, 12)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Service", d.Service != nil)
	check("Resolve", d.Resolve != nil)
	check("ResolveDevice", d.ResolveDevice != nil)
	check("Evidence", d.Evidence != nil)
	check("Topology", d.Topology != nil)
	check("BundleInput", d.BundleInput != nil)
	check("Settings", d.Settings != nil)
	check("Tracker", d.Tracker != nil)
	check("Poller", d.Poller != nil)
	check("PersistCase", d.PersistCase != nil)
	check("Audit", d.Audit != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("Now", d.Now != nil)
	if len(missing) > 0 {
		return fmt.Errorf("tac: EscalateAPIDeps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// EscalateAPI is the one-action surface.
type EscalateAPI struct{ deps EscalateAPIDeps }

// NewEscalateAPI builds it, failing CLOSED on incomplete deps.
func NewEscalateAPI(d EscalateAPIDeps) (*EscalateAPI, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &EscalateAPI{deps: d}, nil
}

// escalateBody is what the Escalate button sends. Everything else — the tenant,
// the device's ownership, the evidence, the contracts — is server-derived.
type escalateBody struct {
	DeviceID        string   `json:"device_id"`
	ClassID         string   `json:"class_id"`
	ConnectorID     string   `json:"connector_id"`
	CaptureID       string   `json:"capture_id"`
	Severity        string   `json:"severity"`
	Title           string   `json:"title"`
	IncludeOptional bool     `json:"include_optional"`
	Consent         []string `json:"consent"`
	Target          struct {
		Interface string `json:"interface"`
		Peer      string `json:"peer"`
		Prefix    string `json:"prefix"`
		VRF       string `json:"vrf"`
		RouterID  string `json:"router_id"`
		Area      string `json:"area"`
	} `json:"target"`
}

// maxTargetField bounds one operator-supplied scoping value.
const maxTargetField = 128

func (b escalateBody) request() EscalateRequest {
	return EscalateRequest{
		ClassID:         clip(strings.TrimSpace(b.ClassID), 64),
		ConnectorID:     clip(strings.TrimSpace(b.ConnectorID), 64),
		CaptureID:       clip(strings.TrimSpace(b.CaptureID), 128),
		Severity:        clip(strings.TrimSpace(b.Severity), 64),
		Title:           clip(strings.TrimSpace(b.Title), 200),
		IncludeOptional: b.IncludeOptional,
		Consent:         b.Consent,
		Target: Target{
			Interface: clip(b.Target.Interface, maxTargetField),
			Peer:      clip(b.Target.Peer, maxTargetField),
			Prefix:    clip(b.Target.Prefix, maxTargetField),
			VRF:       clip(b.Target.VRF, maxTargetField),
			RouterID:  clip(b.Target.RouterID, maxTargetField),
			Area:      clip(b.Target.Area, maxTargetField),
		},
	}
}

// ── CLICK ONE ───────────────────────────────────────────────────────────────

// HandleEscalate classifies, plans, routes and starts collecting. It sends
// NOTHING: there is no path from here to a vendor.
func (a *EscalateAPI) HandleEscalate(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// It runs commands against a device, so it is the write gate.
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body escalateBody
	if !a.decode(w, r, &body) {
		return
	}
	dev, ok := a.deps.ResolveDevice(w, r, subj, strings.TrimSpace(body.DeviceID))
	if !ok {
		return
	}
	ev, sources, missing := a.deps.Evidence(r, subj)
	settings := a.deps.Settings(r, subj, dev.Vendor, dev.Serial)
	svc := a.deps.Service
	infos := svc.Connectors(r.Context(), subj.Tenant)
	req := body.request()
	req.Topology = a.deps.Topology(r, dev.ID)

	st, route, err := svc.Escalate(r.Context(), subj.Tenant, subj.IncidentID, dev, ev, req, settings, infos)
	switch {
	case errors.Is(err, ErrUnknownClass):
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	case errors.Is(err, ErrCollectBusy):
		a.deps.WriteError(w, http.StatusConflict, err)
		return
	case err != nil:
		a.deps.WriteError(w, http.StatusBadGateway, err)
		return
	}
	// The tenant's preferred capture for this platform. A preference is NAMED
	// rather than silently applied: the operator sees which set will run.
	captureNote := ""
	if id, want := PreferredCaptureID(settings, dev.Platform); want && strings.TrimSpace(body.CaptureID) == "" {
		captureNote = "Your team's preferred capture for this platform (" + id +
			") is configured; it is applied when you review the capture list."
	}
	a.deps.Audit(r, subj.Tenant, "tac.escalate", map[string]any{
		"incident_id": subj.IncidentID, "device_id": dev.ID, "connector": route.ConnectorID,
		"route_reason": string(route.Reason), "class_id": req.ClassID,
	})
	a.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"incident_id": subj.IncidentID, "route": route, "state": st.View(),
		"can_collect": svc.CanCollect(), "collect_note": CollectNote(svc.CanCollect()),
		"capture_note":     captureNote,
		"evidence_sources": sources, "evidence_missing": missing,
		"connectors": infos,
	})
}

// ── the confirmation screen ─────────────────────────────────────────────────

// HandlePrepare builds the redacted bundle and the pre-filled form. It is a POST
// because it WRITES a bundle to the store; a GET that did that would be a GET
// with side effects. It still sends nothing to a vendor.
func (a *EscalateAPI) HandlePrepare(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body escalateBody
	if !a.decode(w, r, &body) {
		return
	}
	svc := a.deps.Service
	p, err := svc.Prepare(r.Context(), subj.Tenant, subj.IncidentID, a.deps.BundleInput(r, subj),
		body.request(), subj.Actor, svc.Connectors(r.Context(), subj.Tenant))
	if err != nil {
		a.deps.WriteError(w, http.StatusConflict, err)
		return
	}
	a.deps.Audit(r, subj.Tenant, "tac.escalate.prepare", map[string]any{
		"incident_id": subj.IncidentID, "connector": p.Route.ConnectorID,
		"bundle": p.Bundle.Name, "ready": p.Ready, "blockers": len(p.Blockers),
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"proposal": p, "state": svc.Get(subj.Tenant, subj.IncidentID).View(),
	})
}

// ── the dry run ─────────────────────────────────────────────────────────────

// HandleDryRun authenticates against the configured endpoint with the stored
// credential and describes the exact request(s) a submit would make. It creates
// nothing.
func (a *EscalateAPI) HandleDryRun(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// It spends the tenant's credential against a vendor, so it is the write
	// gate — the same one the connector Test button uses.
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body escalateBody
	if !a.decode(w, r, &body) {
		return
	}
	svc := a.deps.Service
	st := svc.Get(subj.Tenant, subj.IncidentID)
	connector := strings.TrimSpace(body.ConnectorID)
	if connector == "" && st != nil && st.Route != nil {
		connector = st.Route.ConnectorID
	}
	if connector == "" {
		a.deps.WriteError(w, http.StatusConflict,
			errors.New("escalate the incident first, or send connector_id"))
		return
	}
	rep, err := svc.DryRun(r.Context(), subj.Tenant, connector, dryRunCaseRequest(subj, st))
	if err != nil {
		a.deps.WriteError(w, http.StatusConflict, err)
		return
	}
	a.deps.Audit(r, subj.Tenant, "tac.escalate.dry_run", map[string]any{
		"incident_id": subj.IncidentID, "connector": connector,
		"outcome": string(rep.Outcome), "blockers": len(rep.Blockers),
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"dry_run": rep})
}

// dryRunCaseRequest assembles the case a dry run rehearses from the escalation's
// own state — never from the request body, so a client cannot rehearse a case
// with fields the confirmation screen never showed.
func dryRunCaseRequest(subj Subject, st *State) CaseRequest {
	req := CaseRequest{TenantID: subj.Tenant, IncidentID: subj.IncidentID, Actor: subj.Actor}
	if st == nil {
		return req
	}
	if st.Proposal != nil {
		req.Form = st.Proposal.Form
	}
	if st.Capture != nil {
		req.ClassID = st.Capture.ClassID
		req.DeviceID, req.Hostname, req.Platform = st.Capture.DeviceID, st.Capture.Hostname, st.Capture.Platform
	}
	return req
}

// ── CLICK TWO ───────────────────────────────────────────────────────────────

// confirmBody is the edited form the human approved, plus the ephemeral per-case
// upload credential where a vendor mints one.
type confirmBody struct {
	Form struct {
		Title              string `json:"title"`
		Severity           string `json:"severity"`
		Product            string `json:"product"`
		SerialNumber       string `json:"serial_number"`
		ContractID         string `json:"contract_id"`
		ContactName        string `json:"contact_name"`
		ContactEmail       string `json:"contact_email"`
		ExistingCaseNumber string `json:"existing_case_number"`
	} `json:"form"`
	// UploadToken / UploadHost are read straight into CaseSecrets and never
	// stored, echoed or logged — which is why they are not on the form above.
	UploadToken string `json:"upload_token"`
	UploadHost  string `json:"upload_host"`
}

func (b confirmBody) form() CaseForm {
	return CaseForm{
		Title:              clip(strings.TrimSpace(b.Form.Title), 200),
		Severity:           clip(strings.TrimSpace(b.Form.Severity), 64),
		Product:            clip(strings.TrimSpace(b.Form.Product), 128),
		SerialNumber:       clip(strings.TrimSpace(b.Form.SerialNumber), 64),
		ContractID:         clip(strings.TrimSpace(b.Form.ContractID), 64),
		ContactName:        clip(strings.TrimSpace(b.Form.ContactName), 128),
		ContactEmail:       clip(strings.TrimSpace(b.Form.ContactEmail), 200),
		ExistingCaseNumber: clip(strings.TrimSpace(b.Form.ExistingCaseNumber), 64),
	}
}

// HandleConfirm is the human-approved submit, and the ONLY handler in this file
// that can cause a vendor case to exist.
func (a *EscalateAPI) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body confirmBody
	if !a.decode(w, r, &body) {
		return
	}
	svc := a.deps.Service
	res, err := svc.Confirm(r.Context(), subj.Tenant, subj.IncidentID, subj.Actor, body.form(),
		CaseSecrets{
			UploadToken: clip(strings.TrimSpace(body.UploadToken), 512),
			UploadHost:  clip(strings.TrimSpace(body.UploadHost), 253),
		})
	if err != nil {
		a.deps.WriteError(w, http.StatusConflict, err)
		return
	}
	link := a.recordCase(r, subj, res, body.form().Severity)
	a.deps.Audit(r, subj.Tenant, "tac.escalate.confirm", map[string]any{
		"incident_id": subj.IncidentID, "connector": res.ConnectorID, "case_id": res.CaseID,
		"attached": res.Attached, "severity": link.Severity, "tier": string(link.Tier),
	})
	// The escalation becomes an investigation Iris recalls, WITH the case id on
	// it, so the next operator asking about this device is told it was escalated
	// and how. Best-effort: a memory that could not be written must never fail a
	// case a human just opened.
	if a.deps.Remember != nil {
		if b, _, berr := svc.Bundle(r.Context(), subj.Tenant, subj.IncidentID, a.deps.BundleInput(r, subj)); berr == nil {
			a.deps.Remember(r, subj, b, res)
		}
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"result": res, "case": link,
		"status_line": link.StatusLine(a.deps.Now()), "tooltip": link.Tooltip(),
	})
}

// recordCase files the opened case on the incident and starts its
// severity-tiered refresh schedule.
func (a *EscalateAPI) recordCase(r *http.Request, subj Subject, res CaseResult, severity string) CaseLink {
	link := CaseLink{
		Connector: res.ConnectorID, CaseID: res.CaseID, CaseURL: res.CaseURL,
		Status: res.Status, Severity: severity, Attached: res.Attached,
		AttachNote: res.AttachNote, OpenedAt: res.SubmittedAt,
		// Kept so a later reply read can tell THIS case's reply from every other
		// reply in the tenant's mailbox.
		ThreadSubject: res.ThreadSubject,
	}
	for _, info := range a.deps.Service.Connectors(r.Context(), subj.Tenant) {
		if info.ID != res.ConnectorID {
			continue
		}
		link.Vendor, link.AuthMode = info.Vendor, info.AuthMode
		// A path that can read a status back, OR one that can at least learn the
		// case NUMBER from the vendor's reply, is worth refreshing. Nothing else
		// is, and saying so is what stops the chip promising a status that can
		// never arrive.
		link.Pollable = info.Can(CapPollStatus) || (info.NumberLookup && res.CaseID == "")
	}
	link = a.deps.Tracker.Record(subj.Tenant, subj.IncidentID, link)
	a.deps.PersistCase(r.Context(), subj.Tenant, subj.IncidentID, link)
	return link
}

// ── Refresh now ─────────────────────────────────────────────────────────────

// HandleRefresh re-reads one case's status on the operator's demand, floored at
// one refresh per case per minute so a person cannot be the thing that trips a
// vendor's rate limit.
func (a *EscalateAPI) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// A refresh reads the VENDOR, spends this case's manual-refresh budget and
	// writes the answer back onto the incident record → write level.
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	link, found := a.deps.Tracker.Get(subj.Tenant, subj.IncidentID)
	if !found {
		// An incident with no case reads exactly like one that was never
		// escalated, which is the answer §3a wants for a foreign id too.
		http.NotFound(w, r)
		return
	}
	if allowed, wait := a.deps.Tracker.AllowManual(subj.Tenant, subj.IncidentID); !allowed {
		a.deps.WriteError(w, http.StatusTooManyRequests, fmt.Errorf(
			"this case was refreshed less than a minute ago; try again in %d seconds",
			int(wait.Seconds())+1))
		return
	}
	out := a.deps.Poller.Poll(r.Context(), subj.Tenant, subj.IncidentID, link)
	a.deps.PersistCase(r.Context(), subj.Tenant, subj.IncidentID, out)
	a.deps.Audit(r, subj.Tenant, "tac.case.refresh", map[string]any{
		"incident_id": subj.IncidentID, "case_id": out.CaseID, "status": out.Status,
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"case": out, "status_line": out.StatusLine(a.deps.Now()), "tooltip": out.Tooltip(),
	})
}

// decode reads a bounded, unknown-field-rejecting body.
func (a *EscalateAPI) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, escalateMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return false
	}
	return true
}

// DialectChoices lists the platforms a preferred capture may be set for. It is
// on the service because the catalogue is, and the settings surface should not
// have to reach through two packages to ask a question the catalogue answers.
func (s *Service) DialectChoices() []struct{ Dialect, Display string } {
	out := []struct{ Dialect, Display string }{}
	if s == nil || s.catalog == nil {
		return out
	}
	for _, d := range s.catalog.Dialects() {
		display := d
		if dp, ok := s.catalog.PlanFor(d); ok && strings.TrimSpace(dp.Display) != "" {
			display = dp.Display
		}
		out = append(out, struct{ Dialect, Display string }{Dialect: d, Display: display})
	}
	return out
}

// ── the escalation's own state, classification, plan and collection ─────────
//
// These four were the api's before 2026-09-07 and are the package's now, for
// the same reason the one-action handlers are: every judgement in them — which
// class was chosen and from what, what a plan may include, which reviewed list
// may run — belongs to the engine, and the api supplies only the resolved
// caller and the stores it alone can read.

// HandleState renders the escalation as it stands.
func (a *EscalateAPI) HandleState(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	subj, ok := a.deps.Resolve(w, r, false)
	if !ok {
		return
	}
	svc := a.deps.Service
	st := svc.Get(subj.Tenant, subj.IncidentID)
	body := map[string]any{
		"incident_id":     subj.IncidentID,
		"incident_ref":    subj.Ref,
		"title":           subj.Title,
		"can_collect":     svc.CanCollect(),
		"collect_note":    CollectNote(svc.CanCollect()),
		"catalog_version": svc.Catalog().Version,
		"connectors":      svc.Connectors(r.Context(), subj.Tenant),
		"devices":         subj.Devices,
		"state":           st.View(),
	}
	if st == nil {
		body["state_note"] = "This incident has not been escalated in this api process. " +
			"Classify it to start; an escalation started before a restart is not resumed."
	}
	// The case chip's own two strings, computed HERE so the panel, the answer
	// card and the incident list cannot word the same case differently.
	if link, found := a.deps.Tracker.Get(subj.Tenant, subj.IncidentID); found {
		body["case"] = link
		body["case_status_line"] = link.StatusLine(a.deps.Now())
		body["case_tooltip"] = link.Tooltip()
	}
	a.deps.WriteJSON(w, http.StatusOK, body)
}

// HandleClassify records a classification from the evidence already on screen.
func (a *EscalateAPI) HandleClassify(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// Classifying RECORDS the class on the escalation and nulls a plan built for
	// the old one → write level.
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	ev, sources, missing := a.deps.Evidence(r, subj)
	svc := a.deps.Service
	res := svc.Classify(subj.Tenant, subj.IncidentID, ev)
	a.deps.Audit(r, subj.Tenant, "tac.classify", map[string]any{
		"incident_id": subj.IncidentID, "class_id": res.ClassID, "classified": res.Classified,
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"incident_id":      subj.IncidentID,
		"classification":   res,
		"evidence_sources": sources,
		"evidence_missing": missing,
		"classes":          svc.Catalog().ClassSummaries(),
	})
}

// HandlePlan builds the command plan for a class on a device.
func (a *EscalateAPI) HandlePlan(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// Planning OVERWRITES the escalation's prepared plan → write level.
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body escalateBody
	if !a.decode(w, r, &body) {
		return
	}
	dev, ok := a.deps.ResolveDevice(w, r, subj, strings.TrimSpace(body.DeviceID))
	if !ok {
		return
	}
	svc := a.deps.Service
	classID := strings.TrimSpace(body.ClassID)
	if classID == "" {
		if st := svc.Get(subj.Tenant, subj.IncidentID); st != nil && st.Classification != nil {
			classID = st.Classification.ClassID
		}
	}
	if classID == "" {
		a.deps.WriteError(w, http.StatusBadRequest,
			errors.New("classify the incident first, or send class_id"))
		return
	}
	req := body.request()
	plan, err := svc.Plan(subj.Tenant, subj.IncidentID, classID, dev, PlanOptions{
		IncludeOptional: req.IncludeOptional,
		Target:          req.Target,
		Topology:        a.deps.Topology(r, dev.ID),
		Consent:         ConsentSet(req.Consent),
	})
	if err != nil {
		if errors.Is(err, ErrUnknownClass) {
			a.deps.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.deps.WriteError(w, http.StatusBadGateway, err)
		return
	}
	a.deps.Audit(r, subj.Tenant, "tac.plan", map[string]any{
		"incident_id": subj.IncidentID, "device_id": dev.ID, "class_id": classID,
		"commands": len(plan.Steps), "unbound": len(plan.Unbound), "has_plan": plan.HasPlan,
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"plan": plan, "can_collect": svc.CanCollect(), "collect_note": CollectNote(svc.CanCollect()),
	})
}

// collectBody is the collect request: a cancel, a reviewed command list, and the
// paste fallback for a platform with no authored plan.
type collectBody struct {
	Outputs []struct {
		Intent  string `json:"intent"`
		Command string `json:"command"`
		Output  string `json:"output"`
	} `json:"outputs"`
	Cancel bool `json:"cancel"`
	// Steps is the operator's REVIEWED command list. It is UNTRUSTED: every line
	// is re-validated against the output-only policy and the read-only grammar
	// before anything runs, and one refusal fails the WHOLE collection naming
	// the line.
	Steps []struct {
		Command string `json:"command"`
		Note    string `json:"note"`
	} `json:"steps"`
	// TemplateID names the template the list was loaded from. Only the ID is
	// accepted: name, source and version are resolved server-side, so a client
	// cannot forge the provenance a bundle records.
	TemplateID string `json:"template_id"`
}

// Bounds on the paste fallback (§3/§9).
const (
	maxSuppliedOutputs = 40
	maxSuppliedBytes   = 256 << 10
)

// HandleCollect starts (or cancels) the read-only collection.
func (a *EscalateAPI) HandleCollect(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	// A collection operates against a device → write level.
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body collectBody
	if !a.decode(w, r, &body) {
		return
	}
	svc := a.deps.Service
	if body.Cancel {
		stopped := svc.Cancel(subj.Tenant, subj.IncidentID)
		a.deps.Audit(r, subj.Tenant, "tac.collect.cancel",
			map[string]any{"incident_id": subj.IncidentID, "stopped": stopped})
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{
			"cancelled": stopped, "state": svc.Get(subj.Tenant, subj.IncidentID).View(),
		})
		return
	}
	if len(body.Outputs) > maxSuppliedOutputs {
		a.deps.WriteError(w, http.StatusBadRequest,
			fmt.Errorf("at most %d pasted outputs per request", maxSuppliedOutputs))
		return
	}
	if len(body.Steps) > 0 && !a.applyReview(w, r, subj, body) {
		return
	}
	supplied := make([]SuppliedOutput, 0, len(body.Outputs))
	for _, o := range body.Outputs {
		supplied = append(supplied, SuppliedOutput{
			Intent:  clip(strings.TrimSpace(o.Intent), 128),
			Command: clip(strings.TrimSpace(o.Command), 512),
			Output:  clip(o.Output, maxSuppliedBytes),
		})
	}
	job, err := svc.StartCollect(subj.Tenant, subj.IncidentID, supplied)
	switch {
	case errors.Is(err, ErrNoRunner):
		a.deps.WriteError(w, http.StatusServiceUnavailable, errors.New(CollectNote(false)))
		return
	case errors.Is(err, ErrCollectBusy):
		a.deps.WriteError(w, http.StatusConflict, err)
		return
	case err != nil:
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.deps.Audit(r, subj.Tenant, "tac.collect", map[string]any{
		"incident_id": subj.IncidentID, "job_id": job.ID,
		"commands": job.Total, "pasted": len(supplied),
	})
	a.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"job": job, "state": svc.Get(subj.Tenant, subj.IncidentID).View(),
	})
}

// applyReview folds the operator's chosen capture into the plan before the
// collection starts. ApplyCapture resolves the template id in the caller's OWN
// scope (so a bundle can never name a template nobody can find) and refuses the
// WHOLE list on one bad line, naming it.
func (a *EscalateAPI) applyReview(w http.ResponseWriter, r *http.Request, subj Subject, body collectBody) bool {
	if a.deps.Templates == nil {
		a.deps.WriteError(w, http.StatusServiceUnavailable,
			errors.New("command templates are not available on this build"))
		return false
	}
	steps := make([]ReviewedStep, 0, len(body.Steps))
	for _, st := range body.Steps {
		steps = append(steps, ReviewedStep{
			Command: clip(strings.TrimSpace(st.Command), 512),
			Note:    clip(st.Note, 800),
		})
	}
	plan, ref, res, err := a.deps.Service.ApplyCapture(r.Context(), a.deps.Templates(),
		subj.Tenant, subj.IncidentID, strings.TrimSpace(body.TemplateID), steps)
	switch {
	case errors.Is(err, ErrTemplateInvalid):
		a.deps.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error": "the reviewed command list was refused; nothing ran", "validation": res,
		})
		return false
	case errors.Is(err, ErrCollectBusy):
		a.deps.WriteError(w, http.StatusConflict, err)
		return false
	case err != nil:
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return false
	}
	a.deps.Audit(r, subj.Tenant, "tac.collect.review", map[string]any{
		"incident_id": subj.IncidentID, "commands": len(plan.Steps), "edits": len(plan.Edits),
		"template_id": ref.ID, "template_version": ref.Version,
	})
	return true
}

// ── the older two-step case flow ────────────────────────────────────────────
//
// It predates the one-click action and stays: an operator who wants to choose
// the connector and read the form before anything is prepared still can, and
// the escalation-step tests are written against it. Submit=false returns the
// pre-filled form; Submit=true performs the human-approved action.

type caseBody struct {
	ConnectorID string `json:"connector_id"`
	Submit      bool   `json:"submit"`
	Form        struct {
		Title              string `json:"title"`
		Severity           string `json:"severity"`
		Product            string `json:"product"`
		SerialNumber       string `json:"serial_number"`
		ContractID         string `json:"contract_id"`
		ContactName        string `json:"contact_name"`
		ContactEmail       string `json:"contact_email"`
		ExistingCaseNumber string `json:"existing_case_number"`
	} `json:"form"`
	// UploadToken / UploadHost are the EPHEMERAL per-case credential the operator
	// copies from the vendor's portal. They are read straight into CaseSecrets
	// and never stored, echoed or logged, which is why they are not on the form.
	UploadToken string `json:"upload_token"`
	UploadHost  string `json:"upload_host"`
}

// HandleCase prepares or submits a case through a chosen connector.
func (a *EscalateAPI) HandleCase(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	subj, ok := a.deps.Resolve(w, r, true)
	if !ok {
		return
	}
	var body caseBody
	if !a.decode(w, r, &body) {
		return
	}
	connector := strings.TrimSpace(body.ConnectorID)
	if connector == "" {
		connector = PortalTextConnectorID
	}
	svc := a.deps.Service
	st := svc.Get(subj.Tenant, subj.IncidentID)
	if st == nil || st.Capture == nil {
		a.deps.WriteError(w, http.StatusConflict,
			errors.New("collect the evidence before opening a case"))
		return
	}
	// The bundle is built to THE CHOSEN CONNECTOR'S limits, not to this
	// package's defaults: an email path caps well below the profile constant
	// because base64 expands the attachment on the wire, and trimming to the
	// wrong number produces a case the vendor's mail gateway silently rejects.
	in := a.deps.BundleInput(r, subj)
	for _, info := range svc.Connectors(r.Context(), subj.Tenant) {
		if info.ID != connector {
			continue
		}
		in.Profile = ProfileForConnector(info)
		in.MaxBytes = info.MaxAttachmentBytes
	}
	b, meta, err := svc.Bundle(r.Context(), subj.Tenant, subj.IncidentID, in)
	if err != nil {
		a.deps.WriteError(w, http.StatusConflict, err)
		return
	}
	caseReq := CaseRequest{
		TenantID: subj.Tenant, IncidentID: subj.IncidentID,
		ClassID:  b.Manifest.Classification.ClassID,
		DeviceID: st.Capture.DeviceID, Hostname: st.Capture.Hostname, Platform: st.Capture.Platform,
		Actor: subj.Actor,
		Form: CaseForm{
			Title:              clip(strings.TrimSpace(body.Form.Title), 200),
			Description:        b.Statement.Text,
			Severity:           clip(strings.TrimSpace(body.Form.Severity), 32),
			Product:            clip(strings.TrimSpace(body.Form.Product), 128),
			SerialNumber:       clip(strings.TrimSpace(body.Form.SerialNumber), 64),
			ContractID:         clip(strings.TrimSpace(body.Form.ContractID), 64),
			ContactName:        clip(strings.TrimSpace(body.Form.ContactName), 128),
			ContactEmail:       clip(strings.TrimSpace(body.Form.ContactEmail), 200),
			BundleName:         meta.Name,
			BundleBytes:        meta.Bytes,
			ExistingCaseNumber: clip(strings.TrimSpace(body.Form.ExistingCaseNumber), 64),
		},
		Secrets: CaseSecrets{
			UploadToken: clip(strings.TrimSpace(body.UploadToken), 512),
			UploadHost:  clip(strings.TrimSpace(body.UploadHost), 253),
		},
		// The bundle the connector will stream, addressed inside THIS tenant's
		// own bundle tree. The store validates both segments, so a connector can
		// never be handed a path from anywhere else.
		BundlePath: subj.IncidentID + "/" + meta.Name,
	}
	if !body.Submit {
		form, info, ferr := svc.PrepareCase(r.Context(), subj.Tenant, connector, caseReq)
		if ferr != nil {
			a.deps.WriteError(w, http.StatusConflict, ferr)
			return
		}
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{
			"form": form, "connector": info, "bundle": meta,
		})
		return
	}
	res, serr := svc.SubmitCase(r.Context(), subj.Tenant, subj.IncidentID, connector, caseReq)
	if serr != nil {
		a.deps.WriteError(w, http.StatusConflict, serr)
		return
	}
	link := a.recordCase(r, subj, res, caseReq.Form.Severity)
	a.deps.Audit(r, subj.Tenant, "tac.case", map[string]any{
		"incident_id": subj.IncidentID, "connector": connector,
		"case_id": res.CaseID, "attached": res.Attached,
	})
	// The escalation is recorded as an investigation Iris recalls, so the next
	// operator asking about this device is told it was escalated and how. A case
	// id is worth a SECOND memory row even when the bundle already wrote one:
	// "escalated" and "escalated, case 12345" are different facts.
	if a.deps.Remember != nil && (svc.MarkRemembered(subj.Tenant, subj.IncidentID) || res.CaseID != "") {
		a.deps.Remember(r, subj, b, res)
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"result": res, "bundle": meta, "case": link,
	})
}
