// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// captureshttp.go — the Captures HTTP surface.
//
//	GET  /api/tac/captures         — this tenant's saved captures (?dialect=)
//	POST /api/tac/captures         — save a capture as a tenant template
//	POST /api/tac/captures/upload  — parse + validate an uploaded file; stores nothing
//	GET  /api/tac/captures/{id}    — one saved capture
//
// It hangs off the SAME TemplateAPI as the command templates, because a saved
// capture IS a template: one store, one RLS policy, one isolation model, one
// place a scoping bug could live. §3a rule 4 is satisfied by the store the
// templates already go through, not by a second one written to look like it.
//
// §3a, restated for this surface:
//   - every read and write resolves to ONE concrete tenant; a cross-tenant
//     principal is refused, never given a wildcard;
//   - the owner is stamped from the TOKEN — the wire types carry no tenant field
//     at all, so a tenant in the body is a 400 from DisallowUnknownFields;
//   - another tenant's capture id answers the same 404 an absent id does.
//
// THE UPLOAD IS THE HOSTILE PATH and it is treated as one:
//   - the body is bounded by MaxBytesReader BEFORE a byte is parsed;
//   - the filename arrives as a query parameter, is used ONLY to pick a parser
//     and to seed a name, and never touches a path;
//   - every parsed line goes through the SAME TemplateValidator the review step
//     and the collector use, and ONE refused line refuses the WHOLE upload,
//     naming the line number and the rule. Nothing is silently dropped: a
//     customer who uploads twelve commands and gets eleven has been lied to
//     about what will run.
//   - and it STORES NOTHING. An upload is a choice for this escalation; it
//     becomes a row only when the operator presses "Save as template".

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// The registered route strings. `CaptureItemPath` is a subtree: it serves both
// the upload verb and one capture by id, so the adapter registers two patterns
// rather than four and the dispatch that decides between them is here, beside
// the handlers, rather than in the root package.
const (
	CapturesPath      = "/api/tac/captures"
	CaptureItemPath   = "/api/tac/captures/"
	captureUploadLeaf = "upload"
)

// CaptureUploadPath is the upload route as the OpenAPI surface and the UI name
// it. It is served by the subtree handler.
const CaptureUploadPath = CaptureItemPath + captureUploadLeaf

// capturesNote states the standing rule wherever captures are listed. It is the
// ONE line the panel prints about what a capture may hold.
const capturesNote = "Every command — Correlix's own, your saved sets and anything you upload — is held to the " +
	"output-only policy: nothing that changes configuration, restarts or reboots, or addresses a daemon."

// captureUploadRefused is the refusal headline. It says the whole file was
// refused, because that is what happened.
const captureUploadRefused = "That file was not accepted: nothing in it will run until every line passes."

// HandleCaptures serves the collection route.
func (a *TemplateAPI) HandleCaptures(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.listCaptures(w, r)
	case http.MethodPost:
		a.saveCapture(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// HandleCaptureSubtree serves /api/tac/captures/{id} and the upload verb.
func (a *TemplateAPI) HandleCaptureSubtree(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, CaptureItemPath)
	if rest == captureUploadLeaf {
		a.uploadCapture(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if !tplIDRE.MatchString(rest) {
		// An unparseable id is a 404, not a 400: a 400 would confirm that a
		// well-formed id from another tenant is "the right shape".
		http.NotFound(w, r)
		return
	}
	a.getCapture(w, r, rest)
}

// ── GET /api/tac/captures ───────────────────────────────────────────────────

func (a *TemplateAPI) listCaptures(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownTemplateQuery(r, "dialect"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, _, ok := a.scoped(w, r, TemplateGateRead)
	if !ok {
		return
	}
	dialect := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("dialect")))
	mine, err := a.deps.Store.List(r.Context(), tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if dialect != "" {
		mine = filterDialect(mine, dialect)
	}
	SortTemplates(mine)
	out := make([]CommandCapture, 0, len(mine))
	for _, t := range mine {
		out = append(out, CaptureFromTemplate(t))
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"captures": out,
		"count":    len(out),
		"limit":    MaxTemplatesPerTenant,
		"formats":  CaptureFormats,
		"note":     capturesNote,
	})
}

// ── GET /api/tac/captures/{id} ──────────────────────────────────────────────

func (a *TemplateAPI) getCapture(w http.ResponseWriter, r *http.Request, id string) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// A Correlix default is reference data — the same bytes for every tenant —
	// and needs authorization rather than a tenant scope.
	if IsDefaultTemplateID(id) {
		if _, ok := a.deps.Authz(w, r, TemplateGateRead); !ok {
			return
		}
		t, found := a.deps.Catalog.DefaultTemplate(id)
		if !found {
			http.NotFound(w, r)
			return
		}
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{"capture": CaptureFromTemplate(t)})
		return
	}
	tenant, _, ok := a.scoped(w, r, TemplateGateRead)
	if !ok {
		return
	}
	t, err := a.deps.Store.Get(r.Context(), tenant, id)
	if err != nil {
		http.NotFound(w, r) // a cross-tenant id is indistinguishable from absent
		return
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"capture": CaptureFromTemplate(t)})
}

// ── POST /api/tac/captures ──────────────────────────────────────────────────

// captureWire is the save body. As with templateWire there is deliberately NO
// tenant, id, source or created_by field: ownership and provenance are stamped
// server-side, and a tenant on the wire is not merely ignored — it cannot be
// expressed, so DisallowUnknownFields turns an attempt into a 400.
type captureWire struct {
	Dialect  string `json:"dialect"`
	Name     string `json:"name"`
	Commands []struct {
		Command string `json:"command"`
		Note    string `json:"note"`
	} `json:"commands"`
}

func (in captureWire) toTemplate() Template {
	steps := make([]TemplateStep, 0, len(in.Commands))
	for _, c := range in.Commands {
		steps = append(steps, TemplateStep{Command: c.Command, Note: c.Note})
	}
	return Template{Dialect: in.Dialect, Name: in.Name, Steps: steps}
}

// saveCapture stores an uploaded (or edited) capture as one of this tenant's
// templates. It runs the SAME validator the template route runs — there is one
// admission decision in this package and this is not a second one.
func (a *TemplateAPI) saveCapture(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	var in captureWire
	if !a.decode(w, r, &in) {
		return
	}
	t := in.toTemplate()
	t.TenantID = tenant // from the TOKEN, never the body
	t.CreatedBy = p.Subject
	t, res, err := a.deps.Validator.ValidateTemplate(t)
	if err != nil {
		a.writeInvalid(w, res)
		return
	}
	out, cerr := a.deps.Store.Create(r.Context(), t)
	switch {
	case errors.Is(cerr, ErrTemplatesFull):
		a.deps.WriteError(w, http.StatusConflict, cerr)
		return
	case cerr != nil:
		a.deps.WriteError(w, http.StatusBadRequest, cerr)
		return
	}
	a.deps.Audit(r, p, "tac.capture.save", map[string]any{
		"template_id": out.ID, "dialect": out.Dialect, "commands": len(out.Steps),
	})
	a.deps.WriteJSON(w, http.StatusCreated, map[string]any{
		"capture": CaptureFromTemplate(out), "validation": res,
	})
}

// ── POST /api/tac/captures/upload ───────────────────────────────────────────

// CaptureRefusal is one refused line of an upload, reported the way an operator
// can act on it: the line number IN THEIR FILE, the command, and the rule that
// refused it by name.
type CaptureRefusal struct {
	Line    int    `json:"line"`
	Command string `json:"command"`
	Family  string `json:"family,omitempty"`
	Rule    string `json:"rule,omitempty"`
	Reason  string `json:"reason"`
}

func (a *TemplateAPI) uploadCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	if err := rejectUnknownTemplateQuery(r, "filename", "dialect"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// An upload is per-tenant WORK even before it is per-tenant data: it is
	// validated against this tenant's dialect and audited under this tenant's
	// name, so it takes the same concrete scope every other capture route takes.
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	filename := strings.TrimSpace(r.URL.Query().Get("filename"))
	if filename == "" {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("name the file being uploaded (?filename=)"))
		return
	}
	if _, known := CaptureFormatOf(filename); !known {
		a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("%w (accepted: %s)",
			ErrCaptureFormat, formatList()))
		return
	}
	// §9: bound the body BEFORE reading it. The reader is the bound; a
	// Content-Length header is the client's claim and is not trusted.
	r.Body = http.MaxBytesReader(w, r.Body, MaxCaptureUploadBytes)
	data, rerr := io.ReadAll(r.Body)
	if rerr != nil {
		a.deps.WriteError(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("that file is larger than the %d KiB Correlix reads", MaxCaptureUploadBytes>>10))
		return
	}
	parsed, perr := ParseCapture(filename, data)
	if perr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, perr)
		return
	}
	dialect := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("dialect")))
	res := a.deps.Validator.Validate(dialect, commandsOfCapture(parsed.Commands))
	if !res.OK {
		a.deps.Audit(r, p, "tac.capture.upload.refused", map[string]any{
			"format": string(parsed.Format), "commands": len(parsed.Commands), "refused": res.Refused,
		})
		a.deps.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error":      captureUploadRefused,
			"refusals":   captureRefusals(parsed.Commands, res),
			"validation": res,
		})
		return
	}
	a.deps.Audit(r, p, "tac.capture.upload", map[string]any{
		"format": string(parsed.Format), "commands": len(parsed.Commands), "dialect": dialect,
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"capture": CommandCapture{
			ID: "upload:" + string(parsed.Format), TenantID: tenant, Name: parsed.Name,
			Source: CaptureUploaded, Dialect: dialect, Commands: parsed.Commands,
			CreatedBy: p.Subject, CreatedAt: a.deps.Now().UTC(),
		},
		"validation": res,
		"note":       capturesNote,
	})
}

// commandsOfCapture is the validator's input: the commands, in order.
func commandsOfCapture(in []CaptureCommand) []string {
	out := make([]string, 0, len(in))
	for _, c := range in {
		out = append(out, c.Command)
	}
	return out
}

// captureRefusals maps the validator's per-INDEX verdicts back onto the FILE's
// own line numbers. The mapping matters: telling somebody "line 4 was refused"
// when their document's line 4 is a comment sends them to the wrong line.
func captureRefusals(cmds []CaptureCommand, res ValidationResult) []CaptureRefusal {
	out := make([]CaptureRefusal, 0, res.Refused)
	for _, lv := range res.Lines {
		if lv.OK {
			continue
		}
		line := lv.Index + 1
		if lv.Index >= 0 && lv.Index < len(cmds) && cmds[lv.Index].Line > 0 {
			line = cmds[lv.Index].Line
		}
		reason := strings.TrimSpace(lv.Reason)
		if reason == "" {
			reason = "refused by the output-only policy"
		}
		out = append(out, CaptureRefusal{
			Line: line, Command: lv.Command, Family: lv.Family, Rule: lv.Rule, Reason: reason,
		})
	}
	return out
}

// formatList names the accepted formats in a refusal, so the operator is told
// what to bring instead of only what was wrong.
func formatList() string {
	names := make([]string, 0, len(CaptureFormats))
	for _, f := range CaptureFormats {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}
