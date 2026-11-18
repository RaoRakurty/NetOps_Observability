// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// templates.go — Correlix's built-in upgrade procedures (internal/upgrademop) as
// starting points for a workspace's own runbooks:
//
//	GET  /api/ai/runbooks/templates                the procedures, with their sources
//	POST /api/ai/runbooks/templates/{name}/adopt   {name?} — copy one as a DRAFT
//
// Adopting is Create with the procedure's text: version 1 is a draft by the person
// who adopted it, and from there the ordinary flow decides — submit, then approval
// by someone else (orgcontext refuses the author). Nothing reaches Iris until a
// second person has approved exactly that text. A procedure is kind "mop": Iris
// shows it, it never runs it (owner decision 2026-11-18, read-only).

import (
	"errors"
	"net/http"
	"strings"

	"netops/backend/internal/orgcontext"
	"netops/backend/internal/upgrademop"
)

// TemplateView is one built-in procedure as the API shows it.
type TemplateView struct {
	Name      string          `json:"name"`
	Vendor    string          `json:"vendor"`
	Family    string          `json:"family"`
	Title     string          `json:"title"`
	AppliesTo string          `json:"applies_to"`
	Source    TemplateDocView `json:"source"`
	// Steps are the lines a person follows, each saying who performs it and the
	// read-only check Iris can run for it.
	Steps []string `json:"steps"`
	// Checks are the read-only show commands, without repeats.
	Checks []string `json:"checks"`
}

// TemplateDocView is the public document a procedure was written from.
type TemplateDocView struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Version string `json:"version"`
	Read    string `json:"read"`
}

// TemplateViews lists the built-in procedures.
func TemplateViews() []TemplateView {
	all := upgrademop.All()
	out := make([]TemplateView, 0, len(all))
	for _, t := range all {
		steps := make([]string, 0, len(t.Steps))
		for _, s := range t.Steps {
			steps = append(steps, s.StepLine())
		}
		out = append(out, TemplateView{
			Name: t.Name, Vendor: t.Vendor, Family: t.Family, Title: t.Title, AppliesTo: t.AppliesTo,
			Source: TemplateDocView{Title: t.Doc.Title, URL: t.Doc.URL, Version: t.Doc.Version, Read: t.Doc.Read},
			Steps:  steps, Checks: t.Checks(),
		})
	}
	return out
}

// TemplateSource is the runbook text a procedure adopts as, under name ("" =
// the procedure's own name).
func TemplateSource(template, name string) (NewRunbook, error) {
	t, ok := upgrademop.Get(template)
	if !ok {
		return NewRunbook{}, orgcontext.ErrNotFound
	}
	if name = strings.TrimSpace(name); name != "" {
		t.Name = name
	}
	return NewRunbook{Name: t.Name, Kind: KindMOP, Source: Source{SkillMD: t.SkillMD()}}, nil
}

func (d Deps) listTemplates(w http.ResponseWriter, r *http.Request) {
	if _, ok := d.caller(w, r, orgcontext.LevelRead); !ok {
		return
	}
	d.WriteJSON(w, http.StatusOK, map[string]any{"templates": TemplateViews()})
}

func (d Deps) adoptTemplate(w http.ResponseWriter, r *http.Request, template string) {
	c, ok := d.caller(w, r, orgcontext.LevelAuthor)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if r.ContentLength != 0 && !d.decode(w, r, &req) {
		return
	}
	in, err := TemplateSource(template, req.Name)
	if err != nil {
		d.WriteError(w, http.StatusNotFound, errors.New("there is no built-in procedure by that name"))
		return
	}
	rb, err := d.Store.Create(r.Context(), c.Tenant, c.Sub, in)
	if err != nil {
		d.fail(w, r, c, "adopt", "", err)
		return
	}
	det := detail(rb, 1, "adopt_template")
	det["template"] = template
	d.Audit(r, c, "allow", det)
	d.WriteJSON(w, http.StatusCreated, d.viewOf(rb))
}

// templateRoute serves the templates sub-tree; handled=false is not one of its paths.
func (d Deps) templateRoute(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) == 0 || parts[0] != "templates" {
		return false
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		d.listTemplates(w, r)
	case len(parts) == 3 && parts[2] == "adopt" && r.Method == http.MethodPost:
		d.adoptTemplate(w, r, parts[1])
	case len(parts) == 1 || (len(parts) == 3 && parts[2] == "adopt"):
		d.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	default:
		d.WriteError(w, http.StatusNotFound, errors.New("not found"))
	}
	return true
}
