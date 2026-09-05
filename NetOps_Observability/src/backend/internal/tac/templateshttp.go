package tac

// templateshttp.go — the command-template HTTP surface.
//
//	GET    /api/tac/templates          — this tenant's templates + Correlix defaults
//	POST   /api/tac/templates          — save a set (owner stamped from the token)
//	GET    /api/tac/templates/defaults — the Correlix defaults alone (?dialect=)
//	POST   /api/tac/templates/validate — per-line verdicts for a command list
//	GET    /api/tac/templates/{id}     — one template
//	PUT    /api/tac/templates/{id}     — replace its commands/name/description
//	DELETE /api/tac/templates/{id}     — remove it
//
// §3a: the five item/collection routes are per-tenant DATA. A cross-tenant
// principal (the platform owner in the Global view) must scope into a concrete
// tenant before reading or writing — refused, never a wildcard. Another tenant's
// id returns 404, identical to an id that does not exist, so this subtree is not
// an existence oracle. A Correlix DEFAULT is readable by everyone (it is
// reference data, identical for every tenant) and is immutable: PUT/DELETE on a
// `correlix:` id is refused with the reason, and the operator is told to save a
// copy instead.
//
// §3 fail-closed at the boundary: an unknown query parameter is REFUSED, every
// body is bounded before it is decoded, unknown fields are rejected, and the
// tenant on the wire does not exist as a field at all.
//
// THE VALIDATION ROUTE IS NOT A CONVENIENCE. It is the same validator the write
// path and the collect path use, exposed so the operator sees a refusal WHILE
// TYPING rather than after pressing collect. It changes nothing and stores
// nothing; the authoritative check is still the one on the way in.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// TemplateGate is the module's abstract authorization gate; the integrator maps
// it onto the platform's RBAC model.
type TemplateGate int

const (
	// TemplateGateRead — listing and reading templates, and validating a line.
	TemplateGateRead TemplateGate = iota
	// TemplateGateWrite — saving, editing or deleting a template.
	TemplateGateWrite
)

// TemplatePrincipal is the resolved caller.
type TemplatePrincipal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// TemplateAPIDeps are the HTTP layer's injected collaborators. Every one of them
// is required: a surface built from incomplete deps could read unscoped, so the
// constructor fails closed rather than filling a gap with a default.
type TemplateAPIDeps struct {
	// Authz authorizes the caller and returns the resolved principal. It has
	// already written the error response when ok is false.
	Authz func(w http.ResponseWriter, r *http.Request, gate TemplateGate) (TemplatePrincipal, bool)
	// Store is the per-tenant template store.
	Store TemplateStore
	// Validator is the command validator — the SAME one the collect path uses.
	Validator *TemplateValidator
	// Catalog supplies the Correlix defaults and the dialect vocabulary.
	Catalog *Catalog
	// Audit records a write. Required: a template change decides what runs
	// against a customer's routers and must never be a silent edit (§10). It is
	// handed the resolved principal so the integrator writes the actor and the
	// tenant from the SAME values the handler authorised on — never from a
	// second, later re-derivation that could disagree with it.
	Audit func(r *http.Request, p TemplatePrincipal, action string, fields map[string]any)
	// WriteJSON / WriteError are the platform's response writers.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// Now is the clock.
	Now func() time.Time
}

func (d TemplateAPIDeps) validate() error {
	missing := make([]string, 0, 7)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Store", d.Store != nil)
	check("Validator", d.Validator != nil)
	check("Catalog", d.Catalog != nil)
	check("Audit", d.Audit != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("Now", d.Now != nil)
	if len(missing) > 0 {
		return fmt.Errorf("tac: TemplateAPIDeps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// TemplateAPI is the module's HTTP surface.
type TemplateAPI struct{ deps TemplateAPIDeps }

// NewTemplateAPI builds the surface, failing CLOSED on incomplete deps.
func NewTemplateAPI(d TemplateAPIDeps) (*TemplateAPI, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &TemplateAPI{deps: d}, nil
}

// The registered route strings. Exported so the integrator registers exactly
// what this file serves, and so a guard can pin that they still agree.
const (
	TemplatesPath         = "/api/tac/templates"
	TemplateItemPath      = "/api/tac/templates/"
	TemplatesDefaultsPath = "/api/tac/templates/defaults"
	TemplatesValidatePath = "/api/tac/templates/validate"
)

// templateMaxBody bounds a create/update/validate body before it is decoded
// (§9, and the architecture guard that requires MaxBytesReader on every write).
// 200 commands × 512 bytes plus metadata fits inside it with room to spare; a
// body larger than this is not a command set.
const templateMaxBody = 256 << 10

// ── shared plumbing ─────────────────────────────────────────────────────────

// rejectUnknownTemplateQuery refuses any query parameter this surface does not
// know. as_tenant is always allowed: it is the platform-wide tenant switcher and
// can only ever NARROW.
func rejectUnknownTemplateQuery(r *http.Request, allowed ...string) error {
	ok := map[string]bool{"as_tenant": true}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range r.URL.Query() {
		if !ok[k] {
			known := append([]string{"as_tenant"}, allowed...)
			sort.Strings(known)
			return fmt.Errorf("unknown query parameter %q (accepted: %s)", clip(k, 32), strings.Join(known, ", "))
		}
	}
	return nil
}

// scoped resolves the caller to ONE concrete tenant, refusing a cross-tenant
// read or write of per-tenant data (§3a). It writes the error response itself.
func (a *TemplateAPI) scoped(w http.ResponseWriter, r *http.Request, gate TemplateGate) (string, TemplatePrincipal, bool) {
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return "", TemplatePrincipal{}, false
	}
	t, err := concreteTenantID(p.Tenant)
	if err != nil || p.Cross {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New(
			"select a tenant to manage its TAC command templates (they are per-tenant data; cross-tenant access is refused)"))
		return "", TemplatePrincipal{}, false
	}
	return t, p, true
}

// decode reads a bounded, unknown-field-rejecting JSON body.
func (a *TemplateAPI) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, templateMaxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // a typo'd field must fail, not be silently dropped
	if err := dec.Decode(v); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("invalid template payload"))
		return false
	}
	return true
}

// templateWire is the POST/PUT body. There is deliberately NO tenant, source,
// version or id field: ownership and provenance are stamped by the store, and a
// tenant on the wire is not merely ignored — it is impossible to express
// (§3a rule 2). DisallowUnknownFields turns an attempt into a 400.
type templateWire struct {
	Dialect     string `json:"dialect"`
	Name        string `json:"name"`
	Description string `json:"description"`
	BasedOn     string `json:"based_on"`
	Steps       []struct {
		Intent  string `json:"intent"`
		Title   string `json:"title"`
		Command string `json:"command"`
		Section string `json:"section"`
		Note    string `json:"note"`
	} `json:"steps"`
}

func (in templateWire) toTemplate() Template {
	steps := make([]TemplateStep, 0, len(in.Steps))
	for _, s := range in.Steps {
		steps = append(steps, TemplateStep{
			Intent: s.Intent, Title: s.Title, Command: s.Command,
			Section: normSection(Section(s.Section)), Note: s.Note,
		})
	}
	return Template{
		Dialect: in.Dialect, Name: in.Name, Description: in.Description,
		BasedOn: in.BasedOn, Steps: steps,
	}
}

// ── GET|POST /api/tac/templates ─────────────────────────────────────────────

// HandleTemplates serves the collection route.
func (a *TemplateAPI) HandleTemplates(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.list(w, r)
	case http.MethodPost:
		a.create(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (a *TemplateAPI) list(w http.ResponseWriter, r *http.Request) {
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
	defaults := a.deps.Catalog.DefaultTemplates()
	if dialect != "" {
		defaults = filterDialect(defaults, dialect)
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"templates": mine,
		"defaults":  defaults,
		"count":     len(mine),
		"limit":     MaxTemplatesPerTenant,
		"dialects":  a.deps.Catalog.Dialects(),
		"policy":    a.policyFamilies(),
		"note":      templatesNote,
	})
}

// templatesNote states the standing rule wherever templates are listed, so the
// boundary is visible in the product and not only in a design doc.
const templatesNote = "Every command in a template — Correlix's own and any your team writes — is held to the " +
	"output-only policy: nothing that changes configuration, restarts or reboots, or addresses a daemon, and a " +
	"bounded ping or traceroute only. Correlix's defaults are read-only; save a copy to make it yours."

func (a *TemplateAPI) policyFamilies() []PolicyFamily {
	if p := a.deps.Catalog.Policy(); p != nil {
		return p.Families
	}
	return nil
}

func filterDialect(in []Template, dialect string) []Template {
	out := make([]Template, 0, len(in))
	for _, t := range in {
		if t.Dialect == dialect {
			out = append(out, t)
		}
	}
	return out
}

func (a *TemplateAPI) create(w http.ResponseWriter, r *http.Request) {
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	var in templateWire
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
	a.deps.Audit(r, p, "tac.template.create", map[string]any{
		"template_id": out.ID, "dialect": out.Dialect, "commands": len(out.Steps), "based_on": out.BasedOn,
	})
	a.deps.WriteJSON(w, http.StatusCreated, map[string]any{"template": out, "validation": res})
}

// writeInvalid renders a validation failure with the PER-LINE verdicts. The
// status is 400 and the body names each refused line, its family and the rule —
// "invalid" alone would tell an operator nothing about what Correlix will not do.
func (a *TemplateAPI) writeInvalid(w http.ResponseWriter, res ValidationResult) {
	a.deps.WriteJSON(w, http.StatusBadRequest, map[string]any{
		"error":      firstRefusal(res),
		"validation": res,
	})
}

// firstRefusal is the one-sentence summary: the first refused line, by index.
func firstRefusal(res ValidationResult) string {
	for _, lv := range res.Lines {
		if !lv.OK {
			return "line " + itoaTAC(lv.Index+1) + " (`" + lv.Command + "`) was refused: " + lv.Reason
		}
	}
	if res.Note != "" {
		return res.Note
	}
	return ErrTemplateInvalid.Error()
}

// ── GET /api/tac/templates/defaults ─────────────────────────────────────────

// HandleDefaults serves Correlix's own templates. They are REFERENCE DATA:
// identical for every tenant, generated from the authored plans, immutable. The
// route is still authenticated — a command set is product knowledge — but it
// carries no tenant data at all, so a cross-tenant principal may read it.
func (a *TemplateAPI) HandleDefaults(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if err := rejectUnknownTemplateQuery(r, "dialect"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if _, ok := a.deps.Authz(w, r, TemplateGateRead); !ok {
		return
	}
	dialect := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("dialect")))
	defaults := a.deps.Catalog.DefaultTemplates()
	note := ""
	if dialect != "" {
		defaults = filterDialect(defaults, dialect)
		if len(defaults) == 0 {
			note = "Correlix has no authored command plan for this platform, so it ships no default command set for " +
				"it. Write your own — every line is still held to the output-only policy."
		}
	}
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"defaults": defaults,
		"version":  DefaultTemplateVersion,
		"dialects": a.deps.Catalog.Dialects(),
		"policy":   a.policyFamilies(),
		"note":     note,
	})
}

// ── POST /api/tac/templates/validate ────────────────────────────────────────

type validateWire struct {
	Dialect  string   `json:"dialect"`
	Commands []string `json:"commands"`
}

// HandleValidate returns per-line verdicts for a command list. It reads nothing,
// writes nothing and stores nothing — it is the review step's live check, and
// the authoritative one still runs on the way into a template and on the way
// into a collection.
func (a *TemplateAPI) HandleValidate(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if _, ok := a.deps.Authz(w, r, TemplateGateRead); !ok {
		return
	}
	var in validateWire
	if !a.decode(w, r, &in) {
		return
	}
	if len(in.Commands) > MaxTemplateSteps {
		a.deps.WriteError(w, http.StatusBadRequest,
			fmt.Errorf("at most %d commands per request", MaxTemplateSteps))
		return
	}
	res := a.deps.Validator.Validate(strings.TrimSpace(strings.ToLower(in.Dialect)), in.Commands)
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"validation": res})
}

// ── GET|PUT|DELETE /api/tac/templates/{id} ──────────────────────────────────

// HandleTemplateItem serves the item route.
func (a *TemplateAPI) HandleTemplateItem(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, TemplateItemPath)
	if !tplIDRE.MatchString(id) {
		// An unparseable id is a 404, not a 400: a 400 would confirm that a
		// well-formed id from another tenant is "the right shape".
		http.NotFound(w, r)
		return
	}
	if err := rejectUnknownTemplateQuery(r); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.get(w, r, id)
	case http.MethodPut:
		a.update(w, r, id)
	case http.MethodDelete:
		a.remove(w, r, id)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

func (a *TemplateAPI) get(w http.ResponseWriter, r *http.Request, id string) {
	// A Correlix default is reference data: it needs authorization, not a
	// tenant scope, and it is the same bytes for everyone.
	if IsDefaultTemplateID(id) {
		if _, ok := a.deps.Authz(w, r, TemplateGateRead); !ok {
			return
		}
		t, found := a.deps.Catalog.DefaultTemplate(id)
		if !found {
			http.NotFound(w, r)
			return
		}
		a.deps.WriteJSON(w, http.StatusOK, map[string]any{"template": t, "editable": false})
		return
	}
	tenant, _, ok := a.scoped(w, r, TemplateGateRead)
	if !ok {
		return
	}
	t, err := a.deps.Store.Get(r.Context(), tenant, id)
	if err != nil {
		http.NotFound(w, r) // cross-tenant id is indistinguishable from absent
		return
	}
	body := map[string]any{"template": t, "editable": true}
	if diff, okDiff := a.deps.Catalog.DiffAgainstDefault(t); okDiff {
		body["diff_vs_default"] = diff
	}
	a.deps.WriteJSON(w, http.StatusOK, body)
}

func (a *TemplateAPI) update(w http.ResponseWriter, r *http.Request, id string) {
	if IsDefaultTemplateID(id) {
		// Authorize first: an unauthenticated caller must not learn which ids
		// are defaults, and the gate is where that is decided.
		if _, ok := a.deps.Authz(w, r, TemplateGateWrite); !ok {
			return
		}
		a.deps.WriteError(w, http.StatusForbidden, ErrTemplateImmutable)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	var in templateWire
	if !a.decode(w, r, &in) {
		return
	}
	next := in.toTemplate()
	next.TenantID = tenant
	next, res, verr := a.deps.Validator.ValidateTemplate(next)
	if verr != nil {
		a.writeInvalid(w, res)
		return
	}
	out, uerr := a.deps.Store.Update(r.Context(), tenant, id, next)
	if errors.Is(uerr, ErrTemplateNotFound) {
		http.NotFound(w, r)
		return
	}
	if uerr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, uerr)
		return
	}
	a.deps.Audit(r, p, "tac.template.update", map[string]any{
		"template_id": out.ID, "dialect": out.Dialect, "commands": len(out.Steps), "version": out.Version,
	})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"template": out, "validation": res})
}

func (a *TemplateAPI) remove(w http.ResponseWriter, r *http.Request, id string) {
	if IsDefaultTemplateID(id) {
		if _, ok := a.deps.Authz(w, r, TemplateGateWrite); !ok {
			return
		}
		a.deps.WriteError(w, http.StatusForbidden, ErrTemplateImmutable)
		return
	}
	tenant, p, ok := a.scoped(w, r, TemplateGateWrite)
	if !ok {
		return
	}
	if err := a.deps.Store.Delete(r.Context(), tenant, id); err != nil {
		if errors.Is(err, ErrTemplateNotFound) {
			http.NotFound(w, r)
			return
		}
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	a.deps.Audit(r, p, "tac.template.delete", map[string]any{"template_id": id})
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{"deleted": id})
}
