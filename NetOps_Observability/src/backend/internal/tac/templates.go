package tac

// templates.go — COMMAND REVIEW and per-dialect COMMAND TEMPLATES.
//
// Owner, 2026-09-05: "it would be nice for NOC admin to view the commands it is
// sending before he submit. Also give him an option to modify the set of
// commands he is sending and also give him an option to templatize the set of
// commands he can send per vendor. We provide some defaults model. But give
// flexibility to customer and change how they want to build that."
//
// THE BOUNDARY THE FLEXIBILITY ENDS AT is the same day's standing rule: a
// command that changes configuration, that restarts or reboots, or that touches
// a daemon is not something Correlix does — for anyone, in any template. An edit
// therefore CHOOSES AMONG OUTPUT COMMANDS; it never widens what may run. That is
// not a policy sentence in a doc, it is this file's validate() and the four
// checks it applies to every line, in this order:
//
//	1. SHAPE      — non-empty, ≤ maxTemplateCommandBytes, printable ASCII only,
//	                no control characters. A command Correlix cannot read is a
//	                command Correlix must not run.
//	2. POLICY     — Policy.Match(dialect, command): config / restart / daemon is
//	                refused BY NAME, with the family and the rule that hit, so
//	                the operator is told what they typed rather than "invalid".
//	3. CATALOG    — if the command is a rendering of an AUTHORED plan template
//	                for this dialect, it is an output command by construction:
//	                the loader already proved it (a read-only show, a bounded
//	                probe, or a documented status read admitted by a CITED
//	                read-only exception — FortiOS spells several pure status
//	                prints `diagnose debug …`). Skipping the grammar here is not
//	                a hole: step 2 has already run, and the exception was
//	                reviewed with its source when the plan was authored.
//	4. PROBE      — a ping/traceroute passes the BOUNDED-probe grammar
//	                (protocoldiag.ValidateBoundedProbe) or it is refused: the
//	                owner allowed reachability probes, not floods.
//	5. READ-ONLY  — everything else must pass protocoldiag.ValidateReadOnly: the
//	                lead token is show/display/get/info and any pipe segment is a
//	                display filter. No metacharacters, no chaining, no redirection.
//
// SESSION-SCOPED SETTERS are the one catalog command a REVIEW still refuses on
// its own. `diagnose sys session filter …` narrows what a read prints and dies
// with the CLI session — it is admitted at all only because the collector runs
// its documented teardown immediately afterwards. A flat command list cannot
// express that pair, so a saved template never carries one and a reviewed line
// carries one only when it came from a plan step that brought its teardown with
// it. Correlix never leaves scope behind on someone's device.
//
// A line that clears all four is an OUTPUT command. It is then labelled by its
// ORIGIN, which is an honesty label and not a second gate:
//
//	OriginCatalog — the command is a rendering of an authored plan template for
//	                this dialect (Gate.AllowsDialect). Correlix cites it and, for
//	                `verified: capture` bindings, has run it on this platform.
//	OriginCustom  — the customer wrote it. It passed the output-only policy and
//	                the read-only grammar; Correlix has never run it here and
//	                says exactly that, in the review UI and in the MANIFEST.
//
// WHY A CUSTOM COMMAND IS ALLOWED TO RUN AT ALL, given gate.go's closed table:
// the closed table answers "could an AUTHORED plan have produced this?", which
// is the right question for a plan the ENGINE built. A reviewed collection is a
// different act — a named human with infrastructure:write read the exact list
// and pressed collect — so its allow-set is closed at COLLECTION START from the
// list the SERVER re-validated, never from the client's bytes and never for
// longer than the collection. ReviewRegistry (below) is that per-device,
// per-collection table; Gate consults it after the authored one. Nothing else
// can put an entry in it, because nothing else calls Register.

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/protocoldiag"
)

// Template limits. Every one of them is a §9 bound, and every one is enforced
// server-side on the way in — a client cannot raise one by asking.
const (
	// MaxTemplateSteps bounds one template's command list. It is the same
	// ceiling the collector refuses a plan at (maxCommandsPerCollection), so a
	// template that saved can always be collected.
	MaxTemplateSteps = maxCommandsPerCollection
	// MaxTemplatesPerTenant bounds one tenant's saved templates.
	MaxTemplatesPerTenant = 200
	// maxTemplateCommandBytes bounds ONE command line.
	maxTemplateCommandBytes = 512
	// maxTemplateNameBytes / maxTemplateTextBytes bound the free text.
	maxTemplateNameBytes = 120
	maxTemplateTextBytes = 800
)

// TemplateSource says who authored a template. It is a CLOSED enum: there is no
// third kind, and a tenant can never write `correlix-default` onto a row of its
// own (the store stamps it, §3a rule 2).
type TemplateSource string

const (
	// SourceCorrelixDefault is a template Correlix generates from the authored
	// plans at build time. It is READ-ONLY: it is not stored per tenant, it is
	// identical for every tenant, and it changes only with a release.
	SourceCorrelixDefault TemplateSource = "correlix-default"
	// SourceTenant is a template this tenant wrote or forked.
	SourceTenant TemplateSource = "tenant"
)

// CommandOrigin is the honesty label on one reviewed command.
type CommandOrigin string

const (
	// OriginCatalog — a rendering of an authored plan template for this dialect.
	OriginCatalog CommandOrigin = "catalog"
	// OriginCustom — customer-written. Output-only and read-only, never verified
	// by Correlix on this platform.
	OriginCustom CommandOrigin = "custom"
)

// customCommandNote is the caveat every custom line carries, in the review UI
// and in the bundle MANIFEST. It is stated once, here, so the promise made in
// the review is the promise kept in the bundle.
const customCommandNote = "written by your team; it passed Correlix's output-only policy and read-only grammar, " +
	"and Correlix has never run it on this platform"

// Template errors.
var (
	// ErrTemplateNotFound is a template id this tenant does not have. A default
	// id and another tenant's id answer the same way — the store is never an
	// existence oracle (§3a rule 1).
	ErrTemplateNotFound = errors.New("tac: template not found")
	// ErrTemplateImmutable is an attempted write to a Correlix default.
	ErrTemplateImmutable = errors.New("tac: Correlix default templates are read-only — save a copy to edit it")
	// ErrTemplatesFull is the per-tenant ceiling.
	ErrTemplatesFull = errors.New("tac: this tenant already holds the maximum number of TAC command templates")
	// ErrTemplateInvalid is a template that failed validation. The per-line
	// verdicts carry the detail; this is the sentinel a handler maps to 400.
	ErrTemplateInvalid = errors.New("tac: the template is not valid")
	// ErrNoTenant is a write with no concrete tenant scope. Default-closed: a
	// cross-tenant principal must scope into one tenant before it may write.
	ErrNoTenant = errors.New("tac: a concrete tenant is required to manage command templates")
)

// tplIDRE is the shape a template id must have to be addressable. Defaults
// use the `correlix:<dialect>:<slug>` form; tenant rows use a random hex id.
var tplIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,127}$`)

// TemplateStep is one line of a template.
//
// Intent is OPTIONAL and is a pointer back into the intent vocabulary when the
// command came from the catalog; a custom line simply has none, and inventing
// one would make a custom capture look authored in the bundle.
type TemplateStep struct {
	Intent  string  `json:"intent,omitempty"`
	Title   string  `json:"title"`
	Command string  `json:"command"`
	Section Section `json:"section,omitempty"`
	// Note is the operator's own note for this step — why it is in the set. It
	// travels into the MANIFEST so a TAC engineer reads the reason too.
	Note string `json:"note,omitempty"`
}

// Template is one saved command set for one dialect.
type Template struct {
	ID string `json:"id"`
	// TenantID is the OWNER, stamped from the authenticated principal and never
	// from a request body (§3a rule 2). It is not serialised: a caller only ever
	// receives its own tenant's rows, so echoing the id back adds nothing and
	// putting it on the wire invites a client to think it is settable.
	TenantID string `json:"-"`

	Dialect     string         `json:"dialect"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Source      TemplateSource `json:"source"`
	// BasedOn names the Correlix default this template was forked from, when it
	// was. It is what the Knowledge view diffs against.
	BasedOn string `json:"based_on,omitempty"`

	Steps []TemplateStep `json:"steps"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	// Version starts at 1 and increments on every update. It is stamped into the
	// bundle MANIFEST, so "which version of ACME's EOS baseline ran" is a
	// question a stored bundle answers by itself.
	Version int `json:"version"`
}

// Editable reports whether this template may be written to.
func (t Template) Editable() bool { return t.Source == SourceTenant }

// CommandList returns the template's commands in order.
func (t Template) CommandList() []string {
	out := make([]string, 0, len(t.Steps))
	for _, s := range t.Steps {
		out = append(out, s.Command)
	}
	return out
}

// LineVerdict is ONE command's validation result. Every refusal names the rule
// that refused it: an operator who is told "invalid" learns nothing, and the
// whole point of showing the commands before submit is that the operator
// understands what Correlix will and will not do.
type LineVerdict struct {
	Index   int           `json:"index"`
	Command string        `json:"command"`
	OK      bool          `json:"ok"`
	Origin  CommandOrigin `json:"origin,omitempty"`
	// Family is the forbidden family (config | restart | daemon) when the
	// output-only policy refused the line, and empty otherwise.
	Family string `json:"family,omitempty"`
	// Rule is the policy rule's token sequence that matched.
	Rule string `json:"rule,omitempty"`
	// Reason is the sentence shown to the operator.
	Reason string `json:"reason,omitempty"`
	// SessionScoped marks a documented session-scoped setter (forbidden.yaml
	// `session_scoped:`). It is not a refusal by itself — the collector pairs it
	// with its teardown when it came from a plan step — but a template may never
	// hold one, and a reviewed line that is one without a plan step behind it is
	// refused by Review.
	SessionScoped bool `json:"session_scoped,omitempty"`
	// Note is the caveat on an ACCEPTED line (a custom command's "never run
	// here" label). It is not a refusal.
	Note string `json:"note,omitempty"`
	// Intent / Title are filled from the catalog when the line matched an
	// authored binding, so a reviewed list keeps its titles.
	Intent string `json:"intent,omitempty"`
	Title  string `json:"title,omitempty"`
}

// ValidationResult is a whole list's verdicts.
type ValidationResult struct {
	Dialect string        `json:"dialect"`
	Lines   []LineVerdict `json:"lines"`
	OK      bool          `json:"ok"`
	// Refused is the count of lines that failed, so a caller can say "3 of 12"
	// without walking the list.
	Refused int `json:"refused"`
	// Policy names the three families in the policy's OWN words, so the review
	// UI states the rule rather than re-typing it.
	Policy []PolicyFamily `json:"policy,omitempty"`
	// Note is the honest statement when the dialect itself is unknown.
	Note string `json:"note,omitempty"`
}

// TemplateValidator validates command lines against ONE catalog. It holds the
// catalog and the compiled gate — both immutable — so it is safe to share.
type TemplateValidator struct {
	cat  *Catalog
	gate *Gate
}

// NewTemplateValidator builds the validator over a loaded catalog. A nil catalog
// is a fail-closed error, never a validator that would accept everything.
func NewTemplateValidator(c *Catalog) (*TemplateValidator, error) {
	if c == nil {
		return nil, errTACCatalogUnavailable
	}
	return &TemplateValidator{cat: c, gate: NewGate(c)}, nil
}

// Dialects returns the dialect slugs a template may be written for.
func (v *TemplateValidator) Dialects() []string { return v.cat.Dialects() }

// KnownDialect reports whether this dialect has an authored plan. A template for
// an unknown dialect is still VALIDATED (the common policy rules and the
// read-only grammar apply to every platform) — it simply cannot carry a catalog
// line, and the result says so instead of silently accepting less scrutiny.
func (v *TemplateValidator) KnownDialect(dialect string) bool {
	_, ok := v.cat.PlanFor(dialect)
	return ok
}

// Validate checks a whole command list for one dialect.
func (v *TemplateValidator) Validate(dialect string, commands []string) ValidationResult {
	res := ValidationResult{Dialect: dialect, Lines: make([]LineVerdict, 0, len(commands)), OK: true}
	if p := v.cat.Policy(); p != nil {
		res.Policy = p.Families
	}
	if !v.KnownDialect(dialect) {
		res.Note = "Correlix has no authored command plan for this platform, so no line here can be one of its own " +
			"commands. Every line is still held to the output-only policy and the read-only grammar."
	}
	for i, raw := range commands {
		lv := v.line(dialect, i, raw)
		if !lv.OK {
			res.OK = false
			res.Refused++
		}
		res.Lines = append(res.Lines, lv)
	}
	if len(commands) == 0 {
		res.OK = false
		res.Note = "A command set with no commands collects nothing."
	}
	if len(commands) > MaxTemplateSteps {
		res.OK = false
		res.Note = "A command set may hold at most " + itoaTAC(MaxTemplateSteps) + " commands."
	}
	return res
}

// ValidateOne is Validate for a single line — what the review UI calls as the
// operator types.
func (v *TemplateValidator) ValidateOne(dialect, command string) LineVerdict {
	return v.line(dialect, 0, command)
}

// line applies the four checks, in order, and returns the first refusal.
func (v *TemplateValidator) line(dialect string, idx int, raw string) LineVerdict {
	cmd := strings.TrimSpace(raw)
	lv := LineVerdict{Index: idx, Command: cmd}
	// (1) shape.
	switch {
	case cmd == "":
		lv.Reason = "the line is empty"
		return lv
	case len(cmd) > maxTemplateCommandBytes:
		lv.Reason = "the command is longer than " + itoaTAC(maxTemplateCommandBytes) + " bytes"
		return lv
	}
	for _, r := range cmd {
		if r < 0x20 || r > 0x7e {
			lv.Reason = "the command carries a control or non-ASCII character; a command Correlix cannot read is one it must not run"
			return lv
		}
	}
	// (2) the owner's output-only policy, first and by name.
	if rule, forbidden := v.cat.Policy().Match(dialect, cmd); forbidden {
		lv.Family = rule.Family
		lv.Rule = rule.String()
		lv.Reason = forbiddenReason(rule)
		return lv
	}
	if _, scoped := v.cat.Policy().SessionScope(dialect, cmd); scoped {
		lv.SessionScoped = true
	}
	// (3) an authored command is an output command by construction.
	if v.gate.AllowsDialect(dialect, cmd) {
		lv.OK = true
		lv.Origin = OriginCatalog
		v.label(dialect, &lv)
		return lv
	}
	// (4) bounded reachability probes have their own grammar.
	if protocoldiag.IsProbeCommand(cmd) {
		if err := protocoldiag.ValidateBoundedProbe(cmd); err != nil {
			lv.Reason = "this is a reachability probe and it is outside Correlix's bounded-probe limits: " + err.Error()
			return lv
		}
		lv.OK = true
		lv.Origin = OriginCustom
		lv.Note = customCommandNote
		lv.Title = cmd
		return lv
	}
	// (5) the read-only grammar.
	if err := protocoldiag.ValidateReadOnly(cmd); err != nil {
		lv.Reason = "this is not an output command: " + err.Error()
		return lv
	}
	lv.OK = true
	lv.Origin = OriginCustom
	lv.Note = customCommandNote
	lv.Title = cmd
	return lv
}

// forbiddenReason renders a policy refusal in the operator's language.
func forbiddenReason(r ForbiddenRule) string {
	what := map[string]string{
		FamilyConfig:  "it changes configuration or clears state",
		FamilyRestart: "it restarts or reboots something",
		FamilyDaemon:  "it addresses a daemon or process directly",
	}[r.Family]
	if what == "" {
		what = "Correlix's output-only policy refuses it"
	}
	out := "refused by the output-only policy (" + r.Family + "): " + what + " — rule `" + r.String() + "`"
	if r.Why != "" {
		out += ". " + r.Why
	}
	return out
}

// label fills the intent and the title from the authored plan when the command
// is an exact rendering of a binding with no arguments. It is a convenience for
// the review list, never a claim: a line that matches no binding keeps the
// command as its own title.
func (v *TemplateValidator) label(dialect string, lv *LineVerdict) {
	if lv.Origin != OriginCatalog {
		lv.Title = lv.Command
		return
	}
	dp, ok := v.cat.PlanFor(dialect)
	if !ok {
		lv.Title = lv.Command
		return
	}
	for _, intent := range sortedKeys(dp.Bindings) {
		b := dp.Bindings[intent]
		if strings.EqualFold(strings.Join(strings.Fields(b.Command), " "), lv.Command) {
			lv.Intent = intent
			if in, ok := v.cat.Intent(intent); ok && in.Title != "" {
				lv.Title = in.Title
			}
			break
		}
	}
	if lv.Title == "" {
		lv.Title = lv.Command
	}
}

// ── the template itself ─────────────────────────────────────────────────────

// ValidateTemplate checks a whole template: its metadata AND every command. It
// returns the normalised template (trimmed, clipped, steps labelled) alongside
// the per-line result, so a store never has to re-derive what the validator
// already computed.
func (v *TemplateValidator) ValidateTemplate(t Template) (Template, ValidationResult, error) {
	t.Name = strings.TrimSpace(clip(t.Name, maxTemplateNameBytes))
	t.Description = strings.TrimSpace(clip(t.Description, maxTemplateTextBytes))
	t.Dialect = strings.TrimSpace(strings.ToLower(t.Dialect))
	res := ValidationResult{Dialect: t.Dialect}
	if t.Name == "" {
		res.Note = "A template needs a name."
		return t, res, ErrTemplateInvalid
	}
	if t.Dialect == "" || !slugRE.MatchString(t.Dialect) {
		res.Note = "A template names the CLI dialect it is written for."
		return t, res, ErrTemplateInvalid
	}
	if len(t.Steps) == 0 {
		res.Note = "A template with no commands collects nothing."
		return t, res, ErrTemplateInvalid
	}
	if len(t.Steps) > MaxTemplateSteps {
		res.Note = "A template may hold at most " + itoaTAC(MaxTemplateSteps) + " commands."
		return t, res, ErrTemplateInvalid
	}
	cmds := make([]string, 0, len(t.Steps))
	for _, s := range t.Steps {
		cmds = append(cmds, s.Command)
	}
	res = v.Validate(t.Dialect, cmds)
	for i := range res.Lines {
		if !res.Lines[i].SessionScoped {
			continue
		}
		// A saved template is a flat command list; it cannot carry the teardown
		// this setter is only ever admitted WITH. Refuse it here rather than
		// let a saved set leave scope behind on a device later.
		res.Lines[i].OK = false
		res.Lines[i].Reason = "this narrows what a later read prints and only runs paired with its documented teardown, " +
			"which a saved command set cannot express — Correlix runs it from the plan, not from a template"
		res.OK = false
		res.Refused++
	}
	if !res.OK {
		return t, res, ErrTemplateInvalid
	}
	steps := make([]TemplateStep, 0, len(t.Steps))
	for i, s := range t.Steps {
		lv := res.Lines[i]
		st := TemplateStep{
			Intent:  lv.Intent,
			Title:   strings.TrimSpace(clip(firstNonEmptyStr(s.Title, lv.Title), maxTemplateNameBytes)),
			Command: lv.Command,
			Section: normSection(s.Section),
			Note:    strings.TrimSpace(clip(s.Note, maxTemplateTextBytes)),
		}
		steps = append(steps, st)
	}
	t.Steps = steps
	return t, res, nil
}

// normSection keeps the section inside the closed enum. An unknown section
// becomes deep-dive rather than being carried through as free text — a section
// label is a grouping the bundle relies on, not a comment field.
func normSection(s Section) Section {
	switch s {
	case SectionBaseline, SectionDeepDive, SectionOptional, SectionTopology:
		return s
	default:
		return SectionDeepDive
	}
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// ── the reviewed collection ─────────────────────────────────────────────────

// ReviewedStep is one line of an operator-approved collection, as it arrives
// from the client. It is UNTRUSTED: nothing here is used before Review has
// re-validated it (§3, and the tampering test proves it).
type ReviewedStep struct {
	Command string `json:"command"`
	Note    string `json:"note,omitempty"`
}

// EditKind is the closed set of things a review can do to the engine's plan.
type EditKind string

const (
	// EditAdded — a command that was not in the plan the engine built.
	EditAdded EditKind = "added"
	// EditRemoved — a planned command the operator took out.
	EditRemoved EditKind = "removed"
	// EditReordered — the same set, in a different order.
	EditReordered EditKind = "reordered"
)

// PlanEdit is one recorded difference between the engine's plan and what the
// operator approved. It is stamped into the bundle MANIFEST: a TAC engineer
// reading the bundle sees what Correlix proposed, what a human changed, and why.
type PlanEdit struct {
	Kind    EditKind      `json:"kind"`
	Command string        `json:"command,omitempty"`
	Intent  string        `json:"intent,omitempty"`
	Origin  CommandOrigin `json:"origin,omitempty"`
	Note    string        `json:"note,omitempty"`
}

// TemplateRef records WHICH template a reviewed collection came from.
type TemplateRef struct {
	ID      string         `json:"id,omitempty"`
	Name    string         `json:"name,omitempty"`
	Source  TemplateSource `json:"source,omitempty"`
	Version int            `json:"version,omitempty"`
}

// Review re-validates an operator's approved command list against a plan and
// returns the plan that will actually run.
//
// IT NEVER TRUSTS THE CLIENT. The submitted list is validated line by line by
// the SAME validator that guards template writes; ONE refusal fails the WHOLE
// review, naming the line, because a collection that silently dropped the
// forbidden command and ran the rest would teach an operator that Correlix
// quietly edits their intent.
//
// Per-command budgets (timeout, output cap, teardown, verified label, sources)
// are inherited from the authored plan step whose command matches; a custom line
// gets the package defaults and the custom caveat. A client cannot raise a
// budget by asking, because no budget is read from the request at all.
func (v *TemplateValidator) Review(p *Plan, steps []ReviewedStep, ref TemplateRef) (*Plan, ValidationResult, error) {
	if p == nil {
		return nil, ValidationResult{}, errors.New("tac: no plan to review")
	}
	cmds := make([]string, 0, len(steps))
	for _, s := range steps {
		cmds = append(cmds, s.Command)
	}
	res := v.Validate(p.Dialect, cmds)
	// Index the engine's own plan by its normalised command text, so a reviewed
	// line that IS a planned line keeps that step's budgets verbatim.
	planned := map[string]Step{}
	order := make([]string, 0, len(p.Steps))
	for _, st := range p.Steps {
		key := normCommandKey(st.Command)
		if _, dup := planned[key]; !dup {
			order = append(order, key)
		}
		planned[key] = st
	}

	// A session-scoped setter is admitted ONLY as the plan's own step, which
	// brought its teardown with it. Typed in by hand it would narrow a device's
	// output and never be cleared, so it is refused here — after the plan index
	// exists, which is what makes the distinction possible.
	for i := range res.Lines {
		if !res.Lines[i].SessionScoped {
			continue
		}
		if st, ok := planned[normCommandKey(res.Lines[i].Command)]; ok && st.Teardown != "" {
			continue
		}
		res.Lines[i].OK = false
		res.Lines[i].Reason = "this narrows what a later read prints and only runs paired with its documented teardown; " +
			"Correlix runs it as part of the plan it built, and will not run one typed in by hand"
		res.OK = false
		res.Refused++
	}
	if !res.OK {
		return nil, res, ErrTemplateInvalid
	}

	out := *p
	out.Steps = make([]Step, 0, len(steps))
	kept := map[string]bool{}
	newOrder := make([]string, 0, len(steps))
	for i, s := range steps {
		lv := res.Lines[i]
		key := normCommandKey(lv.Command)
		newOrder = append(newOrder, key)
		st, fromPlan := planned[key]
		if fromPlan {
			kept[key] = true
		} else {
			st = Step{
				Intent: lv.Intent, Title: lv.Title, Section: SectionDeepDive, Bound: true,
				Command: lv.Command, MaxBytes: defaultMaxOutputBytes,
				TimeoutSeconds: int(defaultCommandTimeout / time.Second),
			}
			if lv.Origin == OriginCustom {
				st.Verified = ""
				st.Note = customCommandNote
			}
		}
		if n := strings.TrimSpace(clip(s.Note, maxTemplateTextBytes)); n != "" {
			st.Note = strings.TrimSpace(st.Note + " · operator note: " + n)
		}
		out.Steps = append(out.Steps, st)
	}

	edits := []PlanEdit{}
	for _, key := range order {
		if kept[key] {
			continue
		}
		st := planned[key]
		edits = append(edits, PlanEdit{Kind: EditRemoved, Command: st.Command, Intent: st.Intent})
	}
	for i, lv := range res.Lines {
		if _, fromPlan := planned[normCommandKey(lv.Command)]; fromPlan {
			continue
		}
		edits = append(edits, PlanEdit{
			Kind: EditAdded, Command: lv.Command, Intent: lv.Intent, Origin: lv.Origin,
			Note: strings.TrimSpace(clip(steps[i].Note, maxTemplateTextBytes)),
		})
	}
	if len(edits) == 0 && !sameOrder(order, newOrder) {
		edits = append(edits, PlanEdit{Kind: EditReordered,
			Note: "the same commands, in the order the operator approved"})
	}
	out.Edits = edits
	out.Reviewed = true
	out.Template = ref
	// The estimate is recomputed from the list that will actually run: a preview
	// figure carried over from a plan half of whose steps were removed would be
	// a number that describes nothing.
	out.EstimatedBytes, out.EstimatedSeconds = 0, 0
	for _, st := range out.Steps {
		out.EstimatedBytes += st.MaxBytes
		out.EstimatedSeconds += st.TimeoutSeconds
	}
	out.EstimatedSeconds += len(out.Steps) * int(defaultPacing/time.Second)
	out.ID = planID(&out)
	return &out, res, nil
}

// normCommandKey is the comparison form of a command: whitespace collapsed and
// case folded, because `show ip bgp` and `Show  ip  bgp` are the same command
// and an edit list that reported them as an add plus a remove would be noise.
func normCommandKey(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func sameOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── the per-collection allow set ────────────────────────────────────────────

// ReviewRegistry is the CLOSED TABLE OF THE MOMENT: for one device, the exact
// command strings a human approved and the server re-validated, for as long as
// that collection runs.
//
// It exists because a custom command is by definition not in the authored table,
// and the runner gates every string it puts on a wire against a table. Making
// the reviewed list that table — rather than widening the authored one — keeps
// the property that matters: at any instant, the set of commands that can reach
// a device is enumerable, was validated, and belongs to one collection.
//
// It is mutable state, so it is a mutex-guarded map on a struct that the process
// injects (§5: no package globals, no hidden singletons).
type ReviewRegistry struct {
	mu   sync.Mutex
	rows map[string]map[string]bool // device key → normalised command → true
}

// NewReviewRegistry builds an empty registry.
func NewReviewRegistry() *ReviewRegistry {
	return &ReviewRegistry{rows: map[string]map[string]bool{}}
}

// Register replaces the allow set for one device. The caller passes commands the
// SERVER validated; passing anything else is the one way to break this feature's
// safety property, which is why the only caller is Service.StartCollect.
func (r *ReviewRegistry) Register(deviceKey string, commands []string) {
	if r == nil || deviceKey == "" {
		return
	}
	set := make(map[string]bool, len(commands))
	for _, c := range commands {
		if k := normCommandKey(c); k != "" {
			set[k] = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[deviceKey] = set
}

// Release drops one device's allow set. It runs from a defer, so a panic or an
// early return cannot leave a command allowed after its collection ended.
func (r *ReviewRegistry) Release(deviceKey string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, deviceKey)
}

// allows reports whether this device currently has command in its reviewed set.
func (r *ReviewRegistry) allows(deviceKey, command string) bool {
	if r == nil || deviceKey == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[deviceKey][normCommandKey(command)]
}

// Size reports how many devices currently hold an allow set (observability, and
// the test that proves Release actually releases).
func (r *ReviewRegistry) Size() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rows)
}

// ── ordering helpers ────────────────────────────────────────────────────────

// SortTemplates orders a listing: Correlix defaults first (they are the starting
// point an operator reaches for), then the tenant's own by name.
func SortTemplates(in []Template) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if (a.Source == SourceCorrelixDefault) != (b.Source == SourceCorrelixDefault) {
			return a.Source == SourceCorrelixDefault
		}
		if a.Dialect != b.Dialect {
			return a.Dialect < b.Dialect
		}
		if !strings.EqualFold(a.Name, b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return a.ID < b.ID
	})
}
