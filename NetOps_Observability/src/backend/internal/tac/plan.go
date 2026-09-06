package tac

// plan.go — class + device → the command plan, with the gaps named.
//
// The plan is shown to the operator BEFORE anything runs. That is the whole
// contract of this file: everything the collection will do must be visible and
// countable here — which commands, in which sections, how much output they might
// produce, roughly how long they will take, what will be redacted, and, most
// importantly, WHAT WE CANNOT DO. An intent this dialect does not bind appears
// as an unbound line with the reason; a platform with no authored plan at all
// says so and offers the paste fallback. Nothing is silently rendered in another
// vendor's dialect — that is the failure QA 2026-09-03 (D-2) recorded as worse
// than admitting ignorance.

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/protocoldiag"
)

// Section groups a plan step for the preview.
type Section string

const (
	// SectionBaseline is the vendor-standard set collected for every class.
	SectionBaseline Section = "baseline"
	// SectionDeepDive is the class's own intent list.
	SectionDeepDive Section = "deep-dive"
	// SectionOptional is opt-in, off by default (large/slow captures).
	SectionOptional Section = "optional"
	// SectionTopology is Correlix's own model, not a device command.
	SectionTopology Section = "topology"
)

// Target carries the optional arguments a plan substitutes into its commands.
// Every field is UNTRUSTED input from the caller and is shape-checked before it
// can reach a command line; an empty field renders the command's unscoped form.
type Target struct {
	Interface string `json:"interface,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	VRF       string `json:"vrf,omitempty"`
	RouterID  string `json:"router_id,omitempty"`
	Area      string `json:"area,omitempty"`
}

// Step is one line of the plan.
type Step struct {
	Intent   string   `json:"intent"`
	Title    string   `json:"title"`
	Section  Section  `json:"section"`
	Bound    bool     `json:"bound"`
	Command  string   `json:"command,omitempty"`
	Verified Verified `json:"verified,omitempty"`
	// Note is the honest reason an unbound step is unbound, or the
	// "documented, not verified" caveat on a doc_claimed one.
	Note string `json:"note,omitempty"`
	// NeedsConsent marks a step held back because the vendor's own documentation
	// says it is not routine. The UI renders it with a consent control, never as
	// a plain missing capability.
	NeedsConsent bool     `json:"needs_consent,omitempty"`
	Sources      []Source `json:"sources,omitempty"`
	// Teardown is the command that undoes a session-scoped setter. When it is
	// set the collector ALWAYS runs it after the step, including after a failure
	// or a cancellation, so scope is never left behind on someone's device.
	Teardown string `json:"teardown,omitempty"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
	// TimeoutSeconds is the per-command deadline this step will run under.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// maxBindingSources is how many pages one step may cite.
//
// A citation on a step answers ONE question — "where did this command come
// from" — and two links answer it. The dialect's whole bibliography answers a
// different question and belongs to the pack, not to a command: attaching it to
// every step rendered 8,418 links on a single Nokia SR Linux preview
// (2026-09-06, incident c150bbc5, spine1/ospf-adjacency) and made the plan
// unreadable. The cap is enforced where a Step is BUILT, so no future path into
// the plan can reintroduce the pool.
const maxBindingSources = 2

// stepSources is the citation set one step may carry: the binding's own pages,
// one entry per page, at most maxBindingSources of them. A binding with no
// citation of its own gets none — an invented provenance is worse than a blank.
func stepSources(in []Source) []Source {
	out := dedupeSources(in)
	if len(out) > maxBindingSources {
		out = out[:maxBindingSources]
	}
	if len(out) == 0 {
		return nil
	}
	return append([]Source(nil), out...)
}

// TopologyNote is one line of the connected-topology context Correlix supplies
// from its OWN model. It is evidence, not a command — the plan carries it so a
// TAC engineer sees the neighbourhood the device sits in.
type TopologyNote struct {
	Kind   string `json:"kind"` // neighbor | link | seam | site
	Ref    string `json:"ref"`
	Detail string `json:"detail,omitempty"`
}

// Plan is the whole preview.
type Plan struct {
	ID         string `json:"id"`
	TenantID   string `json:"-"`
	IncidentID string `json:"incident_id"`

	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`

	// Dialect is the resolved dialect slug; DialectDisplay its label. HasPlan is
	// false when this platform has no authored command set — the honest path.
	// Address and Port are carried for the collector and are deliberately NOT
	// serialised: the plan preview travels to a browser and a management address
	// is not part of the operator's decision about which commands to run.
	Address string `json:"-"`
	Port    int    `json:"-"`

	Dialect        string `json:"dialect"`
	DialectDisplay string `json:"dialect_display"`
	HasPlan        bool   `json:"has_plan"`
	PlanVersion    string `json:"plan_version,omitempty"`

	ClassID      string `json:"class_id"`
	ClassTitle   string `json:"class_title"`
	TACFirstLook string `json:"tac_first_look,omitempty"`

	Target          Target `json:"target"`
	IncludeOptional bool   `json:"include_optional"`

	// Steps are the commands that WILL run, in collection order.
	Steps []Step `json:"steps"`
	// Unbound are the intents this class wanted and this dialect cannot supply.
	// They are the honest gap, shown beside the plan, never dropped.
	Unbound []Step `json:"unbound"`
	// Topology is Correlix's own context for the device.
	Topology []TopologyNote `json:"topology"`

	// EstimatedBytes and EstimatedSeconds bound the collection for the operator.
	// They are CEILINGS derived from the per-command caps, not predictions.
	EstimatedBytes   int64 `json:"estimated_bytes"`
	EstimatedSeconds int   `json:"estimated_seconds"`

	// Editable is the standing promise the review step rests on: this plan may
	// be edited before it is collected. It is a constant `true` on every plan
	// the engine builds — it is on the wire so the UI never has to infer the
	// capability from the absence of something.
	Editable bool `json:"editable"`
	// Reviewed is true once a human approved an explicit command list and the
	// server re-validated it (templates.go). A plan that was never reviewed
	// collects exactly what the engine proposed, which is also a fact a bundle
	// reader is entitled to.
	Reviewed bool `json:"reviewed"`
	// Template names the command template the reviewed list came from, when one
	// was used. It is stamped into the bundle MANIFEST.
	Template TemplateRef `json:"template,omitzero"`
	// Edits are the differences between the plan the engine built and the list
	// the operator approved. Empty on an unedited collection — and empty is a
	// statement, not an omission.
	Edits []PlanEdit `json:"edits,omitempty"`

	// RedactionNote states, in the preview, what the bundle will mask.
	RedactionNote string `json:"redaction_note"`
	// Note is the plan-level honest statement (no authored plan, partial
	// coverage, everything bound).
	Note string `json:"note"`

	CatalogVersion string `json:"catalog_version"`
	EngineVersion  string `json:"engine_version"`
}

// BoundCount / UnboundCount are what the coverage line reads from.
func (p *Plan) BoundCount() int   { return len(p.Steps) }
func (p *Plan) UnboundCount() int { return len(p.Unbound) }

// RedactionNoteText is the single sentence the preview and the MANIFEST both
// use, so the promise made before collection is the promise kept in the bundle.
const RedactionNoteText = "Every captured output is passed through Correlix's TAC redactor before it is stored, " +
	"shown or exported: local passwords and enable secrets, SNMP communities, OSPF/IS-IS/BGP authentication " +
	"keys and key-strings, IPsec pre-shared keys and PEM private-key blocks are replaced with [REDACTED]. " +
	"The surrounding line is kept so a TAC engineer still sees which knob it was. Hostnames, interface names, " +
	"addresses and the tenant id are NOT redacted — they are what makes the capture useful."

// PlanOptions are the caller's choices for one plan.
type PlanOptions struct {
	Target          Target
	IncludeOptional bool
	Topology        []TopologyNote
	// Consent is the set of intents the operator has EXPLICITLY approved, for
	// the commands a vendor's own documentation says are not routine — SR OS's
	// `admin tech-support` is a core dump Nokia says needs their authorisation;
	// Huawei's `display diagnostic-information` measurably loads the control
	// plane and writes a file. `include_optional` is not enough for those: the
	// operator has to say yes to that specific command, having read the vendor's
	// caveat, which the plan preview shows verbatim.
	Consent map[string]bool
}

// Device is the subject of a plan: the minimal identity, resolved UPSTREAM in
// the caller's own scope. TenantID is the owner, stamped from that resolved
// inventory row and never from a request body (§3a.2).
type Device struct {
	ID       string
	Hostname string
	Platform string
	TenantID string
	// Address and Port are the management endpoint the LIVE collection dials.
	// They are empty for planning (a plan is data and needs no transport) and
	// are populated at the call site from the SAME principal-scoped inventory
	// row that authorised the device — never from a request body.
	Address string
	Port    int
}

// Plan builds the command plan for a class on a device.
//
// It never errors on "this platform is unsupported": that is a Plan with
// HasPlan=false, every requested intent listed as unbound, and a Note that says
// what to do instead. An unknown CLASS is a real error — the caller sent an id
// the taxonomy does not carry.
func (c *Catalog) Plan(classID string, dev Device, opt PlanOptions) (*Plan, error) {
	if c == nil {
		// A nil catalog means the embedded data did not load. Say so instead of
		// dereferencing: the caller's honest answer is "escalation is
		// unavailable on this build", not a panicked request goroutine.
		return nil, errTACCatalogUnavailable
	}
	cl, ok := c.classes[classID]
	if !ok {
		return nil, ErrUnknownClass
	}
	dialect, display, resolved := DialectForPlatform(dev.Platform)
	p := &Plan{
		TenantID: dev.TenantID, DeviceID: dev.ID, Hostname: dev.Hostname, Platform: dev.Platform,
		Address: dev.Address, Port: dev.Port,
		Dialect: dialect, DialectDisplay: display,
		ClassID: cl.ID, ClassTitle: cl.Title, TACFirstLook: cl.TACFirstLook,
		Target: opt.Target, IncludeOptional: opt.IncludeOptional,
		Editable:       true,
		Topology:       append([]TopologyNote(nil), opt.Topology...),
		RedactionNote:  RedactionNoteText,
		CatalogVersion: c.Version, EngineVersion: Version,
		Steps: []Step{}, Unbound: []Step{},
	}
	if p.Topology == nil {
		p.Topology = []TopologyNote{}
	}

	dp, havePlan := c.plans[dialect]
	p.HasPlan = resolved && havePlan
	if !p.HasPlan {
		// The honest path. Every intent the class wanted is listed as unbound
		// with the platform-level reason, so the operator sees exactly what
		// Correlix would have collected if it knew this platform.
		reason := "no authored command plan for this platform"
		if !resolved {
			reason = "Correlix does not recognise this platform string, so it has no CLI dialect for it"
			p.DialectDisplay = strings.TrimSpace(dev.Platform)
		}
		for _, in := range c.classIntents(cl) {
			p.Unbound = append(p.Unbound, c.unboundStep(in, SectionDeepDive, reason))
		}
		p.Note = "No authored command plan for this platform (" + p.displayPlatform() + "). " +
			"Correlix will not render another vendor's commands at this device. " +
			"Collect the outputs manually and paste them into the collect step — the bundle, the evidence " +
			"timeline and the problem statement are built the same way."
		return p, nil
	}
	p.PlanVersion = dp.Version
	p.DialectDisplay = dp.Display

	seen := map[string]bool{}
	addBound := func(intent string, sec Section, b Binding) {
		if seen[intent] {
			return
		}
		seen[intent] = true
		in := c.intents[intent]
		note := ""
		if b.Verified == VerifiedDocClaimed {
			note = "documented by the vendor, not yet verified by Correlix on this platform"
		}
		if b.ReadOnlyException != "" {
			note = strings.TrimSpace(note + " · admitted by a cited read-only exception: " + b.ReadOnlyException)
		}
		if b.Consent {
			note = strings.TrimSpace(note + " · approved by the operator: " + b.ConsentNote)
		}
		to := int(defaultCommandTimeout / time.Second)
		if b.Timeout > 0 {
			to = int(b.Timeout / time.Second)
		}
		mb := b.MaxBytes
		if mb <= 0 {
			mb = defaultMaxOutputBytes
		}
		cmd := renderCommand(b.Command, dp.vrfScopeKeyword, opt.Target)
		// A bounded probe whose destination did not render is NOT run: on several
		// platforms a bare ping opens an interactive dialog, and an unscoped
		// probe is meaningless anyway. It is reported as unbound, with the
		// reason, which is the honest outcome.
		if protocoldiag.IsProbeCommand(cmd) && protocoldiag.ValidateBoundedProbe(cmd) != nil {
			if !seen[intent] {
				seen[intent] = true
				p.Unbound = append(p.Unbound, c.unboundStep(intent, sec,
					"this dialect binds a reachability probe for it, but the incident supplied no address to probe"))
			}
			return
		}
		p.Steps = append(p.Steps, Step{
			Intent: intent, Title: in.Title, Section: sec, Bound: true,
			Command: cmd, Verified: b.Verified,
			Note: note, Sources: stepSources(b.Sources), Teardown: b.Teardown, MaxBytes: mb, TimeoutSeconds: to,
		})
	}
	addUnbound := func(intent string, sec Section) {
		if seen[intent] {
			return
		}
		seen[intent] = true
		p.Unbound = append(p.Unbound, c.unboundStep(intent, sec,
			"no binding on the "+dp.Display+" dialect"))
	}

	for _, in := range dp.Baseline {
		if b, ok := dp.Bound(in); ok {
			addBound(in, SectionBaseline, b)
		}
	}
	for _, in := range c.classIntents(cl) {
		b, ok := dp.Bound(in)
		switch {
		case !ok:
			addUnbound(in, SectionDeepDive)
		case b.Consent && !opt.Consent[in]:
			// The vendor says this one is not routine. It is SHOWN, with their
			// own words, and it does not run until the operator says yes.
			if !seen[in] {
				seen[in] = true
				st := c.unboundStep(in, SectionDeepDive,
					"needs your explicit approval — "+b.ConsentNote)
				st.NeedsConsent = true
				st.Command = renderCommand(b.Command, dp.vrfScopeKeyword, opt.Target)
				st.Verified = b.Verified
				st.Sources = stepSources(b.Sources)
				p.Unbound = append(p.Unbound, st)
			}
		default:
			addBound(in, SectionDeepDive, b)
		}
	}
	if opt.IncludeOptional {
		for _, in := range dp.Optional {
			if b, ok := dp.Bound(in); ok {
				addBound(in, SectionOptional, b)
			}
		}
	} else {
		for _, in := range dp.Optional {
			if seen[in] {
				continue
			}
			seen[in] = true
			st := c.unboundStep(in, SectionOptional,
				"available on this dialect but OFF by default — it can be tens of megabytes and slow; enable it in the plan preview")
			st.Command = ""
			p.Unbound = append(p.Unbound, st)
		}
	}

	for _, st := range p.Steps {
		p.EstimatedBytes += st.MaxBytes
		p.EstimatedSeconds += st.TimeoutSeconds
	}
	// The estimate is a CEILING, and pacing adds to the wall clock.
	p.EstimatedSeconds += len(p.Steps) * int(defaultPacing/time.Second)

	switch {
	case len(p.Unbound) == 0:
		p.Note = "Every command this class needs is authored for " + dp.Display + "."
	default:
		p.Note = itoaTAC(len(p.Steps)) + " of " + itoaTAC(len(p.Steps)+len(p.Unbound)) +
			" intents are bound on " + dp.Display + ". The unbound ones are listed below — " +
			"Correlix will not invent a command for them; collect those by hand and paste them in."
	}
	p.ID = planID(p)
	return p, nil
}

// classIntents returns the class's deep-dive intents in authoring order.
func (c *Catalog) classIntents(cl Class) []string {
	return append([]string(nil), cl.Intents...)
}

func (c *Catalog) unboundStep(intent string, sec Section, reason string) Step {
	in := c.intents[intent]
	title := in.Title
	if title == "" {
		title = intent
	}
	return Step{Intent: intent, Title: title, Section: sec, Bound: false, Note: reason}
}

func (p *Plan) displayPlatform() string {
	if s := strings.TrimSpace(p.Platform); s != "" {
		return s
	}
	return "platform not reported"
}

// renderCommand substitutes the target's arguments into a template and collapses
// the whitespace an empty placeholder leaves behind, so the result is always a
// clean command line. An argument that does not match the narrow argument shape
// is DROPPED (the command renders in its unscoped form) rather than passed
// through — a malformed argument must never reach a device, and refusing the
// whole command would lose the unscoped capture that is still useful.
func renderCommand(tmpl, vrfKeyword string, tgt Target) string {
	arg := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "" || !argTokenRE.MatchString(s) {
			return ""
		}
		return s
	}
	out := strings.NewReplacer(
		"{if}", arg(tgt.Interface),
		"{peer}", arg(tgt.Peer),
		"{prefix}", arg(tgt.Prefix),
		"{rid}", arg(tgt.RouterID),
		"{area}", arg(tgt.Area),
		"{vrf-scope}", vrfScope(vrfKeyword, arg(tgt.VRF)),
		"{vrf-name}", arg(tgt.VRF),
	).Replace(tmpl)
	return strings.Join(strings.Fields(out), " ")
}

// vrfScope renders the keyword that scopes a lookup to a VRF / routing-instance
// ahead of the instance name. The concept is one; the keyword is the dialect's,
// and it is DATA (vendorprofile.Dialect.VRFScopeKeyword, resolved onto the plan
// at load) — never a switch here, so a new dialect arrives as profile data
// rather than a code edit. An empty keyword is the authored "bare name" answer:
// that dialect's own templates already carry whatever keyword the CLI needs.
//
// THE TEMPLATE CONTRACT (ai/tac/README.md §2, tracker row 261): `{vrf-scope}`
// EMITS the keyword, so a template must NOT spell it as well — `show ip route
// vrf {vrf-scope}` rendered `show ip route vrf vrf CUST-A`, which every one of
// those devices rejects. A command whose CLI puts the instance name after a word
// that is not the dialect's scoping keyword (`show ip vrf detail <name>`,
// `show route extensive table <name>`) takes `{vrf-name}` — the same value,
// rendered bare — rather than being bent onto `{vrf-scope}`.
func vrfScope(keyword, vrf string) string {
	if vrf == "" {
		return ""
	}
	if keyword == "" {
		return vrf
	}
	return keyword + " " + vrf
}

// planID is a deterministic, non-secret id for a plan: the same class, device,
// dialect, target and step list always yield the same id, so a collection can be
// matched back to the exact plan an operator approved. It carries no tenant id
// (the id travels into filenames and the MANIFEST).
func planID(p *Plan) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, s := range parts {
			h.Write([]byte(s))
			h.Write([]byte{0})
		}
	}
	write(Version, p.CatalogVersion, p.PlanVersion, p.ClassID, p.DeviceID, p.Dialect,
		p.Target.Interface, p.Target.Peer, p.Target.Prefix, p.Target.VRF, p.Target.RouterID, p.Target.Area)
	steps := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		steps = append(steps, string(s.Section)+"|"+s.Intent+"|"+s.Command)
	}
	sort.Strings(steps)
	write(steps...)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
