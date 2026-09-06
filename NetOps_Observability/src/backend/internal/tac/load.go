package tac

// load.go — the DATA LOADER and its schema validation.
//
// It is the first of the three safety guards (§8). Nothing reaches a device that
// this file did not first prove is a read-only show, in the closed placeholder
// grammar, for a declared dialect, naming a declared intent. A file that fails
// any of those is a LOAD ERROR: the process refuses the data rather than
// shipping a plan with one command in it nobody validated.
//
// It is also the "typo is a refusal, not silence" boundary: every mapping is
// checked against its allowed field set, so a misspelled key fails the build
// instead of quietly dropping the value it carried.

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/vendorprofile"
)

// Load builds a Catalog from a filesystem laid out as the ai/tac directory:
// classes.yaml at the root and plans/<dialect>.yaml beside it.
func Load(fsys fs.FS) (*Catalog, error) {
	raw, err := fs.ReadFile(fsys, "classes.yaml")
	if err != nil {
		return nil, fmt.Errorf("tac: classes.yaml: %w", err)
	}
	c, err := loadClasses(string(raw))
	if err != nil {
		return nil, err
	}
	// The command policy is loaded BEFORE any plan, because every plan is
	// validated against it: a build whose data carries a config / restart /
	// daemon command must not boot (owner decision, 2026-09-05).
	if c.policy, err = LoadPolicy(fsys); err != nil {
		return nil, err
	}
	names, err := fs.Glob(fsys, "plans/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("tac: plans: %w", err)
	}
	sort.Strings(names)
	c.plans = map[string]*DialectPlan{}
	for _, name := range names {
		body, rerr := fs.ReadFile(fsys, name)
		if rerr != nil {
			return nil, fmt.Errorf("tac: %s: %w", name, rerr)
		}
		slug := strings.TrimSuffix(path.Base(name), ".yaml")
		p, perr := loadPlan(c, slug, string(body))
		if perr != nil {
			return nil, fmt.Errorf("tac: %s: %w", name, perr)
		}
		c.plans[p.Dialect] = p
		c.planOrder = append(c.planOrder, p.Dialect)
	}
	if _, ok := c.classes[GenericClassID]; !ok {
		return nil, fmt.Errorf("tac: classes.yaml must declare the mandatory %q fallback class", GenericClassID)
	}
	return c, nil
}

// loadClasses parses and validates classes.yaml.
func loadClasses(src string) (*Catalog, error) {
	doc, err := parseYAML(src)
	if err != nil {
		return nil, fmt.Errorf("tac: classes.yaml: %w", err)
	}
	if !doc.isMap() {
		return nil, fmt.Errorf("tac: classes.yaml: document must be a mapping")
	}
	if err := yonly(doc, "classes.yaml", "schema_version", "version", "intents", "classes"); err != nil {
		return nil, fmt.Errorf("tac: classes.yaml: %w", err)
	}
	if err := requireSchemaVersion(doc); err != nil {
		return nil, fmt.Errorf("tac: classes.yaml: %w", err)
	}
	version, err := ystr(doc, "version")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("tac: classes.yaml: `version` is required (it is stamped into every bundle)")
	}
	c := &Catalog{
		Version: version,
		intents: map[string]Intent{},
		classes: map[string]Class{},
	}

	intentNodes, err := ylist(doc, "intents")
	if err != nil {
		return nil, fmt.Errorf("tac: classes.yaml: %w", err)
	}
	for _, n := range intentNodes {
		in, ierr := loadIntent(n)
		if ierr != nil {
			return nil, fmt.Errorf("tac: classes.yaml: %w", ierr)
		}
		if _, dup := c.intents[in.ID]; dup {
			return nil, fmt.Errorf("tac: classes.yaml: line %d: duplicate intent %q", n.line, in.ID)
		}
		c.intents[in.ID] = in
		c.intentOrder = append(c.intentOrder, in.ID)
	}

	classNodes, err := ylist(doc, "classes")
	if err != nil {
		return nil, fmt.Errorf("tac: classes.yaml: %w", err)
	}
	if len(classNodes) == 0 {
		return nil, fmt.Errorf("tac: classes.yaml: no classes declared")
	}
	for _, n := range classNodes {
		cl, cerr := loadClass(c, n)
		if cerr != nil {
			return nil, fmt.Errorf("tac: classes.yaml: %w", cerr)
		}
		if _, dup := c.classes[cl.ID]; dup {
			return nil, fmt.Errorf("tac: classes.yaml: line %d: duplicate class %q", n.line, cl.ID)
		}
		c.classes[cl.ID] = cl
		c.classOrder = append(c.classOrder, cl.ID)
	}
	return c, nil
}

func requireSchemaVersion(doc *ynode) error {
	sv, err := ystr(doc, "schema_version")
	if err != nil {
		return err
	}
	if sv != "1" {
		return fmt.Errorf("schema_version must be 1 (got %q)", sv)
	}
	return nil
}

func loadIntent(n *ynode) (Intent, error) {
	if err := yonly(n, "an intent", "id", "area", "title", "note"); err != nil {
		return Intent{}, err
	}
	id, err := ystr(n, "id")
	if err != nil {
		return Intent{}, err
	}
	if !intentRE.MatchString(id) {
		return Intent{}, fmt.Errorf("line %d: intent id %q does not match the intent grammar", n.line, id)
	}
	area, err := ystr(n, "area")
	if err != nil {
		return Intent{}, err
	}
	if _, ok := intentAreas[area]; !ok {
		return Intent{}, fmt.Errorf("line %d: intent %q declares area %q, which is not in the closed area set", n.line, id, area)
	}
	if head, _, _ := strings.Cut(id, "."); head != area {
		return Intent{}, fmt.Errorf("line %d: intent %q must start with its area %q", n.line, id, area)
	}
	title, err := ystr(n, "title")
	if err != nil {
		return Intent{}, err
	}
	if strings.TrimSpace(title) == "" {
		return Intent{}, fmt.Errorf("line %d: intent %q has no title", n.line, id)
	}
	note, err := ystr(n, "note")
	if err != nil {
		return Intent{}, err
	}
	return Intent{ID: id, Area: area, Title: title, Note: note}, nil
}

func loadClass(c *Catalog, n *ynode) (Class, error) {
	if err := yonly(n, "a class", "id", "title", "protocol", "summary",
		"tac_first_look", "detect", "intents", "sources"); err != nil {
		return Class{}, err
	}
	id, err := ystr(n, "id")
	if err != nil {
		return Class{}, err
	}
	if !slugRE.MatchString(id) {
		return Class{}, fmt.Errorf("line %d: class id %q is not a kebab slug", n.line, id)
	}
	title, err := ystr(n, "title")
	if err != nil {
		return Class{}, err
	}
	if strings.TrimSpace(title) == "" {
		return Class{}, fmt.Errorf("line %d: class %q has no title", n.line, id)
	}
	proto, err := ystr(n, "protocol")
	if err != nil {
		return Class{}, err
	}
	if _, ok := classProtocols[proto]; !ok {
		return Class{}, fmt.Errorf("line %d: class %q declares protocol %q, which is not in the closed set", n.line, id, proto)
	}
	summary, err := ystr(n, "summary")
	if err != nil {
		return Class{}, err
	}
	first, err := ystr(n, "tac_first_look")
	if err != nil {
		return Class{}, err
	}
	intents, err := ystrs(n, "intents")
	if err != nil {
		return Class{}, err
	}
	det, err := loadDetect(n)
	if err != nil {
		return Class{}, fmt.Errorf("class %q: %w", id, err)
	}
	if id == GenericClassID {
		if !det.empty() {
			return Class{}, fmt.Errorf("line %d: the %q class must carry NO detection rules — it is the honest fallback, not a catch-all matcher", n.line, GenericClassID)
		}
	} else if det.empty() && len(intents) == 0 {
		// A class with no detection rules is NOT dead: the operator may override
		// to any class, so one that can only be selected by hand is a real
		// (if manual) capability, and the coverage view labels it that way. A
		// class with neither detection rules NOR a command list is dead, because
		// selecting it would collect nothing beyond the baseline.
		return Class{}, fmt.Errorf("line %d: class %q has neither detection rules nor command "+
			"intents; selecting it would collect nothing beyond the baseline", n.line, id)
	}
	seen := map[string]bool{}
	for _, in := range intents {
		if _, ok := c.intents[in]; !ok {
			return Class{}, fmt.Errorf("line %d: class %q asks for intent %q, which is not in the `intents:` vocabulary", n.line, id, in)
		}
		if seen[in] {
			return Class{}, fmt.Errorf("line %d: class %q lists intent %q twice", n.line, id, in)
		}
		seen[in] = true
	}
	srcs, err := loadSources(n)
	if err != nil {
		return Class{}, fmt.Errorf("class %q: %w", id, err)
	}
	return Class{
		ID: id, Title: title, Protocol: proto, Summary: summary,
		TACFirstLook: first, Detect: det, Intents: intents, Sources: srcs,
	}, nil
}

func loadDetect(n *ynode) (Detect, error) {
	dn, err := ymap(n, "detect")
	if err != nil {
		return Detect{}, err
	}
	if dn == nil {
		return Detect{}, nil
	}
	if err := yonly(dn, "detect", "alerts", "hypotheses", "signatures", "skills", "issues", "log_regex"); err != nil {
		return Detect{}, err
	}
	var d Detect
	for _, spec := range []struct {
		key string
		dst *[]string
	}{
		{"alerts", &d.Alerts}, {"hypotheses", &d.Hypotheses}, {"signatures", &d.Signatures},
		{"skills", &d.Skills}, {"issues", &d.Issues}, {"log_regex", &d.LogRegex},
	} {
		v, verr := ystrs(dn, spec.key)
		if verr != nil {
			return Detect{}, verr
		}
		for _, s := range v {
			if strings.TrimSpace(s) == "" {
				return Detect{}, fmt.Errorf("line %d: empty entry in detect.%s", dn.line, spec.key)
			}
		}
		*spec.dst = v
	}
	for _, pat := range d.LogRegex {
		re, cerr := regexp.Compile(pat)
		if cerr != nil {
			return Detect{}, fmt.Errorf("line %d: detect.log_regex %q does not compile: %w", dn.line, pat, cerr)
		}
		d.logRE = append(d.logRE, re)
	}
	return d, nil
}

// normSourceURL is a citation's IDENTITY. Two entries that point at the same
// page are one citation however their titles were written, so the comparison
// folds the scheme and host, drops a fragment and an empty trailing slash.
// Everything after the host keeps its case — a documentation path is
// case-sensitive and folding it would merge two genuinely different pages.
func normSourceURL(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "/")
	i := strings.Index(s, "://")
	if i < 0 {
		return strings.ToLower(s)
	}
	head, rest := strings.ToLower(s[:i+3]), s[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return head + strings.ToLower(rest[:j]) + rest[j:]
	}
	return head + strings.ToLower(rest)
}

// dedupeSources keeps the FIRST entry for each page. It is applied at load, so
// no consumer has to defend itself against a citation list that repeats: the
// Nokia SR Linux pack carried its 61 pages six times over, and every binding
// that inherited that pool put 366 links under one command in the escalation
// preview.
func dedupeSources(in []Source) []Source {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := make([]Source, 0, len(in))
	for _, s := range in {
		key := normSourceURL(s.URL)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

func loadSources(n *ynode) ([]Source, error) {
	items, err := ylist(n, "sources")
	if err != nil {
		return nil, err
	}
	out := make([]Source, 0, len(items))
	for _, it := range items {
		if err := yonly(it, "a source", "title", "url", "retrieved"); err != nil {
			return nil, err
		}
		title, terr := ystr(it, "title")
		if terr != nil {
			return nil, terr
		}
		url, uerr := ystr(it, "url")
		if uerr != nil {
			return nil, uerr
		}
		ret, rerr := ystr(it, "retrieved")
		if rerr != nil {
			return nil, rerr
		}
		if !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("line %d: source url %q must be https", it.line, url)
		}
		if strings.TrimSpace(title) == "" {
			return nil, fmt.Errorf("line %d: source %q has no title", it.line, url)
		}
		out = append(out, Source{Title: title, URL: url, Retrieved: ret})
	}
	return dedupeSources(out), nil
}

// loadPlan parses and validates one plans/<dialect>.yaml.
func loadPlan(c *Catalog, slug, src string) (*DialectPlan, error) {
	doc, err := parseYAML(src)
	if err != nil {
		return nil, err
	}
	if !doc.isMap() {
		return nil, fmt.Errorf("document must be a mapping")
	}
	if err := yonly(doc, "a plan", "schema_version", "dialect", "profile", "display",
		"version", "sources", "baseline", "optional", "bindings"); err != nil {
		return nil, err
	}
	if err := requireSchemaVersion(doc); err != nil {
		return nil, err
	}
	dialect, err := ystr(doc, "dialect")
	if err != nil {
		return nil, err
	}
	if dialect != slug {
		return nil, fmt.Errorf("`dialect: %s` does not match the file name %q", dialect, slug+".yaml")
	}
	profile, err := ystr(doc, "profile")
	if err != nil {
		return nil, err
	}
	prof, ok := vendorprofile.Default().Lookup(profile)
	if !ok {
		return nil, fmt.Errorf("`profile: %s` is not a vendorprofile profile id", profile)
	}
	if got := DialectSlug(profile); got != dialect {
		return nil, fmt.Errorf("profile %q slugs to %q, not %q", profile, got, dialect)
	}
	display, err := ystr(doc, "display")
	if err != nil {
		return nil, err
	}
	version, err := ystr(doc, "version")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(version) == "" {
		return nil, fmt.Errorf("`version` is required")
	}
	// Plan-level `sources` are the dialect's DEFAULT citation set — the vendor's
	// own command reference. A doc_claimed binding inherits them unless it names
	// its own, so "where did this command come from" is always answerable
	// without repeating the same URL under two hundred bindings.
	planSources, err := loadSources(doc)
	if err != nil {
		return nil, err
	}
	p := &DialectPlan{
		Dialect: dialect, Profile: profile, Display: display, Version: version,
		Sources: planSources, Bindings: map[string]Binding{},
		// The `{vrf-scope}` keyword is VENDOR DATA, resolved once here from the
		// profile this plan already names — never a switch on the dialect id.
		// A profile that authors none scopes with the bare instance name.
		vrfScopeKeyword: prof.Dialect.VRFScopeKeyword,
	}

	bn, err := ymap(doc, "bindings")
	if err != nil {
		return nil, err
	}
	if bn == nil {
		return nil, fmt.Errorf("`bindings` is required (a plan with no commands is not a plan)")
	}
	for _, intent := range bn.keys {
		b, berr := loadBinding(c, dialect, intent, bn.m[intent], planSources)
		if berr != nil {
			return nil, berr
		}
		p.Bindings[intent] = b
	}

	for _, spec := range []struct {
		key string
		dst *[]string
	}{{"baseline", &p.Baseline}, {"optional", &p.Optional}} {
		list, lerr := ystrs(doc, spec.key)
		if lerr != nil {
			return nil, lerr
		}
		seen := map[string]bool{}
		for _, in := range list {
			if _, ok := c.intents[in]; !ok {
				return nil, fmt.Errorf("%s lists intent %q, which is not in the classes.yaml vocabulary", spec.key, in)
			}
			b, ok := p.Bindings[in]
			if !ok {
				return nil, fmt.Errorf("%s lists intent %q, which this dialect does not bind", spec.key, in)
			}
			if spec.key == "baseline" && b.Consent {
				return nil, fmt.Errorf("baseline lists intent %q, which needs operator consent — "+
					"a command the vendor says is not routine can never be in a baseline that runs by default", in)
			}
			if seen[in] {
				return nil, fmt.Errorf("%s lists intent %q twice", spec.key, in)
			}
			seen[in] = true
		}
		*spec.dst = list
	}
	if len(p.Baseline) == 0 {
		return nil, fmt.Errorf("`baseline` is required — the vendor-standard set every class collects")
	}
	for _, in := range p.Optional {
		for _, b := range p.Baseline {
			if in == b {
				return nil, fmt.Errorf("intent %q is in both baseline and optional", in)
			}
		}
	}
	return p, nil
}

func loadBinding(c *Catalog, dialect, intent string, n *ynode, planSources []Source) (Binding, error) {
	if _, ok := c.intents[intent]; !ok {
		return Binding{}, fmt.Errorf("binding %q names an intent that is not in the classes.yaml vocabulary", intent)
	}
	if n == nil || !n.isMap() {
		return Binding{}, fmt.Errorf("binding %q must be a mapping", intent)
	}
	if err := yonly(n, "binding "+intent, "command", "verified", "sources", "max_bytes",
		"timeout_s", "consent", "consent_note", "read_only_exception", "teardown"); err != nil {
		return Binding{}, err
	}
	cmd, err := ystr(n, "command")
	if err != nil {
		return Binding{}, err
	}
	cmd = strings.Join(strings.Fields(cmd), " ")
	if cmd == "" {
		return Binding{}, fmt.Errorf("binding %q has no command", intent)
	}
	exception, err := ystr(n, "read_only_exception")
	if err != nil {
		return Binding{}, err
	}
	// THE OWNER'S RULE (2026-09-05), applied to authored data BEFORE the grammar:
	// a command in the config / restart / daemon families is not something
	// Correlix carries at all. The research corpus is purged of them and the
	// merge refuses them at the door; this is the layer that makes a hand-edited
	// plan file fail the LOAD rather than reach a device.
	if rule, hit := c.policy.Match(dialect, cmd); hit {
		return Binding{}, fmt.Errorf("binding %q: command %q is in the %s family of the output-only "+
			"command policy (rule %q: %s) — Correlix does not carry it",
			intent, cmd, rule.Family, rule.String(), rule.Why)
	}
	teardown, err := ystr(n, "teardown")
	if err != nil {
		return Binding{}, err
	}
	teardown = strings.Join(strings.Fields(teardown), " ")
	scope, scoped := c.policy.SessionScope(dialect, cmd)
	switch {
	case scoped && teardown == "":
		return Binding{}, fmt.Errorf("binding %q is a session-scoped setter and carries no `teardown` — "+
			"it is allowed only because Correlix undoes it, so %q is required", intent, scope.Teardown)
	case scoped && teardown != scope.Teardown:
		return Binding{}, fmt.Errorf("binding %q declares teardown %q; the policy's documented teardown for this setter is %q",
			intent, teardown, scope.Teardown)
	case !scoped && teardown != "":
		return Binding{}, fmt.Errorf("binding %q declares a teardown but its command is not a documented "+
			"session-scoped setter; a teardown is not a way to run a second command", intent)
	}
	if scoped {
		// A documented session-scoped setter is not a read, so the read-only
		// grammar can never admit it. It is admitted by the POLICY instead — the
		// same way a cited read-only exception is — and every structural rule
		// still applies to both it and its teardown.
		if verr := ValidateScopedSetter(cmd); verr != nil {
			return Binding{}, fmt.Errorf("binding %q: %w", intent, verr)
		}
		if verr := ValidateScopedSetter(teardown); verr != nil {
			return Binding{}, fmt.Errorf("binding %q teardown: %w", intent, verr)
		}
	} else if err := ValidateCommandWithException(cmd, exception); err != nil {
		return Binding{}, fmt.Errorf("binding %q: %w", intent, err)
	}
	ver, err := ystr(n, "verified")
	if err != nil {
		return Binding{}, err
	}
	switch Verified(ver) {
	case VerifiedCapture, VerifiedDocClaimed:
	default:
		return Binding{}, fmt.Errorf("binding %q: `verified` must be %q or %q (got %q)",
			intent, VerifiedCapture, VerifiedDocClaimed, ver)
	}
	srcs, err := loadSources(n)
	if err != nil {
		return Binding{}, fmt.Errorf("binding %q: %w", intent, err)
	}
	// A binding's `sources` are the pages that establish THIS command, and
	// nothing else — a binding that cites none gets none. The plan-level list
	// is the file's BIBLIOGRAPHY: it still answers "where did this dialect come
	// from" and it still satisfies the doc_claimed citation requirement below,
	// but it never becomes a binding's own citation set. It used to
	// (`srcs = planSources`), which put the whole pool on every step of every
	// plan — 8,418 links on one Nokia SR Linux preview, 2026-09-06.
	if len(srcs) > maxBindingSources {
		srcs = srcs[:maxBindingSources]
	}
	if Verified(ver) == VerifiedDocClaimed && len(srcs) == 0 && len(planSources) == 0 {
		return Binding{}, fmt.Errorf("binding %q is doc_claimed and neither it nor its plan carries `sources` — an unverified command must say where it came from", intent)
	}
	if exception != "" && len(srcs) == 0 {
		return Binding{}, fmt.Errorf("binding %q claims a read-only exception and carries no `sources` — "+
			"an exception to the safety grammar must cite the page that establishes it", intent)
	}
	consentRaw, err := ystr(n, "consent")
	if err != nil {
		return Binding{}, err
	}
	consentNote, err := ystr(n, "consent_note")
	if err != nil {
		return Binding{}, err
	}
	consent := consentRaw == "true"
	if consentRaw != "" && consentRaw != "true" && consentRaw != "false" {
		return Binding{}, fmt.Errorf("binding %q: `consent` must be true or false (got %q)", intent, consentRaw)
	}
	if consent && strings.TrimSpace(consentNote) == "" {
		return Binding{}, fmt.Errorf("binding %q needs consent and says nothing about why — "+
			"the operator is being asked to approve something, so the vendor's own caveat is required", intent)
	}
	b := Binding{
		Intent: intent, Command: cmd, Verified: Verified(ver), Sources: srcs,
		Consent: consent, ConsentNote: consentNote, ReadOnlyException: exception,
		Teardown: teardown,
		tokens:   tokenize(cmd),
	}
	if teardown != "" {
		b.teardownTokens = tokenize(teardown)
	}
	if raw, verr := ystr(n, "max_bytes"); verr != nil {
		return Binding{}, verr
	} else if raw != "" {
		v, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil || v <= 0 {
			return Binding{}, fmt.Errorf("binding %q: max_bytes must be a positive integer", intent)
		}
		b.MaxBytes = v
	}
	if raw, verr := ystr(n, "timeout_s"); verr != nil {
		return Binding{}, verr
	} else if raw != "" {
		v, perr := strconv.Atoi(raw)
		if perr != nil || v <= 0 {
			return Binding{}, fmt.Errorf("binding %q: timeout_s must be a positive integer", intent)
		}
		b.Timeout = time.Duration(v) * time.Second
	}
	return b, nil
}

// ValidateCommand is the LOADER's safety gate on one authored command: it must
// be a read-only show by the protocoldiag grammar (the SAME function the live
// runner re-applies), and every `{token}` it carries must be in the closed
// placeholder set.
//
// It is exported because the research-merge script's Go-side test and the
// repo-level data test both assert it over the shipped files, and because a
// second implementation of "is this safe" is exactly the drift this rule exists
// to prevent.
func ValidateCommand(cmd string) error { return ValidateCommandWithException(cmd, "") }

// ValidateCommandWithException is ValidateCommand with the per-dialect
// DOCUMENTED-STATUS-READ allowlist applied.
//
// Why an exception exists at all: the read-only grammar judges a command by its
// LEAD TOKEN, and several vendors spell a pure status print with a token that
// reads like an action. FortiOS's `diagnose debug crashlog read` prints a crash
// log; `diagnose debug rating` prints FortiGuard server ratings. Refusing them
// on the word "debug" would drop real evidence a TAC engineer asks for first.
//
// The exception is therefore NARROW and it is DATA, not a code path: the binding
// names the reason, cites the page, and only THAT command is admitted. Every
// other structural rule still applies — no chaining, no redirection, no
// substitution, display-only pipe filters, closed placeholders — and a command
// with no exception still fails closed. There is no wildcard and no prefix
// match.
func ValidateCommandWithException(cmd, exception string) error {
	if err := protocoldiag.ValidateReadOnly(cmd); err != nil {
		// A bounded reachability probe is the one thing that is not a read and
		// is still allowed (owner, 2026-09-05: "Ping and traceroute are good
		// examples, should be allowed"). It has its OWN grammar rather than a
		// hole in the read-only one, and every parameter must be in bounds.
		if protocoldiag.IsProbeCommand(cmd) {
			if perr := protocoldiag.ValidateBoundedProbe(cmd); perr != nil {
				return fmt.Errorf("command %q is a probe outside the bounded-probe grammar: %w", cmd, perr)
			}
			return validatePlaceholders(cmd)
		}
		if exception == "" {
			return fmt.Errorf("command %q is not a read-only show: %w", cmd, err)
		}
		// Even under an exception, the structural refusals stand: those are
		// about what the string can DO, not about what it is called.
		if err := validateStructure(cmd); err != nil {
			return fmt.Errorf("command %q claims a read-only exception but %w", cmd, err)
		}
	}
	return validatePlaceholders(cmd)
}

// validatePlaceholders enforces the CLOSED substitution grammar on one command:
// every `{token}` it carries must be one Correlix can actually fill from an
// incident. A malformed or unknown placeholder fails closed.
func validatePlaceholders(cmd string) error {
	for _, tok := range tokenize(cmd) {
		if !strings.HasPrefix(tok, "{") {
			continue
		}
		if !strings.HasSuffix(tok, "}") {
			return fmt.Errorf("command %q has a malformed placeholder %q", cmd, tok)
		}
		if _, ok := placeholders[tok]; !ok {
			return fmt.Errorf("command %q uses placeholder %q, which is not in the closed substitution grammar", cmd, tok)
		}
	}
	return nil
}

// DialectSlug maps a vendorprofile profile id ("cisco/ios_xe") to this package's
// dialect slug ("cisco-iosxe"): the vendor, a hyphen, then the platform with its
// own separators removed. It is total and deterministic — the one place the two
// id spaces are joined.
func DialectSlug(profileID string) string {
	vendor, platform, ok := strings.Cut(profileID, "/")
	if !ok {
		return ""
	}
	platform = strings.NewReplacer("_", "", "-", "", ".", "").Replace(platform)
	return vendor + "-" + platform
}

// DialectForPlatform resolves a free-form device platform string onto a dialect
// slug through the vendorprofile registry — the ONLY authority, exactly as
// internal/showparse does it. An unrecognized platform returns ("", false): the
// caller then reports "no authored plan for this platform" rather than rendering
// some other vendor's commands at a device.
func DialectForPlatform(platform string) (string, string, bool) {
	prof, ok := vendorprofile.Default().ProfileForPlatformText(platform)
	if !ok {
		return "", "", false
	}
	return DialectSlug(prof.ID), prof.DisplayName, true
}

// ValidateScopedSetter is the grammar a DOCUMENTED SESSION-SCOPED SETTER must
// pass. Such a command narrows what a read prints and dies with the CLI session;
// it changes no configuration and clears nothing, which is why the owner's
// 2026-09-05 rule leaves it open. It is admitted by ai/tac/forbidden.yaml's
// `session_scoped:` list and by nothing else — there is no prefix match and no
// wildcard — and every structural rule the read-only grammar carries still
// applies: no chaining, no redirection, no substitution, display-only pipe
// filters, closed placeholders.
func ValidateScopedSetter(cmd string) error {
	if strings.TrimSpace(cmd) == "" {
		return fmt.Errorf("empty command")
	}
	if err := validateStructure(cmd); err != nil {
		return fmt.Errorf("command %q is a session-scoped setter but %w", cmd, err)
	}
	return validatePlaceholders(cmd)
}

// validateStructure applies the read-only grammar's STRUCTURAL half — the rules
// that are about what a string can do rather than what it is called: no command
// chaining, no redirection, no substitution, and display-only pipe filters. It
// is what a documented-status-read exception must still pass.
func validateStructure(cmd string) error {
	for _, bad := range []string{";", "\n", "\r", "&", "`", "$(", "${", ">", "<", "!"} {
		if strings.Contains(cmd, bad) {
			return fmt.Errorf("contains the disallowed metacharacter %q", bad)
		}
	}
	segments := strings.Split(cmd, "|")
	for _, seg := range segments[1:] {
		fields := strings.Fields(seg)
		if len(fields) == 0 {
			return fmt.Errorf("has an empty pipe segment")
		}
		if err := protocoldiag.ValidateReadOnly("show x | " + seg); err != nil {
			return fmt.Errorf("pipes into %q, which is not a display-only filter", fields[0])
		}
	}
	return nil
}
