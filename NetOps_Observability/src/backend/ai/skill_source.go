// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_source.go — a CUSTOMER'S runbook entering through the skill loader
// (tracker 337 N-F2).
//
// ParseSkillSource is parseSkill and parseSkillCaseFile, unchanged, so an author
// gets the same error a Correlix engineer would; the rules below only tighten.
// Overlay is how a parsed runbook joins the compiled methods, in a new set, for
// one tenant.
//
// Nothing here stores anything or decides who may submit what. A runbook's tenant
// is stamped by the caller from the authenticated principal (§3a rule 2): there
// is no frontmatter key for it, and an unknown key is refused.

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// The bounds on one submission. Enforced before any parsing (§15 LLM04).
const (
	maxTenantSkillMDBytes   = 16 << 10
	maxTenantCasesBytes     = 32 << 10
	maxTenantCases          = 40
	maxTenantSkillNameBytes = 48
)

// tenantSkillKeys is the closed frontmatter vocabulary of a customer's runbook.
// parseSkill reads the keys it knows and ignores the rest, which is safe for files
// reviewed in this repository and not for a submission: a misspelt `kind:` would
// quietly make a MOP a method, and an `origin:` line would read as though it did
// something.
var tenantSkillKeys = map[string]bool{
	"name": true, "layer": true, "version": true, "kind": true,
	"when_to_use": true, "symptom_kinds": true, "tools": true,
	"gather": true, "look_for": true, "decisions": true, "steps": true,
	// applies_when (NetClaw ingestion Batch 0): a runbook may say which
	// discovered devices it fits, over the same closed fact vocabulary.
	"applies_when": true,
}

// ParseSkillSource parses and validates one customer runbook from its two source
// texts. The result has Origin tenant and no TenantID: the caller stamps that from
// the principal before Overlay will accept it.
//
// A MOP is parsed but carries no cases: its gather is never dispatched, so a case
// could only assert a run that never happens.
func ParseSkillSource(name, skillMD, casesYAML string) (*Skill, error) {
	if len(skillMD) > maxTenantSkillMDBytes {
		return nil, fmt.Errorf("SKILL.md is %d bytes; a runbook may be at most %d", len(skillMD), maxTenantSkillMDBytes)
	}
	if len(casesYAML) > maxTenantCasesBytes {
		return nil, fmt.Errorf("CASES.yaml is %d bytes; a runbook's cases may be at most %d", len(casesYAML), maxTenantCasesBytes)
	}
	if !utf8.ValidString(skillMD) || !utf8.ValidString(casesYAML) {
		return nil, fmt.Errorf("a runbook's source must be valid UTF-8")
	}
	if err := validateTenantSkillName(name); err != nil {
		return nil, err
	}
	if err := validateTenantSkillKeys(skillMD); err != nil {
		return nil, err
	}
	sk, err := parseSkill(name, skillMD)
	if err != nil {
		return nil, err
	}
	if sk.Layer == LayerMethod {
		return nil, fmt.Errorf("layer %q is reserved: there is exactly one entry method, and it is Correlix's", LayerMethod)
	}
	sk.Origin = SkillOriginTenant
	docs := splitCaseDocs(casesYAML)
	if sk.isMOP() {
		if len(docs) > 0 {
			return nil, fmt.Errorf("a %s is never executed, so it has no behavioural cases: remove them", SkillKindMOP)
		}
		return sk, nil
	}
	if len(docs) > maxTenantCases {
		return nil, fmt.Errorf("declares %d cases; a runbook may carry at most %d", len(docs), maxTenantCases)
	}
	cases, err := parseSkillCaseFile(sk, casesYAML)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", skillCasesFile, err)
	}
	sk.Cases = cases
	return sk, nil
}

func validateTenantSkillName(name string) error {
	switch {
	case len(name) > maxTenantSkillNameBytes:
		return fmt.Errorf("name is %d bytes; a runbook's name may be at most %d", len(name), maxTenantSkillNameBytes)
	case !reSkillName.MatchString(name):
		return fmt.Errorf("name %q must match %s", name, reSkillName)
	}
	compiled, err := compiledSkillNames()
	if err != nil {
		return err
	}
	if compiled[name] {
		return fmt.Errorf("name %q is one of Correlix's own methods: choose another", name)
	}
	return nil
}

func validateTenantSkillKeys(skillMD string) error {
	front, _, err := splitSkillFrontmatter(skillMD)
	if err != nil {
		return err
	}
	fields, blocks, err := parseFrontmatter(front)
	if err != nil {
		return err
	}
	for _, keys := range []map[string]bool{stringKeys(fields), blockKeys(blocks)} {
		for _, k := range sortedKeys(keys) {
			if !tenantSkillKeys[k] {
				return fmt.Errorf("unknown key %q (keys: %v)", k, sortedKeys(tenantSkillKeys))
			}
		}
	}
	return nil
}

func stringKeys(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func blockKeys(m map[string][]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// compiledSkillNames reads the embedded corpus's directory names, which is all the
// collision check needs and needs no parsed set.
func compiledSkillNames() (map[string]bool, error) {
	entries, err := fs.Glob(skillsFS, "skills/*/SKILL.md")
	if err != nil {
		return nil, fmt.Errorf("skills: glob: %w", err)
	}
	out := make(map[string]bool, len(entries))
	for _, p := range entries {
		out[path.Base(path.Dir(p))] = true
	}
	return out, nil
}

// Overlay returns a NEW set: this compiled set plus one tenant's runbooks, with
// the whole-set checks LoadSkills runs repeated over the union. The receiver is not
// changed, and neither set has a mutator.
//
// Reach is one-directional (hopAllowed), and every runbook must belong to the same
// tenant, so nothing here can ever show one tenant another's method (§3a).
func (s *SkillSet) Overlay(tenant []*Skill) (*SkillSet, error) {
	if s == nil {
		return nil, fmt.Errorf("skills: overlay: no compiled set")
	}
	out := &SkillSet{byName: make(map[string]*Skill, len(s.order)+len(tenant))}
	for _, n := range s.order {
		base := s.byName[n]
		if base.customerAuthored() {
			return nil, fmt.Errorf("skills: overlay: base skill %q is not compiled: an overlay is built on the compiled set only", n)
		}
		out.byName[n] = base
		out.order = append(out.order, n)
	}
	owner := ""
	for i, sk := range tenant {
		if err := validateOverlayMember(i, sk); err != nil {
			return nil, err
		}
		if owner != "" && sk.TenantID != owner {
			return nil, fmt.Errorf("skills: overlay: %s belongs to another tenant: one overlay holds one tenant's runbooks", sk.Name)
		}
		owner = sk.TenantID
		if _, dup := out.byName[sk.Name]; dup {
			return nil, fmt.Errorf("skills: overlay: %q is already in the set", sk.Name)
		}
		out.byName[sk.Name] = sk
		out.order = append(out.order, sk.Name)
	}
	sort.Strings(out.order)
	if err := validateNextGraph(out); err != nil {
		return nil, err
	}
	if err := validateCaseGraph(out); err != nil {
		return nil, err
	}
	return out, nil
}

// validateOverlayMember re-checks what ParseSkillSource promised, because the
// Skill reaching here may have been through a store since.
func validateOverlayMember(i int, sk *Skill) error {
	switch {
	case sk == nil:
		return fmt.Errorf("skills: overlay: runbook %d is nil", i)
	case sk.Origin != SkillOriginTenant:
		return fmt.Errorf("skills: overlay: %s is not a tenant runbook (origin %q)", sk.Name, sk.Origin)
	case strings.TrimSpace(sk.TenantID) == "":
		return fmt.Errorf("skills: overlay: %s has no owning tenant", sk.Name)
	case sk.isMOP():
		return fmt.Errorf("skills: overlay: %s is a %s: nothing runs one, so it never joins a set", sk.Name, SkillKindMOP)
	case sk.Layer == LayerMethod:
		return fmt.Errorf("skills: overlay: %s claims the reserved %s layer", sk.Name, LayerMethod)
	case len(sk.Cases) == 0:
		return fmt.Errorf("skills: overlay: %s carries ZERO cases: a method with no proven behaviour may not run", sk.Name)
	}
	return nil
}
