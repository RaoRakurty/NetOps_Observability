// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// validate.go — what a runbook may say. The parser decides its structure; every
// line a person wrote then passes the Org Context rule, because this text reaches a
// prompt as data and a reviewer has to be able to see all of it. It is refused with
// a reason, never cleaned. Tool names are legitimate in the tools: and gather:
// blocks, which the parser closes against an allowlist, and nowhere else.

import (
	"fmt"
	"strings"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
)

// Parse parses and validates a runbook's source for tenant. Every refusal is an
// orgcontext.Problem.
func Parse(tenant, name string, kind Kind, src Source, tools []string) (*ai.Skill, error) {
	if !ValidKind(kind) {
		return nil, orgcontext.Problem{Field: "kind", Rule: "unknown", Say: "a runbook is investigative or a mop"}
	}
	if !ValidName(name) {
		return nil, orgcontext.Problem{Field: "name", Rule: "shape", Say: "a name is lower-case letters, digits and hyphens, starts with a letter, and is at most 48 characters"}
	}
	if _, err := CanonicalBody(src); err != nil {
		return nil, err
	}
	sk, err := ai.ParseSkillSource(name, src.SkillMD, src.CasesYAML)
	if err != nil {
		return nil, orgcontext.Problem{Field: "skill_md", Rule: "parse", Say: err.Error()}
	}
	if string(sk.Kind) != string(kind) {
		return nil, orgcontext.Problem{Field: "kind", Rule: "mismatch", Say: fmt.Sprintf("the runbook says it is %s, not %s", sk.Kind, kind)}
	}
	if err := checkProse(sk, tools); err != nil {
		return nil, err
	}
	sk.TenantID = tenant
	return sk, nil
}

// checkProse runs the text rule over every field a person wrote.
func checkProse(sk *ai.Skill, tools []string) error {
	reasons := make([]string, 0, len(sk.Decisions))
	for _, d := range sk.Decisions {
		reasons = append(reasons, d.Reason)
	}
	caseNames := make([]string, 0, len(sk.Cases))
	for _, c := range sk.Cases {
		caseNames = append(caseNames, c.Name) // echoed back in harness problems
	}
	for _, f := range []struct {
		field string
		lines []string
	}{
		{"name", []string{sk.Name}},
		{"when_to_use", sk.WhenToUse},
		{"symptom_kinds", sk.SymptomKinds},
		{"look_for", sk.LookFor},
		{"decisions", reasons},
		{"steps", sk.Steps},
		{"body", []string{sk.Body}},
		{"case", caseNames},
	} {
		for _, s := range f.lines {
			if err := orgcontext.CheckText(f.field, s, tools, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func whenToUseOf(sk *ai.Skill) string { return strings.Join(sk.WhenToUse, ", ") }
