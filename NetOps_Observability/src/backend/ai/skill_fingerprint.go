// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_fingerprint.go — what a case result is a result OF (tracker 337 N-F2).
//
// A runbook's cases passed against one system prompt, one set of tools and one
// model. HarnessFingerprint names that combination, so a later change to any of
// them is visible as "these results are stale" rather than discovered in front of
// a customer. This file only computes it; nothing here re-runs anything.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"netops/backend/internal/irishypo"
)

// skillPromptTemplateVersion names the shape of the prompts skillSystemBlock,
// skillPrompt, chainRouteSystemBlock and chainRoutePrompt write. Bump it when any
// of them changes: their text is code, so the fingerprint cannot read it directly.
// TestCompiledSkillPromptBytesAreFrozen is what notices you forgot.
const skillPromptTemplateVersion = 1

// harnessInputs is everything the fingerprint covers, as rendered strings.
type harnessInputs struct {
	systemPrompt     string
	templateVersion  string
	fence            string
	toolMetas        string
	toolAllowlist    string
	stateFacets      string
	factValues       string
	contractVersions string
	hypothesisIDs    string
	compiledSkills   string
	tierModels       string
}

// fingerprint hashes every input, each under its own name and NUL-terminated so a
// byte cannot move between two inputs unnoticed.
func (h harnessInputs) fingerprint() string {
	d := sha256.New()
	for _, part := range [][2]string{
		{"system_prompt", h.systemPrompt},
		{"template_version", h.templateVersion},
		{"fence", h.fence},
		{"tool_metas", h.toolMetas},
		{"tool_allowlist", h.toolAllowlist},
		{"state_facets", h.stateFacets},
		{"fact_values", h.factValues},
		{"contract_versions", h.contractVersions},
		{"hypothesis_ids", h.hypothesisIDs},
		{"compiled_skills", h.compiledSkills},
		{"tier_models", h.tierModels},
	} {
		d.Write([]byte(part[0]))
		d.Write([]byte{0})
		d.Write([]byte(part[1]))
		d.Write([]byte{0})
	}
	return hex.EncodeToString(d.Sum(nil))
}

// HarnessFingerprint is the sha256 of everything a runbook's case results depend
// on: the base system prompt, the prompt template version, the fence, the tools a
// skill may name and their contracts, the state vocabulary, the hypothesis
// catalogue, the compiled methods and the models answering each tier.
func HarnessFingerprint(tiers TierModels) string {
	return liveHarnessInputs(tiers).fingerprint()
}

func liveHarnessInputs(tiers TierModels) harnessInputs {
	return harnessInputs{
		systemPrompt:     baseSystemPromptText(),
		templateVersion:  strconv.Itoa(skillPromptTemplateVersion),
		fence:            DataNotInstructionsFence(),
		toolMetas:        canonicalToolMetas(),
		toolAllowlist:    canonicalJSON(sortedKeys(skillToolAllowlist)),
		stateFacets:      canonicalJSON(skillStateFacets),
		factValues:       canonicalJSON(map[string]any{"fact": skillFactValues, "topo": skillTopoFacets}),
		contractVersions: canonicalContractVersions(),
		hypothesisIDs:    canonicalHypothesisIDs(),
		compiledSkills:   canonicalCompiledSkills(),
		tierModels: canonicalJSON(map[string]string{
			"default": tiers.For(""),
			"fast":    tiers.For(TierFast),
			"strong":  tiers.For(TierStrong),
		}),
	}
}

// canonicalJSON is json.Marshal, which sorts map keys. The inputs here are strings
// and maps of them and cannot fail to encode; if one ever does, the error text is
// what gets hashed, so the fingerprint moves instead of collapsing to one value.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "unencodable: " + err.Error()
	}
	return string(b)
}

func canonicalToolMetas() string {
	type arg struct {
		Name     string `json:"name"`
		Desc     string `json:"desc"`
		Required bool   `json:"required"`
	}
	type meta struct {
		Description string `json:"description"`
		Label       string `json:"label"`
		Args        []arg  `json:"args"`
	}
	out := make(map[string]meta, len(toolMetas))
	for name, m := range toolMetas {
		args := make([]arg, 0, len(m.args))
		for _, a := range m.args {
			args = append(args, arg{Name: a.name, Desc: a.desc, Required: a.required})
		}
		out[name] = meta{Description: m.description, Label: m.label, Args: args}
	}
	return canonicalJSON(out)
}

func canonicalContractVersions() string {
	out := make(map[string]int, len(toolContracts))
	for name, c := range toolContracts {
		out[name] = c.Version
	}
	return canonicalJSON(out)
}

func canonicalHypothesisIDs() string {
	var ids []string
	for _, d := range irishypo.Catalogue() {
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return canonicalJSON(ids)
}

// canonicalCompiledSkills lists name@version. A corpus that does not load names
// the failure instead, which moves the fingerprint and fails its callers' checks.
func canonicalCompiledSkills() string {
	set, err := LoadSkills()
	if err != nil {
		return "unloadable: " + err.Error()
	}
	out := make([]string, 0, set.Len())
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		out = append(out, name+"@"+strconv.Itoa(sk.Version))
	}
	return canonicalJSON(out)
}
