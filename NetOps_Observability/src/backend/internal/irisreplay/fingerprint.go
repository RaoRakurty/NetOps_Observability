// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"netops/backend/ai"
)

// Fingerprint components. A report's fingerprint names what a run was made of,
// so two reports that differ can say which of these moved.
const (
	ComponentSkills        = "skills"
	ComponentPrompts       = "prompts"
	ComponentToolContracts = "tool_contracts"
	ComponentEnginePins    = "engine_pins"
	ComponentModels        = "models"
)

// Fingerprint is SHA-256 over the BYTES of what the answer path is made of. Items
// holds each input's own hash, so a comparison can name the file that changed.
type Fingerprint struct {
	SHA256     string                       `json:"sha256"`
	Components map[string]string            `json:"components"`
	Items      map[string]map[string]string `json:"items"`
}

// FingerprintInputs is what is hashed.
type FingerprintInputs struct {
	SkillFiles    map[string][]byte
	Prompts       map[string]string
	ToolContracts map[string]string
	// EnginePins are the ENGINE_SEMVER values the cases pin (not the engine's
	// code: replay does not run it), plus what the reader runs.
	EnginePins []string
	// ModelNames are the leg and each case's model of record.
	ModelNames []string
}

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ComputeFingerprint hashes the inputs. Each component covers each item's name
// and its content hash, so a one-byte edit or a rename both move it.
func ComputeFingerprint(in FingerprintInputs) Fingerprint {
	items := map[string]map[string]string{
		ComponentSkills: {}, ComponentPrompts: {}, ComponentToolContracts: {},
		ComponentEnginePins: {}, ComponentModels: {},
	}
	for name, b := range in.SkillFiles {
		items[ComponentSkills][name] = hexSum(b)
	}
	for name, s := range in.Prompts {
		items[ComponentPrompts][name] = hexSum([]byte(s))
	}
	for name, s := range in.ToolContracts {
		items[ComponentToolContracts][name] = hexSum([]byte(s))
	}
	for _, s := range in.EnginePins {
		items[ComponentEnginePins][s] = hexSum([]byte(s))
	}
	for _, s := range in.ModelNames {
		items[ComponentModels][s] = hexSum([]byte(s))
	}
	fp := Fingerprint{Components: map[string]string{}, Items: items}
	componentNames := make([]string, 0, len(items))
	for comp := range items {
		componentNames = append(componentNames, comp)
	}
	sort.Strings(componentNames)
	overall := sha256.New()
	for _, comp := range componentNames {
		names := make([]string, 0, len(items[comp]))
		for name := range items[comp] {
			names = append(names, name)
		}
		sort.Strings(names)
		h := sha256.New()
		for _, name := range names {
			h.Write([]byte(name))
			h.Write([]byte{0})
			h.Write([]byte(items[comp][name]))
			h.Write([]byte{0})
		}
		fp.Components[comp] = hex.EncodeToString(h.Sum(nil))
		overall.Write([]byte(comp))
		overall.Write([]byte{0})
		overall.Write([]byte(fp.Components[comp]))
		overall.Write([]byte{0})
	}
	fp.SHA256 = hex.EncodeToString(overall.Sum(nil))
	return fp
}

// contractLine is everything a tool's contract declares.
func contractLine(c ai.ToolContract) string {
	return fmt.Sprintf("version=%d risk=%s timeout=%s rate=%d output=%+v", c.Version, c.Risk, c.Timeout, c.RatePerMin, c.Output)
}

// CurrentInputs reads the inputs of this build: the compiled-in skill files, the
// rendered prompt builders, the tool contract table, and the pins and models of
// these cases.
func CurrentInputs(cases []Case, opt Options, leg ModelLeg) (FingerprintInputs, error) {
	skills, err := ai.ReplaySkillFiles()
	if err != nil {
		return FingerprintInputs{}, err
	}
	prompts, err := ai.ReplayPromptProbes()
	if err != nil {
		return FingerprintInputs{}, err
	}
	contracts := map[string]string{}
	for _, name := range ai.ToolNames() {
		if c, ok := ai.ContractFor(name); ok {
			contracts[name] = contractLine(c)
		}
	}
	in := FingerprintInputs{SkillFiles: skills, Prompts: prompts, ToolContracts: contracts}
	if leg != nil {
		in.ModelNames = append(in.ModelNames, "leg:"+leg.Name())
	}
	if opt.EngineSemver != "" {
		in.EnginePins = append(in.EnginePins, "current:"+opt.EngineSemver)
	}
	for i := range cases {
		if v := cases[i].EngineVersion; v != "" {
			in.EnginePins = append(in.EnginePins, "case:"+v)
		}
		if m := cases[i].Model; m != nil && (m.Provider != "" || m.Name != "") {
			in.ModelNames = append(in.ModelNames, "case:"+m.Provider+"/"+m.Name)
		}
	}
	return in, nil
}
