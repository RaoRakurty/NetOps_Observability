// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package aientitlement is the ATOMIC AI entitlement vocabulary (tracker 337,
// row N-A7): the one place the product asks "may this caller use AI capability
// X right now?".
//
// # Why a separate vocabulary from internal/entitlement
//
// internal/entitlement's Feature set is CLOSED and LOCKED by the owner (seven
// commercial features; adding an eighth "gates a capability for every
// customer, so it is an owner decision, not a diff"). Where the AI
// capabilities sit commercially is still an OPEN owner decision (plan
// docs/architecture/iris-natural-language-platform.md, owner decision 1:
// "Tier placement of the AI capabilities — N-A7 makes it an entitlement
// mapping, not code"). So the AI capabilities get their own atomic vocabulary,
// and their tier placement is DATA (tiers.json, embedded beside this file),
// never code. No tier or plan NAME appears in this package's Go source: a tier
// is an opaque key the caller hands in, looked up in the data.
//
// # The three inputs, ANDed (default-closed)
//
// A capability is granted only when ALL of these say yes:
//
//  1. TIER     — the licence tier in force grants it (tiers.json). An unknown
//     tier, an unparseable mapping or a nil Policy grants nothing.
//  2. DEPLOYMENT — the existing feature flags allow it (FEATURE_AI /
//     FEATURE_COPILOT for Iris as a whole, FEATURE_AI_TOOLS for the bounded
//     investigation loop). These are the operator's on/off switches and keep
//     their exact pre-N-A7 meaning.
//  3. TENANT   — the caller's tenant is enabled for it (the platform owner's
//     per-tenant AI switches, ai.TenantConfigStore). Cross-tenant principals
//     (the platform owner) are not tenant-gated, exactly as before.
//
// # What this package does NOT do
//
// It is not authorization. RBAC (requirePerm / requirePlatformAdmin) still
// decides WHO may read WHAT; an entitlement only decides whether the AI
// capability exists for the caller at all. A route needs both. And it is not a
// safety property: no isolation, RLS, auth or integrity path consults it.
//
// The package is stdlib-only and imports nothing from the backend, so the
// mapping logic is testable in isolation and cannot reach a safety path.
package aientitlement

import (
	"bytes"
	_ "embed" // tiers.json — the tier → entitlement mapping is data, not code
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Entitlement is one atomic AI capability. The vocabulary is CLOSED: a name
// outside it is never granted, and a mapping that names one fails to load.
type Entitlement string

const (
	// Chat — the Iris assistant: grounded asks (/api/ai/ask), the provider
	// chat proxy (/api/copilot/chat), the "/" command menu, module listing and
	// answer feedback.
	Chat Entitlement = "ai.chat"
	// Investigate — the bounded, tool-using investigation loop (the agent
	// loop inside the chat turn, "AI Investigations"). Additionally needs
	// FEATURE_AI_TOOLS and the tenant's investigation switch.
	Investigate Entitlement = "ai.investigate"
	// NLQuery — natural-language query: compile / execute, entity resolution
	// and aliases, conversations, the query log and corrections, and the data
	// arm of /api/ai/ask.
	NLQuery Entitlement = "ai.nlquery"

	// The three below are DEFINED BUT GATE NOTHING YET: no route, feature or
	// tool backs them today (tracker 337 N-F1 tenant context authoring, N-F2
	// tenant-authored runbooks, N-I5 MCP adapter). They exist now so the tier
	// mapping, the frontend and the licence conversation can name them before
	// the features land — and so the feature that lands gates on an
	// entitlement that already exists instead of inventing one. Backed()
	// reports false for them, and the route guard test refuses a route that
	// claims one until Backed() is flipped in the same change.

	// ContextAuthor — tenant-authored context for Iris (N-F1). Unbacked.
	ContextAuthor Entitlement = "ai.context.author"
	// RunbookAuthor — tenant-authored runbooks (N-F2). Unbacked.
	RunbookAuthor Entitlement = "ai.runbook.author"
	// MCP — the MCP adapter over the tool gateway (N-I5). Unbacked.
	MCP Entitlement = "ai.mcp"
)

// order is the closed vocabulary in display order.
var order = []Entitlement{Chat, Investigate, NLQuery, ContextAuthor, RunbookAuthor, MCP}

// backed records which entitlements a shipped route or feature gates on.
var backed = map[Entitlement]bool{
	Chat:        true,
	Investigate: true,
	NLQuery:     true,
	// ContextAuthor, RunbookAuthor, MCP: not backed yet — see the const block.
}

// All returns the closed vocabulary in display order.
func All() []Entitlement { return append([]Entitlement(nil), order...) }

// Valid reports whether e is in the closed vocabulary.
func Valid(e Entitlement) bool {
	for _, k := range order {
		if k == e {
			return true
		}
	}
	return false
}

// Backed reports whether a shipped route or feature gates on e today.
func Backed(e Entitlement) bool { return backed[e] }

// Label is the operator-facing name.
func Label(e Entitlement) string {
	switch e {
	case Chat:
		return "Iris assistant"
	case Investigate:
		return "AI investigations"
	case NLQuery:
		return "natural-language questions"
	case ContextAuthor:
		return "Iris context authoring"
	case RunbookAuthor:
		return "runbook authoring"
	case MCP:
		return "MCP access"
	}
	return string(e)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tier mapping — DATA
// ─────────────────────────────────────────────────────────────────────────────

//go:embed tiers.json
var defaultTiers []byte

// Policy is a parsed tier → entitlement mapping. The zero value and a nil
// *Policy grant nothing.
type Policy struct {
	tiers map[string]map[Entitlement]bool
}

// policyDoc is the on-disk shape of tiers.json. Note is free text for the
// human reading the file (who decided, when); it is never interpreted.
type policyDoc struct {
	Note  string              `json:"note"`
	Tiers map[string][]string `json:"tiers"`
}

// Parse reads a mapping document strictly: unknown fields, an empty tier key,
// an unknown entitlement name or trailing data are errors. A mapping that does
// not parse must be a loud failure at build/boot, never a capability that
// silently appears or disappears.
func Parse(b []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var doc policyDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("ai entitlement mapping: %w", err)
	}
	if dec.More() {
		return nil, errors.New("ai entitlement mapping: trailing data after the document")
	}
	if len(doc.Tiers) == 0 {
		return nil, errors.New("ai entitlement mapping: no tiers")
	}
	p := &Policy{tiers: make(map[string]map[Entitlement]bool, len(doc.Tiers))}
	for tier, names := range doc.Tiers {
		if strings.TrimSpace(tier) == "" || tier != strings.TrimSpace(tier) {
			return nil, fmt.Errorf("ai entitlement mapping: invalid tier key %q", tier)
		}
		set := make(map[Entitlement]bool, len(names))
		for _, n := range names {
			e := Entitlement(n)
			if !Valid(e) {
				return nil, fmt.Errorf("ai entitlement mapping: tier %q names unknown entitlement %q", tier, n)
			}
			set[e] = true
		}
		p.tiers[tier] = set
	}
	return p, nil
}

// Default parses the embedded tiers.json. An error here is content drift in
// the shipped file; the caller logs it loudly and runs with an empty (grant
// nothing) policy — fail closed.
func Default() (*Policy, error) { return Parse(defaultTiers) }

// TierGrants reports whether the mapping grants e to tier. Unknown tier, nil
// policy or unknown entitlement → false.
func (p *Policy) TierGrants(tier string, e Entitlement) bool {
	if p == nil || !Valid(e) {
		return false
	}
	return p.tiers[tier][e]
}

// Tiers lists the tier keys the mapping carries, sorted.
func (p *Policy) Tiers() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.tiers))
	for t := range p.tiers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment flags — the existing switches, unchanged in meaning
// ─────────────────────────────────────────────────────────────────────────────

// Flag names. These are the pre-existing operator switches; N-A7 maps them,
// it does not rename or reinterpret them.
const (
	EnvAI           = "FEATURE_AI"           // Iris as a whole; wins when set
	EnvCopilot      = "FEATURE_COPILOT"      // legacy Iris switch, honoured when FEATURE_AI is unset
	EnvAITools      = "FEATURE_AI_TOOLS"     // the bounded investigation loop
	EnvAIToolsAllTn = "AI_TOOLS_ALL_TENANTS" // investigation loop for every tenant at once
)

// IrisOn is the platform Iris switch with its historical semantics: ON by
// default (key-free grounded mode makes no external call), FEATURE_AI wins
// when set, else the legacy FEATURE_COPILOT is honoured.
func IrisOn(env func(string) string) bool {
	if env == nil {
		return false
	}
	if v := env(EnvAI); v != "" {
		return v == "true"
	}
	if v := env(EnvCopilot); v != "" {
		return v == "true"
	}
	return true
}

// DeploymentAllows reports whether the deployment's flags allow e.
func DeploymentAllows(e Entitlement, env func(string) string) bool {
	if !Valid(e) || !IrisOn(env) {
		return false
	}
	if e == Investigate {
		return env(EnvAITools) == "true"
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Tenant switches
// ─────────────────────────────────────────────────────────────────────────────

// TenantSwitches is the per-tenant AI configuration (ai.TenantConfigStore
// satisfies it). An interface so the decision is testable without the store.
type TenantSwitches interface {
	AssistantEnabled(tenant string) bool
	AgentToolsEnabled(tenant string) bool
}

// TenantAllows reports whether the caller's tenant is switched on for e.
// Cross-tenant principals are not tenant-gated (unchanged from before N-A7).
// A nil switch source grants nothing to a tenant caller.
func TenantAllows(e Entitlement, tenant string, cross bool, sw TenantSwitches, env func(string) string) bool {
	if !Valid(e) {
		return false
	}
	if cross {
		return true
	}
	if sw == nil {
		return false
	}
	if e == Investigate {
		if env != nil && env(EnvAIToolsAllTn) == "true" {
			return true
		}
		return sw.AgentToolsEnabled(tenant)
	}
	return sw.AssistantEnabled(tenant)
}

// ─────────────────────────────────────────────────────────────────────────────
// The decision
// ─────────────────────────────────────────────────────────────────────────────

// Inputs is everything a decision depends on. Tier is the licence tier in
// force as an opaque string; it is only ever used as a key into the mapping.
type Inputs struct {
	Tier     string
	Env      func(string) string
	Tenant   string
	Cross    bool
	Switches TenantSwitches
}

// Reason is why a capability was refused, as a stable machine token.
type Reason string

const (
	ReasonNone      Reason = ""
	ReasonUnknown   Reason = "unknown_entitlement"
	ReasonDisabled  Reason = "disabled"    // a deployment flag is off
	ReasonNotInTier Reason = "not_in_tier" // the licence tier's mapping does not grant it
	ReasonTenantOff Reason = "tenant_off"  // the caller's tenant is not switched on
)

// Decision is the answer for one entitlement.
type Decision struct {
	Entitlement Entitlement
	Granted     bool
	Reason      Reason
}

// Decide answers one entitlement. The checks run in a fixed order —
// deployment, tier, tenant — so a refusal names the outermost switch that is
// off (an operator who disabled Iris is told that, not that the tier lacks it).
func Decide(p *Policy, e Entitlement, in Inputs) Decision {
	d := Decision{Entitlement: e}
	switch {
	case !Valid(e):
		d.Reason = ReasonUnknown
	case !DeploymentAllows(e, in.Env):
		d.Reason = ReasonDisabled
	case !p.TierGrants(in.Tier, e):
		d.Reason = ReasonNotInTier
	case !TenantAllows(e, in.Tenant, in.Cross, in.Switches, in.Env):
		d.Reason = ReasonTenantOff
	default:
		d.Granted = true
	}
	return d
}

// Resolve returns every granted entitlement, in display order. It is what the
// frontend receives to hide what the caller cannot use; it is cosmetic there,
// and the server still gates every route with Decide.
func Resolve(p *Policy, in Inputs) []Entitlement {
	out := []Entitlement{}
	for _, e := range order {
		if Decide(p, e, in).Granted {
			out = append(out, e)
		}
	}
	return out
}
