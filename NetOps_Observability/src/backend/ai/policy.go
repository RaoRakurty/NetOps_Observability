// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import "fmt"

// policy.go — the Tool Policy Engine (HLD P0 deliverable). This is the SINGLE,
// deterministic (non-LLM) place that decides what Iris AI may run vs. not.
// Every tool call and module route passes through here BEFORE execution. The
// model never decides its own permissions; this Go code does.
//
// The gate enforces, in order:
//   1. Capability — v1 allows ONLY read tools. Write/execute are hard-denied
//      until the gated action subsystem exists (HLD P6); this is where its
//      allow/deny lists, blast-radius caps, change windows and two-person rule
//      will plug in.
//   2. Module availability — disabled / future modules can't be queried.
//   3. RBAC/PBAC — the caller must hold a required permission (tenant-scoped).
//   4. Explicit allow/deny lists — per-deployment / per-tenant overrides.

// PolicyConfig is the operator-defined policy. Defaults are safe: read-only,
// no actions. It's the knob for "what can the AI execute vs not."
type PolicyConfig struct {
	// AllowActions master-enables write/execute tools. Default false (v1).
	// Even when true, each action still passes the full P6 action gate; this
	// flag only lifts the blanket capability ban.
	AllowActions bool `json:"allow_actions"`
	// DenyTools always blocks these tool names (deny wins over allow).
	DenyTools []string `json:"deny_tools,omitempty"`
	// AllowTools, if non-empty, is an allowlist: only these tools may run.
	AllowTools []string `json:"allow_tools,omitempty"`
	// DenyModules blocks whole modules regardless of availability.
	DenyModules []string `json:"deny_modules,omitempty"`
}

// Decision is the gate's verdict — always with a reason (for audit + UI).
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

func deny(format string, a ...any) Decision {
	return Decision{Allow: false, Reason: fmt.Sprintf(format, a...)}
}

var allow = Decision{Allow: true, Reason: "ok"}

// PolicyEngine evaluates module routes and tool calls against PolicyConfig +
// the principal + feature flags. One instance per request (cheap).
type PolicyEngine struct {
	Cfg   PolicyConfig
	Flags FlagLookup
}

// NewPolicyEngine builds the gate. A zero PolicyConfig = the safe v1 default
// (read-only, no actions).
func NewPolicyEngine(cfg PolicyConfig, flags FlagLookup) *PolicyEngine {
	return &PolicyEngine{Cfg: cfg, Flags: flags}
}

// EvaluateModule decides whether the AI may route to / query a module for this
// principal: not deny-listed, enabled for the tenant, and the caller is permitted.
func (e *PolicyEngine) EvaluateModule(moduleID string, p Principal) Decision {
	mod, ok := ModuleByID(moduleID)
	if !ok {
		return deny("unknown module %q", moduleID)
	}
	if contains(e.Cfg.DenyModules, moduleID) {
		return deny("%s is disabled by policy", mod.DisplayName)
	}
	if !IsModuleEnabled(moduleID, e.Flags) {
		return deny("%s isn't enabled for this tenant", mod.DisplayName)
	}
	if !p.HasAnyPerm(mod.Permissions) {
		return deny("you don't have permission to query %s", mod.DisplayName)
	}
	return allow
}

// EvaluateTool is the core gate: capability first (the execute-vs-not decision),
// then allow/deny lists, then RBAC/PBAC. Returns Allow only if every check passes.
func (e *PolicyEngine) EvaluateTool(t AITool, p Principal) Decision {
	// 1. Capability — the "what can the AI execute" line. v1: read-only.
	switch t.Capability() {
	case CapRead:
		// permitted (subject to the rest)
	case CapWrite, CapExecute:
		if !e.Cfg.AllowActions {
			return deny("%s is a %s action — disabled (read-only mode); requires the gated action subsystem (HLD P6)", t.Name(), t.Capability())
		}
		// NOTE: even with AllowActions, a CapWrite/CapExecute tool must additionally
		// pass the deterministic action gate (dry-run, blast-radius, approval,
		// two-person, audit) before the executor runs it — built in HLD P6.
	default:
		return deny("%s has an unknown capability %q", t.Name(), t.Capability())
	}

	// 2. Explicit deny wins over everything.
	if contains(e.Cfg.DenyTools, t.Name()) {
		return deny("%s is denied by policy", t.Name())
	}
	// 3. Allowlist (if set, must be on it).
	if len(e.Cfg.AllowTools) > 0 && !contains(e.Cfg.AllowTools, t.Name()) {
		return deny("%s is not on the tool allowlist", t.Name())
	}
	// 4. Module + RBAC/PBAC.
	if d := e.EvaluateModule(t.Module(), p); !d.Allow {
		return d
	}
	if !p.HasAnyPerm(t.RequiredPerms()) {
		return deny("you don't have permission to run %s", t.Name())
	}
	return allow
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
