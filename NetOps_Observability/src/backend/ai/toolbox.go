// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// toolbox.go — one brain, one registry (tracker 337 N-A5).
//
// Iris has two ways of running a tool: the grounded engine, where the PLATFORM
// picks the tools (a route's tool list, a skill's gather steps), and the
// copilot agent loop, where the MODEL picks from a manifest. Until N-A5 they
// were built separately — the engine got the Phase-A troubleshooting tools but
// not search_docs, the agent loop got search_docs but none of the Phase-A
// tools — so "what can Iris read" depended on which door a question came in by.
//
// A Toolbox is the single answer to that question for one request: ONE
// registry, built by ONE function, behind ONE policy engine. Both paths take
// their tools from it and pass the same two gates:
//
//   - Gate 1, Manifest: what the model may even SEE (agent loop only — on the
//     engine's deterministic paths the platform, not a model, names the tool,
//     so there is no manifest to filter);
//   - Gate 2, Authorize: re-evaluated at the instant a tool runs, on BOTH
//     paths, reading nothing the model said.
//
// Tenant scope is not the Toolbox's business and it adds none: every tool
// reads through the DataSource / TroubleshootDeps the server built from the
// caller's token, exactly as before.

// Toolbox is the shared tool surface for one request: the registry and the
// policy engine that governs it. The zero value has no tools and denies.
type Toolbox struct {
	Registry *ToolRegistry
	Policy   *PolicyEngine
}

// BuildToolRegistry is the ONE constructor for the Iris tool registry, used by
// both the grounded engine and the copilot agent loop:
//
//   - the correlation / window / wireless / module read tools (Tools(ds));
//   - the Phase-A troubleshooting tools for every seam actually wired in deps
//     (a nil seam registers nothing — unchanged from AddTroubleshootTools);
//   - search_docs over the product documentation index (nil index → absent).
//
// Adding a tool to one path only is no longer expressible: there is no second
// constructor to add it to.
func BuildToolRegistry(ds DataSource, deps TroubleshootDeps, docs *DocsIndex) *ToolRegistry {
	reg := Tools(ds)
	reg.AddTroubleshootTools(ds, deps)
	reg.AddDocsSearch(docs)
	return reg
}

// Manifest is gate 1: the tool specs this principal's model may see — every
// registered tool with a declared argument schema that passes EvaluateTool.
func (b Toolbox) Manifest(p Principal) []ToolSpec {
	return Manifest(b.Registry, b.Policy, p)
}

// Authorize is gate 2, run at execution time on both paths: the named tool if
// it is registered (registered=false otherwise) and the policy decision for
// this principal. A missing registry or policy engine fails closed.
func (b Toolbox) Authorize(name string, p Principal) (tool AITool, d Decision, registered bool) {
	if b.Registry == nil {
		return nil, deny("no tools are available"), false
	}
	tool, ok := b.Registry.Get(name)
	if !ok {
		return nil, deny("unknown tool %q", name), false
	}
	if b.Policy == nil {
		return tool, deny("%s is not permitted: no policy engine", name), true
	}
	return tool, b.Policy.EvaluateTool(tool, p), true
}

// Toolbox returns the engine's own tool surface — the registry and policy its
// deterministic paths execute through — so the copilot agent loop runs on the
// very same entries, not a parallel set.
func (o *Orchestrator) Toolbox() Toolbox {
	return Toolbox{Registry: o.Tools, Policy: o.policy()}
}
