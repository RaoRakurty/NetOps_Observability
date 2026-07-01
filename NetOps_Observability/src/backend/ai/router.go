package ai

// router.go — the Model Router (HLD §10). A provider-neutral routing POLICY: it
// classifies each answer by the model tier it needs, whether the unsupported-claim
// verifier applies, and (implicitly) the safe evidence-only fallback. Many Correlix
// answers are DETERMINISTIC (navigation, KB, shift/time-range/incident-list) and
// never call a model; the ones that do (RCA, current-state, module health) are
// grounded + verified. The router makes that policy explicit + auditable, and is
// the seam where per-tier providers (fast vs strong) plug in without touching the
// orchestrator — today they resolve through the single provider chain + fallback.

// ModelTier is the class of model an answer needs.
type ModelTier string

const (
	TierDeterministic ModelTier = "deterministic" // no model call — built from tools/KB/registry
	TierFast          ModelTier = "fast"          // a short grounded headline
	TierStrong        ModelTier = "strong"        // multi-fact reasoning narrative
)

// ModelRoute is the routing decision for one answer mode.
type ModelRoute struct {
	Tier   ModelTier `json:"tier"`
	UseLLM bool      `json:"use_llm"` // false → fully deterministic (no provider call)
	Verify bool      `json:"verify"`  // run the unsupported-claim verifier on model output
}

// RouteFor maps an answer mode to its model route. Kept in one place so the
// tier policy is inspectable and testable, and matches the orchestrator's actual
// behavior (deterministic modes skip the provider entirely).
func RouteFor(mode AnswerMode) ModelRoute {
	switch mode {
	case ModeProblemExplanation:
		return ModelRoute{Tier: TierStrong, UseLLM: true, Verify: true}
	case ModeCurrentStateSummary, ModeModuleHealthSummary:
		return ModelRoute{Tier: TierFast, UseLLM: true, Verify: true}
	default:
		// Navigation, KB (investigation_plan), shift-handoff, time-range,
		// incident-list, unavailable — all built deterministically from
		// tools/registry/KB, no provider call.
		return ModelRoute{Tier: TierDeterministic, UseLLM: false, Verify: false}
	}
}
