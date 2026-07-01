package ai

import "testing"

// The model router's tier policy matches the orchestrator's real behavior:
// deterministic modes never call a provider; model modes verify.
func TestRouteFor(t *testing.T) {
	cases := []struct {
		mode   AnswerMode
		useLLM bool
		verify bool
		tier   ModelTier
	}{
		{ModeProblemExplanation, true, true, TierStrong},
		{ModeCurrentStateSummary, true, true, TierFast},
		{ModeModuleHealthSummary, true, true, TierFast},
		{ModeInvestigationPlan, false, false, TierDeterministic},
		{ModeProductNavigationHelp, false, false, TierDeterministic},
		{ModeShiftHandoff, false, false, TierDeterministic},
		{ModeTimeRangeOutageSummary, false, false, TierDeterministic},
		{ModeUnavailable, false, false, TierDeterministic},
	}
	for _, c := range cases {
		r := RouteFor(c.mode)
		if r.UseLLM != c.useLLM || r.Verify != c.verify || r.Tier != c.tier {
			t.Errorf("RouteFor(%s) = %+v, want useLLM=%v verify=%v tier=%s", c.mode, r, c.useLLM, c.verify, c.tier)
		}
		// Invariant: a deterministic route never verifies (nothing to verify) and a
		// verified route is always a model route.
		if r.Verify && !r.UseLLM {
			t.Errorf("%s: verify without a model call is meaningless", c.mode)
		}
	}
}
