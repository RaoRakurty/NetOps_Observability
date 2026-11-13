// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"os"
	"testing"
	"time"

	"netops/backend/internal/aientitlement"
	"netops/backend/internal/featureflags"
	"netops/backend/internal/licence"
)

// setAIModelsForTest puts s in the state an administrator reaches on a
// licensed install: the AI add-on licensed (the licence-neutral harness
// service, unless the test wired its own) and the two console-only switches
// set as given. It is how a test that exercises model-backed Iris says so —
// the zero-value server has the add-on OFF, exactly like production.
//
// The switches are real featureflags state (a fresh registry over an in-memory
// store, seeded once), so the gate under test is the production gate.
func setAIModelsForTest(t testing.TB, s *server, models, investigations bool) {
	t.Helper()
	if s.entitlements == nil {
		s.entitlements = licence.NewUnlimitedService()
	}
	reg := featureflags.New(featureflags.PlatformSpecs(), &memEnv{m: map[string]string{}}, &memStore{})
	if err := reg.Load(); err != nil {
		t.Fatal(err)
	}
	s.features = reg
	reg.SetRequirements(func(string) (bool, string) {
		return s.aiModelLicensed(), "the AI add-on is not licensed in this test"
	})
	for flag, on := range map[string]bool{aientitlement.SwitchModels: models, aientitlement.SwitchInvestigations: investigations} {
		if _, err := reg.Seed(flag, on, "test", time.Now()); err != nil {
			t.Fatalf("seed %s: %v", flag, err)
		}
	}
}

// setAIModelsLikeLegacyEnv is the harness default for the shared server
// builders: models ON, and investigations ON exactly when the test set
// FEATURE_AI_TOOLS=true before building the server — the posture each AI test
// was written against, now expressed through the console switches (the
// variable itself gates nothing in production any more).
func setAIModelsLikeLegacyEnv(t testing.TB, s *server) {
	t.Helper()
	setAIModelsForTest(t, s, true, os.Getenv(aientitlement.EnvAITools) == "true")
}
