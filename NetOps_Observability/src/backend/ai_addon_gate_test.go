// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/entitlement"
	"netops/backend/internal/featureflags"
	"netops/backend/internal/licence"
)

// The AI add-on gate (owner 2026-11-12/13): model-backed Iris needs the
// `iris_model` licence add-on AND the platform's console-only "Iris AI models"
// switch. These tests prove the ONE chokepoint (providerCandidatesForTier)
// against the platform key and a tenant's own key, and that Iris keeps
// answering evidence-only when the gate is shut.

// gateServer: a platform key (env) AND acme's own BYO key, the add-on in the
// state given. teamLicence=true wires a real Team licence without the add-on.
func gateServer(t *testing.T, licensed, models bool) *server {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "sk-platform")
	s := oneRegistryServer(t) // acme has a BYO openai key
	if licensed {
		s.entitlements = licence.NewUnlimitedService()
	} else {
		k := newLicTestKey(t)
		s.entitlements = k.service(t, k.issue(t, entitlement.TierTeam, []entitlement.Feature{entitlement.FeatureSecurityFindings}, nil))
	}
	reg := featureflags.New(featureflags.PlatformSpecs(), &memEnv{m: map[string]string{}}, &memStore{})
	if err := reg.Load(); err != nil {
		t.Fatal(err)
	}
	s.features = reg
	s.wireAISwitchesForTest(t, models)
	return s
}

// wireAISwitchesForTest runs the production requirement wiring, then sets the
// models switch the way an administrator would (Set, with the acknowledgement).
func (s *server) wireAISwitchesForTest(t *testing.T, models bool) {
	t.Helper()
	s.features.SetRequirements(func(name string) (bool, string) {
		err := entitlement.Require(s.entitlements, entitlement.Feature(name))
		if err != nil {
			return false, err.Error()
		}
		return true, ""
	})
	if !models {
		return
	}
	if _, _, err := s.features.Set(aientitlement.SwitchModels, true, aientitlement.SwitchModels, "owner", time.Now()); err != nil {
		t.Fatalf("turn the models switch on: %v", err)
	}
}


func testAuditStore(t *testing.T) auditRepo {
	t.Helper()
	au, err := newAuditStore(t.TempDir() + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	return au
}

func TestAIAddOnGateShutsEveryProviderCandidate(t *testing.T) {
	cases := []struct {
		name             string
		licensed, models bool
		want             bool
	}{
		{"licensed and switched on", true, true, true},
		{"licensed, switch left off (the default)", true, false, false},
		{"Team licence without the add-on", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := gateServer(t, c.licensed, c.models)
			for _, who := range []struct {
				label  string
				claims jwtClaims
				source string
			}{
				{"tenant with its own key (BYO)", acme(), "tenant"},
				{"platform principal on the platform key", platformOwner(), "platform"},
			} {
				cands := s.providerCandidatesForTier(who.claims, ai.TierFast)
				if got := len(cands) > 0; got != c.want {
					t.Fatalf("%s: candidates = %d, want any=%v", who.label, len(cands), c.want)
				}
				if c.want && cands[0].source != who.source {
					t.Fatalf("%s: first candidate source = %q, want %q", who.label, cands[0].source, who.source)
				}
			}
		})
	}
}

// TestUnlicensedSwitchCannotBeForcedOn: a Team install cannot turn the
// switch on from the API, and a value saved while licensed stops running when
// the licence goes.
func TestUnlicensedSwitchCannotBeForcedOn(t *testing.T) {
	s := gateServer(t, false, false)
	if _, _, err := s.features.Set(aientitlement.SwitchModels, true, aientitlement.SwitchModels, "owner", time.Now()); err == nil {
		t.Fatal("turning the models switch on must be refused without the add-on")
	}
	lic := gateServer(t, true, true)
	if len(lic.providerCandidatesForTier(acme(), ai.TierFast)) == 0 {
		t.Fatal("precondition: licensed and on")
	}
	k := newLicTestKey(t)
	lic.entitlements = k.service(t, k.issue(t, entitlement.TierTeam, nil, nil)) // the licence is swapped for one without it
	if n := len(lic.providerCandidatesForTier(acme(), ai.TierFast)); n != 0 {
		t.Fatalf("the add-on gone, no provider call may happen (got %d candidates)", n)
	}
}

// TestChatAnswersEvidenceOnlyWhenModelsAreOff: the assistant never dead-ends.
// With the add-on off the provider is not called, and the grounded engine
// answers with a disclosure the panel turns into the right banner.
func TestChatAnswersEvidenceOnlyWhenModelsAreOff(t *testing.T) {
	prov := &scriptedProvider{replies: []string{plainReply}}
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: prov})
	defer restore()

	for _, c := range []struct {
		name             string
		licensed, models bool
		reason           string
	}{
		{"unlicensed", false, false, string(aientitlement.ReasonNotLicensed)},
		{"switched off", true, false, string(aientitlement.ReasonSwitchedOff)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := gateServer(t, c.licensed, c.models)
			out := postChat(t, s, acme(), []copilotMessage{{Role: "user", Content: "is acme-core healthy?"}})
			if out["provider"] != "engine" || out["fallback"] != "models_off" || out["models_reason"] != c.reason || out["is_grounded"] != true {
				t.Fatalf("want an evidence-only engine answer with reason %q, got %v", c.reason, out)
			}
		})
	}
	prov.mu.Lock()
	n := len(prov.bodies)
	prov.mu.Unlock()
	if n != 0 {
		t.Fatalf("no provider call may be made with the add-on off; the provider saw %d", n)
	}
	// And with it on, the same question reaches the provider.
	s := gateServer(t, true, true)
	if out := postChat(t, s, acme(), []copilotMessage{{Role: "user", Content: "is acme-core healthy?"}}); out["provider"] == "engine" {
		t.Fatalf("licensed and on, the model answers: %v", out)
	}
}

// TestInvestigationsNeedTheirOwnSwitch: the loop is off with only the models
// switch on, whatever FEATURE_AI_TOOLS says, and on with both.
func TestInvestigationsNeedTheirOwnSwitch(t *testing.T) {
	t.Setenv("FEATURE_AI_TOOLS", "true") // no longer a gate
	t.Setenv("AI_TOOLS_ALL_TENANTS", "true")
	s := gateServer(t, true, true)
	if s.agentLoopEligible(acme()) {
		t.Fatal("the AI investigations switch is off: no loop, whatever FEATURE_AI_TOOLS says")
	}
	if _, _, err := s.features.Set(aientitlement.SwitchInvestigations, true, aientitlement.SwitchInvestigations, "owner", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.agentLoopEligible(acme()) {
		t.Fatal("both switches on and the tenant covered: the loop runs")
	}
	if _, _, err := s.features.Set(aientitlement.SwitchModels, false, "", "owner", time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.agentLoopEligible(acme()) {
		t.Fatal("models off turns investigations off too")
	}
}

// TestConnectionTestNeedsTheLicence: the Test button is a provider call; on an
// install without the add-on it answers 402 and calls nothing.
func TestConnectionTestNeedsTheLicence(t *testing.T) {
	prov := &scriptedProvider{replies: []string{plainReply}}
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: prov})
	defer restore()
	s := gateServer(t, false, false)
	r := httptest.NewRequest(http.MethodPost, "/api/ai/tenant-config/test", strings.NewReader(`{}`))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, tAdmin("acme")))
	w := httptest.NewRecorder()
	s.handleAITenantConfigTest(w, r)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("want 402 without the add-on, got %d %s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["feature"] != string(entitlement.FeatureIrisModel) {
		t.Fatalf("the refusal must name the add-on: %v", body)
	}
	if len(prov.bodies) != 0 {
		t.Fatal("no provider call on a refused test")
	}
}

// TestUpgradeSeedKeepsAModelInstallOnOnce is the owner's upgrade rule against
// the production wiring: a licensed install already holding a key and running
// the loop comes up with both switches on, once; an install with no key comes
// up off.
func TestUpgradeSeedKeepsAModelInstallOnOnce(t *testing.T) {
	t.Setenv("FEATURE_AI_TOOLS", "true")
	t.Setenv("OPENAI_API_KEY", "sk-platform")
	store := &memStore{}
	newBoot := func() *server {
		s := oneRegistryServer(t)
		s.entitlements = licence.NewUnlimitedService()
		s.audit = testAuditStore(t)
		reg := featureflags.New(featureflags.PlatformSpecs(), &memEnv{m: map[string]string{}}, store)
		if err := reg.Load(); err != nil {
			t.Fatal(err)
		}
		s.features = reg
		s.wireAISwitches(time.Now())
		return s
	}
	s := newBoot()
	if !s.aiModelsSwitchOn() || !s.aiInvestigationsSwitchOn() {
		t.Fatal("an install already using a model and the loop keeps both on after the upgrade")
	}
	if _, _, err := s.features.Set(aientitlement.SwitchModels, false, "", "owner", time.Now()); err != nil {
		t.Fatal(err)
	}
	if again := newBoot(); again.aiModelsSwitchOn() {
		t.Fatal("the next boot must not re-seed over the administrator's choice")
	}

	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("FEATURE_AI_TOOLS", "")
	fresh := aiTSServer(t) // no workspace key, no platform key
	fresh.entitlements = licence.NewUnlimitedService()
	fresh.audit = testAuditStore(t)
	fresh.aiTenantCfg = newAITenantConfigStore(t.TempDir()+"/ai_tenant_config.json", nil)
	fresh.copilotCfg = newCopilotConfigStore(t.TempDir()+"/cfg.json", nil)
	freshReg := featureflags.New(featureflags.PlatformSpecs(), &memEnv{m: map[string]string{}}, &memStore{})
	if err := freshReg.Load(); err != nil {
		t.Fatal(err)
	}
	fresh.features = freshReg
	fresh.wireAISwitches(time.Now())
	if fresh.aiModelsSwitchOn() || fresh.aiInvestigationsSwitchOn() {
		t.Fatal("an install with no model in use starts with both switches off")
	}
}
