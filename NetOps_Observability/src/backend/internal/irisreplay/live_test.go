// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

// live_test.go — the live leg's gating and wiring, with NO provider: the
// provider seam is a fake here. The real-provider run is live_eval_test.go
// (build tag nlqmodeleval), which default CI never compiles.

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"netops/backend/ai"
)

// The key value is built from parts so no secret-shaped literal lands in history.
var fakeKey = strings.Join([]string{"not", "a", "real", "key"}, "-")

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLiveLegNeedsProviderAndKeyFromTheEnvironment(t *testing.T) {
	for _, m := range []map[string]string{
		{},
		{EnvLiveProvider: "gemini"},
		{EnvLiveKey: fakeKey},
	} {
		if _, err := LiveLegFromEnv(envOf(m)); !errors.Is(err, ErrLiveNotConfigured) {
			t.Fatalf("env %v: %v — want ErrLiveNotConfigured", m, err)
		}
	}
	if _, err := LiveLegFromEnv(envOf(map[string]string{EnvLiveProvider: "llama", EnvLiveKey: fakeKey})); err == nil {
		t.Fatal("an unknown provider was accepted")
	}
	leg, err := LiveLegFromEnv(envOf(map[string]string{EnvLiveProvider: "Google", EnvLiveKey: fakeKey, EnvLiveModel: "gemini-3.5-flash-lite"}))
	if err != nil {
		t.Fatal(err)
	}
	if leg.Name() != "live:gemini/gemini-3.5-flash-lite" {
		t.Fatalf("name %q", leg.Name())
	}
	if strings.Contains(leg.Name(), fakeKey) {
		t.Fatal("the leg name carries the key")
	}
}

func TestRunLiveWithoutAKeyIsAUsageErrorBeforeAnyCase(t *testing.T) {
	t.Setenv(EnvLiveProvider, "")
	t.Setenv(EnvLiveKey, "")
	var out, errb bytes.Buffer
	code := CLI(context.Background(), []string{"run", "--cases", "../../ai/testdata/golden_incidents", "--report", t.TempDir() + "/r.json", "--live"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), EnvLiveKey) {
		t.Fatalf("run --live without a key: code %d stderr %q", code, errb.String())
	}
}

func TestLiveLegReportsTheProvidersUsageAndKeepsOutages(t *testing.T) {
	cases := loadCorpus(t)
	var calls atomic.Int64
	leg := &LiveLeg{provider: "gemini", key: fakeKey, model: "m", call: func(_ context.Context, provider, key, model, _ string, _ []ai.ChatMessage) (ai.Completion, error) {
		calls.Add(1)
		if provider != "gemini" || key != fakeKey || model != "m" {
			t.Errorf("provider call got %s/%s", provider, model)
		}
		return ai.Completion{Text: "The leading hypothesis is unconfirmed.", Usage: ai.TokenUsage{InputTokens: 120, OutputTokens: 30, Reported: true}}, nil
	}}
	rep, err := Run(context.Background(), cases, Options{Leg: leg})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ModelLeg != "live:gemini/m" {
		t.Fatalf("report leg %q", rep.ModelLeg)
	}
	if calls.Load() == 0 {
		t.Fatal("the live leg never reached the provider seam")
	}
	sawTokens := false
	for i, cr := range rep.Cases {
		if cases[i].ProviderDown && cr.Cost.InputTokens != nil && *cr.Cost.InputTokens > 0 {
			t.Fatalf("case %s scripts an outage but the live leg answered it", cr.ID)
		}
		if cr.Cost.InputTokens != nil && *cr.Cost.InputTokens > 0 {
			sawTokens = true
		}
	}
	if !sawTokens {
		t.Fatal("no case carried the provider's own token accounting")
	}
}

func TestTheScriptedLegIsUnchangedByTheLiveLeg(t *testing.T) {
	cases := loadCorpus(t)
	a, err := Run(context.Background(), cases, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(context.Background(), cases, Options{Leg: ScriptedLeg{}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Compare(Stable(a), Stable(b))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Identical {
		t.Fatalf("the scripted leg is not deterministic: %+v", d)
	}
}
