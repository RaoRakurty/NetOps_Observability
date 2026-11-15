// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

// live.go — the LIVE model leg of Incident Replay (tracker 337 N-H2).
//
// The offline leg (ScriptedLeg) answers every model call with the case's
// scripted reply, so it shows what the guards do with a given reply. The live
// leg puts the same frozen incident to a REAL provider, so a change of model,
// prompt, tool contract, runbook or engine output is judged on what a model
// actually says over the same evidence. Everything else is identical: the same
// frozen seams, the same answer path, the same report, so `irisreplay compare
// scripted.json live.json` names what the live model changed.
//
// SEPARATELY GATED. Nothing here runs unless an operator asks for it on the
// command line (`run --live`) or runs the build-tagged test (nlqmodeleval);
// default CI never compiles a live call. The key comes ONLY from the process
// environment of that run (NLQ_EVAL_PROVIDER / NLQ_EVAL_API_KEY /
// NLQ_EVAL_MODEL — the convention every live model eval in this repo shares).
// It is never a flag (a flag lands in shell history and `ps`), never read from
// the platform's sealed provider settings, and never written into a report:
// the leg's Name carries the provider and model only.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"netops/backend/ai"
)

// Environment variables the live leg reads. Shared with the planner and NL
// query live evals, so one key setup runs every live model eval.
const (
	EnvLiveProvider = "NLQ_EVAL_PROVIDER"
	EnvLiveKey      = "NLQ_EVAL_API_KEY"
	EnvLiveModel    = "NLQ_EVAL_MODEL"
)

// ErrLiveNotConfigured is returned when the live leg is asked for without a
// provider and a key in the environment.
var ErrLiveNotConfigured = errors.New("the live leg needs " + EnvLiveProvider + " and " + EnvLiveKey +
	" in this process's environment (a key is never taken from a flag or from the platform's settings)")

// providerCall is the provider seam: ai.CallProviderUsage in production, a
// fake in tests (no test here reaches a provider).
type providerCall func(ctx context.Context, provider, key, model, system string, msgs []ai.ChatMessage) (ai.Completion, error)

// LiveLeg answers every model call of a case with a real provider.
type LiveLeg struct {
	provider, key, model string
	call                 providerCall
}

// LiveLegFromEnv builds the live leg from env (os.Getenv in production). The
// provider name is normalised ("chatgpt" → "openai"); an unknown provider is
// refused before any case runs.
func LiveLegFromEnv(env func(string) string) (*LiveLeg, error) {
	if env == nil {
		env = os.Getenv
	}
	rawProvider, key := strings.TrimSpace(env(EnvLiveProvider)), strings.TrimSpace(env(EnvLiveKey))
	if rawProvider == "" || key == "" {
		return nil, ErrLiveNotConfigured
	}
	provider := ai.NormalizeProvider(rawProvider)
	if provider == "" {
		return nil, fmt.Errorf("%s=%q is not a provider this build knows (openai, gemini, anthropic)", EnvLiveProvider, rawProvider)
	}
	return &LiveLeg{provider: provider, key: key, model: strings.TrimSpace(env(EnvLiveModel)), call: ai.CallProviderUsage}, nil
}

// Name implements ModelLeg. It names the provider and model, never the key;
// it is recorded in the report and the fingerprint, so a model change moves the
// fingerprint and the comparison names it.
func (l *LiveLeg) Name() string {
	model := l.model
	if model == "" {
		model = "provider-default"
	}
	return "live:" + l.provider + "/" + model
}

// Client implements ModelLeg. A case that scripts a provider outage still
// replays as an outage: the outage path is what that case measures, and the
// live leg must not turn it into a model answer.
func (l *LiveLeg) Client(c *Case) (ai.LLMClient, error) {
	if c.ProviderDown {
		return ai.MockLLM{Err: errProviderDown}, nil
	}
	return &liveLLM{leg: l}, nil
}

// liveLLM is one case's provider client.
type liveLLM struct{ leg *LiveLeg }

func (m *liveLLM) complete(ctx context.Context, system string, msgs []ai.LLMMessage) (ai.Completion, error) {
	cm := make([]ai.ChatMessage, 0, len(msgs))
	for _, x := range msgs {
		cm = append(cm, ai.ChatMessage(x))
	}
	return m.leg.call(ctx, m.leg.provider, m.leg.key, m.leg.model, system, cm)
}

// Complete implements ai.LLMClient.
func (m *liveLLM) Complete(ctx context.Context, system string, msgs []ai.LLMMessage) (string, string, error) {
	c, err := m.complete(ctx, system, msgs)
	return c.Text, m.leg.provider, err
}

// providerUsage reports the provider's OWN token accounting for one call.
// recordingLLM uses it when the case scripts no usage, so the live leg's cost
// section is the provider's numbers (or censored when it reported none),
// never an estimate.
func (m *liveLLM) providerUsage(ctx context.Context, system string, msgs []ai.LLMMessage) (string, string, ai.TokenUsage, error) {
	c, err := m.complete(ctx, system, msgs)
	return c.Text, m.leg.provider, c.Usage, err
}

// usageReporter is implemented by a leg client that carries real usage. It is
// package-private on purpose: only the live leg's client reports it, so the
// scripted leg's accounting (case-stated usage or none) is unchanged.
type usageReporter interface {
	providerUsage(ctx context.Context, system string, msgs []ai.LLMMessage) (string, string, ai.TokenUsage, error)
}
