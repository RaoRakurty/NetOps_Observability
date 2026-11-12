// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// The router's own rules for casual NOC wording (phrasing eval, 2026-11-12).
// Written for the test, not copied from the eval's held-out slice (N-H3).
func TestClassifyCasualNOCWording(t *testing.T) {
	for q, want := range map[string]string{
		"is the wan on fire":                 "incident_list",
		"something on fire?":                 "incident_list",
		"anything going wrong at the moment": "incident_list",
		"what's up with things":              "current_state",
		"all ok?":                            "current_state",
		"we good?":                           "current_state",
		"health?":                            "current_state",
		"any trouble out there":              "current_state",
		"why does the biggest issue keep coming back": "top_incident",
		"who's hogging the bandwidth":                 "flow_analytics_summary",
		"what's chewing up the internet link":         "flow_analytics_summary",
		"status rn":                                   "capability", // not a lone "status": no rule claims it
	} {
		if got := Classify(q, nil).Intent; got != want {
			t.Errorf("Classify(%q) = %q, want %q", q, got, want)
		}
	}
	// Negative controls: the new rules must not capture these.
	for q, not := range map[string]string{
		"show the status page settings":            "current_state",
		"what does all good mean on the dashboard": "current_state",
		"explain the fire alarm integration":       "incident_list",
	} {
		if got := Classify(q, nil).Intent; got == not {
			t.Errorf("Classify(%q) must not be %q", q, not)
		}
	}
}

// "what do I check" asks for a method, not a listing: the data arm never takes it.
func TestWhatDoICheckIsDiagnostic(t *testing.T) {
	for _, q := range []string{"bgp down on edge-1 what do i check", "what should we look at first for packet loss"} {
		if !diagnosticCue.MatchString(q) {
			t.Errorf("%q must carry the diagnostic cue", q)
		}
	}
	if diagnosticCue.MatchString("check bgp on edge-1") {
		t.Error("an imperative check is a listing, not a diagnosis")
	}
}

// One strike per request: a model that timed out (or is overloaded, out of
// quota, retired) is skipped by every later call of the same request, and the
// skip reads as the first failure's class.
func TestOneStrikePerRequest(t *testing.T) {
	const m = "gemini-flash-latest"
	ctx, _ := WithModelNote(context.Background())
	if ModelStruck(ctx, "gemini", m) != nil {
		t.Fatal("nothing failed yet")
	}
	NoteModelFailed(ctx, "gemini", m, fmt.Errorf("wrapped: %w", context.DeadlineExceeded))
	err := ModelStruck(ctx, "gemini", m)
	var skip *ModelSkippedError
	if !errors.As(err, &skip) || skip.Provider != "gemini" || skip.Model != m {
		t.Fatalf("a struck model must be skipped: %v", err)
	}
	if ClassifyProviderError(err) != ProvTimeout || FallbackNoteFor(err) != NoteModelTimedOut {
		t.Fatalf("the skip must read as the first failure: %s / %q", ClassifyProviderError(err), FallbackNoteFor(err))
	}
	if ModelStruck(ctx, "openai", "gpt-4o-mini") != nil {
		t.Fatal("a strike is per model: another provider is still tried")
	}
	if ModelStruck(ctx, "gemini", "gemini-2.5-flash") != nil {
		t.Fatal("a strike is per model: the same provider's other model is still tried")
	}
	// The first failure is the one kept.
	NoteModelFailed(ctx, "gemini", m, &ProviderStatusError{Status: 503})
	if ClassifyProviderError(ModelStruck(ctx, "gemini", m)) != ProvTimeout {
		t.Fatal("the first failure is the reason")
	}
	// Classes that are about the call, not the model, never strike.
	for _, e := range []error{&ProviderStatusError{Status: 400}, &ProviderEmptyError{Provider: "x"}, context.Canceled, ErrBudgetExhausted, ErrProviderBreakerOpen, errors.New("decode")} {
		c, _ := WithModelNote(context.Background())
		NoteModelFailed(c, "p", "m", e)
		if ModelStruck(c, "p", "m") != nil {
			t.Errorf("%v (%s) must not strike", e, ClassifyProviderError(e))
		}
	}
	for _, e := range []error{&ProviderStatusError{Status: 503}, &ProviderStatusError{Status: 429}, &ProviderStatusError{Status: 401}, &ProviderStatusError{Status: 404}} {
		c, _ := WithModelNote(context.Background())
		NoteModelFailed(c, "p", "m", e)
		if ModelStruck(c, "p", "m") == nil {
			t.Errorf("%v (%s) must strike", e, ClassifyProviderError(e))
		}
	}
	// No note (a caller outside a request): nothing is remembered.
	NoteModelFailed(context.Background(), "p", "m", context.DeadlineExceeded)
	if ModelStruck(context.Background(), "p", "m") != nil {
		t.Fatal("no note, no strike")
	}
}

// Which failures are about the whole provider (2026-11-12): a refused key or
// an unreachable provider strikes every model of it; an overloaded, retired,
// rate-limited or slow model strikes only itself; and a SECOND model of the
// same provider timing out strikes the provider, so a provider that hangs on
// every model costs at most two waits in one request.
func TestStrikeScopeModelVersusProvider(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		providerWide bool
	}{
		{"key refused", &ProviderStatusError{Status: 401}, true},
		{"gemini bad key", &ProviderStatusError{Status: 400, Reason: "API_KEY_INVALID"}, true},
		{"unreachable", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"overloaded", &ProviderStatusError{Status: 503, Reason: "UNAVAILABLE"}, false},
		{"anthropic overloaded", &ProviderStatusError{Status: 529}, false},
		{"model retired", &ProviderStatusError{Status: 404, Reason: "NOT_FOUND"}, false},
		{"model quota", &ProviderStatusError{Status: 429, Reason: "RESOURCE_EXHAUSTED"}, false},
		{"slow", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		ctx, _ := WithModelNote(context.Background())
		NoteModelFailed(ctx, "gemini", "gemini-flash-latest", tc.err)
		if ModelStruck(ctx, "gemini", "gemini-flash-latest") == nil {
			t.Errorf("%s: the failed model must be struck", tc.name)
		}
		other := ModelStruck(ctx, "gemini", "gemini-2.5-flash")
		if tc.providerWide != (other != nil) {
			t.Errorf("%s: provider-wide=%v, other model struck=%v", tc.name, tc.providerWide, other != nil)
		}
		if tc.providerWide && ModelStruck(ctx, "gemini", "") == nil {
			t.Errorf("%s: the provider as a whole must read struck", tc.name)
		}
	}

	ctx, _ := WithModelNote(context.Background())
	NoteModelFailed(ctx, "gemini", "a", context.DeadlineExceeded)
	NoteModelFailed(ctx, "gemini", "a", context.DeadlineExceeded) // the same model again is still one model
	if ModelStruck(ctx, "gemini", "b") != nil {
		t.Fatal("one model timing out (twice) must not strike the provider")
	}
	NoteModelFailed(ctx, "gemini", "b", context.DeadlineExceeded)
	if ModelStruck(ctx, "gemini", "c") == nil {
		t.Fatal("two models of one provider timing out must strike the provider")
	}
	if ModelStruck(ctx, "openai", "x") != nil {
		t.Fatal("another provider is untouched")
	}

	// 503s on two models do not strike the provider: each answered, quickly.
	ctx, _ = WithModelNote(context.Background())
	NoteModelFailed(ctx, "gemini", "a", &ProviderStatusError{Status: 503})
	NoteModelFailed(ctx, "gemini", "b", &ProviderStatusError{Status: 503})
	if ModelStruck(ctx, "gemini", "c") != nil {
		t.Fatal("overloaded models are per model")
	}
}
