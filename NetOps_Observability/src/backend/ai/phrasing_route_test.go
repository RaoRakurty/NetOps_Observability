// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"fmt"
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

// One strike per request: a provider that timed out (or is down, out of
// quota, refusing the key) is skipped by every later call of the same request,
// and the skip reads as the first failure's class.
func TestOneStrikePerRequest(t *testing.T) {
	ctx, _ := WithModelNote(context.Background())
	if ModelStruck(ctx, "gemini") != nil {
		t.Fatal("nothing failed yet")
	}
	NoteModelFailed(ctx, "gemini", fmt.Errorf("wrapped: %w", context.DeadlineExceeded))
	err := ModelStruck(ctx, "gemini")
	var skip *ModelSkippedError
	if !errors.As(err, &skip) || skip.Provider != "gemini" {
		t.Fatalf("a struck provider must be skipped: %v", err)
	}
	if ClassifyProviderError(err) != ProvTimeout || FallbackNoteFor(err) != NoteModelTimedOut {
		t.Fatalf("the skip must read as the first failure: %s / %q", ClassifyProviderError(err), FallbackNoteFor(err))
	}
	if ModelStruck(ctx, "openai") != nil {
		t.Fatal("a strike is per provider: another provider is still tried")
	}
	// The first failure is the one kept.
	NoteModelFailed(ctx, "gemini", &ProviderStatusError{Status: 503})
	if ClassifyProviderError(ModelStruck(ctx, "gemini")) != ProvTimeout {
		t.Fatal("the first failure is the reason")
	}
	// Classes that are about the call, not the provider, never strike.
	for _, e := range []error{&ProviderStatusError{Status: 400}, &ProviderEmptyError{Provider: "x"}, context.Canceled, ErrBudgetExhausted, ErrProviderBreakerOpen, errors.New("decode")} {
		c, _ := WithModelNote(context.Background())
		NoteModelFailed(c, "p", e)
		if ModelStruck(c, "p") != nil {
			t.Errorf("%v (%s) must not strike", e, ClassifyProviderError(e))
		}
	}
	for _, e := range []error{&ProviderStatusError{Status: 503}, &ProviderStatusError{Status: 429}, &ProviderStatusError{Status: 401}, &ProviderStatusError{Status: 404}} {
		c, _ := WithModelNote(context.Background())
		NoteModelFailed(c, "p", e)
		if ModelStruck(c, "p") == nil {
			t.Errorf("%v (%s) must strike", e, ClassifyProviderError(e))
		}
	}
	// No note (a caller outside a request): nothing is remembered.
	NoteModelFailed(context.Background(), "p", context.DeadlineExceeded)
	if ModelStruck(context.Background(), "p") != nil {
		t.Fatal("no note, no strike")
	}
}
