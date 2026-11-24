// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adaptivecard

import (
	"strings"
	"testing"
)

func card(extra map[string]any) map[string]any {
	c := map[string]any{
		"type": "AdaptiveCard", "version": "1.4",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"body": []any{
			map[string]any{"type": "TextBlock", "text": "BGP down", "weight": "Bolder", "size": "Medium", "wrap": true, "color": "attention"},
			map[string]any{"type": "FactSet", "facts": []any{map[string]any{"title": "Severity", "value": "critical"}}},
		},
		"actions": []any{map[string]any{"type": "Action.OpenUrl", "title": "Open in Correlix", "url": "https://correlix.example/#/x"}},
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func mustNew(t *testing.T, ext ...HostExtension) *Validator {
	t.Helper()
	v, err := New14(ext...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAValidCardPasses(t *testing.T) {
	if errs := mustNew(t).ValidateCard(card(nil)); errs != nil {
		t.Fatalf("valid card refused: %v", errs)
	}
}

// The validator must say no, or a broken validator would pass every card.
func TestTheValidatorRefusesWhatTheSchemaRefuses(t *testing.T) {
	v := mustNew(t, TeamsHostExtensions...)
	cases := map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"unknown root property": {func(c map[string]any) { c["themeColor"] = "FF0000" }, `property "themeColor" is not allowed`},
		"wrong card type":       {func(c map[string]any) { c["type"] = "MessageCard" }, "is not one of"},
		"text block without text": {func(c map[string]any) {
			c["body"] = []any{map[string]any{"type": "TextBlock", "wrap": true}}
		}, "matches none of the allowed forms"},
		"colour outside the palette": {func(c map[string]any) {
			c["body"] = []any{map[string]any{"type": "TextBlock", "text": "x", "color": "red"}}
		}, "matches none of the allowed forms"},
		"fact without value": {func(c map[string]any) {
			c["body"] = []any{map[string]any{"type": "FactSet", "facts": []any{map[string]any{"title": "a"}}}}
		}, "matches none of the allowed forms"},
		"unknown element": {func(c map[string]any) {
			c["body"] = []any{map[string]any{"type": "Marquee", "text": "x"}}
		}, "matches none of the allowed forms"},
		"open-url without url": {func(c map[string]any) {
			c["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "x"}}
		}, "matches none of the allowed forms"},
		"wrap is not a boolean": {func(c map[string]any) {
			c["body"] = []any{map[string]any{"type": "TextBlock", "text": "x", "wrap": "yes"}}
		}, "matches none of the allowed forms"},
	}
	for name, tc := range cases {
		c := card(nil)
		tc.mutate(c)
		errs := v.ValidateCard(c)
		if errs == nil || !strings.Contains(strings.Join(errs, "\n"), tc.want) {
			t.Errorf("%s: want an error containing %q, got %v", name, tc.want, errs)
		}
	}
}

// msteams is a documented Teams host extension, not part of the core schema:
// refused by the bare schema, accepted only where Teams documents it.
func TestTheTeamsHostExtensionIsAllowedOnlyAtTheRoot(t *testing.T) {
	withTeams := card(map[string]any{"msteams": map[string]any{"width": "Full"}})
	if errs := mustNew(t).ValidateCard(withTeams); errs == nil {
		t.Fatal("the core schema must refuse msteams without the host extension")
	}
	if errs := mustNew(t, TeamsHostExtensions...).ValidateCard(withTeams); errs != nil {
		t.Fatalf("msteams at the root must pass with the Teams extension: %v", errs)
	}
	nested := card(nil)
	nested["body"] = []any{map[string]any{"type": "TextBlock", "text": "x", "msteams": map[string]any{}}}
	if errs := mustNew(t, TeamsHostExtensions...).ValidateCard(nested); errs == nil {
		t.Fatal("msteams is a root-only extension; on an element it must be refused")
	}
}

func TestEveryKeywordInTheVendoredSchemaIsUnderstood(t *testing.T) {
	v := mustNew(t)
	// A schema node with a keyword this interpreter does not implement must be
	// reported, never silently passed.
	var errs []string
	v.check(map[string]any{"oneOf": []any{}}, "x", "", &errs)
	if len(errs) == 0 || !strings.Contains(errs[0], `"oneOf" is not supported`) {
		t.Fatalf("an unknown keyword must be an error, got %v", errs)
	}
	// And the vendored schema itself uses none: validating a card walks most
	// of it; any unsupported keyword would surface as an error above.
	if errs := v.ValidateCard(card(nil)); errs != nil {
		t.Fatalf("vendored schema uses an unsupported keyword or the card is invalid: %v", errs)
	}
}
