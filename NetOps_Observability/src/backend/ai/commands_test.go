// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import "testing"

// A slash command and its natural-language equivalent must converge on the SAME
// intent — the core requirement of the command system (HLD §5, §19.7).
func TestSlashAndNaturalLanguageConverge(t *testing.T) {
	cases := []struct {
		cmd, nl string
	}{
		{"/status", "what is going on right now"},
		{"/flows", "show me the top talkers"},
		{"/telemetry", "any metric anomalies?"},
		{"/integrations", "are my integrations healthy"},
		{"/playbook bgp flap", "how do I troubleshoot a bgp flap"},
		{"/history", "what happened overnight"},
		{"/recap last 4 hours", "summarize the last 4 hours"},
	}
	for _, c := range cases {
		q, _, ok := ResolveCommand(c.cmd)
		if !ok {
			t.Errorf("%q not resolved", c.cmd)
			continue
		}
		viaCmd := Classify(q, nil).Intent
		viaNL := Classify(c.nl, nil).Intent
		if viaCmd != viaNL {
			t.Errorf("%q→%q (intent %q) but NL %q→intent %q — must converge", c.cmd, q, viaCmd, c.nl, viaNL)
		}
	}
}

func TestResolveCommandAliasesAndArgs(t *testing.T) {
	// Alias resolves to the same command.
	if q, c, ok := ResolveCommand("/now"); !ok || c.Command != "/status" || q == "" {
		t.Errorf("/now should alias to /status: %q %q %v", q, c.Command, ok)
	}
	// Trailing text is appended to the canonical phrasing.
	q, _, ok := ResolveCommand("/playbook ospf neighbor down")
	if !ok || q != "how do I troubleshoot ospf neighbor down" {
		t.Errorf("playbook arg passthrough wrong: %q", q)
	}
	// /help has the help intent (handled specially by the gateway).
	if _, c, ok := ResolveCommand("/help"); !ok || c.Intent != "help" {
		t.Errorf("/help should resolve with intent 'help'")
	}
	// Non-command and unknown command.
	if _, _, ok := ResolveCommand("what is going on"); ok {
		t.Error("plain text must not resolve as a command")
	}
	if _, _, ok := ResolveCommand("/bogus"); ok {
		t.Error("unknown command must not resolve")
	}
}

func TestSuggestCommands(t *testing.T) {
	if all := SuggestCommands(""); len(all) != len(commands) {
		t.Errorf("empty query should return all %d commands, got %d", len(commands), len(all))
	}
	if hits := SuggestCommands("/flow"); len(hits) == 0 || hits[0].Command != "/flows" {
		t.Errorf("'/flow' should suggest /flows, got %v", hits)
	}
	if hits := SuggestCommands("ticket"); len(hits) == 0 {
		t.Error("'ticket' should match the ITSM command via its description/alias")
	}
}
