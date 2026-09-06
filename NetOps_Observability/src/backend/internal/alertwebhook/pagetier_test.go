// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alertwebhook

// pagetier_test.go — the mechanical pin under the "four conditions, nine rules"
// comment in hostroute.go.
//
// The routing contract of this package is that ONLY a server-controlled
// `tier: page` label wakes a human. That claim is only as good as the rule
// files it describes, and a comment cannot enforce anything. This test reads
// the SHIPPED rule files and fails when the count drifts, so the next person to
// add a page rule is forced to decide — and to record — whether they added a
// new lane for one of the four approved conditions or a FIFTH condition the
// owner never approved.
//
// Parsing is a deliberate line scan (stdlib only, §6: no YAML module). The
// property under test is textual — "how many rules carry this label" — and a
// grep-shaped test is a test the next reader can reproduce with grep.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rule files live in src/config; this package is src/backend/internal/alertwebhook.
// Same relative-path convention as alerts/rules_file_test.go, three levels
// deeper.
const (
	scaleSLORulesPath = "../../../config/rules-scale-slo.yaml"
	engineRulesPath   = "../../../config/rules.yaml"
)

// pageRules returns the names of the rules in a rule file whose labels carry
// `tier: page`, in file order. Comment lines are ignored — the tier block in
// rules-scale-slo.yaml documents the label in prose and must not be counted.
func pageRules(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// Skip, never fail: the backend module is built and tested on its own
		// in contexts where the sibling config tree is not checked out.
		t.Skipf("rule file not reachable at %s (%v) — nothing to pin here", path, err)
	}
	defer func() { _ = f.Close() }()

	var (
		names   []string
		current = "(before the first alert)"
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "- alert:"); ok {
			current = strings.TrimSpace(rest)
		}
		if strings.Contains(line, "tier: page") {
			names = append(names, current)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return names
}

// TestPageTierRuleCountMatchesTheComment pins both halves of the hostroute.go
// claim: rules-scale-slo.yaml carries exactly pageRuleCount page rules, and
// rules.yaml carries none.
func TestPageTierRuleCountMatchesTheComment(t *testing.T) {
	got := pageRules(t, scaleSLORulesPath)
	if len(got) != pageRuleCount {
		t.Fatalf("%s has %d rules labelled `tier: page`, but hostroute.go's pageRuleCount says %d.\n"+
			"Rules found: %v\n"+
			"The owner ruling (CLAUDE.md \"Monitoring\") is FOUR page CONDITIONS: an engine consumer not\n"+
			"consuming, ingest silent when it should not be, storage refusing writes, the alerting\n"+
			"heartbeat missing. If the new rule is another lane/vantage point on one of those four,\n"+
			"update pageRuleCount and its enumeration in hostroute.go. If it is a FIFTH condition, it\n"+
			"needs an owner decision before it wakes anyone.", scaleSLORulesPath, len(got), pageRuleCount, got)
	}
}

// TestEngineRulesFileCarriesNoPageTier pins the second half of the comment: the
// page tier is vmalert-only on purpose, so that it keeps firing when the api —
// the other reader of rules.yaml, and the process most of these rules are ABOUT
// — is the thing that is down.
func TestEngineRulesFileCarriesNoPageTier(t *testing.T) {
	if got := pageRules(t, engineRulesPath); len(got) != 0 {
		t.Fatalf("%s carries `tier: page` rules %v — the page tier belongs in %s only, "+
			"so it survives the api being the failure", engineRulesPath, got, scaleSLORulesPath)
	}
}

// TestPageRuleNamesAreTheFourApprovedConditions maps the rules onto the four
// conditions by name, so a rename or an unclassified addition is caught with a
// message that says WHICH condition lost its rule — a bare count cannot.
func TestPageRuleNamesAreTheFourApprovedConditions(t *testing.T) {
	condition := map[string]string{
		"CorrelationConsumerDead":  "1. an engine consumer is not consuming",
		"CorrelationLagGrowing":    "1. an engine consumer is not consuming",
		"RouterConsumerDead":       "1. an engine consumer is not consuming",
		"RouterConsumerLagGrowing": "1. an engine consumer is not consuming",
		"CorrConsumerNotRunning":   "1. an engine consumer is not consuming",
		"CorrConsumerRestartLoop":  "1. an engine consumer is not consuming",
		"IngestPipelineSilent":     "2. ingest silent when it should not be",
		"ClickHouseWritesRejected": "3. storage refusing writes",
		"AlertDeliveryBroken":      "4. the alerting heartbeat missing",
	}
	seen := map[string]bool{}
	for _, name := range pageRules(t, scaleSLORulesPath) {
		cond, ok := condition[name]
		if !ok {
			t.Errorf("page rule %q maps to NO approved page condition. Either it is a new lane on one "+
				"of the four (add it here and to the hostroute.go enumeration) or it pages on a FIFTH "+
				"condition, which is an owner decision — see CLAUDE.md \"Monitoring\".", name)
			continue
		}
		seen[cond] = true
	}
	for _, cond := range condition {
		if !seen[cond] {
			t.Errorf("no `tier: page` rule implements page condition %q any more — the phone has gone "+
				"quiet for a condition the owner approved paging on", cond)
		}
	}
}
