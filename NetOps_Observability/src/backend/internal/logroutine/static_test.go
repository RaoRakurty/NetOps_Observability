// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const staticFixture = "../../../../tests/fixtures/logroutine/static.json"

type staticCase struct {
	Name    string            `json:"name"`
	Record  map[string]string `json:"record"`
	Routine bool              `json:"routine"`
}

func loadStaticCases(t *testing.T) []staticCase {
	t.Helper()
	b, err := os.ReadFile(staticFixture)
	if err != nil {
		t.Fatalf("read %s: %v", staticFixture, err)
	}
	var f struct {
		Cases []staticCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("decode %s: %v", staticFixture, err)
	}
	if len(f.Cases) < 10 {
		t.Fatalf("the shared fixture has only %d cases — the parity check would be thin", len(f.Cases))
	}
	return f.Cases
}

// Tracker 410: the Go half of the write-time parity check. The router's VRL
// runs the same cases (tests/test_syslog_routine_split.py).
func TestStaticRoutineMatchesTheSharedFixture(t *testing.T) {
	for _, c := range loadStaticCases(t) {
		if got := StaticRoutine(c.Record); got != c.Routine {
			t.Errorf("%s: StaticRoutine(%v) = %v, want %v", c.Name, c.Record, got, c.Routine)
		}
	}
}

// Every record the write-time rule calls routine is ALSO matched by the
// read-time Clause's rules (the write rule is a strict subset: it may keep a
// routine record in the main family, never move a non-routine one out). This
// is checked structurally: the write rule uses only Clause's address-free
// vocabularies, and every one of them is rendered into Clause.
func TestStaticRoutineIsASubsetOfClause(t *testing.T) {
	clause, err := json.Marshal(Clause(Sources{}))
	if err != nil {
		t.Fatal(err)
	}
	s := string(clause)
	types, prefixes, failure := StaticLists()
	for _, v := range append(append(append([]string{}, types...), prefixes...), failure...) {
		if !strings.Contains(s, v) {
			t.Errorf("the write-time rule uses %q but the read-time Clause does not render it", v)
		}
	}
	for _, v := range []string{`"snmp"`, `"snmp_"`, `"` + Category + `"`, RulePoll, RuleSessionDetail} {
		if !strings.Contains(s, v) {
			t.Errorf("Clause no longer carries %s — the write-time rule would drift from it", v)
		}
	}
}
