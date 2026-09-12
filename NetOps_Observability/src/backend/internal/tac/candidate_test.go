// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// candidate_test.go — the properties the signature-candidate loop must hold.
//
//   1. §7 is not relaxed for a candidate: a config/restart/daemon command is
//      refused BY NAME, so the research corpus cannot be poisoned through this
//      door;
//   2. a class outside the taxonomy is EXPORTED as `proposed_class: true` —
//      what the merge script demands of one — and `proposed` is derived from
//      the taxonomy, never claimed by a client;
//   3. everything stored is redacted;
//   4. the export is the exact shape scripts/tac-merge-research.py consumes,
//      and the checked-in fixture the python test merges is regenerated here so
//      the two sides cannot drift;
//   5. nothing here changes the shipped catalogue.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func candCatalog(t *testing.T) (*Catalog, *TemplateValidator) {
	t.Helper()
	cat, err := Default()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	v, verr := NewTemplateValidator(cat)
	if verr != nil {
		t.Fatalf("validator: %v", verr)
	}
	return cat, v
}

func goodCandidate() Candidate {
	return Candidate{
		Dialect: "cisco-iosxe",
		ClassID: "bgp-session",
		Title:   "BGP session stuck in Idle after a policy change",
		Symptoms: []string{
			"Neighbor never reaches Established in show ip bgp summary",
		},
		LogSignatures: []string{"%BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down BGP Notification sent"},
		LikelyCauses:  []string{"An inbound route-map references a prefix-list that does not exist"},
		Commands: []CandidateCommand{
			{Intent: "bgp.summary", Command: "show ip bgp summary"},
			{Intent: "bgp.neighbor.detail", Command: "show ip bgp neighbors"},
		},
		TACFirstLook: "Read the notification subcode before anything else.",
		Sources:      []CandidateSource{{Title: "Cisco BGP configuration guide", URL: "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/xe-17/irg-xe-17-book.html"}},
		Answer:       "TAC confirmed the peer was refused by an empty prefix-list.",
		FromIncident: "inc-77",
	}
}

func TestCandidateRefusesAForbiddenCommandByName(t *testing.T) {
	cat, v := candCatalog(t)
	in := goodCandidate()
	in.Commands = append(in.Commands, CandidateCommand{Intent: "bgp.clear", Command: "clear ip bgp *"})
	_, lines, err := ValidateCandidate(in, cat, v)
	if err == nil {
		t.Fatal("a state-clearing command was accepted into a candidate — §7 is not relaxed for a proposal")
	}
	var named bool
	for _, lv := range lines {
		if !lv.OK && strings.Contains(lv.Command, "clear ip bgp") {
			named = true
			if lv.Family == "" || lv.Rule == "" {
				t.Fatalf("the refusal must name the family and the rule, not just say invalid: %+v", lv)
			}
		}
	}
	if !named {
		t.Fatalf("the refused line was not named back to the operator: %+v", lines)
	}
}

func TestCandidateProposedClassIsDerivedNotClaimed(t *testing.T) {
	cat, v := candCatalog(t)

	// A class that IS in the taxonomy is never marked proposed, whatever the
	// client sent.
	known := goodCandidate()
	known.Proposed = true
	out, _, err := ValidateCandidate(known, cat, v)
	if err != nil {
		t.Fatalf("valid candidate refused: %v", err)
	}
	if out.Proposed {
		t.Fatal("a class that exists in the taxonomy was marked proposed because the CLIENT said so")
	}

	// One that is not gets marked, so the export can carry proposed_class: true.
	novel := goodCandidate()
	novel.ClassID = "bgp-graceful-restart-stall"
	out2, _, err2 := ValidateCandidate(novel, cat, v)
	if err2 != nil {
		t.Fatalf("a novel class must be allowed as a PROPOSAL: %v", err2)
	}
	if !out2.Proposed {
		t.Fatal("a class outside the taxonomy must be exported as proposed_class: true, or the merge script refuses it")
	}
}

func TestCandidateRefusesTheGenericFallbackAndANonHTTPSSource(t *testing.T) {
	cat, v := candCatalog(t)
	gen := goodCandidate()
	gen.ClassID = GenericClassID
	if _, _, err := ValidateCandidate(gen, cat, v); err == nil {
		t.Fatal("`generic` is what \"nothing matched\" means; a detection rule on it would erase the honest answer")
	}
	insecure := goodCandidate()
	insecure.Sources = []CandidateSource{{URL: "http://vendor.example/kb/1"}}
	if _, _, err := ValidateCandidate(insecure, cat, v); err == nil {
		t.Fatal("a citation must be an https link — the merge script refuses anything else")
	}
}

func TestCandidateRedactsAndFlattensEverythingStored(t *testing.T) {
	cat, v := candCatalog(t)
	in := goodCandidate()
	in.Answer = "TAC says: the config held\nsnmp-server community s3cr3t-community RO\nand that was the cause"
	in.Symptoms = []string{"peer down\nusername admin password 0 hunter2"}
	out, _, err := ValidateCandidate(in, cat, v)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	joined := out.Answer + " " + strings.Join(out.Symptoms, " ")
	for _, leak := range []string{"s3cr3t-community", "hunter2"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("a candidate stored %q — the TAC redactor applies to everything here", leak)
		}
	}
	if strings.ContainsAny(joined, "\n\r") {
		t.Fatalf("a newline survived into a stored scalar; the research format is line-oriented:\n%q", joined)
	}
}

func TestExportIsTheResearchShapeAndNeverTouchesTheCatalogue(t *testing.T) {
	cat, v := candCatalog(t)
	before := len(cat.Classes())

	c1, _, err := ValidateCandidate(goodCandidate(), cat, v)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	c1.ID = "cand-1"
	novel := goodCandidate()
	novel.ClassID = "bgp-graceful-restart-stall"
	novel.Title = "Graceful restart never completes after a supervisor switchover"
	c2, _, err2 := ValidateCandidate(novel, cat, v)
	if err2 != nil {
		t.Fatalf("refused: %v", err2)
	}
	c2.ID = "cand-2"

	body, eerr := ExportResearch("cisco-iosxe", []Candidate{c2, c1}, time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC))
	if eerr != nil {
		t.Fatalf("export: %v", eerr)
	}
	for _, want := range []string{
		"vendor: 'cisco-iosxe'", "dialect: 'cisco-iosxe'", "issues:",
		"class: 'bgp-session'", "proposed_class: 'true'",
		"cmd: 'show ip bgp summary'", "intent: 'bgp.summary'",
		"candidate only",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("export is missing %q:\n%s", want, body)
		}
	}
	if len(cat.Classes()) != before {
		t.Fatal("exporting a candidate changed the shipped taxonomy — a candidate is never promoted")
	}

	// A rejected candidate is not carried out to a research file.
	c1.Status = CandidateRejected
	if _, err := ExportResearch("cisco-iosxe", []Candidate{c1}, time.Now()); err == nil {
		t.Fatal("a rejected candidate was exported")
	}
	// A dialect with nothing to say says so rather than emitting an empty doc.
	if _, err := ExportResearch("juniper-junos", []Candidate{c1, c2}, time.Now()); err == nil {
		t.Fatal("an export with no candidates for the dialect must refuse, not emit an issueless file")
	}
}

// TestExportFixtureMatchesTheCheckedInFile keeps the Go exporter and the python
// merge test on ONE artifact.
//
// tests/test_tac_merge_research.py runs the REAL merge script over this file.
// If the exporter changes shape and the fixture is not regenerated, the python
// side would keep proving something Correlix no longer emits — so this test
// fails until they agree. Run with -update to regenerate.
func TestExportFixtureMatchesTheCheckedInFile(t *testing.T) {
	cat, v := candCatalog(t)
	c1, _, err := ValidateCandidate(goodCandidate(), cat, v)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	c1.ID = "cand-fixture-1"
	novel := goodCandidate()
	novel.ClassID = "bgp-graceful-restart-stall"
	novel.Title = "Graceful restart never completes after a supervisor switchover"
	novel.LogSignatures = []string{"%BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down Graceful Restart timer expired"}
	novel.Commands = []CandidateCommand{{Intent: "bgp.summary", Command: "show ip bgp summary"}}
	c2, _, err2 := ValidateCandidate(novel, cat, v)
	if err2 != nil {
		t.Fatalf("refused: %v", err2)
	}
	c2.ID = "cand-fixture-2"

	body, eerr := ExportResearch("cisco-iosxe", []Candidate{c1, c2}, time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC))
	if eerr != nil {
		t.Fatalf("export: %v", eerr)
	}
	path := filepath.Join("testdata", "candidate-export.yaml")
	if os.Getenv("UPDATE_TAC_FIXTURE") == "1" {
		if werr := os.WriteFile(path, []byte(body), 0o644); werr != nil {
			t.Fatalf("write fixture: %v", werr)
		}
		return
	}
	have, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("read fixture (regenerate with UPDATE_TAC_FIXTURE=1): %v", rerr)
	}
	if string(have) != body {
		t.Fatalf("%s is out of date. The python merge test runs the real script over it, so a stale fixture "+
			"proves something Correlix no longer emits. Regenerate with UPDATE_TAC_FIXTURE=1 go test ./internal/tac/ "+
			"-run TestExportFixture.\n--- checked in ---\n%s\n--- exported now ---\n%s", path, have, body)
	}
}
