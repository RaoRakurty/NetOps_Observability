// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Iris reads device syslog through search_logs. Routine management sessions
// are about 96 % of a managed estate's syslog (lab, 2026-11-13): left in, the
// newest lines the model reads are all polls. The tool leaves the class out
// exactly as the Logs page does (post_filter only, never the scope filter),
// counts it, and says so; include_routine=true keeps it. §3a: only the
// caller's own controller addresses classify, and the tenant clause is the
// same either way.

import (
	"context"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/logroutine"
)

const irisRoutineReply = `{"hits":{"total":{"value":1},"hits":[{"_source":{"message":"%BGP-5-ADJCHANGE: neighbor 10.0.0.2 Down","timestamp":"2026-11-13T00:00:00Z","host":"acme-core"}}]},` +
	`"aggregations":{"cx_routine_mgmt":{"doc_count":1234}}}`

func TestIrisLogSearchLeavesOutRoutineMgmt(t *testing.T) {
	_, bodies := fakeOS(t, irisRoutineReply)
	s := routineServer(t)
	claims := acme()
	d := aiDataSource{srv: s, ctx: context.Background(), claims: claims}

	tr, err := d.ModuleQuery(context.Background(), s.aiPrincipal(claims), "search_logs", ai.ToolArgs{"window": "1h"})
	if err != nil {
		t.Fatal(err)
	}
	body := decodeStoreBody(t, (*bodies)[0])
	pf := jsonOf(body["post_filter"])
	for _, want := range []string{`"must_not"`, logroutine.RulePoll, logroutine.RuleSessionDetail, logroutine.RuleControllerSource, acmeCtl} {
		if !strings.Contains(pf, want) {
			t.Errorf("post_filter missing %q:\n%s", want, pf)
		}
	}
	if strings.Contains(pf, globexCtl) {
		t.Errorf("another tenant's controller classified acme's records (§3a): %s", pf)
	}
	b := queryBool(t, body)
	if strings.Contains(jsonOf(b["filter"]), "routine_mgmt") {
		t.Errorf("the routine class reached the scope filter: %s", jsonOf(b["filter"]))
	}
	if !strings.Contains(jsonOf(body["aggs"]), logroutine.AggName) {
		t.Errorf("no routine count: %s", jsonOf(body["aggs"]))
	}
	if len(tr.Items) != 1 {
		t.Fatalf("items = %+v", tr.Items)
	}
	if !strings.Contains(strings.Join(tr.Notes, " | "), "left out 1234 routine management-session lines") {
		t.Errorf("the tool did not say what it left out: %q", tr.Notes)
	}
	scopeOff := jsonOf(b["filter"])

	// Asked for: nothing filtered, still counted, and the scope is unchanged.
	tr, err = d.ModuleQuery(context.Background(), s.aiPrincipal(claims), "search_logs", ai.ToolArgs{"window": "1h", "include_routine": "true"})
	if err != nil {
		t.Fatal(err)
	}
	body = decodeStoreBody(t, (*bodies)[1])
	if _, has := body["post_filter"]; has {
		t.Errorf("include_routine=true still filtered: %s", jsonOf(body["post_filter"]))
	}
	if got := jsonOf(queryBool(t, body)["filter"]); got != scopeOff {
		t.Errorf("the tenant scope changed with the flag:\n off %s\n on  %s", scopeOff, got)
	}
	if !strings.Contains(strings.Join(tr.Notes, " | "), "includes 1234 routine management-session lines") {
		t.Errorf("notes = %q", tr.Notes)
	}

	// Any other value is the default: left out.
	if _, err = d.ModuleQuery(context.Background(), s.aiPrincipal(claims), "search_logs", ai.ToolArgs{"window": "1h", "include_routine": "yes please"}); err != nil {
		t.Fatal(err)
	}
	if _, has := decodeStoreBody(t, (*bodies)[2])["post_filter"]; !has {
		t.Error("a non-true include_routine must leave the class out")
	}
}

// globex reads with its own controller, never acme's.
func TestIrisLogSearchRoutineUsesTheCallersControllers(t *testing.T) {
	_, bodies := fakeOS(t, irisRoutineReply)
	s := routineServer(t)
	claims := globex()
	d := aiDataSource{srv: s, ctx: context.Background(), claims: claims}
	if _, err := d.ModuleQuery(context.Background(), s.aiPrincipal(claims), "search_logs", ai.ToolArgs{"window": "1h"}); err != nil {
		t.Fatal(err)
	}
	pf := jsonOf(decodeStoreBody(t, (*bodies)[0])["post_filter"])
	if !strings.Contains(pf, globexCtl) || strings.Contains(pf, acmeCtl) {
		t.Errorf("globex's routine class must name only globex's controller: %s", pf)
	}
}
