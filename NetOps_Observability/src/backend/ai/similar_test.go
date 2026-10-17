// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const simCase = "11111111-2222-4333-8444-555555555555"

func TestFindSimilarIncidentsIsHistoryNeverASignal(t *testing.T) {
	tool := similarIncidentsTool{deps: tsDeps()}
	tr, err := tool.Run(context.Background(), tenantA(), ToolArgs{"correlation_id": simCase})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Items) != 1 || !strings.HasPrefix(tr.Items[0].CitationID, "similar:") || tr.Items[0].Kind != "history" {
		t.Fatalf("items: %+v", tr.Items)
	}
	if !strings.Contains(tr.Items[0].Text, "not confirmation") {
		t.Fatalf("every match must say it is context: %q", tr.Items[0].Text)
	}
	if len(tr.Signals) != 0 {
		t.Fatalf("history must never steer an investigation: %v", tr.Signals)
	}
	if ToolStatementClass("find_similar_incidents") != ClassHistorical {
		t.Fatal("the tool's evidence is HISTORICAL")
	}
}

func TestFindSimilarIncidentsRefusesAndIsolates(t *testing.T) {
	tool := similarIncidentsTool{deps: tsDeps()}
	for _, args := range []ToolArgs{{}, {"correlation_id": simCase, "window": "7d"}, {"correlation_id": "x\ny"}} {
		if _, err := tool.Run(context.Background(), tenantA(), args); err == nil {
			t.Errorf("%v must be refused", args)
		}
	}
	b := tenantA()
	b.Tenant = "t-b"
	if _, err := tool.Run(context.Background(), b, ToolArgs{"correlation_id": simCase}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant's case must be NOT FOUND: %v", err)
	}
	if _, ok := ContractFor("find_similar_incidents"); !ok {
		t.Fatal("the tool needs a contract")
	}
}
