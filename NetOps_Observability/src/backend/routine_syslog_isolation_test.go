// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// routine_syslog_isolation_test.go — CLAUDE.md §3a rule 5 for the routine
// management-session syslog families (tracker 410): the originals
// (netops-syslogroutine-*) are a per-tenant log family like netops-syslog-*,
// and every syslog read names them through the ONE chokepoint
// (oslog.TenantIndexPattern via logsScope / the Iris log tool). Proven here:
//   - a scoped tenant's resolved syslog index names its own + untagged routine
//     indices and never another tenant's;
//   - as_tenant into another org is ignored for a scoped principal;
//   - over a fake OpenSearch that answers ONLY for the indices actually named,
//     tenant B's routine document never reaches tenant A's Iris log search.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
)

func TestRoutineSyslogLogsScopeIsTheCallersOwn(t *testing.T) {
	s := claimFixtureServer(t)
	for _, tc := range []struct {
		claims      jwtClaims
		own, foreig string
	}{
		{acmeClaims(), "acme", "globex"},
		{globexClaims(), "globex", "acme"},
	} {
		r := req(http.MethodGet, "/api/logs/search", "", tc.claims)
		index, _, _, deny, forbidden := s.logsScope(r, "syslog")
		if deny || forbidden {
			t.Fatalf("%s: unexpected deny/forbidden", tc.own)
		}
		if !strings.Contains(index, "netops-syslogroutine-"+tc.own+"-*") || !strings.Contains(index, "netops-syslogroutine-untagged-*") {
			t.Errorf("%s: syslog read does not name its own routine family: %q", tc.own, index)
		}
		if strings.Contains(index, tc.foreig) {
			t.Errorf("CROSS-TENANT LEAK: %s's syslog index names %s: %q", tc.own, tc.foreig, index)
		}
	}
	// as_tenant never widens a scoped principal into another org.
	sneaky := acmeClaims()
	sneaky.ActingTenant = "globex"
	index, _, _, _, _ := s.logsScope(req(http.MethodGet, "/api/logs/search", "", sneaky), "syslog")
	if strings.Contains(index, "globex") {
		t.Errorf("as_tenant widened acme into globex: %q", index)
	}
}

// The fake answers each _search with the documents of the indices the request
// NAMES — exactly the storage-layer isolation per-tenant indices give. Globex's
// routine document can only come back if the path names globex's index.
func TestRoutineSyslogForeignDocNeverReachesIrisLogSearch(t *testing.T) {
	var paths []string
	osSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "netops-syslogroutine-globex-") {
			_, _ = w.Write([]byte(`{"hits":{"total":{"value":1},"hits":[{"_index":"netops-syslogroutine-globex-2026.11.19","_source":{"timestamp":"2026-11-19T01:00:00Z","host":"globex-edge","message":"GLOBEX-ROUTINE-SECRET","tenant_id":"globex"}}]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":0},"hits":[]}}`))
	}))
	defer osSrv.Close()
	t.Setenv("OPENSEARCH_URL", osSrv.URL)
	s := claimFixtureServer(t)
	d := aiDataSource{srv: s, ctx: context.Background(), scope: "acme", claims: acmeClaims()}
	out, err := d.moduleSearchLogs(ai.Principal{Tenant: "acme"}, ai.ToolArgs{"query": "*", "include_routine": "true"})
	if err != nil {
		t.Fatalf("moduleSearchLogs: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("the Iris log tool sent no search")
	}
	for _, p := range paths {
		if strings.Contains(p, "globex") {
			t.Errorf("CROSS-TENANT LEAK: acme's log search named %q", p)
		}
		if strings.Contains(p, "_search") && !strings.Contains(p, "netops-syslogroutine-acme-") {
			t.Errorf("acme's syslog search does not cover its routine family: %q", p)
		}
	}
	if rendered := fmt.Sprintf("%+v", out); strings.Contains(rendered, "GLOBEX-ROUTINE-SECRET") {
		t.Errorf("CROSS-TENANT LEAK: globex's routine document reached acme: %s", rendered)
	}
}
