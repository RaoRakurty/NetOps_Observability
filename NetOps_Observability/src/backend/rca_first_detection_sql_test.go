// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_first_detection_sql_test.go — RCA document v2 §3.5: the object meta read
// carries first_version_created_at (version 1's created_at) so the report can
// date "first Correlix detection" as the moment the case was created.
//
// §3a: the value is read by a scalar subquery INSIDE the existing meta
// statement, so it runs under the same tenant_scope (row policy) as the outer
// read; this test pins that it also carries the caller's tenant-exclusion
// predicate, so an operator-restricted tenant's creation stamp cannot be read
// through it, and that it targets version 1 of the same object only.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const firstDetCaseID = "3e0400bc-aa22-543b-95e4-1b6afa9cf75e"

func TestCorrSliceMetaCarriesFirstVersionCreatedAtUnderTheSameScope(t *testing.T) {
	type call struct{ scope, sql string }
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := readAllLimited(r)
		calls = append(calls, call{r.URL.Query().Get("tenant_scope"), sql})
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(sql, "SELECT version, tenant_id, state") {
			_, _ = w.Write([]byte(`{"data":[{"version":3,"tenant_id":"acme","state":"open",` +
				`"first_version_created_at":"2026-11-12T04:51:02.118Z",` +
				`"window_start":"2026-11-12T04:50:50.589Z","window_end":"2026-11-12T04:54:41.391Z"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")

	s := &server{}
	exclude := "tenant_id NOT IN ('globex')"
	meta, _, _, _, status, err := s.loadCorrSliceAtScope(context.Background(), "acme", exclude, firstDetCaseID, 0)
	if err != nil {
		t.Fatalf("load slice: status %d: %v", status, err)
	}
	if got := meta["first_version_created_at"]; got != "2026-11-12T04:51:02.118Z" {
		t.Fatalf("meta first_version_created_at = %v", got)
	}
	if len(calls) == 0 {
		t.Fatal("no ClickHouse call recorded")
	}
	metaCall := calls[0]
	if metaCall.scope != "acme" {
		t.Fatalf("meta read scope = %q, want the caller's scope", metaCall.scope)
	}
	sub := metaCall.sql
	i := strings.Index(sub, "AS first_version_created_at")
	if i < 0 {
		t.Fatalf("meta SQL lacks first_version_created_at:\n%s", sub)
	}
	subq := sub[:i]
	subq = subq[strings.LastIndex(subq, "(SELECT"):]
	for _, want := range []string{
		"FROM netops.corr_objects",
		"correlation_id = '" + firstDetCaseID + "'",
		"version = 1",
		"AND " + exclude, // the restriction predicate rides into the subquery too
	} {
		if !strings.Contains(subq, want) {
			t.Errorf("first-version subquery missing %q:\n%s", want, subq)
		}
	}
	// one statement: the creation stamp is not a separate read with its own scope
	for _, c := range calls[1:] {
		if strings.Contains(c.sql, "first_version_created_at") {
			t.Errorf("first_version_created_at must not be a separate read: %s", c.sql)
		}
	}

	// No exclusion (a cross-tenant platform read): the subquery carries none.
	calls = nil
	if _, _, _, _, _, err := s.loadCorrSliceAtScope(context.Background(), "__all__", "", firstDetCaseID, 0); err != nil {
		t.Fatalf("load slice (no exclusion): %v", err)
	}
	if strings.Contains(calls[0].sql, "NOT IN") {
		t.Errorf("no exclusion was asked for, the SQL carries one:\n%s", calls[0].sql)
	}
}
