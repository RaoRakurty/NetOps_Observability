// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// lows_a_test.go — review findings 3.1-17 and 3.1-18.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/tac"
	"netops/backend/internal/ticketing/vendors/juniper"
)

// 3.1-18 — ONE TENANT CANNOT SPEND ANOTHER TENANT'S VENDOR BUDGET.
//
// Juniper publishes the 1000-invocations-per-hour ceiling PER CUSTOMER, but the
// registry builds ONE connector (and therefore one wire client) for the whole
// platform, so the counter was shared: the first customer to reach the ceiling
// refused every other customer's case for up to an hour.
func TestJuniperInvocationBudgetIsPerCustomerNotPerProcess(t *testing.T) {
	f := newJuniperFake(t)
	c := NewJuniperConnector(f.client()) // one connector, as the registry builds it
	ctx := context.Background()

	first := juniperCfg()
	second := juniperCfg()
	second.Juniper.AppID = "app-2"
	second.Juniper.CustomerSourceID = "src-2"

	for i := 0; i < juniper.HourlyInvocationLimit; i++ {
		if _, err := c.FetchSeverityValues(ctx, first); err != nil {
			t.Fatalf("customer one, call %d: %v", i, err)
		}
	}
	if _, err := c.FetchSeverityValues(ctx, first); err == nil {
		t.Fatal("the first customer's own ceiling did not fire")
	}

	if _, err := c.FetchSeverityValues(ctx, second); err != nil {
		t.Fatalf("a SECOND customer was refused (%v) by the first customer's exhausted budget — "+
			"the published ceiling is per customer, not per process", err)
	}
}

// 3.1-17 — A FAILED WRITE IS NOT "ALREADY GONE".
//
// The DELETE arm mapped every store error to 404, so a routing record that
// could not be removed told the operator it had been, with no audit row and no
// log. The GET arm did the same to a failed read. The PUT arm beside them has
// always split the two cases.
func TestRoutingStoreFailuresAreNotReportedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tac_routing.json")
	store := NewTACRoutingStore(path)
	if _, err := store.Set("t1", false, "t1", TACRoutingConfig{
		RouteByVendor: map[string]string{"juniper": "juniper"},
	}, func(string) bool { return true }); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// The next persist cannot succeed: the file's own path is now a directory.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}

	audits := 0
	api := newRoutingProbe(t, store, func() { audits++ })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/settings/tac-routing", nil)
	api.HandleRouting(w, r)

	if w.Code == http.StatusNoContent {
		t.Fatal("a delete that could not be persisted answered 204")
	}
	if w.Code == http.StatusNotFound {
		t.Fatal("a FAILED WRITE was reported as 404 — the operator is told the record is gone while it is still there")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if audits == 0 {
		t.Fatal("the refusal left no audit row")
	}
	// The record is still there, which is the whole point of not saying it is gone.
	if _, found, err := store.Get("t1", false, "t1"); err != nil || !found {
		t.Fatalf("the record the API reported on: found=%v err=%v", found, err)
	}
}

// newRoutingProbe wires TACRoutingAPI with the minimum the handler needs.
func newRoutingProbe(t *testing.T, store *TACRoutingStore, onAudit func()) *TACRoutingAPI {
	t.Helper()
	api, err := NewTACRoutingAPI(TACRoutingAPIDeps{
		Store: func() *TACRoutingStore { return store },
		Authz: func(_ http.ResponseWriter, _ *http.Request, _ ConnectorGate) (ConnectorPrincipal, bool) {
			return ConnectorPrincipal{Tenant: "t1", Subject: "op@example.test"}, true
		},
		Connectors: func(context.Context, string) []tac.ConnectorInfo { return nil },
		Dialects:   func() []RoutingDialect { return nil },
		Audit:      funcSink(func(CaseAuditEvent) { onAudit() }),
		WriteJSON: func(w http.ResponseWriter, status int, _ any) {
			w.WriteHeader(status)
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			http.Error(w, err.Error(), status)
		},
		Now: time.Now,
	})
	if err != nil {
		t.Fatalf("routing api: %v", err)
	}
	return api
}
