// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/appid"
)

func TestInsertObservationsAndIdentities(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	ctx := context.Background()

	obs := []appid.ApplicationObservation{{
		TenantID: "acme", ObservationID: "o1", Source: appid.SrcNGFWAppID,
		VendorAppName: "Microsoft Teams", DstIP: "1.2.3.4", DstPort: 443, EventTime: time.Unix(0, 0).UTC(),
	}}
	if err := appid.InsertObservations(ctx, chWorker(), obs); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], "INSERT INTO netops.app_observations FORMAT JSONEachRow") {
		t.Fatalf("bad observation insert: %q", bodies[0])
	}
	if !strings.Contains(bodies[0], `"observation_id":"o1"`) || !strings.Contains(bodies[0], `"vendor_app_name":"Microsoft Teams"`) {
		t.Errorf("observation row missing fields: %q", bodies[0])
	}

	ids := []appid.FusedIdentity{{
		TenantID: "acme", FusionID: "f1", Band: appid.BandAuthoritative, State: appid.StateObserved,
		EvidenceScore: 100, Explanations: []appid.ExplanationCode{appid.ExSessionUpstream},
		FusedAt: time.Unix(0, 0).UTC(), Verdict: appid.Verdict{App: "Microsoft Teams", Tier: appid.Confirmed, Confidence: 1},
	}}
	if err := appid.InsertIdentities(ctx, chWorker(), ids); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bodies[1], "netops.app_identities") || !strings.Contains(bodies[1], `"app":"Microsoft Teams"`) {
		t.Errorf("identity row missing fields: %q", bodies[1])
	}
	if !strings.Contains(bodies[1], `"band":"authoritative"`) || !strings.Contains(bodies[1], `"state":"observed"`) {
		t.Errorf("identity band/state missing: %q", bodies[1])
	}

	// empty batch = no POST.
	if err := appid.InsertObservations(ctx, chWorker(), nil); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Errorf("empty batch should not POST, bodies=%d", len(bodies))
	}
}

func TestChWorkerQueryParsesData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"app":"Teams"},{"app":"Zoom"}]}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	rows, err := chWorkerQuery(context.Background(), "SELECT app FROM netops.app_identities")
	if err != nil || len(rows) != 2 || rows[0]["app"] != "Teams" {
		t.Fatalf("query parse failed: rows=%v err=%v", rows, err)
	}
}

func TestChWorkerExecError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad sql"))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	if err := chWorkerExec(context.Background(), "INSERT bad"); err == nil {
		t.Error("a 4xx from ClickHouse must surface as an error (controlled failure)")
	}
}
