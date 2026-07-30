package backend

// credential_durability_test.go — F-76.
//
// Cloud-connector and NMS credentials were accepted into RAM behind a 201. On
// the file backend the constructor fell back to an in-memory store, so an
// operator pasted an AWS/Azure/GCP key or a controller password, saw "Created",
// and lost it at the next restart — with webhook URLs already registered with
// the provider left pointing at permanent 404s.
//
// The audit's own words: "The honest-refusal path is dead code —
// cloud_connectors_handlers.go:108,184 guard `if s.cloudConn == nil { 501 }`;
// the constructor never returns nil." These tests keep it reachable.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"netops/backend/cloudconn"
	"netops/backend/internal/platformdb"
	"netops/backend/nms"
	"testing"
)

// The constructor must refuse rather than substitute a RAM store. `backend` is
// not a *pgStore in tests, which is exactly the production file-backend case.
func TestCloudConnStoreRefusesWithoutDurableStorage(t *testing.T) {
	if _, isPG := platformdb.ActivePG(); isPG {
		t.Skip("postgres backend configured; the fallback path is not exercised")
	}
	if got := newCloudConnStore(); got != nil {
		t.Fatalf("newCloudConnStore() = %T, want nil so the 501 guards are reachable "+
			"(an in-memory fallback holds credentials in RAM behind a 201)", got)
	}
}

// With no store wired, the connector endpoints must answer 501 — not panic, and
// not accept the credential.
func TestCloudConnectorEndpointsRefuseWhenStorageIsAbsent(t *testing.T) {
	_, s := newTestServerState(t)
	s.cloudConn = nil

	for _, path := range []string{"/api/cloud/connectors", "/api/cloud/connectors/abc"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		switch path {
		case "/api/cloud/connectors":
			s.handleCloudConnectors(rec, req)
		default:
			s.handleCloudConnectorByID(rec, req)
		}
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s = %d, want 501", path, rec.Code)
		}
	}
}

// cloudStoreReady is the shared guard; prove it refuses rather than passing.
func TestCloudStoreReadyRefusesNilStore(t *testing.T) {
	_, s := newTestServerState(t)
	s.cloudConn = nil
	rec := httptest.NewRecorder()
	if s.cloudStoreReady(rec) {
		t.Fatal("cloudStoreReady must be false with no store")
	}
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("guard wrote %d, want 501", rec.Code)
	}
	// And it must PASS when a store is present, or every endpoint is bricked.
	s.cloudConn = cloudconn.NewMemStore()
	if !s.cloudStoreReady(httptest.NewRecorder()) {
		t.Error("cloudStoreReady must be true when a store is wired")
	}
}

// ---- NMS ------------------------------------------------------------------

// The NMS runtime stays wired off Postgres (the connector gallery must render
// on a fresh install), but credential writes are refused.
func TestNonDurableNMSStoreRefusesCredentials(t *testing.T) {
	st := nms.NewNonDurableStore()
	err := st.SetCredentials(context.Background(), "t-a", "nmsi-1", map[string]string{"password": "hunter2"})
	if err == nil {
		t.Fatal("a non-durable store must refuse credentials, not hold them in RAM")
	}
	if !errors.Is(err, nms.ErrStorageNotDurable) {
		t.Errorf("err = %v, want nms.ErrStorageNotDurable", err)
	}
	if st.Durable() {
		t.Error("nms.NonDurableStore.Durable() must be false")
	}
}

// The probe must not accidentally mark every store non-durable — that would
// refuse credentials on Postgres too.
func TestDurabilityProbeDefaultsToDurable(t *testing.T) {
	if !nms.StoreDurable(nms.NewMemStore()) {
		t.Error("the bare mem store (tests) must probe as durable")
	}
	if nms.StoreDurable(nms.NewNonDurableStore()) {
		t.Error("the production file-backend wrapper must probe as NOT durable")
	}
}

// Config reads must still work — refusing credentials must not brick the
// gallery, which is the reason the runtime is wired at all.
func TestNonDurableNMSStoreStillServesConfig(t *testing.T) {
	st := nms.NewNonDurableStore()
	ctx := context.Background()
	if err := st.Upsert(ctx, nms.Integration{Tenant: "t-a", ID: "nmsi-1", Vendor: "meraki"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	list, err := st.List(ctx, "t-a", false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list = %d integrations, want 1 — config reads must still work", len(list))
	}
}
