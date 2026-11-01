package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/nms"
)

// runRecordingStore captures every RecordRun with the state of the context it
// was written under, so a test can tell "recorded" from "recorded on a dead
// context" (which the PG store refuses).
type runRecordingStore struct {
	nms.ConfigStore
	mu   sync.Mutex
	runs []recordedRun
}

type recordedRun struct {
	rec    nms.RunRecord
	ctxErr error
}

func (s *runRecordingStore) RecordRun(ctx context.Context, rec nms.RunRecord) error {
	s.mu.Lock()
	s.runs = append(s.runs, recordedRun{rec: rec, ctxErr: ctx.Err()})
	s.mu.Unlock()
	return s.ConfigStore.RecordRun(ctx, rec)
}

// TestNMSPollNowSurvivesClientDisconnect pins the 2026-11-01 lab finding: the
// "Poll now" cycle ran on the request context, the proxy's 60 s read timeout
// cut a ~61 s vManage cycle, and every sink write plus the run record failed
// with "context canceled" — a whole collected cycle thrown away. A client that
// has gone away must not cancel the cycle: it runs and is recorded on a live
// context, bounded by the scheduler's own deadlines.
func TestNMSPollNowSurvivesClientDisconnect(t *testing.T) {
	_, s := newTestServerState(t)
	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(controller.Close)

	store := &runRecordingStore{ConfigStore: nms.NewMemStore()}
	s.nms = newNMSRuntime(store)
	const tenant = "t_pollnow"
	ic := nms.Integration{Tenant: tenant, ID: "nmsi-pollnow", Vendor: "generic",
		DisplayName: "Generic", BaseURL: controller.URL, Enabled: true}
	if err := store.Upsert(context.Background(), ic); err != nil {
		t.Fatalf("seed integration: %v", err)
	}

	// The client is already gone when the handler runs.
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	claims := jwtClaims{Sub: "op", Tenant: tenant, Role: "admin"}
	r := httptest.NewRequest(http.MethodPost, "/api/nms/integrations/"+ic.ID+"/poll", nil)
	r = r.WithContext(context.WithValue(gone, userCtxKey, claims))
	w := httptest.NewRecorder()
	s.handleNMSIntegrationItem(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("poll now: status %d, body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "context canceled") {
		t.Fatalf("the cycle was cancelled by the departed client: %s", w.Body.String())
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.runs) != 1 {
		t.Fatalf("want exactly one recorded run, got %d", len(store.runs))
	}
	got := store.runs[0]
	if got.ctxErr != nil {
		t.Fatalf("run recorded on a dead context (%v): the record would be lost", got.ctxErr)
	}
	if strings.Contains(got.rec.Error, "context canceled") {
		t.Fatalf("recorded run carries the client's cancellation: %q", got.rec.Error)
	}
	if got.rec.Tenant != tenant || got.rec.IntegrationID != ic.ID {
		t.Fatalf("run recorded for %s/%s, want %s/%s", got.rec.Tenant, got.rec.IntegrationID, tenant, ic.ID)
	}
}
