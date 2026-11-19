// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// routine_rollup_store_test.go — tracker 410: the api's OpenSearch adapter for
// internal/routinerollup, end to end against a fake OpenSearch: one real tick
// lists the routine originals, aggregates them, and bulk-writes the roll-ups
// into the SAME tenant segment's roll-up index, as NDJSON, and nowhere else.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/routinerollup"
)

func TestRoutineRollupStoreEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var bulkBody, bulkType string
	var searched []string
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	day := minute.Format("2006.01.02")
	acmeIdx := "netops-syslogroutine-acme-" + day
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_cat/indices/netops-syslogroutine-"):
			_, _ = w.Write([]byte(`[{"index":"` + acmeIdx + `"}]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_search"):
			searched = append(searched, r.URL.Path+"?"+r.URL.RawQuery)
			if strings.Contains(string(b), `"composite"`) && strings.HasPrefix(r.URL.Path, "/"+acmeIdx) {
				key := map[string]any{"tenant_id": "acme", "device_id": "edge-1", "host": "edge-1", "hostname": nil,
					"source_ip": "10.0.0.1", "audit_source": "10.9.9.9:830", "audit_user": "vmanage", "minute": minute.UnixMilli()}
				resp, _ := json.Marshal(map[string]any{"aggregations": map[string]any{"k": map[string]any{
					"buckets": []any{map[string]any{"key": key, "doc_count": 7,
						"first": map[string]any{"value": minute.UnixMilli()}, "last": map[string]any{"value": minute.Add(30 * time.Second).UnixMilli()}}}}}})
				_, _ = w.Write(resp)
				return
			}
			_, _ = w.Write([]byte(`{"hits":{"total":{"value":0}},"aggregations":{"n":{"value":0},"k":{"buckets":[]}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/_bulk":
			bulkBody, bulkType = string(b), r.Header.Get("Content-Type")
			_, _ = w.Write([]byte(`{"errors":false,"items":[{"index":{"status":201}}]}`))
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusTeapot)
		}
	}))
	defer srv.Close()
	t.Setenv("OPENSEARCH_URL", srv.URL)

	m := routinerollup.NewMetrics()
	j := &routinerollup.Job{Store: routineRollupStore{}, Metrics: m}
	if err := j.Tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if bulkType != "application/x-ndjson" {
		t.Errorf("bulk content type = %q", bulkType)
	}
	lines := strings.Split(strings.TrimSpace(bulkBody), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one action + one document, got:\n%s", bulkBody)
	}
	var meta map[string]map[string]string
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["index"]["_index"] != "netops-syslogrollup-acme-"+day || len(meta["index"]["_id"]) != 64 {
		t.Errorf("bulk action = %v", meta)
	}
	if !strings.Contains(lines[1], `"occurrence_count":7`) || !strings.Contains(lines[1], `"audit_user":"vmanage"`) {
		t.Errorf("roll-up document = %s", lines[1])
	}
	for _, p := range searched {
		if !strings.Contains(p, "ignore_unavailable=true") {
			t.Errorf("a search without ignore_unavailable fails on a roll-up index not created yet: %s", p)
		}
	}
	var out bytes.Buffer
	m.Write(&out)
	if !strings.Contains(out.String(), "netops_routine_rollup_documents_written_total 1") ||
		!strings.Contains(out.String(), "netops_routine_rollup_last_success_timestamp_seconds") {
		t.Errorf("metrics after one tick:\n%s", out.String())
	}
}

// An OpenSearch refusal (a 403 because securityadmin was not re-run, say) is
// an error the tick returns, with the status in it — never a silent success.
func TestRoutineRollupStoreSurfacesARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"no permissions for [indices:data/write/bulk]"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	t.Setenv("OPENSEARCH_URL", srv.URL)
	if _, err := (routineRollupStore{}).Indices(context.Background(), "netops-syslogroutine-*"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a 403 must surface with its status, got %v", err)
	}
	if _, err := (routineRollupStore{}).Bulk(context.Background(), []byte("{}\n{}\n")); err == nil {
		t.Fatal("a refused bulk must be an error")
	}
}
