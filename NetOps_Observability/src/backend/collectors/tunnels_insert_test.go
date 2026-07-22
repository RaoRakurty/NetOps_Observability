package collectors

// tunnels_insert_test.go — regression guards for audit F-56.
//
// The finding, verbatim:
//
//	resp, err := client.Do(req)
//	if err != nil { return }
//	_ = resp.Body.Close()
//
// The status code was NEVER inspected, so a 400/401/500 was indistinguishable
// from success — no log, no counter, no retry. And a repo-wide grep for
// input_format_skip_unknown_fields / date_time_input_format returned ZERO hits
// in Go and Python, so one unknown JSON key 400s the entire batch. The two
// Vector ClickHouse sinks DO set skip_unknown_fields: the discipline existed in
// the config tier and was absent from both code tiers.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestInsertTunnelsReportsNonOKStatus(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			http.Error(w, "Code: 27. DB::Exception: Cannot parse input", code)
		}))
		t.Setenv("CLICKHOUSE_URL", srv.URL)
		err := insertTunnels(context.Background(), []tunnelRow{{ID: "t1", Status: "up"}})
		srv.Close()
		if err == nil {
			t.Fatalf("HTTP %d was reported as success — the write result must be observed (F-56)", code)
		}
		if !strings.Contains(err.Error(), "DB::Exception") {
			t.Errorf("HTTP %d: error %q does not carry ClickHouse's own diagnosis", code, err)
		}
	}
}

func TestInsertTunnelsSucceedsAndCarriesToleranceSettings(t *testing.T) {
	var gotQuery url.Values
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)

	rows := []tunnelRow{
		{ID: "core-1/tun0", Type: "ipsec", LocalDevice: "core-1", Status: "up", TenantID: "acme"},
		{ID: "core-2/tun0", Type: "gre", LocalDevice: "core-2", Status: "down", TenantID: ""},
	}
	if err := insertTunnels(context.Background(), rows); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Insert tolerance: one unknown key must not 400 the whole batch.
	if got := gotQuery.Get("input_format_skip_unknown_fields"); got != "1" {
		t.Errorf("input_format_skip_unknown_fields = %q, want 1 (F-56: absent from the whole Go tier)", got)
	}
	if got := gotQuery.Get("date_time_input_format"); got != "best_effort" {
		t.Errorf("date_time_input_format = %q, want best_effort", got)
	}
	// tenant_scope: without it the tenant_iso_tunnels row policy, re-evaluated
	// on INSERT, admits only tenant_id='' rows — so a tenant-stamped row would
	// fail outright.
	if got := gotQuery.Get("tenant_scope"); got != "__all__" {
		t.Errorf("tenant_scope = %q, want __all__", got)
	}
	// allow_errors would trade a loud batch failure for silent per-row loss —
	// the exact thing this audit exists to eliminate. It must NOT be set.
	for _, banned := range []string{"input_format_allow_errors_num", "input_format_allow_errors_ratio"} {
		if gotQuery.Get(banned) != "" {
			t.Errorf("%s is set — it silently DISCARDS malformed rows, converting a loud "+
				"batch failure into invisible partial loss", banned)
		}
	}

	// The tenant travels with the row (§3a.4 at-rest isolation).
	if !strings.Contains(gotBody, `"tenant_id":"acme"`) {
		t.Errorf("the insert body does not stamp tenant_id — every tunnel would land untagged "+
			"and be shared into EVERY tenant's view by the row policy (F-56): %s", gotBody)
	}
	if !strings.Contains(gotBody, "INSERT INTO netops.tunnels FORMAT JSONEachRow") {
		t.Errorf("unexpected insert body: %s", gotBody)
	}
}

func TestInsertTunnelsNoRowsIsNotAnError(t *testing.T) {
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:1")
	if err := insertTunnels(context.Background(), nil); err != nil {
		t.Errorf("an empty batch must be a no-op, got %v", err)
	}
}

func TestInsertTunnelsReportsTransportFailure(t *testing.T) {
	// Port 1 on loopback refuses: a dial failure must surface, not vanish.
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:1")
	if err := insertTunnels(context.Background(), []tunnelRow{{ID: "t1"}}); err == nil {
		t.Error("a transport failure was reported as success")
	}
}
