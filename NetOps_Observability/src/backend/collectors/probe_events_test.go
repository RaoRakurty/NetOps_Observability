package collectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestForwardProbeEvents pins the wire contract with src/correlation
// handle_probe: one JSON object per POST, snake_case field names.
func TestForwardProbeEvents(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			t.Errorf("body not a JSON object: %v", err)
		}
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("PROBE_EVENT_SINK_URL", srv.URL)

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	forwardProbeEvents(context.Background(), []ProbeEvent{
		{Kind: "stamp", Prober: "prober-1", Target: "10.0.0.1:8620",
			OK: true, RTTms: 4.2, JitterMs: 0.3, LossPct: 0, TS: ts},
		{Kind: "icmp", Prober: "prober-1", Target: "10.0.0.2",
			OK: false, LossPct: 100, TS: ts},
	})

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected 2 POSTs, got %d", len(got))
	}
	first := got[0]
	for _, k := range []string{"kind", "prober", "target", "ok", "rtt_ms", "loss_pct", "ts"} {
		if _, present := first[k]; !present {
			t.Errorf("event missing wire field %q: %v", k, first)
		}
	}
	if first["kind"] != "stamp" || first["prober"] != "prober-1" {
		t.Errorf("unexpected first event: %v", first)
	}
	if got[1]["loss_pct"].(float64) != 100 {
		t.Errorf("loss_pct not preserved: %v", got[1])
	}
}

// TestProbeEventSinkDisabled: the operator can turn the lane off without
// breaking the measurement loop.
func TestProbeEventSinkDisabled(t *testing.T) {
	t.Setenv("PROBE_EVENT_SINK_URL", "off")
	if probeEventSink() != "" {
		t.Fatal("'off' must disable the sink")
	}
	// Must be a no-op, not a hang or panic.
	forwardProbeEvents(context.Background(), []ProbeEvent{{Kind: "tcp", Prober: "x", Target: "y"}})
}

func TestProberIDPrecedence(t *testing.T) {
	t.Setenv("PROBER_ID", "vantage-dallas-1")
	if id := proberID(); id != "vantage-dallas-1" {
		t.Fatalf("PROBER_ID not honored: %s", id)
	}
}
