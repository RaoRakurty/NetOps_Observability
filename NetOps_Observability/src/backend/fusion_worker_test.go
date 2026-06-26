package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"netops/backend/appid"
)

type fakeFusionSource struct {
	events []map[string]any
	err    error
}

func (f fakeFusionSource) Name() string { return "fake" }
func (f fakeFusionSource) Fetch(_ context.Context, _ time.Time) ([]map[string]any, error) {
	return f.events, f.err
}

func newTestWorker(src FusionSource) (*fusionWorker, *[]appid.ApplicationObservation, *[]appid.FusedIdentity) {
	var gotObs []appid.ApplicationObservation
	var gotID []appid.FusedIdentity
	w := newFusionWorker(src)
	w.persistObs = func(_ context.Context, o []appid.ApplicationObservation) error {
		gotObs = append(gotObs, o...)
		return nil
	}
	w.persistID = func(_ context.Context, i []appid.FusedIdentity) error { gotID = append(gotID, i...); return nil }
	return w, &gotObs, &gotID
}

func TestWorkerCycle_ParseFusePersist(t *testing.T) {
	src := fakeFusionSource{events: []map[string]any{
		// a FortiGate Teams event (recognized → observation → fused).
		{"vendor": "fortinet", "devname": "FGT", "app": "Microsoft.Teams", "appcat": "Collaboration",
			"sessionid": "s1", "srcip": "10.0.0.1", "dstip": "52.1.1.1", "dstport": "443", "proto": "6", "tenant_id": "acme"},
		// an unrecognized event (no adapter).
		{"foo": "bar"},
		// a FortiGate event with no app (recognized, ok=false).
		{"vendor": "fortinet", "devname": "FGT", "appcat": "x", "app": "N/A", "srcip": "10.0.0.2", "dstip": "9.9.9.9"},
	}}
	w, gotObs, gotID := newTestWorker(src)
	n, err := w.cycle(context.Background(), time.Unix(1782460000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(*gotObs) != 1 || (*gotObs)[0].VendorAppName != "Microsoft.Teams" {
		t.Fatalf("expected 1 observation, got %d", len(*gotObs))
	}
	if n != 1 || len(*gotID) != 1 || (*gotID)[0].App != "Microsoft.Teams" {
		t.Fatalf("expected 1 fused identity, got %d", len(*gotID))
	}
	snap := w.metrics.snapshot()
	if snap["unsupported"].(int64) != 1 {
		t.Errorf("unsupported count wrong: %v", snap["unsupported"])
	}
	if bv := snap["by_vendor"].(map[string]int64); bv["fortinet"] != 1 {
		t.Errorf("by_vendor wrong: %v", bv)
	}
}

func TestWorkerCycle_DeadLetterDoesNotCrash(t *testing.T) {
	// a fortinet event with app present but NO src/dst ip → adapter dead-letters.
	src := fakeFusionSource{events: []map[string]any{
		{"vendor": "fortinet", "devname": "FGT", "app": "Dropbox", "appcat": "x"},
	}}
	w, gotObs, _ := newTestWorker(src)
	if _, err := w.cycle(context.Background(), time.Now()); err != nil {
		t.Fatalf("cycle should not error on a dead-letter: %v", err)
	}
	if len(*gotObs) != 0 {
		t.Error("dead-lettered event must not become an observation")
	}
	if w.metrics.snapshot()["dead_letter"].(int64) != 1 {
		t.Error("dead-letter not counted")
	}
}

func TestWorkerCycle_SourceErrorReported(t *testing.T) {
	w, _, _ := newTestWorker(fakeFusionSource{err: errors.New("opensearch down")})
	if _, err := w.cycle(context.Background(), time.Now()); err == nil {
		t.Error("a source error should surface from the cycle")
	}
	if w.metrics.snapshot()["last_error"] == "" {
		t.Error("source error should be recorded in metrics")
	}
}

func TestFlattenJSON(t *testing.T) {
	out := map[string]any{}
	flattenJSON("", map[string]any{"fgt": map[string]any{"app": "Teams"}, "app_id": "Zoom"}, out)
	if out["fgt.app"] != "Teams" || out["app_id"] != "Zoom" {
		t.Errorf("flatten wrong: %v", out)
	}
}
