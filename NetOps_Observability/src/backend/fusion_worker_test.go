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
	// Stub emit so the suite never makes a real pandaproxy HTTP call. The real
	// emitIdentities is covered by the dedicated identityEvent + cycle-emit tests.
	w.emitID = func(_ context.Context, i []appid.FusedIdentity) (int, error) { return len(i), nil }
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

func TestIdentityEvent_MapsContractAndDedupsSources(t *testing.T) {
	fi := appid.FusedIdentity{
		TenantID: "acme", Band: appid.BandAuthoritative, State: appid.StateFused,
		EvidenceScore: 92, FusionVersion: "appfuse-1", CatalogVersion: 7,
		CanonicalAppID: "app-123", Provider: "Microsoft",
		Scope: appid.IdentityScope{DstIP: "13.107.6.152", DstPort: 443, Proto: "6", FlowID: "f-1"},
		Verdict: appid.Verdict{App: "Microsoft Teams", Signals: []appid.Signal{
			{Source: appid.SrcNGFWAppID}, {Source: appid.SrcIPCatalog}, {Source: appid.SrcNGFWAppID},
		}},
	}
	ev, ok := identityEvent(fi)
	if !ok {
		t.Fatal("nameable identity should map")
	}
	if ev["app"] != "Microsoft Teams" || ev["tenant_id"] != "acme" {
		t.Errorf("core fields wrong: %v", ev)
	}
	if ev["band"] != "authoritative" || ev["state"] != "fused" || ev["evidence_score"] != 92 {
		t.Errorf("provenance wrong: %v", ev)
	}
	srcs, _ := ev["sources"].([]string)
	if len(srcs) != 2 || srcs[0] != "ngfw_app_id" || srcs[1] != "ip_catalog" {
		t.Errorf("sources should dedup preserving order: %v", srcs)
	}
	if ev["dst_ip"] != "13.107.6.152" || ev["dst_port"] != 443 || ev["flow_id"] != "f-1" {
		t.Errorf("scope wrong: %v", ev)
	}
	if _, present := ev["session_id"]; present {
		t.Error("empty optional fields must be omitted (honest defaults on the consumer)")
	}
}

func TestIdentityEvent_SkipsUnknown(t *testing.T) {
	for _, app := range []string{"", "unknown", "Unknown", "  "} {
		if _, ok := identityEvent(appid.FusedIdentity{Verdict: appid.Verdict{App: app}}); ok {
			t.Errorf("app %q must not be emitted (no enrichment value)", app)
		}
	}
}

func TestWorkerCycle_EmitErrorDoesNotAbort(t *testing.T) {
	src := fakeFusionSource{events: []map[string]any{
		{"vendor": "fortinet", "devname": "FGT", "app": "Microsoft.Teams", "appcat": "Collaboration",
			"sessionid": "s1", "srcip": "10.0.0.1", "dstip": "52.1.1.1", "dstport": "443", "proto": "6", "tenant_id": "acme"},
	}}
	w, _, gotID := newTestWorker(src)
	w.emitID = func(_ context.Context, _ []appid.FusedIdentity) (int, error) { return 0, errors.New("proxy down") }
	n, err := w.cycle(context.Background(), time.Unix(1782460000, 0).UTC())
	if err != nil {
		t.Fatalf("emit failure must NOT abort the cycle: %v", err)
	}
	if n != 1 || len(*gotID) != 1 {
		t.Fatalf("persist still happened (source of truth): n=%d ids=%d", n, len(*gotID))
	}
	if w.metrics.snapshot()["emit_errors"].(int64) != 1 {
		t.Error("emit error should be counted")
	}
}

func TestWorkerCycle_EmitCounts(t *testing.T) {
	src := fakeFusionSource{events: []map[string]any{
		{"vendor": "fortinet", "devname": "FGT", "app": "Microsoft.Teams", "appcat": "Collaboration",
			"sessionid": "s1", "srcip": "10.0.0.1", "dstip": "52.1.1.1", "dstport": "443", "proto": "6", "tenant_id": "acme"},
	}}
	w, _, _ := newTestWorker(src)
	w.emitID = func(_ context.Context, i []appid.FusedIdentity) (int, error) { return len(i), nil }
	if _, err := w.cycle(context.Background(), time.Unix(1782460000, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if w.metrics.snapshot()["emitted"].(int64) != 1 {
		t.Errorf("emitted count wrong: %v", w.metrics.snapshot()["emitted"])
	}
}

func TestFlattenJSON(t *testing.T) {
	out := map[string]any{}
	flattenJSON("", map[string]any{"fgt": map[string]any{"app": "Teams"}, "app_id": "Zoom"}, out)
	if out["fgt.app"] != "Teams" || out["app_id"] != "Zoom" {
		t.Errorf("flatten wrong: %v", out)
	}
}
