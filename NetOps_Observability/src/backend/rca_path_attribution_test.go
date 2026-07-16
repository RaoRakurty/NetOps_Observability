package main

// rca_path_attribution_test.go — the path-causality RCA P2 attribution passthrough:
// the RCA report must surface the engine's on-path attribution column (named cause,
// verdict lift, honesty cap, discovered typed path) additively, and omit it honestly
// when no cause was attributed.

import (
	"encoding/json"
	"strings"
	"testing"
)

// the exact shape the correlation engine writes to corr_objects.attribution
// (engine ObjectSnapshot.attribution_blob): the P2 attribution + the typed path.
const onPathAttributionBlob = `{
  "src":"10.20.30.40","dst":"52.216.100.6","tenant_id":"acme",
  "headline":"10.20.30.40->52.216.100.6 broke at CLOUD/load balancer correlix-edge-urlmap (cloud_lb_log) [confirmed]",
  "attributed":{
    "device":{"address":"52.216.100.5","role":"load_balancer","label":"correlix-edge-urlmap",
              "segment_index":1,"segment_type":"cloud","segment_confidence":"strong",
              "upstream_rank":1,"ambiguous":false},
    "kind":"cloud_lb_log","modality":"passive_flow","observers":["cloud:1234:us-east-1"],
    "signal_ids":["11111111-1111-1111-1111-111111111111"],
    "headline":"CLOUD/load balancer correlix-edge-urlmap (cloud_lb_log)"},
  "explained_away":[],
  "discounted":[{"identity":"cloud_dns_log:other.example.com","kind":"cloud_dns_log",
                 "reason":"off-path: device not on the affected SRC->DST path — severity is not causality (discounted)"}],
  "verdict":{"verdict_tier":"confirmed","reasons":["independent confirming pair"]},
  "baseline_verdict":{"verdict_tier":"suspected","reasons":["single modality class"]},
  "confidence_lifted":true,"capped":false,"cap_reason":"","on_path_device_count":2,
  "path":{"src":"10.20.30.40","dst":"52.216.100.6","head":null,"ambiguous":false,
    "segments":[
      {"index":0,"segment_type":"lan","boundary":"LAN","provider":"","confidence":"medium",
       "key_devices":[],"member_addresses":["10.20.30.40"],"hop_indices":[0],"unknown_hops":[],
       "reason":"","ambiguous":false},
      {"index":1,"segment_type":"cloud","boundary":"CLOUD","provider":"aws","confidence":"strong",
       "key_devices":[{"address":"52.216.100.5","role":"load_balancer","label":"correlix-edge-urlmap","confidence":"strong"},
                      {"address":"52.216.100.6","role":"host","label":"app-host-01","confidence":"strong"}],
       "member_addresses":["52.216.100.5","52.216.100.6"],"hop_indices":[1,2],"unknown_hops":[],
       "reason":"","ambiguous":false}],
    "ecmp_pairs":[],"notes":[]}
}`

func TestRcaReportSurfacesOnPathAttribution(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.app.saas-experience-degraded", nil)
	meta["attribution"] = onPathAttributionBlob
	rep := buildTestReport(t, meta, nil)

	pa := rep.PathAttribution
	if pa == nil {
		t.Fatal("path_attribution must be present when the engine attributed an on-path cause")
	}
	if pa.Attributed == nil || pa.Attributed.Device.Role != "load_balancer" ||
		pa.Attributed.Device.Label != "correlix-edge-urlmap" || pa.Attributed.Kind != "cloud_lb_log" {
		t.Fatalf("attributed cause not decoded: %+v", pa.Attributed)
	}
	// the verdict LIFT is carried (suspected baseline → confirmed with the on-path witness).
	if pa.VerdictTier != "confirmed" || pa.BaselineTier != "suspected" || !pa.ConfidenceLifted {
		t.Fatalf("verdict lift not surfaced: tier=%s baseline=%s lifted=%v",
			pa.VerdictTier, pa.BaselineTier, pa.ConfidenceLifted)
	}
	if pa.Capped || pa.CapReason != "" {
		t.Fatalf("clean span must not be capped: capped=%v reason=%q", pa.Capped, pa.CapReason)
	}
	if len(pa.Discounted) != 1 || !strings.Contains(pa.Discounted[0].Reason, "off-path") {
		t.Fatalf("off-path discount not carried: %+v", pa.Discounted)
	}
	// the DISCOVERED typed path travels with it: ordered segments + key devices.
	if pa.Path == nil || len(pa.Path.Segments) != 2 {
		t.Fatalf("typed path not decoded: %+v", pa.Path)
	}
	var labels []string
	for _, seg := range pa.Path.Segments {
		for _, kd := range seg.KeyDevices {
			labels = append(labels, kd.Label)
		}
	}
	if !labelsContain(labels, "correlix-edge-urlmap") {
		t.Fatalf("typed path must carry the LB key device, got %v", labels)
	}

	// it must round-trip in the served JSON as `path_attribution`.
	out, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"path_attribution"`) {
		t.Fatal("path_attribution must be present in the served report JSON")
	}
}

func TestRcaReportCappedAttributionStaysSuspected(t *testing.T) {
	// a partial/opaque span: the cause is still named, but the verdict is CAPPED at
	// suspected with an honest reason — the report must never upgrade it to confirmed.
	blob := `{"src":"a","dst":"b","attributed":{"device":{"role":"load_balancer","label":"lb1","segment_index":2},"kind":"cloud_lb_log"},` +
		`"verdict":{"verdict_tier":"suspected"},"baseline_verdict":{"verdict_tier":"suspected"},` +
		`"confidence_lifted":false,"capped":true,"cap_reason":"path segment 1 is unknown/opaque on the SRC->cause span",` +
		`"on_path_device_count":1,"path":{"src":"a","dst":"b","segments":[]}}`
	meta := testMeta("open", "suspected", "sig.ent.app.saas-experience-degraded", nil)
	meta["attribution"] = blob
	rep := buildTestReport(t, meta, nil)
	pa := rep.PathAttribution
	if pa == nil || !pa.Capped || pa.VerdictTier != "suspected" {
		t.Fatalf("capped attribution must stay suspected: %+v", pa)
	}
	if !strings.Contains(pa.CapReason, "unknown/opaque") {
		t.Fatalf("honesty-cap reason must be carried, got %q", pa.CapReason)
	}
}

func TestRcaReportNoAttributionColumnIsOmitted(t *testing.T) {
	// the common case: an object with no on-path cause ('{}' or absent) → nil block,
	// omitted from the JSON, never an invented attribution.
	for _, val := range []any{"{}", "", nil} {
		meta := testMeta("open", "suspected", "undetermined", nil)
		if val != nil {
			meta["attribution"] = val
		}
		rep := buildTestReport(t, meta, nil)
		if rep.PathAttribution != nil {
			t.Fatalf("attribution=%v must yield no path_attribution block", val)
		}
		out, _ := json.Marshal(rep)
		if strings.Contains(string(out), `"path_attribution"`) {
			t.Fatalf("attribution=%v must omit path_attribution from JSON", val)
		}
	}
}

func labelsContain(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
