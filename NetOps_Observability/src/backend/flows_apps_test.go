package backend

import (
	"testing"

	"netops/backend/appid"
)

func TestAggregateFlowApps(t *testing.T) {
	// catalog: two M365 prefixes + one AWS prefix
	es, _ := appid.ParseM365([]byte(`[{"serviceArea":"Exchange","ips":["13.107.6.152/31","40.92.0.0/15"]}]`))
	aws, _ := appid.ParseAWS([]byte(`{"prefixes":[{"ip_prefix":"52.94.0.0/22","service":"S3"}]}`))
	cat := appid.NewCatalog(append(es, aws...))

	rows := []map[string]any{
		{"d": "13.107.6.153", "b": float64(1000), "f": float64(10)}, // M365 Exchange
		{"d": "40.92.1.1", "b": float64(500), "f": float64(5)},      // M365 Exchange (same app, different dest)
		{"d": "52.94.0.9", "b": float64(3000), "f": float64(3)},     // AWS S3
		{"d": "8.8.8.8", "b": float64(50), "f": float64(1)},         // unknown
	}
	out := aggregateFlowApps(rows, cat, nil)

	if len(out) != 3 {
		t.Fatalf("want 3 apps (M365, AWS, unknown), got %d: %+v", len(out), out)
	}
	// sorted by bytes desc → AWS S3 (3000) first
	if out[0].App != "AWS S3" || out[0].Bytes != 3000 {
		t.Fatalf("expected AWS S3 top by bytes, got %+v", out[0])
	}
	// M365 Exchange aggregates the two destinations: 1500 bytes, 2 dests
	var m365 *appFlowRow
	for i := range out {
		if out[i].App == "Microsoft 365 Exchange" {
			m365 = &out[i]
		}
	}
	if m365 == nil || m365.Bytes != 1500 || m365.Dests != 2 {
		t.Fatalf("M365 should aggregate to 1500 bytes / 2 dests, got %+v", m365)
	}
	// unknown is a first-class bucket
	var sawUnknown bool
	for _, r := range out {
		if r.App == "unknown" {
			sawUnknown = true
		}
	}
	if !sawUnknown {
		t.Fatal("uncatalogued traffic must surface as the unknown bucket")
	}
}

func TestAggregateFlowApps_Empty(t *testing.T) {
	if out := aggregateFlowApps(nil, appid.NewCatalog(nil), nil); len(out) != 0 {
		t.Fatalf("no rows should yield no apps, got %+v", out)
	}
}

func TestAggregateFlowApps_NGFWPromotes(t *testing.T) {
	// IP-catalog alone would call 8.8.8.8 "unknown"; the firewall's authoritative
	// app-id for that dst overrides → a confirmed, named verdict.
	rows := []map[string]any{{"d": "8.8.8.8", "b": float64(1000), "f": float64(10)}}
	extraFor := func(dst string) []appid.Signal {
		if dst == "8.8.8.8" {
			return []appid.Signal{{Source: appid.SrcNGFWAppID, App: "Zoom"}}
		}
		return nil
	}
	out := aggregateFlowApps(rows, appid.NewCatalog(nil), extraFor)
	if len(out) != 1 || out[0].App != "Zoom" || out[0].Tier != string(appid.Confirmed) {
		t.Fatalf("ngfw app-id should confirm Zoom, got %+v", out)
	}
}

// #81 P3G: the SOURCE side resolves through the same path — rows carry src_app,
// pairs split per (dst app, src app), and distinct-dest counting stays honest
// when one destination appears in several pairs.
func TestAggregateFlowApps_SrcResolution(t *testing.T) {
	aws, _ := appid.ParseAWS([]byte(`{"prefixes":[{"ip_prefix":"52.94.0.0/22","service":"S3"}]}`))
	cat := appid.NewCatalog(aws)

	extraFor := func(addr string) []appid.Signal {
		if addr == "10.0.1.10" { // a tagged cloud workload as the SOURCE
			return []appid.Signal{{Source: appid.SrcCloudTag, App: "payroll"}}
		}
		return nil
	}
	rows := []map[string]any{
		{"d": "52.94.0.9", "s": "10.0.1.10", "b": float64(3000), "f": float64(3)}, // payroll → AWS S3
		{"d": "52.94.0.9", "s": "10.0.9.9", "b": float64(1000), "f": float64(1)},  // unknown → AWS S3 (same dest!)
	}
	out := aggregateFlowApps(rows, cat, extraFor)
	if len(out) != 2 {
		t.Fatalf("want 2 pair rows, got %d: %+v", len(out), out)
	}
	if out[0].App != "AWS S3" || out[0].SrcApp != "payroll" || out[0].Bytes != 3000 {
		t.Fatalf("top pair should be payroll → AWS S3, got %+v", out[0])
	}
	if out[1].SrcApp != "unknown" {
		t.Fatalf("unresolved src must be the first-class unknown, got %+v", out[1])
	}
	// the same destination in two pairs still counts as ONE distinct dest each
	for _, r := range out {
		if r.Dests != 1 {
			t.Fatalf("dests must count distinct destination IPs, got %+v", r)
		}
	}
}
