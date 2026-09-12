// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adapter

import (
	"testing"
	"time"

	"netops/backend/appid"
)

// vendor_golden_logs_test.go — #81 per-vendor "golden log" guardrail. For every
// supported vendor it pushes 1–2 REAL-FORMAT log records through the PRODUCTION path
// (the registry's Detect→Parse routing, not a single adapter in isolation) and
// asserts the application name the system extracts. This is the durable answer to
// "can we read app names from each vendor's logs?": if a vendor's log shape drifts
// or an adapter regresses, this test fails instead of the field silently going blank.
//
// Honesty note: FortiGate is validated against a REAL device on the lab fabric; the
// Palo Alto / Cisco / NBAR rows are validated against the DOCUMENTED log format, not
// a live device — they prove the parser, and flip to device-grade once a real
// appliance feeds us (run on representative real output before trusting in prod).

var goldenT = time.Unix(1782460000, 0).UTC()

type goldenLog struct {
	name    string         // human label for the case
	vendor  string         // expected adapter Vendor()
	wantApp string         // expected extracted business-app name
	ev      map[string]any // the raw log record (real field shape)
}

var vendorGoldenLogs = []goldenLog{
	// ── FortiGate (FortiOS kv "app=") — DEVICE-VALIDATED on the lab fabric ──
	{"FortiGate · Teams", "fortinet", "Microsoft.Teams", map[string]any{
		"vendor": "fortinet", "devname": "FGT-TOR-01", "devid": "FGT60F123",
		"sessionid": "123456", "srcip": "10.10.20.50", "dstip": "52.113.194.132",
		"srcport": "54321", "dstport": "443", "proto": "6",
		"app": "Microsoft.Teams", "appid": "40568", "appcat": "Collaboration", "action": "accept",
	}},
	{"FortiGate · Dropbox", "fortinet", "Dropbox", map[string]any{
		"vendor": "fortinet", "devname": "FGT-TOR-01", "sessionid": "123457",
		"srcip": "10.10.20.51", "dstip": "162.125.248.20", "srcport": "55000", "dstport": "443",
		"proto": "6", "app": "Dropbox", "appcat": "File.Sharing", "action": "accept",
	}},

	// ── Palo Alto (PAN-OS TRAFFIC, "app=") — format-validated ──
	{"Palo Alto · ms-teams", "paloalto", "ms-teams", map[string]any{
		"type": "TRAFFIC", "device_name": "PA-3220", "serial": "001", "sessionid": "98765",
		"src": "10.10.20.50", "dst": "52.113.194.132", "sport": "51000", "dport": "443",
		"proto": "tcp", "app": "ms-teams", "app_category": "collaboration", "from": "trust", "to": "untrust",
	}},
	{"Palo Alto · youtube-base", "paloalto", "youtube-base", map[string]any{
		"type": "TRAFFIC", "device_name": "PA-3220", "sessionid": "98766",
		"src": "10.10.20.60", "dst": "142.250.72.14", "sport": "51010", "dport": "443",
		"proto": "tcp", "app": "youtube-base", "app_category": "streaming-media",
	}},

	// ── Cisco Secure Firewall / FTD — business app = WebApplication, NOT protocol ──
	{"Cisco FTD · Office 365", "cisco", "Office 365", map[string]any{
		"vendor": "cisco-ftd", "DeviceName": "FTD-1", "ConnectionID": "c-1",
		"SrcIP": "10.10.20.50", "DstIP": "52.113.194.132", "SrcPort": "50000", "DstPort": "443",
		"Protocol": "6", "ApplicationProtocol": "HTTPS", "Client": "Microsoft Office",
		"WebApplication": "Office 365", "ApplicationCategory": "collaboration",
	}},

	// ── NBAR2 / Flexible NetFlow IE95 (router DPI) — application_name ──
	{"NBAR2/IPFIX · ms-office-365", "cisco", "ms-office-365", map[string]any{
		"application_name": "ms-office-365", "application_id": "13:838", "exporter": "10.0.0.254",
		"flow_id": "f-1", "src_addr": "10.10.20.50", "dst_addr": "52.113.194.132",
		"src_port": "50000", "dst_port": "443", "proto": "6",
	}},
}

func TestVendorGoldenLogs(t *testing.T) {
	reg := New()
	for _, g := range vendorGoldenLogs {
		t.Run(g.name, func(t *testing.T) {
			res, adapterName := reg.Parse(g.ev, "acme", goldenT)
			if adapterName == "" {
				t.Fatalf("no adapter recognized the %s log", g.name)
			}
			if res.Err != nil {
				t.Fatalf("%s dead-lettered: %v", g.name, res.Err)
			}
			if !res.OK {
				t.Fatalf("%s produced no observation (ok=false)", g.name)
			}
			o := res.Obs
			if o.VendorAppName != g.wantApp {
				t.Errorf("%s: app = %q, want %q", g.name, o.VendorAppName, g.wantApp)
			}
			if o.Vendor != g.vendor {
				t.Errorf("%s: vendor = %q, want %q", g.name, o.Vendor, g.vendor)
			}
			if o.Source != appid.SrcNGFWAppID && o.Source != appid.SrcIPFIXAppID {
				t.Errorf("%s: source = %q, want an authoritative app-id source", g.name, o.Source)
			}
			// Readable per-vendor evidence in `go test -v`.
			t.Logf("%-26s adapter=%-10s app=%-16q source=%s tuple=%s:%d/%s",
				g.name, adapterName, o.VendorAppName, o.Source, o.DstIP, o.DstPort, o.Proto)
		})
	}
}
