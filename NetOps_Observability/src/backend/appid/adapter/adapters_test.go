// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adapter

import (
	"testing"

	"netops/backend/appid"
)

func TestPaloAltoParse(t *testing.T) {
	ev := map[string]any{
		"type": "TRAFFIC", "device_name": "PA-3220", "serial": "001",
		"sessionid": "98765", "src": "10.10.20.50", "dst": "52.113.194.132",
		"sport": "51000", "dport": "443", "proto": "tcp",
		"app": "ms-teams", "app_category": "collaboration", "risk_of_app": "3",
		"srcuser": "corp\\jdoe", "from": "trust", "to": "untrust", "bytes": "60000", "packets": "400",
	}
	r := paloAlto{}.Parse(ev, "acme", ingestT)
	if !r.OK || r.Err != nil {
		t.Fatalf("ok=%v err=%v", r.OK, r.Err)
	}
	o := r.Obs
	if o.VendorAppName != "ms-teams" || o.VendorAppID != "ms-teams" { // PAN: name IS the id
		t.Errorf("vendor app wrong: %q/%q", o.VendorAppName, o.VendorAppID)
	}
	if o.Source != appid.SrcNGFWAppID || o.Vendor != "paloalto" || o.DstPort != 443 || o.Proto != "tcp" {
		t.Errorf("provenance/tuple wrong: %+v", o)
	}
	if !New().routesTo(ev, "paloalto") {
		t.Error("registry should route TRAFFIC+app to paloalto")
	}
}

func TestCiscoFWBusinessAppNotProtocol(t *testing.T) {
	ev := map[string]any{
		"vendor": "cisco-ftd", "DeviceName": "FTD-1", "ConnectionID": "c-1",
		"SrcIP": "10.10.20.50", "DstIP": "52.113.194.132", "SrcPort": "50000", "DstPort": "443",
		"Protocol": "6", "ApplicationProtocol": "HTTPS", "Client": "Microsoft Office",
		"WebApplication": "Office 365", "ApplicationCategory": "collaboration",
		"InitiatorBytes": "10000", "ResponderBytes": "50000",
	}
	r := ciscoFW{}.Parse(ev, "acme", ingestT)
	if !r.OK {
		t.Fatalf("expected ok, err=%v", r.Err)
	}
	o := r.Obs
	// the BUSINESS app is the web application, NOT the protocol
	if o.VendorAppName != "Office 365" {
		t.Errorf("business app should be WebApplication, got %q", o.VendorAppName)
	}
	if o.AppProtocol != "HTTPS" {
		t.Errorf("app protocol should be recorded separately, got %q", o.AppProtocol)
	}
	if o.Bytes != 60000 {
		t.Errorf("byte sum wrong: %d", o.Bytes)
	}
}

func TestCiscoFWProtocolOnlyIsNotAnApp(t *testing.T) {
	// only ApplicationProtocol (QUIC), no Client/WebApplication → NOT a business app.
	ev := map[string]any{
		"vendor": "cisco-ftd", "SrcIP": "10.0.0.1", "DstIP": "8.8.8.8",
		"ApplicationProtocol": "QUIC",
	}
	r := ciscoFW{}.Parse(ev, "acme", ingestT)
	if r.OK || r.Err != nil {
		t.Errorf("protocol-only should be ok=false err=nil (protocol != app), got ok=%v err=%v", r.OK, r.Err)
	}
}

func TestNBARIPFIXParse(t *testing.T) {
	ev := map[string]any{
		"application_name": "ms-office-365", "application_id": "13:838",
		"exporter": "10.0.0.254", "flow_id": "f-1",
		"src_addr": "10.10.20.50", "dst_addr": "52.113.194.132",
		"src_port": "50000", "dst_port": "443", "proto": "6",
		"bytes": "60000", "packets": "400",
	}
	r := nbarIPFIX{}.Parse(ev, "acme", ingestT)
	if !r.OK {
		t.Fatalf("expected ok, err=%v", r.Err)
	}
	o := r.Obs
	if o.Source != appid.SrcIPFIXAppID { // router did NBAR2 DPI → authoritative ipfix
		t.Errorf("source=%v want ipfix_app_id", o.Source)
	}
	if o.VendorAppName != "ms-office-365" || o.VendorAppID != "13:838" {
		t.Errorf("nbar values wrong: %q/%q", o.VendorAppName, o.VendorAppID)
	}
	if o.SourceType != "ipfix" || o.Product != "nbar2" {
		t.Errorf("provenance wrong: %s/%s", o.SourceType, o.Product)
	}
}

func TestNBARUnclassifiedIsNotAnApp(t *testing.T) {
	ev := map[string]any{"application_id": "0", "src_addr": "10.0.0.1", "dst_addr": "8.8.8.8"}
	if r := (nbarIPFIX{}).Parse(ev, "acme", ingestT); r.OK {
		t.Error("nbar app-id 0 (unclassified) should not be an observation")
	}
}

func TestRegistryDetectionPrecedence(t *testing.T) {
	r := New()
	// each vendor routes to its own adapter, no cross-claims.
	cases := map[string]map[string]any{
		"fortigate":  fgtEvent(),
		"paloalto":   {"type": "TRAFFIC", "app": "ssl"},
		"ciscofw":    {"vendor": "cisco-ftd", "WebApplication": "Box", "SrcIP": "1.1.1.1", "DstIP": "2.2.2.2"},
		"nbar_ipfix": {"application_name": "webex-meeting", "src_addr": "1.1.1.1", "dst_addr": "2.2.2.2"},
	}
	for want, ev := range cases {
		if !r.routesTo(ev, want) {
			t.Errorf("event should route to %q", want)
		}
	}
}

// routesTo is a test helper: does the registry pick adapter `name` for ev?
func (r *Registry) routesTo(ev map[string]any, name string) bool {
	_, got := r.Parse(ev, "acme", ingestT)
	return got == name
}
