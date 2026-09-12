// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adapter

import (
	"testing"
	"time"

	"netops/backend/appid"
)

var ingestT = time.Unix(1782460100, 0).UTC()

// a sanitized FortiGate FortiOS traffic log (key=value, as Vector delivers it).
func fgtEvent() map[string]any {
	return map[string]any{
		"vendor": "fortinet", "devname": "FGT-TOR-01", "devid": "FGT60F123",
		"eventtime": "1782460000000000000", "sessionid": "123456",
		"srcip": "10.10.20.50", "dstip": "52.113.194.132",
		"srcport": "54321", "dstport": "443", "proto": "6",
		"app": "Microsoft.Teams", "appid": "40568", "appcat": "Collaboration", "apprisk": "elevated",
		"action": "accept", "srcintf": "lan", "dstintf": "wan1",
		"sentbyte": "12000", "rcvdbyte": "48000", "sentpkt": "120", "rcvdpkt": "300",
		"user": "jdoe",
	}
}

func TestFortiGateDetect(t *testing.T) {
	a := fortiGate{}
	if !a.Detect(fgtEvent()) {
		t.Error("should detect a FortiGate event")
	}
	if a.Detect(map[string]any{"app": "ssl"}) { // app alone, no FortiOS markers
		t.Error("should not detect a bare event as FortiGate")
	}
	if a.Detect(map[string]any{"vendor": "paloalto", "app": "x"}) {
		t.Error("should not claim a Palo Alto event")
	}
}

func TestFortiGateParseTeams(t *testing.T) {
	r := fortiGate{}.Parse(fgtEvent(), "acme", ingestT)
	if r.Err != nil || !r.OK {
		t.Fatalf("expected ok observation, got ok=%v err=%v", r.OK, r.Err)
	}
	o := r.Obs
	if o.VendorAppName != "Microsoft.Teams" || o.VendorAppID != "40568" {
		t.Errorf("original vendor values not preserved: name=%q id=%q", o.VendorAppName, o.VendorAppID)
	}
	if o.Source != appid.SrcNGFWAppID {
		t.Errorf("source=%v want ngfw_app_id (authoritative)", o.Source)
	}
	if o.SourceType != "ngfw" || o.Vendor != "fortinet" || o.Product != "fortios" {
		t.Errorf("provenance wrong: %s/%s/%s", o.SourceType, o.Vendor, o.Product)
	}
	if o.TenantID != "acme" || o.Device != "FGT-TOR-01" || o.SessionID != "123456" {
		t.Errorf("scope/tenant wrong: %+v", o)
	}
	if o.DstIP != "52.113.194.132" || o.DstPort != 443 || o.Proto != "tcp" {
		t.Errorf("tuple wrong: %s:%d/%s", o.DstIP, o.DstPort, o.Proto)
	}
	if o.VendorCategory != "Collaboration" || o.VendorRisk != "elevated" {
		t.Errorf("category/risk wrong: %s/%s", o.VendorCategory, o.VendorRisk)
	}
	if o.Bytes != 60000 || o.Packets != 420 {
		t.Errorf("byte/pkt sum wrong: %d/%d", o.Bytes, o.Packets)
	}
	if o.EventTime.Unix() != 1782460000 {
		t.Errorf("event time not parsed from eventtime ns: %v", o.EventTime)
	}
	if o.RawHash == "" || o.ParserVersion != "fortigate-1" {
		t.Errorf("raw hash / parser version missing")
	}
	// projects onto the existing fusion Signal as an authoritative candidate.
	if s := o.ToSignal(); s.Source != appid.SrcNGFWAppID || s.App != "Microsoft.Teams" {
		t.Errorf("ToSignal projection wrong: %+v", s)
	}
}

func TestFortiGateNoAppIsNotAnError(t *testing.T) {
	ev := fgtEvent()
	ev["app"] = "N/A"
	r := fortiGate{}.Parse(ev, "acme", ingestT)
	if r.Err != nil || r.OK {
		t.Errorf("N/A app should be ok=false err=nil, got ok=%v err=%v", r.OK, r.Err)
	}
}

func TestFortiGateMissingTupleDeadLetters(t *testing.T) {
	ev := fgtEvent()
	delete(ev, "srcip")
	delete(ev, "dstip")
	r := fortiGate{}.Parse(ev, "acme", ingestT)
	if r.Err == nil {
		t.Error("missing src+dst ip should dead-letter (Err set)")
	}
}

func TestFortiGateObservationIDIsDeterministic(t *testing.T) {
	a := fortiGate{}
	id1 := a.Parse(fgtEvent(), "acme", ingestT).Obs.ObservationID
	id2 := a.Parse(fgtEvent(), "acme", ingestT.Add(time.Hour)).Obs.ObservationID // ingest differs
	if id1 == "" || id1 != id2 {
		t.Errorf("observation id must be deterministic (idempotent re-ingest): %q vs %q", id1, id2)
	}
}

func TestRegistryRoutesToFortiGate(t *testing.T) {
	res, name := New().Parse(fgtEvent(), "acme", ingestT)
	if name != "fortigate" || !res.OK {
		t.Errorf("registry should route to fortigate; got name=%q ok=%v", name, res.OK)
	}
	// an unrecognized event → no adapter, no crash.
	if _, n := New().Parse(map[string]any{"foo": "bar"}, "acme", ingestT); n != "" {
		t.Errorf("unrecognized event should yield no adapter, got %q", n)
	}
}
