// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adapter

import (
	"time"

	"netops/backend/appid"
)

// fortiGate parses FortiGate (FortiOS) traffic/UTM logs whose key=value fields Vector
// already extracts (the `.fgt.*` namespace). FortiGate's App Control classified the
// app on-box (FortiGuard signatures) — Correlix CONSUMES that verdict (authoritative,
// SrcNGFWAppID); no DPI on our side.
//
// Representative fields: app, appid, appcat, apprisk, action, sessionid, srcip, dstip,
// srcport, dstport, proto, srcintf, dstintf, sent/rcvd byte/pkt, user, devname.
type fortiGate struct{}

func (fortiGate) Name() string    { return "fortigate" }
func (fortiGate) Vendor() string  { return "fortinet" }
func (fortiGate) Product() string { return "fortios" }
func (fortiGate) Version() string { return "fortigate-1" }

// Detect: a FortiGate log carries the FortiOS marker fields. Accept either the raw
// key set (devid/devname + app/appcat) or the Vector-namespaced ".fgt.app".
func (fortiGate) Detect(ev map[string]any) bool {
	if str(ev, "vendor") == "fortinet" {
		return true
	}
	if str(ev, "app", "fgt.app") != "" && str(ev, "appcat", "fgt.appcat", "devname", "devid") != "" {
		return true
	}
	return false
}

func (a fortiGate) Parse(ev map[string]any, tenant string, ingest time.Time) Result {
	app := str(ev, "app", "fgt.app")
	if notApp(app) {
		// recognized FortiGate log, but no app identity on this record — not an error.
		return Result{OK: false}
	}
	srcIP := str(ev, "srcip", "fgt.srcip")
	dstIP := str(ev, "dstip", "fgt.dstip")
	if srcIP == "" && dstIP == "" {
		return Result{Err: errMissing("fortigate: no src/dst ip")}
	}
	evt := eventTime(ev, ingest)
	obs := appid.ApplicationObservation{
		ObservationID:  observationID("fortigate", str(ev, "sessionid", "fgt.sessionid"), srcIP, dstIP, app, evt),
		TenantID:       tenant,
		EventTime:      evt,
		IngestTime:     ingest,
		SourceType:     "ngfw",
		Vendor:         a.Vendor(),
		Product:        a.Product(),
		Device:         str(ev, "devname", "fgt.devname", "devid", "fgt.devid"),
		ParserVersion:  a.Version(),
		SessionID:      str(ev, "sessionid", "fgt.sessionid"),
		SrcIP:          srcIP,
		DstIP:          dstIP,
		SrcPort:        intv(ev, "srcport", "fgt.srcport"),
		DstPort:        intv(ev, "dstport", "fgt.dstport"),
		Proto:          protoName(str(ev, "proto", "fgt.proto")),
		VendorAppID:    str(ev, "appid", "fgt.appid"),
		VendorAppName:  app,
		VendorCategory: str(ev, "appcat", "fgt.appcat"),
		VendorRisk:     str(ev, "apprisk", "fgt.apprisk"),
		Method:         "app-control",
		Source:         appid.SrcNGFWAppID,
		Interface:      iface(str(ev, "srcintf", "fgt.srcintf"), str(ev, "dstintf", "fgt.dstintf")),
		User:           redactUser(str(ev, "user", "fgt.user", "srcname", "fgt.srcname")),
		RawHash:        rawHash(ev),
		Bytes:          int64v(ev, "sentbyte", "fgt.sentbyte") + int64v(ev, "rcvdbyte", "fgt.rcvdbyte"),
		Packets:        int64v(ev, "sentpkt", "fgt.sentpkt") + int64v(ev, "rcvdpkt", "fgt.rcvdpkt"),
	}
	return Result{Obs: obs, OK: true}
}
