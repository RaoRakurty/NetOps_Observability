// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adapter

import (
	"time"

	"netops/backend/appid"
)

// nbarIPFIX parses IPFIX/NetFlow-v9 records that carry a Cisco NBAR2 application id
// (IPFIX applicationId, IE 95) and/or application-name. The ROUTER ran NBAR2 DPI and
// exported the classification — Correlix consumes it (SrcIPFIXAppID, authoritative);
// no DPI on our side. When only the numeric id is exported, it is preserved and the
// catalog/alias layer maps it to a canonical name (Phase 3); the name is used when
// the exporter includes it.
type nbarIPFIX struct{}

func (nbarIPFIX) Name() string    { return "nbar_ipfix" }
func (nbarIPFIX) Vendor() string  { return "cisco" }
func (nbarIPFIX) Product() string { return "nbar2" }
func (nbarIPFIX) Version() string { return "nbar-ipfix-1" }

func (nbarIPFIX) Detect(ev map[string]any) bool {
	if str(ev, "vendor") == "nbar" || str(ev, "vendor") == "ipfix" {
		return true
	}
	// IE95 applicationId / NBAR application-name are the marker fields.
	return str(ev, "application_id", "applicationId", "nbar_app_id") != "" ||
		str(ev, "application_name", "applicationName", "nbar_name") != ""
}

func (a nbarIPFIX) Parse(ev map[string]any, tenant string, ingest time.Time) Result {
	name := str(ev, "application_name", "applicationName", "nbar_name")
	id := str(ev, "application_id", "applicationId", "nbar_app_id")
	if notApp(name) && (id == "" || id == "0" || id == "0:0") {
		// recognized flow record but NBAR reported no application (id 0 = unclassified).
		return Result{OK: false}
	}
	srcIP := str(ev, "src_addr", "srcaddr", "sourceIPv4Address", "src_ip")
	dstIP := str(ev, "dst_addr", "dstaddr", "destinationIPv4Address", "dst_ip")
	if srcIP == "" && dstIP == "" {
		return Result{Err: errMissing("nbar_ipfix: no src/dst ip")}
	}
	evt := eventTime(ev, ingest)
	appName := name
	if notApp(appName) {
		appName = "" // id-only: canonicalization resolves the name later (Phase 3)
	}
	obs := appid.ApplicationObservation{
		ObservationID: observationID("nbar_ipfix", str(ev, "flow_id", "flowId"), srcIP, dstIP, name+"|"+id, evt),
		TenantID:      tenant,
		EventTime:     evt,
		IngestTime:    ingest,
		SourceType:    "ipfix",
		Vendor:        a.Vendor(),
		Product:       a.Product(),
		Device:        str(ev, "exporter", "exporter_ip", "sampler_address"),
		ParserVersion: a.Version(),
		FlowID:        str(ev, "flow_id", "flowId"),
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       intv(ev, "src_port", "sourceTransportPort", "srcport"),
		DstPort:       intv(ev, "dst_port", "destinationTransportPort", "dstport"),
		Proto:         protoName(str(ev, "proto", "protocolIdentifier", "protocol")),
		VendorAppID:   id, // IE95 id (engine:selector) — preserved for catalog mapping
		VendorAppName: appName,
		Method:        "nbar2",
		Source:        appid.SrcIPFIXAppID,
		Interface:     iface(str(ev, "ingress_if", "ingressInterface", "in_if"), str(ev, "egress_if", "egressInterface", "out_if")),
		RawHash:       rawHash(ev),
		Bytes:         int64v(ev, "bytes", "octetDeltaCount"),
		Packets:       int64v(ev, "packets", "packetDeltaCount"),
	}
	return Result{Obs: obs, OK: true}
}
