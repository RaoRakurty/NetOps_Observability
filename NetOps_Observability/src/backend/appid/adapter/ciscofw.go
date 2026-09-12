// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package adapter

import (
	"time"

	"netops/backend/appid"
)

// ciscoFW parses Cisco Secure Firewall (FTD / Firepower) connection events. Cisco
// splits the identity across three fields: ApplicationProtocol (the L7 protocol,
// e.g. HTTPS/QUIC), Client (the client app), and WebApplication (the business web
// app, e.g. "Office 365"/"Teams"). The BUSINESS app is WebApplication (then Client);
// ApplicationProtocol is recorded as the protocol, never as the business app — a
// protocol-only event yields NO app observation (spec: protocol ≠ application).
type ciscoFW struct{}

func (ciscoFW) Name() string    { return "ciscofw" }
func (ciscoFW) Vendor() string  { return "cisco" }
func (ciscoFW) Product() string { return "secure-firewall" }
func (ciscoFW) Version() string { return "ciscofw-1" }

func (ciscoFW) Detect(ev map[string]any) bool {
	switch str(ev, "vendor") {
	case "cisco-ftd", "firepower", "cisco-secure-firewall":
		return true
	}
	// WebApplication is a Cisco-specific field; ApplicationProtocol+Client also marks FTD.
	if str(ev, "WebApplication", "web_application") != "" {
		return true
	}
	if str(ev, "ApplicationProtocol", "application_protocol") != "" && str(ev, "Client", "client_application") != "" {
		return true
	}
	return false
}

func (a ciscoFW) Parse(ev map[string]any, tenant string, ingest time.Time) Result {
	appProto := str(ev, "ApplicationProtocol", "application_protocol")
	app := str(ev, "WebApplication", "web_application")
	if app == "" {
		app = str(ev, "Client", "client_application")
	}
	if notApp(app) {
		// recognized FTD event but only a protocol (HTTPS/QUIC) — not a business app.
		return Result{OK: false}
	}
	srcIP := str(ev, "SrcIP", "src_ip", "InitiatorIP")
	dstIP := str(ev, "DstIP", "dst_ip", "ResponderIP")
	if srcIP == "" && dstIP == "" {
		return Result{Err: errMissing("ciscofw: no src/dst ip")}
	}
	evt := eventTime(ev, ingest)
	session := str(ev, "ConnectionID", "connection_id")
	obs := appid.ApplicationObservation{
		ObservationID:  observationID("ciscofw", session, srcIP, dstIP, app, evt),
		TenantID:       tenant,
		EventTime:      evt,
		IngestTime:     ingest,
		SourceType:     "ngfw",
		Vendor:         a.Vendor(),
		Product:        a.Product(),
		Device:         str(ev, "DeviceName", "device_name", "Sensor"),
		ParserVersion:  a.Version(),
		SessionID:      session,
		SrcIP:          srcIP,
		DstIP:          dstIP,
		SrcPort:        intv(ev, "SrcPort", "src_port"),
		DstPort:        intv(ev, "DstPort", "dst_port"),
		Proto:          protoName(str(ev, "Protocol", "protocol")),
		AppProtocol:    appProto, // HTTPS/QUIC — protocol, not the business app
		VendorAppID:    app,
		VendorAppName:  app,
		VendorCategory: str(ev, "ApplicationCategory", "app_category"),
		VendorRisk:     str(ev, "ApplicationRisk", "app_risk"),
		Method:         "secure-firewall-appid",
		Source:         appid.SrcNGFWAppID,
		Interface:      iface(str(ev, "IngressInterface", "ingress_interface"), str(ev, "EgressInterface", "egress_interface")),
		User:           redactUser(str(ev, "User", "user")),
		RawHash:        rawHash(ev),
		Bytes:          int64v(ev, "InitiatorBytes") + int64v(ev, "ResponderBytes"),
		Packets:        int64v(ev, "InitiatorPackets") + int64v(ev, "ResponderPackets"),
	}
	return Result{Obs: obs, OK: true}
}
