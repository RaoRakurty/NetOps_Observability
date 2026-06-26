package adapter

import (
	"time"

	"netops/backend/appid"
)

// paloAlto parses Palo Alto PAN-OS TRAFFIC/THREAT logs. PAN App-ID classified the
// session on-box; Correlix consumes that verdict (SrcNGFWAppID, authoritative). The
// adapter consumes the NAMED fields a Vector PAN parser extracts from the positional
// CSV (the CSV→field mapping is the Vector/pipeline concern, Phase 4) — so the parser
// is robust and not blind-positional. In PAN-OS the App-ID name IS the identity
// (no separate numeric id), so vendor_app_id == vendor_app_name.
type paloAlto struct{}

func (paloAlto) Name() string    { return "paloalto" }
func (paloAlto) Vendor() string  { return "paloalto" }
func (paloAlto) Product() string { return "panos" }
func (paloAlto) Version() string { return "paloalto-1" }

func (paloAlto) Detect(ev map[string]any) bool {
	if str(ev, "vendor") == "paloalto" || str(ev, "vendor") == "panw" {
		return true
	}
	// PAN logs carry a TRAFFIC/THREAT type + an app field; serial/device_name disambiguate.
	t := str(ev, "type", "log_type")
	if (t == "TRAFFIC" || t == "THREAT") && str(ev, "app", "application") != "" {
		return true
	}
	return false
}

func (a paloAlto) Parse(ev map[string]any, tenant string, ingest time.Time) Result {
	app := str(ev, "app", "application")
	if notApp(app) {
		return Result{OK: false}
	}
	srcIP := str(ev, "src", "source_ip", "srcip")
	dstIP := str(ev, "dst", "dest_ip", "dstip")
	if srcIP == "" && dstIP == "" {
		return Result{Err: errMissing("paloalto: no src/dst ip")}
	}
	evt := eventTime(ev, ingest)
	session := str(ev, "sessionid", "session_id")
	obs := appid.ApplicationObservation{
		ObservationID:  observationID("paloalto", session, srcIP, dstIP, app, evt),
		TenantID:       tenant,
		EventTime:      evt,
		IngestTime:     ingest,
		SourceType:     "ngfw",
		Vendor:         a.Vendor(),
		Product:        a.Product(),
		Device:         str(ev, "device_name", "devname", "serial"),
		ParserVersion:  a.Version(),
		SessionID:      session,
		SrcIP:          srcIP,
		DstIP:          dstIP,
		SrcPort:        intv(ev, "sport", "src_port"),
		DstPort:        intv(ev, "dport", "dest_port"),
		Proto:          protoName(str(ev, "proto", "protocol")),
		VendorAppID:    app, // PAN App-ID name IS the identity
		VendorAppName:  app,
		VendorCategory: str(ev, "app_category", "category_of_app", "category"),
		VendorRisk:     str(ev, "risk_of_app", "risk-of-app", "risk"),
		Method:         "app-id",
		Source:         appid.SrcNGFWAppID,
		Interface:      iface(str(ev, "from", "inbound_if", "from_zone"), str(ev, "to", "outbound_if", "to_zone")),
		User:           redactUser(str(ev, "srcuser", "source_user")),
		RawHash:        rawHash(ev),
		Bytes:          int64v(ev, "bytes"),
		Packets:        int64v(ev, "packets"),
	}
	return Result{Obs: obs, OK: true}
}
