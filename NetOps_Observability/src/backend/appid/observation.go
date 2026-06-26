package appid

import "time"

// ApplicationObservation is ONE upstream application-identity opinion as reported by
// a source (NGFW/NBAR/proxy/NDR/workload/cloud/DNS/...), with full provenance. It is
// the durable, vendor-NEUTRAL record that fusion consumes — the original vendor
// values are preserved verbatim (never collapsed into one string) so a fused result
// is always explainable back to its source.
//
// It deliberately does NOT carry the raw log body — only a reference + an integrity
// hash (RawRef/RawHash) so the raw event stays in its store (OpenSearch) once.
type ApplicationObservation struct {
	ObservationID string    `json:"observation_id"` // immutable, deterministic per (source, session/tuple, app, event_time)
	TenantID      string    `json:"tenant_id"`      // opaque tenant id (stamped at the source, never from payload)
	EventTime     time.Time `json:"event_time"`     // when the source observed it
	IngestTime    time.Time `json:"ingest_time"`    // when Correlix received it

	// provenance
	SourceType       string `json:"source_type"`       // ngfw | ipfix | proxy | ndr | workload | cloud | dns | sni | ...
	Vendor           string `json:"vendor,omitempty"`  // paloalto | fortinet | cisco | ...
	Product          string `json:"product,omitempty"` // panos | fortios | secure-firewall | nbar2 | ...
	Device           string `json:"device,omitempty"`  // the reporting device
	CollectorVersion string `json:"collector_version,omitempty"`
	ParserVersion    string `json:"parser_version,omitempty"`

	// flow / session scope
	FlowID    string `json:"flow_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Proto     string `json:"proto,omitempty"`

	// ORIGINAL vendor values — NEVER discarded (canonicalization is additive)
	VendorAppID    string `json:"vendor_app_id,omitempty"`   // raw vendor app-id (namespaced at the catalog, not here)
	VendorAppName  string `json:"vendor_app_name,omitempty"` // raw vendor application name
	VendorCategory string `json:"vendor_category,omitempty"`
	VendorRisk     string `json:"vendor_risk,omitempty"`

	// classification
	Method      string  `json:"method,omitempty"`       // identification method as reported / inferred
	Source      Source  `json:"source"`                 // mapped onto the Correlix trust ladder (authority)
	Confidence  float64 `json:"confidence,omitempty"`   // source's own confidence (0 ⇒ use baseConfidence)
	AppProtocol string  `json:"app_protocol,omitempty"` // L7 protocol (HTTPS/QUIC) — a protocol, NOT the business app

	// context (joined from topology/inventory where available)
	Site      string `json:"site,omitempty"`
	Interface string `json:"interface,omitempty"`
	User      string `json:"user,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Path      string `json:"path,omitempty"`
	Seam      string `json:"seam,omitempty"`

	// raw-event linkage (NOT the raw body)
	RawRef  string `json:"raw_ref,omitempty"`  // pointer to the raw event (e.g. OpenSearch doc id)
	RawHash string `json:"raw_hash,omitempty"` // integrity hash of the raw event

	// volume (for impact/dedup; optional)
	Bytes   int64 `json:"bytes,omitempty"`
	Packets int64 `json:"packets,omitempty"`
}

// ToSignal projects an observation onto the fusion Signal (the existing Fuse input).
// It carries the RAW vendor name as the candidate app; canonicalization (vendor alias
// → canonical display name) is applied by the catalog/fusion step, not here, so the
// projection stays lossless and pure. App=="" when the source had no app opinion.
func (o ApplicationObservation) ToSignal() Signal {
	detail := o.Vendor
	if o.Method != "" {
		if detail != "" {
			detail += " "
		}
		detail += o.Method
	}
	return Signal{
		Source:     o.Source,
		App:        o.VendorAppName,
		Confidence: o.Confidence,
		Detail:     detail,
	}
}
