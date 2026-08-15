package appid

import (
	"bytes"
	"context"
	"encoding/json"
)

// jsonEachRow renders rows as a "FORMAT JSONEachRow" insert body for table.
func jsonEachRow(table string, rows []map[string]any) (string, error) {
	var b bytes.Buffer
	b.WriteString("INSERT INTO " + table + " FORMAT JSONEachRow\n")
	enc := json.NewEncoder(&b)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// ── observation store ────────────────────────────────────────────────────────

// insertObservations batch-writes observations to netops.app_observations (idempotent
// on observation_id). No-op for an empty batch.
// CHWorker is the injected worker-scope ClickHouse seam (main's chWorkerExec/
// chWorkerQuery: tenant_scope=__all__ writes; row policies isolate reads).
type CHWorker struct {
	Exec  func(ctx context.Context, body string) error
	Query func(ctx context.Context, sql string) ([]map[string]any, error)
}

// InsertObservations batch-writes app_observations via the worker seam.
func InsertObservations(ctx context.Context, ch CHWorker, obs []ApplicationObservation) error {
	if len(obs) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(obs))
	for _, o := range obs {
		rows = append(rows, map[string]any{
			"tenant_id": o.TenantID, "observation_id": o.ObservationID,
			"event_time":  o.EventTime.UTC().UnixMilli(), // epoch-ms scaled insert (S4/R1)
			"source_type": o.SourceType, "vendor": o.Vendor, "product": o.Product, "device": o.Device,
			"parser_version": o.ParserVersion, "flow_id": o.FlowID, "session_id": o.SessionID,
			"src_ip": o.SrcIP, "dst_ip": o.DstIP, "src_port": o.SrcPort, "dst_port": o.DstPort, "proto": o.Proto,
			"vendor_app_id": o.VendorAppID, "vendor_app_name": o.VendorAppName,
			"vendor_category": o.VendorCategory, "vendor_risk": o.VendorRisk,
			"method": o.Method, "source": string(o.Source), "confidence": o.Confidence,
			"site": o.Site, "interface": o.Interface, "user": o.User, "workload": o.Workload,
			"path": o.Path, "seam": o.Seam, "raw_ref": o.RawRef, "raw_hash": o.RawHash,
			"bytes": o.Bytes, "packets": o.Packets,
		})
	}
	body, err := jsonEachRow("netops.app_observations", rows)
	if err != nil {
		return err
	}
	return ch.Exec(ctx, body)
}

// ── identity store ───────────────────────────────────────────────────────────

func tierCode(t Tier) int {
	switch t {
	case Confirmed:
		return 2
	case Suspected:
		return 1
	default:
		return 0
	}
}

// insertIdentities batch-writes fused identities to netops.app_identities (idempotent
// on fusion_id; a catalog/engine version bump yields a new id = a new version).
// InsertIdentities batch-writes app_identities via the worker seam.
func InsertIdentities(ctx context.Context, ch CHWorker, ids []FusedIdentity) error {
	if len(ids) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(ids))
	for _, fi := range ids {
		expl := make([]string, 0, len(fi.Explanations))
		for _, c := range fi.Explanations {
			expl = append(expl, string(c))
		}
		alts, _ := json.Marshal(fi.Alternatives) // discard: marshalling an in-memory value cannot fail
		rows = append(rows, map[string]any{
			"tenant_id": fi.TenantID, "fusion_id": fi.FusionID,
			"fused_at": fi.FusedAt.UTC().UnixMilli(), // epoch-ms scaled insert (S4/R1)
			"flow_id":  fi.Scope.FlowID, "session_id": fi.Scope.SessionID, "workload_id": fi.Scope.WorkloadID,
			"correlation_id": fi.Scope.CorrelationID, "src_ip": fi.Scope.SrcIP, "dst_ip": fi.Scope.DstIP,
			"dst_port": fi.Scope.DstPort, "proto": fi.Scope.Proto,
			"canonical_app_id": fi.CanonicalAppID, "app": orUnknown(fi.App), "provider": fi.Provider,
			"component": fi.Component, "app_protocol": fi.AppProtocol, "transport": fi.TransportProtocol,
			"tier": tierCode(fi.Tier), "band": string(fi.Band), "state": string(fi.State),
			"confidence": fi.Confidence, "contradicted": b2i(fi.Contradicted),
			"explanations": expl, "alternatives": string(alts), "evidence_missing": fi.EvidenceMissing,
			"catalog_version": fi.CatalogVersion, "fusion_version": fi.FusionVersion,
		})
	}
	body, err := jsonEachRow("netops.app_identities", rows)
	if err != nil {
		return err
	}
	return ch.Exec(ctx, body)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
