package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netops/backend/appid"
)

// appid_fusion_store.go — #81 Fusion Layer Phase 4 persistence. A non-request-scoped
// ClickHouse client (the fusion worker runs in the background, not per-request) that
// batch-writes app_observations + app_identities and reads recent observations. Writes
// are idempotent (deterministic ids → ReplacingMergeTree dedups), so re-ingest/replay
// is safe. No new dependency — stdlib net/http over the CH HTTP interface, the same
// transport proxyClickHouse uses.

// chWorkerExec POSTs a statement (INSERT … FORMAT JSONEachRow or DDL) to ClickHouse as
// the worker (tenant_scope=__all__: the worker spans tenants; per-tenant isolation is
// enforced by the row policies on READ + the tenant_id stamped on every row).
func chWorkerExec(ctx context.Context, body string) error {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("tenant_scope", "__all__")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(envOr("CLICKHOUSE_USER", "netops"), envOr("CLICKHOUSE_PASSWORD", ""))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := backendHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// chWorkerQuery POSTs a SELECT … FORMAT JSON and returns the data rows.
func chWorkerQuery(ctx context.Context, sql string) ([]map[string]any, error) {
	base := envOr("CLICKHOUSE_URL", "http://clickhouse:8123")
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("tenant_scope", "__all__")
	q.Set("log_comment", "worker:cross-tenant") // #100 read-budget attribution
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(envOr("CLICKHOUSE_USER", "netops"), envOr("CLICKHOUSE_PASSWORD", ""))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := backendHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

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
func insertObservations(ctx context.Context, obs []appid.ApplicationObservation) error {
	if len(obs) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(obs))
	for _, o := range obs {
		rows = append(rows, map[string]any{
			"tenant_id": o.TenantID, "observation_id": o.ObservationID,
			"event_time":  o.EventTime.UTC().Format("2006-01-02 15:04:05.000"),
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
	return chWorkerExec(ctx, body)
}

// ── identity store ───────────────────────────────────────────────────────────

func tierCode(t appid.Tier) int {
	switch t {
	case appid.Confirmed:
		return 2
	case appid.Suspected:
		return 1
	default:
		return 0
	}
}

// insertIdentities batch-writes fused identities to netops.app_identities (idempotent
// on fusion_id; a catalog/engine version bump yields a new id = a new version).
func insertIdentities(ctx context.Context, ids []appid.FusedIdentity) error {
	if len(ids) == 0 {
		return nil
	}
	rows := make([]map[string]any, 0, len(ids))
	for _, fi := range ids {
		expl := make([]string, 0, len(fi.Explanations))
		for _, c := range fi.Explanations {
			expl = append(expl, string(c))
		}
		alts, _ := json.Marshal(fi.Alternatives)
		rows = append(rows, map[string]any{
			"tenant_id": fi.TenantID, "fusion_id": fi.FusionID,
			"fused_at": fi.FusedAt.UTC().Format("2006-01-02 15:04:05.000"),
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
	return chWorkerExec(ctx, body)
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
