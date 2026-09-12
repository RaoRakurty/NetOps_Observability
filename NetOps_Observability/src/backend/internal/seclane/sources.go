// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// sources.go — the three INPUT adapters that feed the producer lanes, plus the
// jitter primitive. Each is bounded, tenant-scoped and fails CLOSED: an
// unavailable source returns an error so the caller reports "unassessed", never
// an empty (falsely clean) result.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/chschema"
	"netops/backend/internal/hardening"
	"netops/backend/internal/oslog"
	"netops/backend/internal/threatlane"
)

// osResponseCap bounds the bytes read from one OpenSearch response (§9).
const osResponseCap = 32 << 20

// jitter returns base shifted by a uniform offset within ±(frac·base).
// crypto/rand because gosec forbids math/rand; on any rand failure the plain
// base is returned — jitter is best-effort, the schedule must never fail.
func jitter(base time.Duration, frac float64) time.Duration {
	if base <= 0 || frac <= 0 {
		return base
	}
	span := int64(float64(base) * frac * 2)
	if span <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return base
	}
	return base - time.Duration(int64(float64(base)*frac)) + time.Duration(n.Int64())
}

// ── device-log source (OpenSearch syslog) ───────────────────────────────────

// LogSource returns the bounded, tenant-scoped device-log reader for a window.
// It names ONLY the caller's tenant indices (oslog.TenantIndexPattern) and
// carries the per-doc tenant clause (oslog.TenantFilter) underneath — the same
// two-layer §3a chokepoint the security read API uses.
func (l *Lane) LogSource(tenant string, devices []Device, since, until time.Time) threatlane.LogSource {
	return &osLogSource{
		search: l.deps.Search, tenant: tenant, devices: devices, since: since, until: until,
	}
}

type osLogSource struct {
	search  func(method, path string, body any) (*http.Response, error)
	tenant  string
	devices []Device
	since   time.Time
	until   time.Time
}

// mnemonicRe extracts a Cisco-style facility-severity-mnemonic tag from a raw
// syslog message (`%SYS-5-CONFIG_I: …`). threatlane's rules key on the mnemonic
// where one exists; normalizing it out of the message is the step its LogSource
// contract says the CALLER owns.
var mnemonicRe = regexp.MustCompile(`%([A-Za-z0-9_]+-\d-[A-Za-z0-9_]+)`)

// LogEvents implements threatlane.LogSource.
func (s *osLogSource) LogEvents(_ context.Context) ([]threatlane.LogEvent, error) {
	keys, addrs := deviceKeys(s.devices)
	index := oslog.TenantIndexPattern("syslog", s.tenant, false)
	filters := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{
		"gte": s.since.UTC().Format(time.RFC3339),
		"lt":  s.until.UTC().Format(time.RFC3339),
	}}}}
	if tf := oslog.TenantFilter(s.tenant, false, keys, addrs); tf != nil {
		filters = append(filters, tf)
	}
	body := map[string]any{
		"size":  LogScanMax,
		"sort":  []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": map[string]any{"filter": filters}},
	}
	resp, err := s.search(http.MethodPost, "/"+index+"/_search?ignore_unavailable=true", body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, osResponseCap))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("seclane: syslog search returned status %d", resp.StatusCode)
	}
	var parsed struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	byName := map[string]Device{}
	for _, d := range s.devices {
		if d.Name != "" {
			byName[strings.ToLower(d.Name)] = d
		}
		if d.ID != "" {
			byName[strings.ToLower(d.ID)] = d
		}
	}
	tenant := strings.ToLower(strings.TrimSpace(s.tenant))
	out := make([]threatlane.LogEvent, 0, len(parsed.Hits.Hits))
	for _, h := range parsed.Hits.Hits {
		src := h.Source
		host := str(src, "hostname")
		if host == "" {
			host = str(src, "host")
		}
		msg := str(src, "message")
		ev := threatlane.LogEvent{
			// §3a: the SCAN tenant — the index pattern and the per-doc filter
			// already bounded this document to it. NEVER a value read out of the
			// document, which is attacker-influenceable input (§3 zero trust).
			TenantID: tenant,
			Hostname: host,
			DeviceID: host,
			Facility: str(src, "facility"),
			Severity: str(src, "severity"),
			Message:  msg,
			User:     str(src, "user"),
			Time:     docTime(src),
		}
		if m := mnemonicRe.FindStringSubmatch(msg); len(m) == 2 {
			ev.Mnemonic = m[1]
		}
		if d, ok := byName[strings.ToLower(host)]; ok {
			ev.DeviceID = d.ID
			ev.Hostname = d.Name
			ev.Platform = d.Platform()
		}
		if ev.DeviceID == "" {
			continue // nothing to ground on — a subject is never invented
		}
		out = append(out, ev)
	}
	return out, nil
}

// ── flow source (ClickHouse netops.flows) ───────────────────────────────────

// FlowSource returns the bounded, tenant-scoped flow reader for a window. The
// read carries the caller's tenant_scope (→ the ClickHouse row policies) AND an
// explicit tenant_id predicate — defense in depth, as every flow handler does.
func (l *Lane) FlowSource(tenant string, devices []Device, window time.Duration) threatlane.FlowSource {
	return &chFlowSource{query: l.deps.CHQuery, tenant: tenant, devices: devices, window: window}
}

type chFlowSource struct {
	query   func(ctx context.Context, scope, sql string) ([]map[string]any, error)
	tenant  string
	devices []Device
	window  time.Duration
}

// tenantSQLSafe is the strict allowlist a tenant id must satisfy before it may
// appear in SQL. Tenant ids are minted through the platform's slug validator,
// but a value reaching a query builder is re-validated at the boundary (§3).
var tenantSQLSafe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:@+-]{0,62}$`)

// Flows implements threatlane.FlowSource.
func (s *chFlowSource) Flows(ctx context.Context) ([]threatlane.FlowRecord, error) {
	tenant := strings.ToLower(strings.TrimSpace(s.tenant))
	if !tenantSQLSafe.MatchString(tenant) {
		return nil, fmt.Errorf("seclane: flow read refused — %q is not a valid tenant scope token", tenant)
	}
	secs := int(s.window / time.Second)
	if secs <= 0 {
		secs = int(DefaultScanInterval / time.Second)
	}
	sql := `
SELECT ` + chschema.ISO("ts") + ` AS ts_s,
       sampler_address    AS sampler_address,
       src_addr           AS src_addr,
       dst_addr           AS dst_addr,
       toUInt32(dst_port) AS dst_port,
       toUInt32(proto)    AS proto,
       toUInt64(bytes   * if(sampling_rate = 0, 1, sampling_rate)) AS bytes_scaled,
       toUInt64(packets * if(sampling_rate = 0, 1, sampling_rate)) AS packets_scaled
  FROM netops.flows
 WHERE ts >= now() - INTERVAL ` + itoa(secs) + ` SECOND
   AND tenant_id = '` + tenant + `'
 ORDER BY ts ASC
 LIMIT ` + itoa(FlowScanMax) + `
 FORMAT JSON`
	rows, err := s.query(ctx, tenant, sql)
	if err != nil {
		return nil, err
	}
	byAddr := map[string]Device{}
	for _, d := range s.devices {
		if d.Address != "" {
			byAddr[d.Address] = d
		}
	}
	out := make([]threatlane.FlowRecord, 0, len(rows))
	for _, row := range rows {
		sampler := str(row, "sampler_address")
		rec := threatlane.FlowRecord{
			// §3a: the scan tenant; the row policy already bounded the read.
			TenantID: tenant,
			DeviceID: sampler,
			Hostname: sampler,
			SrcAddr:  str(row, "src_addr"),
			DstAddr:  str(row, "dst_addr"),
			DstPort:  int(num(row, "dst_port")),
			Proto:    int(num(row, "proto")),
			Bytes:    uint64(num(row, "bytes_scaled")),
			Packets:  uint64(num(row, "packets_scaled")),
		}
		if d, ok := byAddr[sampler]; ok {
			rec.DeviceID = d.ID
			rec.Hostname = d.Name
		}
		if rec.DeviceID == "" {
			continue
		}
		if ts, err := oslog.ParseTimeFlexible(str(row, "ts_s")); err == nil {
			rec.Start = ts.UTC()
		}
		out = append(out, rec)
	}
	return out, nil
}

// ── seam resolver (the §5e exposure input) ──────────────────────────────────

// UntrustedSeamType is the canonical seam that hands packets to the public
// internet. DX / VPN / SDWAN / CLOUD_BACKBONE are private or tunnelled
// transports and are NOT, on their own, evidence that a management service is
// internet-reachable — calling them untrusted would manufacture critical
// exposure findings the topology does not support.
const UntrustedSeamType = "DIA"

// seamResolver builds the per-device seam view for one tenant. Fail CLOSED: if
// the seam model is unreadable or silent for a device, the exposure evaluator
// gets ok=false and emits StatusUnknown — it must never conclude "not exposed"
// from an absence of data.
func (l *Lane) seamResolver(ctx context.Context, tenant string) hardening.SeamResolver {
	res := &seamResolver{byDevice: map[string][]hardening.SeamInfo{}}
	rows, err := l.deps.Seams(ctx, tenant)
	if err != nil {
		l.deps.LogWarn("seam inventory unreadable — exposure probes report UNASSESSED, never clear",
			map[string]any{"tenant_seg": l.deps.TenantSeg(tenant), "err": err.Error()})
		return res
	}
	for _, r := range rows {
		dev := strings.ToLower(strings.TrimSpace(r.OnPrem))
		if dev == "" {
			continue
		}
		res.byDevice[dev] = append(res.byDevice[dev], hardening.SeamInfo{
			SeamID:    r.SeamID,
			SeamType:  r.SeamType,
			Interface: r.Interface,
			Untrusted: r.SeamType == UntrustedSeamType,
		})
	}
	return res
}

type seamResolver struct {
	byDevice map[string][]hardening.SeamInfo
}

// DeviceSeams implements hardening.SeamResolver.
func (r *seamResolver) DeviceSeams(_ context.Context, deviceID string) ([]hardening.SeamInfo, bool, error) {
	seams, ok := r.byDevice[strings.ToLower(strings.TrimSpace(deviceID))]
	if !ok {
		return nil, false, nil
	}
	out := make([]hardening.SeamInfo, len(seams))
	copy(out, seams)
	return out, true, nil
}

// ── small helpers ───────────────────────────────────────────────────────────

func str(m map[string]any, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	return ""
}

func num(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case string:
		var f float64
		if _, err := fmt.Sscanf(v, "%g", &f); err == nil {
			return f
		}
	}
	return 0
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func docTime(src map[string]any) time.Time {
	for _, key := range []string{"timestamp", "@timestamp", "ts"} {
		if raw := str(src, key); raw != "" {
			if t, err := oslog.ParseTimeFlexible(raw); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// deviceKeys returns the device name/id keys and addresses that let the per-doc
// tenant filter admit UNTAGGED documents emitted by the tenant's own devices —
// the populate-time fallback every log read uses.
func deviceKeys(devs []Device) (keys, addrs []string) {
	seen := map[string]bool{}
	for _, d := range devs {
		for _, k := range []string{d.ID, d.Name} {
			if k != "" && !seen["k:"+k] {
				seen["k:"+k] = true
				keys = append(keys, k)
			}
		}
		if d.Address != "" && !seen["a:"+d.Address] {
			seen["a:"+d.Address] = true
			addrs = append(addrs, d.Address)
		}
	}
	sort.Strings(keys)
	sort.Strings(addrs)
	return keys, addrs
}

// compile-time assertions that the adapters satisfy the producer contracts.
var (
	_ threatlane.LogSource   = (*osLogSource)(nil)
	_ threatlane.FlowSource  = (*chFlowSource)(nil)
	_ hardening.SeamResolver = (*seamResolver)(nil)
)

// TenantSeg renders a tenant id as the storage/metric segment token. It
// delegates to the SINGLE derivation the ingest pipeline uses, so a metric
// label and an index name can never disagree about which tenant a run was for.
func TenantSeg(tenant string) string { return oslog.IndexTenantSeg(tenant) }
