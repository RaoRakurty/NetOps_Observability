// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// iface_names_export.go: keeps netops.iface_names, the table the flows API
// names interfaces through (tracker 387 PR 13b; internal/chschema/
// iface_names_schema.go explains why it is a table and a JOIN).
//
// Every minute it builds one row per (tenant, exporter address, ifIndex) from
// inventory and the ifIndex bridge the SNMP collector already publishes
// (collectors.FetchIfIndexMap, the same data entity_resolver.json carries), and
// writes them when the set changed, or every ifaceNamesRefreshEvery so the 8-day
// TTL never ages out a live name. It only READS the bridge.
//
// Tenant isolation (§3a): a row's tenant is its DEVICE's tenant from inventory
// (deviceTenant), never a request value, and the exporter address is the
// device's own management address. The same rows, held in memory, name the
// Logs page's sampled flow documents, looked up by each document's own tenant.
//
// Never invents a name: ifIndex 0 and 4294967295 are the IPFIX "no interface"
// sentinels and never get a row; an index the device did not name stays a
// number; an address two devices of one tenant share names neither.

const (
	// ifaceNamesMaxRows bounds one export: ~1k devices x 200 ports. Past it the
	// rest are dropped, counted and logged, never silently.
	ifaceNamesMaxRows = 200_000
	// ifaceNameMaxRunes bounds one device-reported name (SNMP data is untrusted).
	ifaceNameMaxRunes = 128
	// ifaceNamesRefreshEvery re-writes an unchanged set well inside the TTL.
	ifaceNamesRefreshEvery = 6 * time.Hour
	// ifaceNamesCoverageEvery is how often the uncovered-exporter count is read.
	ifaceNamesCoverageEvery = 5 * time.Minute
	// ifaceNamesSentinelZero and ifaceNamesSentinelNone are IPFIX "no interface".
	ifaceNamesSentinelZero uint32 = 0
	ifaceNamesSentinelNone uint32 = 4294967295
)

// ifaceNameRow is one netops.iface_names row (JSONEachRow).
type ifaceNameRow struct {
	TenantID     string `json:"tenant_id"`
	DeviceID     string `json:"device_id"`
	ExporterAddr string `json:"exporter_addr"`
	IfIndex      uint32 `json:"ifindex"`
	IfName       string `json:"ifname"`
	IfAlias      string `json:"ifalias"`
	Source       string `json:"source"`
}

// ifaceNameKey is the lookup key: the ROW's tenant, exporter and index.
type ifaceNameKey struct {
	tenant, exporter string
	ifindex          uint32
}

// ifaceIndexSource reads the ifIndex bridge; injectable so tests need no Valkey.
type ifaceIndexSource func(ctx context.Context) (map[string]map[string]string, error)

// ifaceNameWriter writes one row batch; injectable so tests need no ClickHouse.
type ifaceNameWriter func(ctx context.Context, rows []map[string]any) error

// ifaceNameExporter owns the export loop, the in-memory name set and the metrics.
type ifaceNameExporter struct {
	mu    sync.RWMutex
	names map[ifaceNameKey]string

	lastHash  [32]byte
	lastWrite time.Time

	rows          atomic.Int64
	truncated     atomic.Uint64
	writeFailures atomic.Uint64
	readFailures  atomic.Uint64
	uncovered     atomic.Int64 // -1 = not measured yet / unreadable
	lastSuccess   atomic.Int64 // unix seconds of the last good export
}

func newIfaceNameExporter() *ifaceNameExporter {
	e := &ifaceNameExporter{names: map[ifaceNameKey]string{}}
	e.uncovered.Store(-1)
	return e
}

// normIfaceAddr reduces an inventory address (host or host:port) to the
// canonical IP text flows carry in sampler_address; "" when it is no IP.
func normIfaceAddr(a string) string {
	a = strings.TrimSpace(a)
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	ip := net.ParseIP(a)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// clampIfaceName trims and bounds one device-reported name.
func clampIfaceName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > ifaceNameMaxRunes {
		s = string(r[:ifaceNameMaxRunes])
	}
	return s
}

// buildIfaceNameRows is the pure core: devices x ifIndex map → rows, sorted,
// capped. truncated counts the rows the cap dropped.
func buildIfaceNameRows(devs []models.Device, ifidx map[string]map[string]string, maxRows int) (rows []ifaceNameRow, truncated int) {
	type dev struct{ id, tenant, addr string }
	byID := map[string]dev{}
	claim := map[string]map[string]int{} // tenant → address → devices claiming it
	for _, d := range devs {
		addr := normIfaceAddr(d.Address)
		if d.ID == "" || addr == "" {
			continue
		}
		t := deviceTenant(d)
		byID[d.ID] = dev{id: d.ID, tenant: t, addr: addr}
		if claim[t] == nil {
			claim[t] = map[string]int{}
		}
		claim[t][addr]++
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := byID[id]
		if claim[d.tenant][d.addr] != 1 {
			continue // two devices of one tenant share it: name neither
		}
		m := ifidx[id]
		idxs := make([]uint32, 0, len(m))
		names := make(map[uint32]string, len(m))
		for k, v := range m {
			n, err := strconv.ParseUint(strings.TrimSpace(k), 10, 32)
			if err != nil {
				continue
			}
			i := uint32(n)
			name := clampIfaceName(v)
			if i == ifaceNamesSentinelZero || i == ifaceNamesSentinelNone || name == "" {
				continue
			}
			idxs = append(idxs, i)
			names[i] = name
		}
		sort.Slice(idxs, func(a, b int) bool { return idxs[a] < idxs[b] })
		for _, i := range idxs {
			if len(rows) >= maxRows {
				truncated++
				continue
			}
			rows = append(rows, ifaceNameRow{
				TenantID: d.tenant, DeviceID: d.id, ExporterAddr: d.addr,
				IfIndex: i, IfName: names[i], Source: "snmp",
			})
		}
	}
	return rows, truncated
}

// lookup names (tenant, exporter, ifindex) from the last export. ok=false for
// a sentinel or a miss. The tenant is the CALLER-SUPPLIED row tenant: a
// document's own tenant_id, never the principal's.
func (e *ifaceNameExporter) lookup(tenant, exporter string, ifindex uint32) (string, bool) {
	if e == nil || ifindex == ifaceNamesSentinelZero || ifindex == ifaceNamesSentinelNone {
		return "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	n, ok := e.names[ifaceNameKey{tenant: tenant, exporter: normIfaceAddr(exporter), ifindex: ifindex}]
	return n, ok
}

// install swaps in a new name set.
func (e *ifaceNameExporter) install(rows []ifaceNameRow) {
	m := make(map[ifaceNameKey]string, len(rows))
	for _, r := range rows {
		m[ifaceNameKey{tenant: r.TenantID, exporter: r.ExporterAddr, ifindex: r.IfIndex}] = r.IfName
	}
	e.mu.Lock()
	e.names = m
	e.mu.Unlock()
	e.rows.Store(int64(len(rows)))
}

// cycle runs one export: read the bridge, build, write when needed.
func (e *ifaceNameExporter) cycle(ctx context.Context, devs []models.Device, read ifaceIndexSource, write ifaceNameWriter, now time.Time) error {
	ifidx, err := read(ctx)
	if err != nil {
		// Keep the last good set: a read failure is not "no names" (tracker 307).
		e.readFailures.Add(1)
		return fmt.Errorf("ifIndex bridge unread, interface names keep the last export: %w", err)
	}
	rows, truncated := buildIfaceNameRows(devs, ifidx, ifaceNamesMaxRows)
	if truncated > 0 {
		e.truncated.Add(uint64(truncated))
		logWarn("iface-names", "interface-name export hit its row cap; the rest stay unnamed", map[string]any{
			"cap": ifaceNamesMaxRows, "dropped": truncated,
		})
	}
	e.install(rows)
	body, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("marshal interface names: %w", err)
	}
	h := sha256.Sum256(body)
	if h == e.lastHash && now.Sub(e.lastWrite) < ifaceNamesRefreshEvery {
		e.lastSuccess.Store(now.Unix())
		return nil // unchanged and fresh: nothing to write
	}
	if len(rows) > 0 {
		batch := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			batch = append(batch, map[string]any{
				"tenant_id": r.TenantID, "device_id": r.DeviceID, "exporter_addr": r.ExporterAddr,
				"ifindex": r.IfIndex, "ifname": r.IfName, "ifalias": r.IfAlias, "source": r.Source,
			})
		}
		if err := write(ctx, batch); err != nil {
			e.writeFailures.Add(1)
			return fmt.Errorf("write netops.iface_names: %w", err)
		}
	}
	e.lastHash, e.lastWrite = h, now
	e.lastSuccess.Store(now.Unix())
	return nil
}

// ifaceNamesUncoveredSQL counts exporters seen in flows over the last hour
// that have no interface name at all. Platform-scope read (worker).
const ifaceNamesUncoveredSQL = `SELECT uniqExact(sampler_address) AS n
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 1 HOUR
   AND (tenant_id, sampler_address) NOT IN (SELECT tenant_id, exporter_addr FROM netops.iface_names)
 FORMAT JSON`

// measureCoverage refreshes the uncovered-exporter gauge.
func (e *ifaceNameExporter) measureCoverage(ctx context.Context) error {
	rows, err := chSelect(ctx, "__all__", ifaceNamesUncoveredSQL, "worker:iface-names")
	if err != nil {
		e.uncovered.Store(-1)
		return err
	}
	n := int64(0)
	if len(rows) == 1 {
		switch v := rows[0]["n"].(type) {
		case float64:
			n = int64(v)
		case string:
			if p, perr := strconv.ParseInt(v, 10, 64); perr == nil {
				n = p
			}
		}
	}
	e.uncovered.Store(n)
	return nil
}

// WriteMetrics renders the export's gauges and counters. No tenant or device
// label: the series are platform plumbing on the shared exporter.
func (e *ifaceNameExporter) WriteMetrics(w io.Writer) {
	if e == nil {
		return
	}
	fmt.Fprintf(w, "# HELP netops_iface_names_rows Interface names the flows API can resolve, from the last export.\n")
	fmt.Fprintf(w, "# TYPE netops_iface_names_rows gauge\n")
	fmt.Fprintf(w, "netops_iface_names_rows{source=\"snmp\"} %d\n", e.rows.Load())
	fmt.Fprintf(w, "# HELP netops_iface_names_exporters_uncovered Flow exporters seen in the last hour with no interface name (-1 = not measured).\n")
	fmt.Fprintf(w, "# TYPE netops_iface_names_exporters_uncovered gauge\n")
	fmt.Fprintf(w, "netops_iface_names_exporters_uncovered %d\n", e.uncovered.Load())
	fmt.Fprintf(w, "# HELP netops_iface_names_truncated_total Interface names dropped by the export row cap.\n")
	fmt.Fprintf(w, "# TYPE netops_iface_names_truncated_total counter\n")
	fmt.Fprintf(w, "netops_iface_names_truncated_total %d\n", e.truncated.Load())
	fmt.Fprintf(w, "# HELP netops_iface_names_failures_total Interface-name export failures, by stage.\n")
	fmt.Fprintf(w, "# TYPE netops_iface_names_failures_total counter\n")
	fmt.Fprintf(w, "netops_iface_names_failures_total{stage=\"read\"} %d\n", e.readFailures.Load())
	fmt.Fprintf(w, "netops_iface_names_failures_total{stage=\"write\"} %d\n", e.writeFailures.Load())
	fmt.Fprintf(w, "# HELP netops_iface_names_last_success_timestamp_seconds When the interface-name export last completed.\n")
	fmt.Fprintf(w, "# TYPE netops_iface_names_last_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "netops_iface_names_last_success_timestamp_seconds %d\n", e.lastSuccess.Load())
}

// startIfaceNamesExport runs the export every minute until ctx ends. No-op
// without ClickHouse or discovery.
func (s *server) startIfaceNamesExport(ctx context.Context) {
	if s.ifaceNames == nil || s.discovery == nil || envOr("CLICKHOUSE_URL", "") == "" {
		return
	}
	write := func(ctx context.Context, rows []map[string]any) error {
		// One mixed-tenant batch, so the scope is the deliberate "__all__"
		// (chInsertJSON's contract); each row carries its device's tenant.
		return chInsertJSON(ctx, "netops.iface_names", "__all__", rows)
	}
	s.workers.start("iface-names-export", func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		var lastCoverage time.Time
		for {
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			now := time.Now()
			if err := s.ifaceNames.cycle(cctx, s.discovery.Devices(), collectors.FetchIfIndexMap, write, now); err != nil {
				logWarn("iface-names", "interface-name export failed", map[string]any{"error": err.Error()})
			}
			if now.Sub(lastCoverage) >= ifaceNamesCoverageEvery {
				lastCoverage = now
				if err := s.ifaceNames.measureCoverage(cctx); err != nil {
					logWarn("iface-names", "uncovered-exporter count unread", map[string]any{"error": err.Error()})
				}
			}
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
}
