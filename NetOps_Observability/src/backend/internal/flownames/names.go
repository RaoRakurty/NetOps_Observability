// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flownames

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

	"netops/backend/internal/applog"
	"netops/backend/models"
)

// names.go: keeps netops.iface_names, the table the flows API
// names interfaces through (tracker 387 PR 13b; internal/chschema/
// iface_names_schema.go explains why it is a table and a JOIN).
//
// Every minute it builds one row per (tenant, exporter address, ifIndex) from
// inventory and the ifIndex bridge the SNMP collector already publishes
// (collectors.FetchIfIndexMap, the same data entity_resolver.json carries), and
// writes them when the set changed, or every RefreshEvery so the 8-day
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
	// MaxRows bounds one export: ~1k devices x 200 ports. Past it the
	// rest are dropped, counted and logged, never silently.
	MaxRows = 200_000
	// NameMaxRunes bounds one device-reported name (SNMP data is untrusted).
	NameMaxRunes = 128
	// RefreshEvery re-writes an unchanged set well inside the TTL.
	RefreshEvery = 6 * time.Hour
	// CoverageEvery is how often the uncovered-exporter count is read.
	CoverageEvery = 5 * time.Minute
	// SentinelZero and SentinelNone are IPFIX "no interface".
	SentinelZero uint32 = 0
	SentinelNone uint32 = 4294967295
)

// Row is one netops.iface_names row (JSONEachRow).
type Row struct {
	TenantID     string `json:"tenant_id"`
	DeviceID     string `json:"device_id"`
	ExporterAddr string `json:"exporter_addr"`
	IfIndex      uint32 `json:"ifindex"`
	IfName       string `json:"ifname"`
	IfAlias      string `json:"ifalias"`
	Source       string `json:"source"`
}

// key is the lookup key: the ROW's tenant, exporter and index.
type key struct {
	tenant, exporter string
	ifindex          uint32
}

// IndexSource reads the ifIndex bridge; injectable so tests need no Valkey.
type IndexSource func(ctx context.Context) (map[string]map[string]string, error)

// Bridge is the merged interface bridge as the export reads it (tracker 387
// PR 13a: the SNMP collector's rows and the controllers', internal/ifbridge).
type Bridge struct {
	Index  map[string]map[string]string // device → ifIndex → ifName
	Alias  map[string]map[string]string // device → ifIndex → description (ifAlias / controller desc)
	Source map[string]map[string]string // device → ifIndex → "snmp" | "nms"; absent = "snmp"
}

// BridgeSource reads the merged bridge; injectable so tests need no Valkey.
type BridgeSource func(ctx context.Context) (Bridge, error)

// Writer writes one row batch; injectable so tests need no ClickHouse.
type Writer func(ctx context.Context, rows []map[string]any) error

// Exporter owns the export loop, the in-memory name set and the metrics.
type Exporter struct {
	mu    sync.RWMutex
	names map[key]string

	lastHash  [32]byte
	lastWrite time.Time

	rows          atomic.Int64
	truncated     atomic.Uint64
	writeFailures atomic.Uint64
	readFailures  atomic.Uint64
	uncovered     atomic.Int64 // -1 = not measured yet / unreadable
	lastSuccess   atomic.Int64 // unix seconds of the last good export
}

func NewExporter() *Exporter {
	e := &Exporter{names: map[key]string{}}
	e.uncovered.Store(-1)
	return e
}

// NormAddr reduces an inventory address (host or host:port) to the
// canonical IP text flows carry in sampler_address; "" when it is no IP.
func NormAddr(a string) string {
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

// clampName trims and bounds one device-reported name.
func clampName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > NameMaxRunes {
		s = string(r[:NameMaxRunes])
	}
	return s
}

// BuildRows is the pure core: devices x ifIndex map → rows, sorted,
// capped. truncated counts the rows the cap dropped.
func BuildRows(devs []models.Device, tenantOf func(models.Device) string, ifidx map[string]map[string]string, maxRows int) (rows []Row, truncated int) {
	return BuildBridgeRows(devs, tenantOf, Bridge{Index: ifidx}, maxRows)
}

// BuildBridgeRows is BuildRows over the merged bridge: each row also carries
// the port's description and the source that named it.
func BuildBridgeRows(devs []models.Device, tenantOf func(models.Device) string, br Bridge, maxRows int) (rows []Row, truncated int) {
	ifidx := br.Index
	type dev struct{ id, tenant, addr string }
	byID := map[string]dev{}
	claim := map[string]map[string]int{} // tenant → address → devices claiming it
	for _, d := range devs {
		addr := NormAddr(d.Address)
		if d.ID == "" || addr == "" {
			continue
		}
		t := tenantOf(d)
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
			name := clampName(v)
			if i == SentinelZero || i == SentinelNone || name == "" {
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
			key := strconv.FormatUint(uint64(i), 10)
			src := br.Source[id][key]
			if src != "nms" {
				src = "snmp"
			}
			rows = append(rows, Row{
				TenantID: d.tenant, DeviceID: d.id, ExporterAddr: d.addr,
				IfIndex: i, IfName: names[i], IfAlias: clampName(br.Alias[id][key]), Source: src,
			})
		}
	}
	return rows, truncated
}

// lookup names (tenant, exporter, ifindex) from the last export. ok=false for
// a sentinel or a miss. The tenant is the CALLER-SUPPLIED row tenant: a
// document's own tenant_id, never the principal's.
func (e *Exporter) Lookup(tenant, exporter string, ifindex uint32) (string, bool) {
	if e == nil || ifindex == SentinelZero || ifindex == SentinelNone {
		return "", false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	n, ok := e.names[key{tenant: tenant, exporter: NormAddr(exporter), ifindex: ifindex}]
	return n, ok
}

// install swaps in a new name set.
func (e *Exporter) Install(rows []Row) {
	m := make(map[key]string, len(rows))
	for _, r := range rows {
		m[key{tenant: r.TenantID, exporter: r.ExporterAddr, ifindex: r.IfIndex}] = r.IfName
	}
	e.mu.Lock()
	e.names = m
	e.mu.Unlock()
	e.rows.Store(int64(len(rows)))
}

// cycle runs one export: read the bridge, build, write when needed.
func (e *Exporter) Cycle(ctx context.Context, devs []models.Device, tenantOf func(models.Device) string, read IndexSource, write Writer, now time.Time) error {
	return e.CycleBridge(ctx, devs, tenantOf, func(ctx context.Context) (Bridge, error) {
		m, err := read(ctx)
		return Bridge{Index: m}, err
	}, write, now)
}

// CycleBridge is Cycle over the merged bridge (names, descriptions, sources).
func (e *Exporter) CycleBridge(ctx context.Context, devs []models.Device, tenantOf func(models.Device) string, read BridgeSource, write Writer, now time.Time) error {
	br, err := read(ctx)
	if err != nil {
		// Keep the last good set: a read failure is not "no names" (tracker 307).
		e.readFailures.Add(1)
		return fmt.Errorf("ifIndex bridge unread, interface names keep the last export: %w", err)
	}
	rows, truncated := BuildBridgeRows(devs, tenantOf, br, MaxRows)
	if truncated > 0 {
		e.truncated.Add(uint64(truncated))
		applog.Warn("iface-names", "interface-name export hit its row cap; the rest stay unnamed", map[string]any{
			"cap": MaxRows, "dropped": truncated,
		})
	}
	e.Install(rows)
	body, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("marshal interface names: %w", err)
	}
	h := sha256.Sum256(body)
	if h == e.lastHash && now.Sub(e.lastWrite) < RefreshEvery {
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

// UncoveredSQL counts exporters seen in flows over the last hour
// that have no interface name at all. Platform-scope read (worker).
const UncoveredSQL = `SELECT uniqExact(sampler_address) AS n
  FROM netops.flows
 WHERE ts >= now() - INTERVAL 1 HOUR
   AND (tenant_id, sampler_address) NOT IN (SELECT tenant_id, exporter_addr FROM netops.iface_names)
 FORMAT JSON`

// measureCoverage refreshes the uncovered-exporter gauge.
// Query runs one platform-scope (tenant_scope __all__) read and returns its rows.
type Query func(ctx context.Context, sql string) ([]map[string]any, error)

func (e *Exporter) MeasureCoverage(ctx context.Context, query Query) error {
	rows, err := query(ctx, UncoveredSQL)
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
func (e *Exporter) WriteMetrics(w io.Writer) {
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
