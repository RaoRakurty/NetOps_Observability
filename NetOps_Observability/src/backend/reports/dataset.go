package reports

// dataset.go — the report DATASET builders and their legacy text renderers
// (Phase-2 W2.1, extracted from package main's report_scheduler.go). Each
// dataset folds tenant-scoped inventory/alert/telemetry reads into the
// ViewModel sections the HTML/XLSX/PDF renderers consume. All reads go
// through the DataSource seam the caller wires — this package performs no
// I/O of its own and never sees a request principal: tenant scoping is the
// closures' contract (default-closed, the report owner's visibility).

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/models"
)

// DataSource is the seam the scheduler wires: tenant-scoped inventory and
// alert reads, the bounded ClickHouse line read, the VictoriaMetrics instant
// map, and the process start time (platform-uptime line).
type DataSource struct {
	Devices    func(tenant string) []models.Device
	Alerts     func(tenant string) []models.Alert
	DeviceKeys func(tenant string) (keys []string, platform bool)
	CHQuery    func(sql string) []string
	VMMap      func(query string) map[string]float64
	StartedAt  time.Time
}

// firstNonEmpty and sqlInList are duplicated at the boundary per the
// no-utils rule (main keeps its own copies for its other consumers).
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// toMap converts any JSON-encodable value to a generic map (duplicated from
// main's search helpers — the marshal round-trip, NOT a type assertion, so
// struct values convert too).
func toMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func sqlInList(vals []string) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, "'"+strings.ReplaceAll(v, "'", "''")+"'")
	}
	return strings.Join(parts, ", ")
}

func AlertFromViewModel(vm ViewModel, now time.Time) models.Alert {
	var b strings.Builder
	if vm.Description != "" {
		b.WriteString(vm.Description + "\n\n")
	}
	for _, s := range vm.Sections {
		b.WriteString(s.Title + "\n")
		if s.Note != "" {
			b.WriteString(s.Note + "\n")
		}
		for _, row := range s.Rows {
			b.WriteString("  " + strings.Join(row, "  ") + "\n")
		}
		b.WriteString("\n")
	}
	return models.Alert{
		ID:          "report-" + vm.ReportID,
		Rule:        "report",
		Severity:    firstNonEmpty(vm.Severity, "info"),
		Summary:     "Report: " + vm.ReportName + " — " + vm.Summary,
		Description: strings.TrimSpace(b.String()),
		Labels:      map[string]string{"report_id": vm.ReportID, "kind": vm.Kind},
		FiredAt:     now,
	}
}

func (ds DataSource) DatasetAlerts(tenant string) (string, []Section) {
	active := ds.Alerts(tenant)
	bySev := map[string]int{}
	byRule := map[string]int{}
	for _, a := range active {
		bySev[strings.ToLower(a.Severity)]++
		byRule[firstNonEmpty(a.Rule, "—")]++
	}
	crit := bySev["critical"] + bySev["error"]
	warn := bySev["warning"]
	summary := fmt.Sprintf("%d active alert(s) · %d critical/error · %d warning", len(active), crit, warn)
	if len(active) == 0 {
		return "0 active alerts — all clear", []Section{{Title: "Active alerts", Note: "No active alerts. The fleet is operating within thresholds."}}
	}
	var sevRows [][]string
	for _, s := range []string{"critical", "error", "warning", "notice", "info"} {
		if n := bySev[s]; n > 0 {
			sevRows = append(sevRows, []string{titleCase(s), strconv.Itoa(n), pctStr(n, len(active))})
		}
	}
	// Top firing rules — what's noisiest, an at-a-glance triage signal.
	ruleRows := topCounts(byRule, 5)
	sort.Slice(active, func(i, j int) bool { return active[i].FiredAt.After(active[j].FiredAt) })
	var recent [][]string
	for i, a := range active {
		if i >= 25 {
			break
		}
		recent = append(recent, []string{titleCase(a.Severity), firstNonEmpty(a.DeviceID, "—"), a.Summary, agoStr(a.FiredAt, time.Now())})
	}
	secs := []Section{
		{Title: "By severity", Header: []string{"Severity", "Count", "Share"}, Rows: sevRows},
	}
	if len(ruleRows) > 0 {
		secs = append(secs, Section{Title: "Top firing rules", Header: []string{"Rule", "Alerts"}, Rows: ruleRows})
	}
	secs = append(secs, Section{Title: "Most recent", Header: []string{"Severity", "Device", "Alert", "Age"}, Rows: recent})
	return summary, secs
}

func (ds DataSource) DatasetDevices(tenant string) (string, []Section) {
	devs := ds.Devices(tenant)
	if len(devs) == 0 {
		return "0 devices — discovery hasn't returned anything", []Section{{Title: "Devices", Note: "No devices discovered."}}
	}
	up, degraded, down, health := ds.fleetHealth(devs, time.Now())
	byVendor := map[string]int{}
	byType := map[string]int{}
	for _, d := range devs {
		byVendor[firstNonEmpty(titleCase(strings.ToLower(d.Vendor)), "Unknown")]++
		byType[firstNonEmpty(titleCase(d.Type), "Generic")]++
	}
	// Inventory table — name, address, classification, live health and freshness.
	var rows [][]string
	sort.Slice(devs, func(i, j int) bool {
		return firstNonEmpty(devs[i].Name, devs[i].ID) < firstNonEmpty(devs[j].Name, devs[j].ID)
	})
	now := time.Now()
	for _, d := range devs {
		name := firstNonEmpty(d.Name, d.ID)
		rows = append(rows, []string{
			name, d.Address,
			firstNonEmpty(titleCase(strings.ToLower(d.Vendor)), "—"),
			firstNonEmpty(titleCase(d.Type), "—"),
			health[d.ID],
			lastSeenStr(d.LastSeen, now),
		})
	}
	summary := fmt.Sprintf("%d device(s) · %d up · %d degraded · %d down", len(devs), up, degraded, down)
	secs := []Section{
		{Title: "Fleet status", Header: []string{"Status", "Devices", "Share"}, Rows: [][]string{
			{"Up", strconv.Itoa(up), pctStr(up, len(devs))},
			{"Degraded", strconv.Itoa(degraded), pctStr(degraded, len(devs))},
			{"Down", strconv.Itoa(down), pctStr(down, len(devs))},
		}},
		{Title: "By manufacturer", Header: []string{"Manufacturer", "Devices"}, Rows: topCounts(byVendor, 12)},
		{Title: "By type", Header: []string{"Type", "Devices"}, Rows: topCounts(byType, 12)},
		{Title: "Inventory", Header: []string{"Name", "Address", "Manufacturer", "Type", "Status", "Last seen"}, Rows: rows},
	}
	return summary, secs
}

func (ds DataSource) DatasetHealth(now time.Time, tenant string) (string, []Section) {
	uptime := now.Sub(ds.StartedAt).Round(time.Second)
	devs := ds.Devices(tenant)
	alerts := ds.Alerts(tenant)
	up, degraded, down, _ := ds.fleetHealth(devs, now)
	bySev := map[string]int{}
	for _, a := range alerts {
		bySev[strings.ToLower(a.Severity)]++
	}
	crit := bySev["critical"] + bySev["error"]
	warn := bySev["warning"]
	// Availability = share of the fleet with a healthy heartbeat right now.
	avail := 100.0
	if len(devs) > 0 {
		avail = float64(up) / float64(len(devs)) * 100
	}
	// Executive at-a-glance — the numbers leadership reads first.
	exec := [][]string{
		{"Fleet availability", fmt.Sprintf("%.1f%%", avail)},
		{"Devices monitored", strconv.Itoa(len(devs))},
		{"Up / Degraded / Down", fmt.Sprintf("%d / %d / %d", up, degraded, down)},
		{"Active alerts", strconv.Itoa(len(alerts))},
		{"Critical / Warning", fmt.Sprintf("%d / %d", crit, warn)},
		{"Platform uptime", uptime.String()},
	}
	secs := []Section{
		{Title: "Executive summary", Header: []string{"Metric", "Value"}, Rows: exec},
		{Title: "Fleet status", Header: []string{"Status", "Devices", "Share"}, Rows: [][]string{
			{"Up", strconv.Itoa(up), pctStr(up, max1(len(devs)))},
			{"Degraded", strconv.Itoa(degraded), pctStr(degraded, max1(len(devs)))},
			{"Down", strconv.Itoa(down), pctStr(down, max1(len(devs)))},
		}},
	}
	if len(alerts) > 0 {
		var sevRows [][]string
		for _, s := range []string{"critical", "error", "warning", "notice", "info"} {
			if n := bySev[s]; n > 0 {
				sevRows = append(sevRows, []string{titleCase(s), strconv.Itoa(n)})
			}
		}
		secs = append(secs, Section{Title: "Active alerts by severity", Header: []string{"Severity", "Count"}, Rows: sevRows})
	}
	return fmt.Sprintf("%.1f%% availability · %d devices · %d active alerts (%d critical)", avail, len(devs), len(alerts), crit), secs
}

func (ds DataSource) DatasetWAN(tenant string) (string, []Section) {
	keys, platform := ds.DeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = ds.CHQuery(`
SELECT local_device, remote_device, type, status,
       round(latency_ms,1), round(jitter_ms,1), round(loss_pct,2), round(qoe,1)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
	if len(rows) == 0 {
		return "no WAN/overlay links reporting", []Section{{Title: "WAN / overlay links", Note: "No tunnel/overlay telemetry yet."}}
	}
	up, degraded := 0, 0
	var qoeSum float64
	var data [][]string
	for _, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 8 {
			continue
		}
		if c[3] == "up" {
			up++
		} else {
			degraded++
		}
		qoeSum += parseFloatSafe(c[7])
		data = append(data, []string{c[0] + " ↔ " + c[1], c[2], titleCase(c[3]), c[4] + " ms", c[5] + " ms", c[6] + "%", c[7]})
	}
	avgQoE := 0.0
	if len(data) > 0 {
		avgQoE = qoeSum / float64(len(data))
	}
	summary := fmt.Sprintf("%d link(s) · %d up · %d degraded · avg QoE %.1f", len(rows), up, degraded, avgQoE)
	return summary, []Section{
		{Title: "Overview", Header: []string{"Metric", "Value"}, Rows: [][]string{
			{"Links monitored", strconv.Itoa(len(rows))},
			{"Up / Degraded", fmt.Sprintf("%d / %d", up, degraded)},
			{"Average QoE", fmt.Sprintf("%.1f", avgQoE)},
		}},
		{Title: "WAN / overlay links", Header: []string{"Link", "Type", "Status", "Latency", "Jitter", "Loss", "QoE"}, Rows: data},
	}
}

func (ds DataSource) DatasetSecurity(tenant string) (string, []Section) {
	keys, platform := ds.DeviceKeys(tenant)
	var sev, recent []string
	if platform || len(keys) > 0 {
		cond := findingsReportCond(platform, keys)
		sev = ds.CHQuery(`
SELECT severity, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 GROUP BY severity
 ORDER BY count() DESC
 FORMAT TSV`)
		recent = ds.CHQuery(`
SELECT severity, device, summary
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 ORDER BY ts DESC
 LIMIT 10
 FORMAT TSV`)
	}
	var secs []Section
	total := 0
	if len(sev) == 0 {
		secs = append(secs, Section{Title: "Findings (24h)", Note: "No findings in the last 24h."})
	} else {
		var sevRows [][]string
		for _, r := range sev {
			c := strings.Split(r, "\t")
			if len(c) == 2 {
				sevRows = append(sevRows, []string{c[0], c[1]})
				total += atoiSafe(c[1])
			}
		}
		secs = append(secs, Section{Title: "By severity (24h)", Header: []string{"Severity", "Count"}, Rows: sevRows})
	}
	// Top affected devices (24h) — where to look first.
	var byDev []string
	if platform || len(keys) > 0 {
		byDev = ds.CHQuery(`
SELECT device, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR AND device != ''` + findingsReportCond(platform, keys) + `
 GROUP BY device
 ORDER BY count() DESC
 LIMIT 10
 FORMAT TSV`)
	}
	if len(byDev) > 0 {
		var rows [][]string
		for _, r := range byDev {
			c := strings.Split(r, "\t")
			if len(c) == 2 {
				rows = append(rows, []string{c[0], c[1]})
			}
		}
		secs = append(secs, Section{Title: "Top affected devices (24h)", Header: []string{"Device", "Findings"}, Rows: rows})
	}
	if len(recent) > 0 {
		var rows [][]string
		for _, r := range recent {
			c := strings.Split(r, "\t")
			if len(c) >= 3 {
				rows = append(rows, []string{titleCase(c[0]), c[1], c[2]})
			}
		}
		secs = append(secs, Section{Title: "Recent findings", Header: []string{"Severity", "Device", "Summary"}, Rows: rows})
	}
	crit := 0
	for _, a := range ds.Alerts(tenant) {
		if strings.EqualFold(a.Severity, "critical") {
			crit++
		}
	}
	secs = append(secs, Section{Title: "Critical active alerts", Header: []string{"Metric", "Value"}, Rows: [][]string{{"Critical active alerts", strconv.Itoa(crit)}}})
	return fmt.Sprintf("%d finding(s)/24h · %d critical alert(s)", total, crit), secs
}

func (ds DataSource) DatasetDeviceUtil(tenant string) (string, []Section) {
	// Join CPU + memory per device into one ranked table (was two text blobs).
	keys, platform := ds.DeviceKeys(tenant)
	var cpu, mem map[string]float64
	if platform || len(keys) > 0 {
		cpu = ds.VMMap(`device_cpu_percent`)
		mem = ds.VMMap(`device_mem_percent`)
		if !platform {
			cpu, mem = filterDeviceMap(cpu, keys), filterDeviceMap(mem, keys)
		}
	}
	if len(cpu) == 0 && len(mem) == 0 {
		return "no device utilisation metrics", []Section{{Title: "Device utilisation", Note: "No CPU/memory metrics reporting yet."}}
	}
	seen := map[string]bool{}
	var devs []string
	for d := range cpu {
		if !seen[d] {
			seen[d] = true
			devs = append(devs, d)
		}
	}
	for d := range mem {
		if !seen[d] {
			seen[d] = true
			devs = append(devs, d)
		}
	}
	// Rank by the busier of the two dimensions so the hottest devices lead.
	peak := func(d string) float64 {
		if c, m := cpu[d], mem[d]; c > m {
			return c
		} else {
			return m
		}
	}
	sort.Slice(devs, func(i, j int) bool { return peak(devs[i]) > peak(devs[j]) })
	var rows [][]string
	var cpuSum, memSum float64
	hot := 0
	for _, d := range devs {
		cpuSum += cpu[d]
		memSum += mem[d]
		if peak(d) >= 80 {
			hot++
		}
		rows = append(rows, []string{d, fmt.Sprintf("%.0f%%", cpu[d]), fmt.Sprintf("%.0f%%", mem[d])})
		if len(rows) >= 15 {
			break
		}
	}
	n := max(float64(len(devs)), 1)
	summary := fmt.Sprintf("%d device(s) · avg CPU %.0f%% · avg mem %.0f%% · %d over 80%%", len(devs), cpuSum/n, memSum/n, hot)
	return summary, []Section{
		{Title: "Overview", Header: []string{"Metric", "Value"}, Rows: [][]string{
			{"Devices reporting", strconv.Itoa(len(devs))},
			{"Average CPU", fmt.Sprintf("%.0f%%", cpuSum/n)},
			{"Average memory", fmt.Sprintf("%.0f%%", memSum/n)},
			{"Devices over 80%", strconv.Itoa(hot)},
		}},
		{Title: "Top devices by utilisation", Header: []string{"Device", "CPU", "Memory"}, Rows: rows},
	}
}

func (ds DataSource) DatasetLatency(tenant string) (string, []Section) {
	// Per-link latency/jitter/loss as a real table + an availability SLA (was a
	// single text blob).
	keys, platform := ds.DeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = ds.CHQuery(`
SELECT local_device, remote_device, status,
       round(latency_ms,1), round(jitter_ms,1), round(loss_pct,2)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
	if len(rows) == 0 {
		return "no latency/SLA telemetry", []Section{{Title: "Latency, jitter & SLA", Note: "No tunnel latency/jitter telemetry yet."}}
	}
	up := 0
	var data [][]string
	var latSum float64
	for _, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[2] == "up" {
			up++
		}
		latSum += parseFloatSafe(c[3])
		data = append(data, []string{c[0] + " ↔ " + c[1], titleCase(c[2]), c[3] + " ms", c[4] + " ms", c[5] + "%"})
	}
	sla := 100.0
	if len(rows) > 0 {
		sla = float64(up) / float64(len(rows)) * 100
	}
	avgLat := 0.0
	if len(data) > 0 {
		avgLat = latSum / float64(len(data))
	}
	summary := fmt.Sprintf("%d link(s) · %d up · SLA %.2f%% · avg latency %.1f ms", len(rows), up, sla, avgLat)
	return summary, []Section{
		{Title: "SLA overview", Header: []string{"Metric", "Value"}, Rows: [][]string{
			{"Availability SLA", fmt.Sprintf("%.2f%%", sla)},
			{"Links up", fmt.Sprintf("%d / %d", up, len(rows))},
			{"Average latency", fmt.Sprintf("%.1f ms", avgLat)},
		}},
		{Title: "Per-link latency, jitter & loss", Header: []string{"Link", "Status", "Latency", "Jitter", "Loss"}, Rows: data},
	}
}

// tenantDevices returns the devices a report for the given tenant should cover:
// a global/unassigned report sees the whole fleet, a tenant report only its own.
// tunnelReportCond narrows netops.tunnels rows to tunnels terminating on one of
// the report tenant's devices (either endpoint) — the same contract as
// /api/tunnels. The tunnels row policy is hybrid (untagged rows shared), so
// this app-layer clause is what keeps a tenant report from describing other
// tenants' links. Injection-safe via sqlInList (inventory values, escaped
// regardless).
func tunnelReportCond(platform bool, keys []string) string {
	if platform {
		return ""
	}
	in := sqlInList(keys)
	return ` WHERE (local_device IN (` + in + `) OR remote_device IN (` + in + `))
`
}

// findingsReportCond is the findings sibling, keyed on the device name column.
// Scoped reports exclude device-less platform findings (default-closed).
func findingsReportCond(platform bool, keys []string) string {
	if platform {
		return ""
	}
	return " AND device IN (" + sqlInList(keys) + ")"
}

// filterDeviceMap keeps only the metric entries whose device label matches one
// of the tenant's device keys. Pure.
func filterDeviceMap(m map[string]float64, keys []string) map[string]float64 {
	allow := make(map[string]bool, len(keys))
	for _, k := range keys {
		allow[k] = true
	}
	out := make(map[string]float64, len(m))
	for k, v := range m {
		if allow[k] {
			out[k] = v
		}
	}
	return out
}

// topDeviceLines renders the top-n devices of a metric map as "name value<unit>"
// lines, highest first (ties broken by name for determinism). Pure.
func topDeviceLines(m map[string]float64, n int, unit string) []string {
	devs := make([]string, 0, len(m))
	for d := range m {
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool {
		if m[devs[i]] != m[devs[j]] {
			return m[devs[i]] > m[devs[j]]
		}
		return devs[i] < devs[j]
	})
	if len(devs) > n {
		devs = devs[:n]
	}
	lines := make([]string, 0, len(devs))
	for _, d := range devs {
		lines = append(lines, fmt.Sprintf("%s %.0f%s", d, m[d], unit))
	}
	return lines
}

func (ds DataSource) RenderAlerts(tenant string) (string, string) {
	active := ds.Alerts(tenant)
	bySev := map[string]int{}
	for _, a := range active {
		bySev[strings.ToLower(a.Severity)]++
	}
	summary := fmt.Sprintf("%d active alert(s)", len(active))
	var b strings.Builder
	if len(active) == 0 {
		b.WriteString("No active alerts. ✅\n")
	} else {
		for _, sev := range []string{"critical", "error", "warning", "notice", "info"} {
			if n := bySev[sev]; n > 0 {
				fmt.Fprintf(&b, "%s: %d\n", sev, n)
			}
		}
		b.WriteString("\nMost recent:\n")
		// Newest first, cap the list so notifications stay readable.
		sort.Slice(active, func(i, j int) bool { return active[i].FiredAt.After(active[j].FiredAt) })
		for i, a := range active {
			if i >= 10 {
				fmt.Fprintf(&b, "…and %d more\n", len(active)-10)
				break
			}
			fmt.Fprintf(&b, "• [%s] %s\n", a.Severity, a.Summary)
		}
	}
	return summary, b.String()
}

func (ds DataSource) RenderDevices(tenant string) (string, string) {
	devs := ds.Devices(tenant)
	summary := fmt.Sprintf("%d device(s) discovered", len(devs))
	var b strings.Builder
	for i, d := range devs {
		m := toMap(d)
		if i >= 25 {
			fmt.Fprintf(&b, "…and %d more\n", len(devs)-25)
			break
		}
		name := firstNonEmpty(str(m["name"]), str(m["id"]))
		fmt.Fprintf(&b, "• %s  %s\n", name, str(m["address"]))
	}
	if len(devs) == 0 {
		b.WriteString("No devices discovered.\n")
	}
	return summary, b.String()
}

func (ds DataSource) RenderHealth(now time.Time, tenant string) (string, string) {
	uptime := now.Sub(ds.StartedAt).Round(time.Second)
	devs := len(ds.Devices(tenant))
	active := len(ds.Alerts(tenant))
	summary := fmt.Sprintf("uptime %s · %d devices · %d active alerts", uptime, devs, active)
	b := fmt.Sprintf("API uptime: %s\nDevices discovered: %d\nActive alerts: %d\n", uptime, devs, active)
	return summary, b
}

// ---- Executive reports -----------------------------------------------------
//
// These read point-in-time analytics the stack already collects: tunnel/overlay
// telemetry and findings from ClickHouse (netops.tunnels, netops.findings) and
// device resource metrics from VictoriaMetrics. Each renderer degrades to a
// clear "no data" line if its backend is empty/unreachable, so a report never
// fails — it reports the gap, mirroring how Zabbix scheduled summaries
// behave.

// renderWANUtilization summarises per-WAN/overlay link load + health from the
// tunnels telemetry (status, loss, qoe) — the closest the stack has to circuit
// utilisation until per-circuit bandwidth counters land.
func (ds DataSource) RenderWANUtilization(tenant string) (string, string) {
	keys, platform := ds.DeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = ds.CHQuery(`
SELECT local_device, remote_device, type, status,
       round(loss_pct,2), round(qoe,2)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
	if len(rows) == 0 {
		return "no WAN/overlay links reporting", "No tunnel/overlay telemetry yet.\n"
	}
	up := 0
	var b strings.Builder
	for i, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[3] == "up" {
			up++
		}
		if i < 25 {
			fmt.Fprintf(&b, "• %s↔%s [%s] %s — loss %s%%, QoE %s\n",
				c[0], c[1], c[2], c[3], c[4], c[5])
		}
	}
	if len(rows) > 25 {
		fmt.Fprintf(&b, "…and %d more\n", len(rows)-25)
	}
	summary := fmt.Sprintf("%d WAN/overlay link(s), %d up", len(rows), up)
	return summary, b.String()
}

// renderSecurityThreats rolls up correlation findings (severity breakdown +
// recent items) and critical active alerts — the executive "are we under
// threat" view.
func (ds DataSource) RenderSecurityThreats(tenant string) (string, string) {
	keys, platform := ds.DeviceKeys(tenant)
	var sev, recent []string
	if platform || len(keys) > 0 {
		cond := findingsReportCond(platform, keys)
		sev = ds.CHQuery(`
SELECT severity, count()
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 GROUP BY severity
 ORDER BY count() DESC
 FORMAT TSV`)
		recent = ds.CHQuery(`
SELECT severity, device, summary
  FROM netops.findings
 WHERE ts >= now() - INTERVAL 24 HOUR` + cond + `
 ORDER BY ts DESC
 LIMIT 10
 FORMAT TSV`)
	}
	var b strings.Builder
	total := 0
	if len(sev) == 0 {
		b.WriteString("No findings in the last 24h.\n")
	} else {
		b.WriteString("By severity (24h):\n")
		for _, r := range sev {
			c := strings.Split(r, "\t")
			if len(c) == 2 {
				fmt.Fprintf(&b, "  %s: %s\n", c[0], c[1])
				total += atoiSafe(c[1])
			}
		}
	}
	if len(recent) > 0 {
		b.WriteString("\nRecent:\n")
		for _, r := range recent {
			c := strings.Split(r, "\t")
			if len(c) >= 3 {
				fmt.Fprintf(&b, "• [%s] %s — %s\n", c[0], c[1], c[2])
			}
		}
	}
	crit := 0
	for _, a := range ds.Alerts(tenant) {
		if strings.EqualFold(a.Severity, "critical") {
			crit++
		}
	}
	fmt.Fprintf(&b, "\nCritical active alerts: %d\n", crit)
	return fmt.Sprintf("%d finding(s)/24h · %d critical alert(s)", total, crit), b.String()
}

// renderDeviceUtilization lists the busiest devices by CPU and memory from the
// metrics VictoriaMetrics already stores (SNMP + gNMI collectors), ranked
// in-app so a tenant-owned report's top-N is computed over ITS devices only
// (a server-side topk would rank platform-wide and then filter).
func (ds DataSource) RenderDeviceUtilization(tenant string) (string, string) {
	keys, platform := ds.DeviceKeys(tenant)
	var cpuMap, memMap map[string]float64
	if platform || len(keys) > 0 {
		cpuMap = ds.VMMap(`device_cpu_percent`)
		memMap = ds.VMMap(`device_mem_percent`)
		if !platform {
			cpuMap, memMap = filterDeviceMap(cpuMap, keys), filterDeviceMap(memMap, keys)
		}
	}
	cpu := topDeviceLines(cpuMap, 10, "%")
	mem := topDeviceLines(memMap, 10, "%")
	if len(cpu) == 0 && len(mem) == 0 {
		return "no device utilisation metrics", "No CPU/memory metrics reporting yet.\n"
	}
	var b strings.Builder
	if len(cpu) > 0 {
		b.WriteString("Top CPU:\n")
		for _, l := range cpu {
			b.WriteString("  " + l + "\n")
		}
	}
	if len(mem) > 0 {
		b.WriteString("\nTop memory:\n")
		for _, l := range mem {
			b.WriteString("  " + l + "\n")
		}
	}
	return fmt.Sprintf("%d device(s) by CPU, %d by memory", len(cpu), len(mem)), b.String()
}

// renderLatencyJitterSLA reports per-link latency/jitter/loss and a simple SLA
// (% of links currently up) from the tunnels telemetry.
func (ds DataSource) RenderLatencyJitterSLA(tenant string) (string, string) {
	keys, platform := ds.DeviceKeys(tenant)
	var rows []string
	if platform || len(keys) > 0 {
		rows = ds.CHQuery(`
SELECT local_device, remote_device, status,
       round(latency_ms,2), round(jitter_ms,2), round(loss_pct,2)
  FROM netops.tunnels
` + tunnelReportCond(platform, keys) + ` ORDER BY ts DESC
 LIMIT 1 BY id
 FORMAT TSV`)
	}
	if len(rows) == 0 {
		return "no latency/SLA telemetry", "No tunnel latency/jitter telemetry yet.\n"
	}
	up := 0
	var b strings.Builder
	for i, r := range rows {
		c := strings.Split(r, "\t")
		if len(c) < 6 {
			continue
		}
		if c[2] == "up" {
			up++
		}
		if i < 25 {
			fmt.Fprintf(&b, "• %s↔%s [%s] latency %sms, jitter %sms, loss %s%%\n",
				c[0], c[1], c[2], c[3], c[4], c[5])
		}
	}
	sla := 100.0
	if len(rows) > 0 {
		sla = float64(up) / float64(len(rows)) * 100
	}
	summary := fmt.Sprintf("%d link(s), %d up, SLA %.2f%%", len(rows), up, sla)
	fmt.Fprintf(&b, "\nAvailability SLA: %.2f%% (%d/%d up)\n", sla, up, len(rows))
	return summary, b.String()
}

func atoiSafe(s string) int {
	n := 0
	for _, ch := range strings.TrimSpace(s) {
		if ch < '0' || ch > '9' {
			return n
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

// ── Report dataset helpers (UI-9 enrichment) ───────────────────────────────────

// titleCase upper-cases the first letter of a token for display ("warning" →
// "Warning", "cloud-gw" → "Cloud-gw"); empty stays empty.
func titleCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// pctStr renders n/total as a one-decimal percentage string ("42.0%").
func pctStr(n, total int) string {
	if total <= 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", float64(n)/float64(total)*100)
}

// max1 returns at least 1 (avoids divide-by-zero on share/avg columns).
func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// parseFloatSafe parses a float, returning 0 on any error (telemetry strings).
func parseFloatSafe(s string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return f
}

// topCounts turns a label→count map into the top-N rows, count-descending then
// label-ascending for stable output.
func topCounts(m map[string]int, n int) [][]string {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	var rows [][]string
	for i, p := range pairs {
		if i >= n {
			break
		}
		rows = append(rows, []string{p.k, strconv.Itoa(p.v)})
	}
	return rows
}

// agoStr renders a compact relative age ("3m ago", "2h ago").
func agoStr(t, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// lastSeenStr renders a device's heartbeat freshness, or "never" if unseen.
func lastSeenStr(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return agoStr(t, now)
}

// fleetHealth classifies each device into up/degraded/down by the same rules as
// the Devices UI: fresh heartbeat (<5m) = up; alerting or stale (<15m) =
// degraded; older or never-seen = down. Returns the counts and a per-device map.
func (ds DataSource) fleetHealth(devs []models.Device, now time.Time) (up, degraded, down int, perDevice map[string]string) {
	alerted := map[string]bool{}
	for _, a := range ds.Alerts("") {
		s := strings.ToLower(a.Severity)
		if (s == "warning" || s == "critical" || s == "error") && a.DeviceID != "" {
			alerted[a.DeviceID] = true
		}
	}
	perDevice = make(map[string]string, len(devs))
	for _, d := range devs {
		age := now.Sub(d.LastSeen)
		switch {
		case d.LastSeen.IsZero() || age > 15*time.Minute:
			perDevice[d.ID] = "Down"
			down++
		case alerted[d.ID] || age > 5*time.Minute:
			perDevice[d.ID] = "Degraded"
			degraded++
		default:
			perDevice[d.ID] = "Up"
			up++
		}
	}
	return
}

// vmQueryMap runs an instant PromQL query and returns device→value, keyed by the
// friendly device label so several metrics can be joined per device.
