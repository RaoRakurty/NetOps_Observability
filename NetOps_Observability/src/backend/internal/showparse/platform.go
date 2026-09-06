// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// platform.go — control-plane health parsers (CmdPlatformCPU,
// CmdPlatformMemory, CmdPlatformEnv, CmdPlatformUptime).
//
// "CPU > 90 %" is one of the proactive flags the Iris model raises without being
// asked, so the number behind it must be the one the device actually reported.
// Where a platform reports only IDLE (NX-OS, Junos), utilization is derived as
// 100 − idle and that derivation is stated at the call site; where a platform
// reports nothing, the field stays nil. Uptime and last-reload are carried as
// the device's own TEXT: converting "10 weeks, 2 days" into a time.Time would
// require inventing a reference instant.

import "strings"

func registerPlatformParsers(l *Library) {
	l.register(CmdPlatformCPU, parseCiscoProcessesCPU,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR)
	l.register(CmdPlatformCPU, parseNXOSSystemResources, DialectCiscoNXOS)
	l.register(CmdPlatformCPU, parseJunosRoutingEngine, DialectJunos)
	l.register(CmdPlatformCPU, parseVRPCPUUsage, DialectHuaweiVRP)

	l.register(CmdPlatformMemory, parseVRPMemoryUsage, DialectHuaweiVRP)

	l.register(CmdPlatformUptime, parseVersionUptime,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR, DialectCiscoNXOS, DialectAristaEOS)
	l.register(CmdPlatformUptime, parseJunosUptime, DialectJunos)
}

// parseCiscoProcessesCPU reads the `show processes cpu` header line:
//
//	CPU utilization for five seconds: 12%/1%; one minute: 10%; five minutes: 9%
func parseCiscoProcessesCPU(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		if !hasFold(ln, "cpu utilization for") {
			continue
		}
		for _, seg := range strings.Split(ln, ";") {
			k, v, ok := kv(seg)
			if !ok {
				continue
			}
			pct, pctOK := cpuPercent(v)
			if !pctOK {
				continue
			}
			switch {
			case hasFold(k, "five seconds"):
				ph.CPU5Sec = f64Ptr(pct)
				ph.CPUPercent = f64Ptr(pct)
				found = true
			case hasFold(k, "one minute"):
				ph.CPU1Min = f64Ptr(pct)
				found = true
			case hasFold(k, "five minutes"):
				ph.CPU5Min = f64Ptr(pct)
				found = true
			}
		}
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}

// cpuPercent reads "12%" or "12%/1%" (the second figure is the interrupt share,
// which is deliberately not reported as utilization).
func cpuPercent(v string) (float64, bool) {
	v = trim(strings.Fields(v + " x")[0])
	head, _, _ := strings.Cut(v, "/")
	head = strings.TrimSuffix(trim(head), "%")
	return atofOK(head)
}

// parseNXOSSystemResources reads `show system resources`. NX-OS reports the
// IDLE share, so utilization is 100 − idle; that derivation is why the parser
// refuses a line whose idle figure it cannot read rather than reporting 0 %.
func parseNXOSSystemResources(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		switch {
		case strings.HasPrefix(t, "CPU states"):
			_, v, ok := kv(t)
			if !ok {
				continue
			}
			for _, seg := range strings.Split(v, ",") {
				fs := fields(trim(seg))
				if len(fs) != 2 || !strings.EqualFold(fs[1], "idle") {
					continue
				}
				if idle, ok := atofOK(strings.TrimSuffix(fs[0], "%")); ok {
					ph.CPUPercent = f64Ptr(100 - idle)
					found = true
				}
			}
		case strings.HasPrefix(t, "Memory usage"):
			_, v, ok := kv(t)
			if !ok {
				continue
			}
			for _, seg := range strings.Split(v, ",") {
				fs := fields(trim(seg))
				if len(fs) != 2 {
					continue
				}
				n, ok := atoiOK(strings.TrimSuffix(fs[0], "K"))
				if !ok {
					continue
				}
				switch strings.ToLower(fs[1]) {
				case "total":
					ph.MemTotalKB = i64Ptr(n)
					found = true
				case "used":
					ph.MemUsedKB = i64Ptr(n)
					found = true
				case "free":
					ph.MemFreeKB = i64Ptr(n)
					found = true
				}
			}
		}
	}
	if ph.MemTotalKB != nil && ph.MemUsedKB != nil && *ph.MemTotalKB > 0 {
		ph.MemUsedPercent = f64Ptr(float64(*ph.MemUsedKB) / float64(*ph.MemTotalKB) * 100)
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}

// parseJunosRoutingEngine reads `show chassis routing-engine`, which carries CPU
// (as an idle share), memory utilization, RE temperature, uptime and the last
// reboot reason in one block.
func parseJunosRoutingEngine(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		fs := fields(t)
		switch {
		case strings.HasPrefix(t, "Memory utilization"):
			if len(fs) >= 3 && strings.EqualFold(fs[len(fs)-1], "percent") {
				if f, ok := atofOK(fs[len(fs)-2]); ok {
					ph.MemUsedPercent = f64Ptr(f)
					found = true
				}
			}
		case strings.HasPrefix(t, "Idle"):
			if len(fs) == 3 && strings.EqualFold(fs[2], "percent") {
				if idle, ok := atofOK(fs[1]); ok {
					ph.CPUPercent = f64Ptr(100 - idle)
					found = true
				}
			}
		case strings.HasPrefix(t, "Temperature"), strings.HasPrefix(t, "CPU temperature"):
			if v, ok := junosDegreesC(t); ok {
				name := "Routing Engine"
				if strings.HasPrefix(t, "CPU temperature") {
					name = "Routing Engine CPU"
				}
				ph.Temps = append(ph.Temps, SensorReading{Name: name, ValueC: f64Ptr(v)})
				found = true
			}
		case strings.HasPrefix(t, "Uptime"):
			if v := trim(strings.TrimPrefix(t, "Uptime")); v != "" {
				ph.Uptime = strPtr(v)
				found = true
			}
		case strings.HasPrefix(t, "Last reboot reason"):
			if v := trim(strings.TrimPrefix(t, "Last reboot reason")); v != "" {
				ph.LastReload = strPtr(v)
				found = true
			}
		}
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}

// parseVRPCPUUsage reads `display cpu-usage`:
//
//	CPU Usage            : 12% Max: 45%
func parseVRPCPUUsage(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		k, v, ok := kv(trim(ln))
		if !ok || !strings.EqualFold(k, "CPU Usage") {
			continue
		}
		if f, ok := atofOK(strings.TrimSuffix(strings.Fields(v + " x")[0], "%")); ok {
			ph.CPUPercent = f64Ptr(f)
			found = true
		}
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}

// parseVRPMemoryUsage reads `display memory-usage`:
//
//	Memory Using Percentage Is: 42%
func parseVRPMemoryUsage(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		if !hasFold(t, "memory using percentage") {
			continue
		}
		_, v, ok := kv(t)
		if !ok {
			continue
		}
		if f, ok := atofOK(strings.TrimSuffix(strings.Fields(v + " x")[0], "%")); ok {
			ph.MemUsedPercent = f64Ptr(f)
			found = true
		}
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}

// parseVersionUptime reads `show version` for uptime, software version and the
// last reload reason. Both the Cisco ("<host> uptime is …") and the Arista
// ("Uptime: …") spellings are recognized; neither is synthesized when absent.
func parseVersionUptime(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		if ph.Uptime == nil {
			if v, ok := valueAfter(t, " uptime is "); ok && v != "" {
				ph.Uptime = strPtr(v)
				found = true
			} else if v, ok := strings.CutPrefix(t, "Uptime:"); ok && trim(v) != "" {
				ph.Uptime = strPtr(trim(v))
				found = true
			}
		}
		if ph.LastReload == nil {
			if v, ok := valueAfter(t, "System returned to ROM by "); ok && v != "" {
				ph.LastReload = strPtr(v)
				found = true
			} else if v, ok := valueAfter(t, "Last reset reason: "); ok && v != "" {
				ph.LastReload = strPtr(v)
				found = true
			}
		}
		if ph.Version == nil {
			if v, ok := valueAfter(t, ", Version "); ok && v != "" {
				ph.Version = strPtr(strings.TrimRight(strings.Fields(v + " x")[0], ","))
				found = true
			} else if v, ok := strings.CutPrefix(t, "Software image version:"); ok && trim(v) != "" {
				ph.Version = strPtr(trim(v))
				found = true
			}
		}
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}

// parseJunosUptime reads `show system uptime`. The uptime itself is taken from
// the "up <n> days, hh:mm" clause of the load-average line, which is the only
// place Junos prints an ELAPSED time rather than an instant.
func parseJunosUptime(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		if v, ok := strings.CutPrefix(t, "System booted:"); ok && trim(v) != "" {
			// Kept as the reboot marker, not as uptime.
			ph.LastReload = strPtr(trim(v))
			found = true
		}
		if ph.Uptime == nil && hasFold(t, "load averages") {
			if v, ok := valueAfter(t, " up "); ok {
				head, _, _ := strings.Cut(v, " users")
				head = trim(strings.TrimSuffix(trim(head), ","))
				// Drop the trailing user count that precedes " users".
				if fs := fields(head); len(fs) > 1 {
					head = trim(strings.TrimSuffix(strings.Join(fs[:len(fs)-1], " "), ","))
				}
				if head != "" {
					ph.Uptime = strPtr(head)
					found = true
				}
			}
		}
	}
	if !found {
		return res
	}
	res.Platform = ph
	return res
}
