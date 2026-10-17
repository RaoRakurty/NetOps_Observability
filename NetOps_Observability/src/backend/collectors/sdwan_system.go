// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// sdwan_system.go — CPU and memory for SD-WAN edges that answer neither
// HOST-RESOURCES-MIB nor a vendor process/memory-pool MIB. A Viptela vEdge is
// the case in the field: its only CPU/memory source is the systemStatus
// scalars of VIPTELA-OPER-SYSTEM. IOS XE SD-WAN (cEdge) carries the same
// scalars in CISCO-SDWAN-OPER-SYSTEM-MIB, but normally reports through
// CISCO-PROCESS-MIB / CISCO-MEMORY-POOL-MIB already, so for it this is a
// fallback only.
//
// Column numbers are identical in both MIBs and in every published release
// (Viptela 20.9–26.1, IOS XE SD-WAN 17.9–26.1): .16 CpuIdle, .17 MemTotal,
// .18 MemUsed. The BER types are NOT identical: the CPU columns are decimal
// text in both, memory is text on vEdge and Counter64 on cEdge. Every value is
// therefore read by type, and a value that does not parse is dropped — never
// published as 0 %.

var sdwanSystemStatusBase = map[string][]int{
	"viptela":     {1, 3, 6, 1, 4, 1, 41916, 11, 1},
	"cisco-sdwan": {1, 3, 6, 1, 4, 1, 9, 9, 1004, 1, 1},
}

const (
	sysStatusCPUIdle  = 16
	sysStatusMemTotal = 17
	sysStatusMemUsed  = 18
)

// sdwanSystemFamily picks the systemStatus MIB for a device's enterprise
// number; "" when the device is not an SD-WAN family.
func sdwanSystemFamily(enterprise int) string {
	switch enterprise {
	case 41916:
		return "viptela"
	case 9:
		return "cisco-sdwan"
	}
	return ""
}

// sdwanNumber reads an integer-typed or decimal-text value. Text may carry
// surrounding space or a trailing "%". ok=false for anything else.
func sdwanNumber(v berVal) (float64, bool) {
	switch v.tag {
	case 0x02, 0x41, 0x42, 0x46, 0x47: // INTEGER, Counter32, Gauge32, Counter64, Unsigned32
		n := valueInt(v)
		if n < 0 {
			return 0, false
		}
		return float64(n), true
	case 0x04: // OCTET STRING — decimal text
		s := strings.TrimSuffix(strings.TrimSpace(string(v.raw)), "%")
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// sdwanCPUPercent is 100 − CpuIdle, only when idle is a percentage.
func sdwanCPUPercent(idle berVal) (float64, bool) {
	f, ok := sdwanNumber(idle)
	if !ok || f > 100 {
		return 0, false
	}
	return 100 - f, true
}

// sdwanMemPercent is used / total — unit-free, so it holds whatever unit the
// agent reports in. A zero total or used > total is dropped.
func sdwanMemPercent(used, total berVal) (float64, bool) {
	u, ok1 := sdwanNumber(used)
	t, ok2 := sdwanNumber(total)
	if !ok1 || !ok2 || t <= 0 || u > t {
		return 0, false
	}
	return u * 100 / t, true
}

// getFn is a single-OID GET (snmpGet in production; a stub in tests).
type getFn func(ctx context.Context, addr string, creds snmpCreds, oid []int) (berVal, error)

// sdwanSystemSample is what the systemStatus scalars yielded for one device.
type sdwanSystemSample struct {
	cpu, mem       float64
	hasCPU, hasMem bool
}

// readSDWANSystem GETs the systemStatus scalars the caller still needs.
func readSDWANSystem(ctx context.Context, get getFn, addr string, creds snmpCreds, family string, wantCPU, wantMem bool) sdwanSystemSample {
	var out sdwanSystemSample
	base, ok := sdwanSystemStatusBase[family]
	if !ok {
		return out
	}
	scalar := func(n int) (berVal, bool) {
		v, err := get(ctx, addr, creds, append(append([]int(nil), base...), n, 0))
		return v, err == nil
	}
	if wantCPU {
		if v, ok := scalar(sysStatusCPUIdle); ok {
			out.cpu, out.hasCPU = sdwanCPUPercent(v)
		}
	}
	if wantMem {
		if used, ok := scalar(sysStatusMemUsed); ok {
			if total, ok := scalar(sysStatusMemTotal); ok {
				out.mem, out.hasMem = sdwanMemPercent(used, total)
			}
		}
	}
	return out
}

// lines renders the sample as device_cpu_percent / device_mem_percent series,
// labelled source="sdwan-system" so a reader can tell where they came from.
func (s sdwanSystemSample) lines(device, vendor string, now int64) []string {
	var out []string
	if s.hasCPU {
		out = append(out, fmt.Sprintf("device_cpu_percent{device=%q,vendor=%q,index=\"system\",source=\"sdwan-system\"} %.2f %d",
			device, vendor, s.cpu, now))
	}
	if s.hasMem {
		out = append(out, fmt.Sprintf("device_mem_percent{device=%q,vendor=%q,index=\"system\",source=\"sdwan-system\"} %.2f %d",
			device, vendor, s.mem, now))
	}
	return out
}
