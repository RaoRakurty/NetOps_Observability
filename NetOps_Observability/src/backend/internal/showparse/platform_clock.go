// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// platform_clock.go — the NetClaw ingestion Batch 1 platform parsers: Cisco
// IOS-XE processor memory (`show processes memory sorted`) and NTP
// synchronization (`show ntp status`).
//
// Both are authored ONLY against output captured from a real device (Cisco IOS
// XE 17.3.2, a Catalyst 8000V/CSR-class SD-WAN edge, 2026-11-13). They are
// registered for IOS-XE alone: classic IOS and the other dialects print these
// reads in shapes no captured output here proves, and a parser registered for an
// unseen format would turn a different layout into confidently wrong fields.
// Those dialects' commands still run (protocoldiag's battery) and their output
// is honest raw evidence until a capture exists.

import "strings"

func registerClockParsers(l *Library) {
	l.register(CmdPlatformMemory, parseIOSXEProcessesMemory, DialectCiscoIOSXE)
	l.register(CmdPlatformClock, parseIOSXENTPStatus, DialectCiscoIOSXE)
}

// parseIOSXEProcessesMemory reads the processor-pool header of `show processes
// memory sorted`:
//
//	Processor Pool Total: 2121596732 Used:  258195496 Free: 1863401236
//
// The figures are BYTES; they are carried in KiB like every other memory field.
// Only the Processor pool is read — the reserve and lsmpi_io pools are fixed
// carve-outs that sit near full by design, and reporting one of them as
// "memory used" would raise a false pressure flag on every healthy router.
func parseIOSXEProcessesMemory(lines []string) Result {
	var res Result
	for _, ln := range lines {
		t := trim(ln)
		if !strings.HasPrefix(strings.ToLower(t), "processor pool total:") {
			continue
		}
		fs := fields(t)
		total, tok := numberAfter(fs, "Total")
		used, uok := numberAfter(fs, "Used")
		free, fok := numberAfter(fs, "Free")
		if !tok || !uok || total <= 0 || used < 0 || used > total {
			continue // a header with no usable figures is not evidence of anything
		}
		ph := &PlatformHealth{
			MemTotalKB: i64Ptr(total / 1024),
			MemUsedKB:  i64Ptr(used / 1024),
		}
		if fok && free >= 0 {
			ph.MemFreeKB = i64Ptr(free / 1024)
		}
		ph.MemUsedPercent = f64Ptr(float64(used) / float64(total) * 100)
		res.Platform = ph
		return res
	}
	return res
}

// parseIOSXENTPStatus reads `show ntp status`:
//
//	Clock is synchronized, stratum 6, reference is 192.0.2.10
//	...
//	clock offset is 15.8760 msec, root delay is 47.72 msec
//
// An unsynchronized clock prints "Clock is unsynchronized, stratum 16, no
// reference clock". The two sentences are matched exactly; anything else leaves
// ClockSynced nil, because "we could not tell" is not "unsynchronized".
func parseIOSXENTPStatus(lines []string) Result {
	var res Result
	ph := &PlatformHealth{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "clock is synchronized"):
			ph.ClockSynced = boolPtr(true)
			found = true
			readClockHeader(t, ph)
		case strings.HasPrefix(lower, "clock is unsynchronized"):
			ph.ClockSynced = boolPtr(false)
			found = true
			readClockHeader(t, ph)
		case strings.HasPrefix(lower, "clock offset is "):
			v, _ := valueAfter(t, "offset is ") // discard: HasPrefix above guarantees the marker
			fs := fields(v)
			if len(fs) >= 2 && strings.HasPrefix(strings.ToLower(fs[1]), "msec") {
				if ms, ok := atofOK(fs[0]); ok {
					ph.ClockOffsetMs = f64Ptr(ms)
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

// readClockHeader takes the stratum and reference from the "Clock is …" line.
func readClockHeader(t string, ph *PlatformHealth) {
	for _, seg := range strings.Split(t, ",") {
		seg = trim(seg)
		switch {
		case strings.HasPrefix(strings.ToLower(seg), "stratum "):
			if n, ok := atoiOK(trim(seg[len("stratum "):])); ok && n >= 0 && n <= 16 {
				ph.ClockStratum = intPtr(int(n))
			}
		case strings.HasPrefix(strings.ToLower(seg), "reference is "):
			if ref := trim(seg[len("reference is "):]); ref != "" {
				ph.ClockReference = strPtr(ref)
			}
		}
	}
}
