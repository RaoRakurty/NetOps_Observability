// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// Masked sender detection (tracker 373).
//
// A UDP receiver behind a Docker port mapping sees the REAL sender only while
// the packet is DNAT'd straight to the container. When it is not — a stale
// conntrack entry that survived a container recreate (moby#53384: since Engine
// 29.5.0 the flush matches the container port), or an IPv6 sender relayed by
// docker-proxy to an IPv4-only network — docker-proxy re-sends it from the
// bridge GATEWAY. Device and tenant attribution are then silently lost.
//
// The gateway can never be a real device: Docker could not route a reply to
// it. So a packet sourced from the container's default gateway is MASKED, by
// construction, with no false positive. The receiver stamps it and says so;
// the stamp feeds netops_ingest_source_masked_events and the
// IngestSenderAddressMasked alert, so the loss is never silent again.
//
// Opt-in by deployment shape: CX_MASKED_SOURCE_DETECT=docker-bridge (set by
// compose). On host networking or Kubernetes the default gateway is a real LAN
// router, so the detector stays off there.

const maskedSourceModeDockerBridge = "docker-bridge"

// procNetRoute is the kernel's IPv4 routing table for this network namespace.
const procNetRoute = "/proc/net/route"

// maskedSourceDetector reports whether a packet's source is the bridge gateway.
// The zero value detects nothing.
type maskedSourceDetector struct {
	gateways map[string]struct{}
}

// newMaskedSourceDetector builds the detector for `mode`; any mode other than
// docker-bridge, or a routing table with no default gateway, yields a detector
// that detects nothing (and says why in the returned note, for the log).
func newMaskedSourceDetector(mode string, readRoutes func() ([]byte, error)) (maskedSourceDetector, string) {
	if strings.TrimSpace(mode) != maskedSourceModeDockerBridge {
		return maskedSourceDetector{}, ""
	}
	raw, err := readRoutes()
	if err != nil {
		return maskedSourceDetector{}, "masked-source detection off: cannot read the routing table: " + err.Error()
	}
	gws := defaultGateways(raw)
	if len(gws) == 0 {
		return maskedSourceDetector{}, "masked-source detection off: no default gateway in this network namespace"
	}
	d := maskedSourceDetector{gateways: make(map[string]struct{}, len(gws))}
	for _, gw := range gws {
		d.gateways[gw.String()] = struct{}{}
	}
	return d, ""
}

// masked reports whether src (an IP literal, possibly IPv4-mapped IPv6) is
// one of the bridge gateways.
func (d maskedSourceDetector) masked(src string) bool {
	if len(d.gateways) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(src))
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // ::ffff:172.18.0.1 is the same gateway
	}
	_, ok := d.gateways[ip.String()]
	return ok
}

// readProcNetRoute reads the namespace's IPv4 routing table.
func readProcNetRoute() ([]byte, error) { return os.ReadFile(procNetRoute) }

// defaultGateways parses /proc/net/route (whitespace-separated; Destination
// and Gateway are little-endian hex IPv4) and returns the gateway of every
// default route (Destination 00000000, RTF_GATEWAY set). Malformed lines are
// skipped — the table is kernel-written, but the parser trusts nothing.
func defaultGateways(raw []byte) []net.IP {
	const rtfGateway = 0x2
	var out []net.IP
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	first := true
	for sc.Scan() {
		if first {
			first = false // header
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[1] != "00000000" {
			continue
		}
		flags, err := hex.DecodeString(padHex(f[3]))
		if err != nil || len(flags) != 4 || binary.BigEndian.Uint32(flags)&rtfGateway == 0 {
			continue
		}
		gw, err := hex.DecodeString(f[2])
		if err != nil || len(gw) != 4 {
			continue
		}
		ip := net.IPv4(gw[3], gw[2], gw[1], gw[0]) // little-endian on the wire
		if ip.Equal(net.IPv4zero) {
			continue
		}
		out = append(out, ip.To4())
	}
	return out
}

// padHex left-pads a hex field to 8 digits (the Flags column is printed "0003").
func padHex(s string) string {
	if len(s) >= 8 {
		return s
	}
	return strings.Repeat("0", 8-len(s)) + s
}
