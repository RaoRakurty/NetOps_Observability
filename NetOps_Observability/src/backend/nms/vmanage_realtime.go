// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"netops/backend/internal/ifbridge"
)

// vmanage_realtime.go — vManage's REAL-TIME per-device interface and system
// state → the SAME canonical metric families the SNMP poller produces
// (source-equivalence E3, plan of record docs/design/NMS_DEVICE_IDENTITY_
// 2026-11-01.md §7a/§7b).
//
// The `interfaces` / `system` streams read vManage's AGGREGATION API: 10-minute
// buckets that arrive 30–60 minutes late (tracker 357), named
// controller_metric_*. The engine treats such data as context only, and the
// device page — which reads device_if_* — showed a controller-only device with
// NO interfaces at all (lab parity harness: 0 of 24 interface checks).
//
// These two streams read the per-device real-time APIs instead (lab-verified on
// 20.6.1; testdata/vmanage_20.6/*_realtime_*.json): counters advance between
// polls and `lastupdated` is the poll time (the `/synced` variant is a cache
// ~36 h old and is not used). They emit the canonical names with SNMP's
// semantics — IF-MIB status values (1 up, 2 down), cumulative octet / error /
// discard counters consumers rate(), speed in Mbps, CPU and memory in percent —
// labelled `device` (the system-ip, which the pipeline resolves to the tenant's
// inventory id) and `ifName`, exactly as the SNMP series are. A canonical
// sample also feeds the correlation engine's metric lane (scheduler
// Sinks.EmitMetricEvents), stamped with the integration's tenant.

// canonicalDeviceMetrics are the canonical families a connector may emit, with
// the RCA signal family each belongs to. Mirrors the SNMP RCA allowlist
// (collectors/metric_events.go rcaMetricFamilies) for the families a controller
// can supply; vmanage_realtime_test.go pins the mirror.
var canonicalDeviceMetrics = map[string]string{
	"device_if_oper_status":  "interface",
	"device_if_admin_status": "interface",
	"device_if_in_octets":    "interface",
	"device_if_out_octets":   "interface",
	"device_if_in_errors":    "interface",
	"device_if_out_errors":   "interface",
	"device_if_in_discards":  "interface",
	"device_if_out_discards": "interface",
	"device_if_speed":        "interface",
	"device_cpu_percent":     "device_resource",
	"device_mem_percent":     "device_resource",
}

// CanonicalDeviceMetricFamily reports the RCA signal family of a canonical
// device metric a connector emits, or ok=false for any other name.
func CanonicalDeviceMetricFamily(name string) (string, bool) {
	f, ok := canonicalDeviceMetrics[name]
	return f, ok
}

// vmIfStatus maps vManage's interface status words onto IF-MIB values. cEdge
// (IOS-XE) and vEdge use different vocabularies; an unrecognised word yields
// ok=false and no sample — a status is never guessed.
func vmIfStatus(s string) (float64, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up", "if-oper-state-ready", "if-state-up":
		return 1, true
	case "down", "if-oper-state-no-pass", "if-oper-state-lower-layer-down", "if-oper-state-invalid",
		"if-state-down", "admin-down", "lower-layer-down":
		return 2, true
	}
	return 0, false
}

// vmInternalVPN reports a vManage-internal VPN (655xx: the system's own
// loopbacks, which reuse the same addresses on every device). Not the managed
// network's interfaces.
func vmInternalVPN(vpn string) bool { return ifbridge.InternalVPN(vpn) }

// vmIPv6List reads cEdge's `ipv6-addrs`, whose shape the recorded 20.6
// payloads never show filled (null): a string, or a list of strings or of
// objects carrying the address under `ipv6-addr` / `address` / `ip-address`.
// Anything else is no address — never a parse failure of the row.
type vmIPv6List []string

func (l *vmIPv6List) UnmarshalJSON(b []byte) error {
	*l = nil
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = vmIPv6List{one}
		return nil
	}
	var many []json.RawMessage
	if err := json.Unmarshal(b, &many); err != nil {
		return nil //nolint:nilerr // discard: an unknown shape is "not reported", never a parse failure of the row
	}
	for _, raw := range many {
		if len(*l) >= maxInterfaceAddrs {
			break
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			*l = append(*l, s)
			continue
		}
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			continue
		}
		for _, k := range []string{"ipv6-addr", "address", "ip-address"} {
			if v, ok := obj[k].(string); ok {
				*l = append(*l, v)
				break
			}
		}
	}
	return nil
}

// vmanageInterfaceRealtimeTransform reads /dataservice/device/interface into
// the canonical interface metrics AND the interface identity records the
// bridge takes (tracker 387 PR 13a): ifindex, every address (vEdge sends
// "a.b.c.d/len" and one row per address family; cEdge a bare address and
// ipv6-addrs), the VPN and the description. Internal-VPN rows are passed on
// for the bridge to skip and count; they never become metrics.
func vmanageInterfaceRealtimeTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			Device      string     `json:"vdevice-name"`
			HostName    string     `json:"vdevice-host-name"`
			IfName      string     `json:"ifname"`
			IfIndex     vmStr      `json:"ifindex"`
			IPAddr      vmStr      `json:"ip-address"`
			IPv6Addr    vmStr      `json:"ipv6-address"`
			IPv6Addrs   vmIPv6List `json:"ipv6-addrs"`
			VPN         vmStr      `json:"vpn-id"`
			Desc        string     `json:"desc"`
			Description string     `json:"description"`
			OperStatus  string     `json:"if-oper-status"`
			AdminStatus string     `json:"if-admin-status"`
			RxOctets    vmNum      `json:"rx-octets"`
			TxOctets    vmNum      `json:"tx-octets"`
			RxErrors    vmNum      `json:"rx-errors"`
			TxErrors    vmNum      `json:"tx-errors"`
			RxDrops     vmNum      `json:"rx-drops"`
			TxDrops     vmNum      `json:"tx-drops"`
			SpeedMbps   vmNum      `json:"speed-mbps"`
			LastUpdated vmNum      `json:"lastupdated"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range resp.Data {
		ifName := strings.TrimSpace(r.IfName)
		if net.ParseIP(r.Device) == nil || ifName == "" {
			continue
		}
		ts := vmTime(int64(r.LastUpdated))
		addrs := make([]string, 0, 2+len(r.IPv6Addrs))
		for _, a := range append([]string{string(r.IPAddr), string(r.IPv6Addr)}, r.IPv6Addrs...) {
			if a = strings.TrimSpace(a); a != "" && a != "-" && a != "null" {
				addrs = append(addrs, a)
			}
		}
		b.Interfaces = append(b.Interfaces, ControllerInterface{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			DeviceKey: r.Device, DeviceName: strings.TrimSpace(r.HostName),
			IfIndex: string(r.IfIndex), IfName: ifName, VRF: strings.TrimSuffix(string(r.VPN), "null"),
			Description: firstNonEmpty(r.Desc, r.Description), Addrs: addrs, Time: ts,
		})
		if vmInternalVPN(string(r.VPN)) {
			continue
		}
		tags := vmMetricTags(tenant, integrationID, "device", r.Device, "ifName", ifName, "vrf", string(r.VPN))
		m := func(name string, v float64, unit string) ControllerMetric {
			return vmMetric(tenant, integrationID, name, v, unit, ts, tags)
		}
		if v, ok := vmIfStatus(r.OperStatus); ok {
			b.Metrics = append(b.Metrics, m("device_if_oper_status", v, "state"))
		}
		if v, ok := vmIfStatus(r.AdminStatus); ok {
			b.Metrics = append(b.Metrics, m("device_if_admin_status", v, "state"))
		}
		b.Metrics = append(b.Metrics,
			m("device_if_in_octets", float64(r.RxOctets), "bytes"),
			m("device_if_out_octets", float64(r.TxOctets), "bytes"),
			m("device_if_in_errors", float64(r.RxErrors), "errors"),
			m("device_if_out_errors", float64(r.TxErrors), "errors"),
			m("device_if_in_discards", float64(r.RxDrops), "discards"),
			m("device_if_out_discards", float64(r.TxDrops), "discards"),
		)
		if r.SpeedMbps > 0 {
			b.Metrics = append(b.Metrics, m("device_if_speed", float64(r.SpeedMbps), "mbps"))
		}
	}
	return b, nil
}

func vmanageSystemRealtimeTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			Device      string `json:"vdevice-name"`
			CPUIdle     vmStr  `json:"cpu_idle"`
			MemUsed     vmStr  `json:"mem_used"`
			MemTotal    vmStr  `json:"mem_total"`
			LastUpdated vmNum  `json:"lastupdated"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range resp.Data {
		if net.ParseIP(r.Device) == nil {
			continue
		}
		ts := vmTime(int64(r.LastUpdated))
		tags := vmMetricTags(tenant, integrationID, "device", r.Device)
		if idle, err := strconv.ParseFloat(strings.TrimSpace(string(r.CPUIdle)), 64); err == nil {
			b.Metrics = append(b.Metrics, vmMetric(tenant, integrationID, "device_cpu_percent", clampPct(100-idle), "percent", ts, tags))
		}
		used, uerr := strconv.ParseFloat(strings.TrimSpace(string(r.MemUsed)), 64)
		total, terr := strconv.ParseFloat(strings.TrimSpace(string(r.MemTotal)), 64)
		if uerr == nil && terr == nil && total > 0 {
			b.Metrics = append(b.Metrics, vmMetric(tenant, integrationID, "device_mem_percent", clampPct(used/total*100), "percent", ts, tags))
		}
	}
	return b, nil
}
