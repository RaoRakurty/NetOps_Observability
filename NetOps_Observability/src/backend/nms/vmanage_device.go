// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// vmanage_device.go — the three REAL-TIME per-device streams (polled with
// ?deviceId=<system-ip>, see vmanagePoll). Before 2026-10-18 they were never
// polled successfully (400 without deviceId) and, had they been, every row
// would have fallen into the ALARMS parser. They are facts, not alarms:
//   - bfd/sessions         → one bfd state per session (up/down)
//   - control/connections  → one control_conn state per controller peer
//   - tunnel/statistics    → per-tunnel packet/byte counters (metric lane)
// Field names are the 20.x wire names (hyphenated), sampled from a live 20.6.1.

// vmNum reads a JSON number or numeric string; anything else is 0.
type vmNum float64

func (n *vmNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	var f float64
	if _, err := fmt.Sscan(s, &f); err != nil {
		*n = 0
		return nil //nolint:nilerr // discard: a non-numeric value is "not reported", never a parse failure of the row
	}
	*n = vmNum(f)
	return nil
}

// vmStr reads a JSON string or number as text (site-id is a number on the wire).
type vmStr string

func (s *vmStr) UnmarshalJSON(b []byte) error {
	*s = vmStr(strings.Trim(string(b), `"`))
	return nil
}

type vmDeviceRow struct {
	VDevice   string `json:"vdevice-name"`
	VHost     string `json:"vdevice-host-name"`
	DataKey   string `json:"vdevice-dataKey"`
	PeerIP    string `json:"system-ip"`
	SiteID    vmStr  `json:"site-id"`
	State     string `json:"state"`
	LastUpd   int64  `json:"lastupdated"`
	LocalCol  string `json:"local-color"`
	RemoteCol string `json:"remote-color"`
	Color     string `json:"color"` // bfd: the remote colour
	Proto     string `json:"proto"`
	Protocol  string `json:"protocol"`
	PeerType  string `json:"peer-type"`
	TunProto  string `json:"tunnel-protocol"`
	RxPkts    vmNum  `json:"rx_pkts"`
	TxPkts    vmNum  `json:"tx_pkts"`
	RxOctets  vmNum  `json:"rx_octets"`
	TxOctets  vmNum  `json:"tx_octets"`
	Transits  vmNum  `json:"transitions"`
}

func vmRows(raw []byte) ([]vmDeviceRow, error) {
	var resp struct {
		Data []vmDeviceRow `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func vmTime(ms int64) time.Time {
	if t := msToTime(ms); !t.IsZero() {
		return t
	}
	return nowUTC()
}

// vmUpDown keeps the vocabulary closed: anything that is not "up" is down.
func vmUpDown(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "up") {
		return "up"
	}
	return "down"
}

func vmanageBFDTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	rows, err := vmRows(raw)
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range rows {
		if r.VDevice == "" || r.PeerIP == "" {
			continue
		}
		key := r.DataKey
		if key == "" {
			key = r.VDevice + "-" + r.LocalCol + "-" + r.PeerIP + "-" + r.Color
		}
		b.States = append(b.States, ControllerState{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			EntityKey: key, StateKind: "bfd", CurrentState: vmUpDown(r.State),
			DeviceID: r.VDevice, SiteID: string(r.SiteID), Time: vmTime(r.LastUpd),
			// BFD's `color` is the FAR end's colour (both ends mirror it).
			TunnelID: CanonicalTunnelID(r.VDevice, r.LocalCol, r.PeerIP, r.Color), PeerID: r.PeerIP,
			Data: map[string]any{"device_name": r.VHost, "peer_system_ip": r.PeerIP,
				"local_color": r.LocalCol, "remote_color": r.Color, "proto": r.Proto, "transitions": float64(r.Transits)},
		})
	}
	return b, nil
}

func vmanageControlTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	rows, err := vmRows(raw)
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range rows {
		if r.VDevice == "" || r.PeerIP == "" {
			continue
		}
		key := r.DataKey
		if key == "" {
			key = r.VDevice + "-" + r.LocalCol + "-" + r.PeerIP + "-" + r.RemoteCol
		}
		b.States = append(b.States, ControllerState{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
			EntityKey: key, StateKind: "control_conn", CurrentState: vmUpDown(r.State),
			DeviceID: r.VDevice, SiteID: string(r.SiteID), Time: vmTime(r.LastUpd),
			TunnelID: CanonicalTunnelID(r.VDevice, r.LocalCol, r.PeerIP, r.RemoteCol), PeerID: r.PeerIP,
			Data: map[string]any{"device_name": r.VHost, "peer_system_ip": r.PeerIP, "peer_type": r.PeerType,
				"local_color": r.LocalCol, "remote_color": r.RemoteCol, "protocol": r.Protocol},
		})
	}
	return b, nil
}

func vmanageTunnelStatsTransform(tenant, integrationID string, raw []byte) (Batch, error) {
	rows, err := vmRows(raw)
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, r := range rows {
		if r.VDevice == "" {
			continue
		}
		tags := map[string]string{
			"tenant_id": tenant, "integration_id": integrationID, "source_system": "vmanage",
			"device": r.VDevice, "tunnel": r.DataKey, "peer": r.PeerIP, "proto": r.TunProto,
			"transport":   r.LocalCol + "-" + r.RemoteCol,
			"local_color": r.LocalCol, "remote_color": r.RemoteCol,
		}
		ts := vmTime(r.LastUpd)
		mk := func(name string, v vmNum, unit string) ControllerMetric {
			return ControllerMetric{TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				Name: name, Value: float64(v), Unit: unit, Time: ts, Tags: tags}
		}
		b.Metrics = append(b.Metrics,
			mk("controller_metric_tunnel_rx_octets_total", r.RxOctets, "bytes"),
			mk("controller_metric_tunnel_tx_octets_total", r.TxOctets, "bytes"),
			mk("controller_metric_tunnel_rx_packets_total", r.RxPkts, "packets"),
			mk("controller_metric_tunnel_tx_packets_total", r.TxPkts, "packets"),
		)
	}
	return b, nil
}
