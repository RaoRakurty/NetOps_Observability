package nms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/wireless"
)

// catalyst9800.go — Cisco Catalyst 9800 WLC connector (tracker #128 Phase 2,
// design docs/Wireslessdesign.md §14). RESTCONF-first: the richest, versioned,
// model-driven source on IOS-XE. This is a WIRELESS source — distinct from
// catalyst.go (Catalyst Center assurance issues), which has no AP/radio/WLAN/
// client concept.
//
// ── FIDELITY: doc_claimed, and honestly so ─────────────────────────────────
// Every RESTCONF path and JSON key below is authored from the published
// Cisco-IOS-XE-wireless-* YANG models (IOS-XE 17.x). No live Catalyst 9800
// exists in the lab (report B7), so NOTHING here is lab- or live-validated:
// the transformer is tested against hand-authored fixtures that cite their
// model, parsing is tolerant (a missing leaf yields a zero value, never a
// crash), and the spec declares every capability doc_claimed. Per the
// project's fidelity rule: no invented leaves to fill gaps — where a mapping
// was uncertain it is OMITTED and noted, not guessed.
//
// Streams (paths in catalyst9800Poller):
//   wireless_aps     access-point-oper: capwap-data — AP join/inventory + state
//   wireless_radios  access-point-oper: radio-oper-data — per-radio oper state
//   wireless_wlans   wlan-cfg: wlan-cfg-entries — WLAN profiles (config)
//   wireless_clients client-oper: common-oper-data — client COUNT only in
//                    Phase 2 (per-client sessions are Phase 4; and per-client
//                    continuous series are FORBIDDEN by the storage rule §20)
//   wireless_rf      rrm-oper: rrm-measurement — per-radio channel utilization
//
// Auth: RESTCONF is HTTP Basic on IOS-XE (verified against the RESTCONF
// standard, RFC 8040 §2.5 — not vendor-specific). No OAuth exists on the
// platform; declaring it would fail TestAuthPolicy, correctly.

// Catalyst9800Auth returns a static Basic session (RESTCONF authenticates
// every request; there is no login exchange to refresh).
type Catalyst9800Auth struct{}

func (Catalyst9800Auth) Authenticate(_ context.Context, _ string, creds Credentials, _ Doer) (Session, error) {
	if creds.Username == "" || creds.Password == "" {
		return Session{}, fmt.Errorf("catalyst_9800: username/password required for RESTCONF basic auth")
	}
	h := http.Header{}
	h.Set("Authorization", "Basic "+basicCred(creds.Username, creds.Password))
	h.Set("Accept", "application/yang-data+json")
	return Session{Header: h}, nil // non-expiring: Basic re-sent every request
}

// catalyst9800Poller — the RESTCONF data paths, one container per stream.
// {since} is unused: these are current-state reads (the checkpoint pattern is
// for event logs; oper data is a snapshot).
func catalyst9800Poller() Poller {
	return restPoller{paths: map[string]string{
		"wireless_aps":     "/restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/capwap-data",
		"wireless_radios":  "/restconf/data/Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/radio-oper-data",
		"wireless_wlans":   "/restconf/data/Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-data/wlan-cfg-entries",
		"wireless_clients": "/restconf/data/Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data",
		"wireless_rf":      "/restconf/data/Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data/rrm-measurement",
	}}
}

// Catalyst9800Transformer shape-routes on the RESTCONF module key (one
// transformer serves every stream — the VManageAutoTransformer pattern).
type Catalyst9800Transformer struct{}

func (t Catalyst9800Transformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return Batch{}, err
	}
	for key, body := range top {
		switch {
		case strings.Contains(key, "capwap-data"):
			return t.transformCAPWAP(tenant, integrationID, body)
		case strings.Contains(key, "radio-oper-data"):
			return t.transformRadios(tenant, integrationID, body)
		case strings.Contains(key, "wlan-cfg-entries"):
			return t.transformWLANs(tenant, integrationID, body)
		case strings.Contains(key, "common-oper-data"):
			return t.transformClients(tenant, integrationID, body)
		case strings.Contains(key, "rrm-measurement"):
			return t.transformRRM(tenant, integrationID, body)
		}
	}
	// Unknown shape: not an error (a firmware may nest differently) but not
	// silent either — an empty batch is visible in run accounting.
	return Batch{}, nil
}

// c9800ControllerID derives the LOGICAL controller identity from the
// integration (stable per configured WLC; the mgmt address is not in the
// payload).
func c9800ControllerID(tenant, integrationID string) string {
	return wireless.ControllerID(tenant, "cisco_9800", integrationID)
}

// ── capwap-data → AP inventory + join state ────────────────────────────────
//
// Model: Cisco-IOS-XE-wireless-access-point-oper (17.x), container capwap-data.
// Leaves used: wtp-mac, ip-addr, name, ap-operation-state, and the nested
// device-detail/static-info block (board-data/wtp-serial-num, ap-models/model).
// [doc_claimed — verify leaf spelling on a live 9800 before trusting.]

func (Catalyst9800Transformer) transformCAPWAP(tenant, integrationID string, body []byte) (Batch, error) {
	var rows []struct {
		WtpMAC    string `json:"wtp-mac"`
		IPAddr    string `json:"ip-addr"`
		Name      string `json:"name"`
		OperState string `json:"ap-operation-state"`
		Detail    struct {
			StaticInfo struct {
				BoardData struct {
					Serial string `json:"wtp-serial-num"`
				} `json:"board-data"`
				APModels struct {
					Model string `json:"model"`
				} `json:"ap-models"`
			} `json:"static-info"`
		} `json:"device-detail"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return Batch{}, err
	}
	wlcID := c9800ControllerID(tenant, integrationID)
	inv := &wireless.Inventory{Controllers: []wireless.Controller{{
		TenantID: tenant, ControllerID: wlcID, Name: integrationID,
		Vendor: "cisco", Model: "Catalyst 9800", Kind: "controller",
		// HA/cluster detail is a later stream; standalone is the honest default
		// until the redundancy oper model is mapped [doc_claimed gap].
		ClusterRole: wireless.ClusterStandalone,
		Visibility:  "partial",
	}}}
	var b Batch
	now := time.Now().UTC()
	for _, r := range rows {
		serial := strings.TrimSpace(r.Detail.StaticInfo.BoardData.Serial)
		// Identity is MAC-based for THIS connector even when a serial exists:
		// the radio and RRM streams carry only wtp-mac, and an AP's rows from
		// different streams MUST converge on one ap_id or radios/RF would
		// attach to a phantom AP. The serial is still recorded as data.
		apID := wireless.APID(tenant, "cisco", "", r.WtpMAC)
		inv.APs = append(inv.APs, wireless.AccessPoint{
			TenantID: tenant, APID: apID, Name: r.Name, MACBase: r.WtpMAC,
			Serial: serial, Model: r.Detail.StaticInfo.APModels.Model,
			Vendor: "cisco", ControllerRef: wlcID, MgmtAddress: r.IPAddr,
		})
		// Join state: "registered" is up; everything else (downloading,
		// disjoined, unknown) is not-up. State transitions become change
		// events via the flap-tracking StateTracker, like every controller.
		cur := "down"
		if strings.Contains(strings.ToLower(r.OperState), "registered") {
			cur = "up"
		}
		b.States = append(b.States, ControllerState{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_9800",
			EntityKey: wireless.APEntityID(apID), StateKind: "ap_join",
			CurrentState: cur, DeviceID: r.WtpMAC, Time: now,
			Data: map[string]any{"ap_name": r.Name, "oper_state": r.OperState},
		})
	}
	b.Wireless = inv
	return b, nil
}

// ── radio-oper-data → radio inventory + oper state ─────────────────────────
//
// Model: Cisco-IOS-XE-wireless-access-point-oper, container radio-oper-data.
// Leaves used: wtp-mac, radio-slot-id, oper-state, admin-state, radio-type.
// Channel/width/power leaves vary by release and are OMITTED rather than
// guessed [doc_claimed gap — map them against a live 9800].

func (Catalyst9800Transformer) transformRadios(tenant, integrationID string, body []byte) (Batch, error) {
	var rows []struct {
		WtpMAC     string `json:"wtp-mac"`
		SlotID     int    `json:"radio-slot-id"`
		OperState  string `json:"oper-state"`
		AdminState string `json:"admin-state"`
		RadioType  string `json:"radio-type"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return Batch{}, err
	}
	var b Batch
	inv := &wireless.Inventory{}
	now := time.Now().UTC()
	for _, r := range rows {
		// MAC-based identity, matching transformCAPWAP — one ap_id across all
		// of this connector's streams. [Verify wtp-mac framing agrees across
		// streams on a live controller.]
		apID := wireless.APID(tenant, "cisco", "", r.WtpMAC)
		inv.Radios = append(inv.Radios, wireless.Radio{
			TenantID: tenant, RadioID: wireless.RadioID(apID, r.SlotID), APID: apID,
			Slot: r.SlotID, Band: c9800Band(r.RadioType),
			AdminState: c9800AdminState(r.AdminState), OperState: c9800OperState(r.OperState),
		})
		b.States = append(b.States, ControllerState{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_9800",
			EntityKey: wireless.RadioEntityID(apID, r.SlotID), StateKind: "radio_oper",
			CurrentState: c9800OperState(r.OperState), DeviceID: r.WtpMAC, Time: now,
			Data: map[string]any{"slot": r.SlotID, "radio_type": r.RadioType},
		})
	}
	b.Wireless = inv
	return b, nil
}

func c9800Band(radioType string) string {
	t := strings.ToLower(radioType)
	switch {
	case strings.Contains(t, "6ghz") || strings.Contains(t, "6-ghz"):
		return "6GHz"
	// b/g (2.4) BEFORE a (5): "80211bg" must not fall through to the 5GHz arm,
	// and both hyphenations of the identityref literal are accepted.
	case strings.Contains(t, "80211b") || strings.Contains(t, "802-11b") ||
		strings.Contains(t, "2-dot-4") || strings.Contains(t, "2.4"):
		return "2.4GHz"
	case strings.Contains(t, "5ghz") || strings.Contains(t, "80211a") || strings.Contains(t, "802-11a"):
		return "5GHz"
	default:
		return ""
	}
}

func c9800OperState(s string) string {
	t := strings.ToLower(s)
	switch {
	case strings.Contains(t, "up") || strings.Contains(t, "enabled"):
		return "up"
	case strings.Contains(t, "down") || strings.Contains(t, "disabled"):
		return "down"
	default:
		return "unknown"
	}
}

func c9800AdminState(s string) string {
	t := strings.ToLower(s)
	switch {
	case strings.Contains(t, "enabled") || strings.Contains(t, "up"):
		return "enabled"
	case strings.Contains(t, "disabled") || strings.Contains(t, "down"):
		return "disabled"
	default:
		return "unknown"
	}
}

// ── wlan-cfg-entries → WLAN profiles ───────────────────────────────────────
//
// Model: Cisco-IOS-XE-wireless-wlan-cfg, list wlan-cfg-entry. Leaves used:
// profile-name, apf-vap-id-data/ssid, apf-vap-id-data/wlan-status.
// Security/auth mapping is release-variant and lands with the onboarding
// phase work (Phase 4); auth_method stays "unknown" rather than guessed.

func (Catalyst9800Transformer) transformWLANs(tenant, integrationID string, body []byte) (Batch, error) {
	var wrapper struct {
		Entries []struct {
			ProfileName string `json:"profile-name"`
			VapIDData   struct {
				SSID   string `json:"ssid"`
				Status bool   `json:"wlan-status"`
			} `json:"apf-vap-id-data"`
		} `json:"wlan-cfg-entry"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return Batch{}, err
	}
	wlcID := c9800ControllerID(tenant, integrationID)
	inv := &wireless.Inventory{}
	for _, e := range wrapper.Entries {
		inv.WLANs = append(inv.WLANs, wireless.WLAN{
			TenantID: tenant, WLANID: wireless.WLANID(tenant, wlcID, e.ProfileName),
			ProfileName: e.ProfileName, SSIDName: e.VapIDData.SSID,
			SSIDRef:       wireless.SSIDID(tenant, e.VapIDData.SSID),
			ControllerRef: wlcID, Enabled: e.VapIDData.Status,
			SecurityMode: "unknown", AuthMethod: "unknown",
		})
	}
	return Batch{Wireless: inv}, nil
}

// ── client common-oper-data → client-count metrics ONLY ────────────────────
//
// Model: Cisco-IOS-XE-wireless-client-oper, list common-oper-data. Leaves
// used: client-mac (counted, never emitted), ap-name, co-state.
// Phase 2 deliberately emits COUNTS, not clients: per-client sessions are
// Phase 4 (ClickHouse event tier), and a per-client metric series is
// forbidden by the storage rule (§20) — a client MAC is never a label.

func (Catalyst9800Transformer) transformClients(tenant, integrationID string, body []byte) (Batch, error) {
	var rows []struct {
		ClientMAC string `json:"client-mac"`
		APName    string `json:"ap-name"`
		State     string `json:"co-state"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return Batch{}, err
	}
	now := time.Now().UTC()
	perAP := map[string]float64{}
	run := 0.0
	for _, r := range rows {
		if !strings.Contains(strings.ToLower(r.State), "run") {
			continue // only associated-and-running clients count
		}
		run++
		if r.APName != "" {
			perAP[r.APName]++
		}
	}
	var b Batch
	b.Metrics = append(b.Metrics, ControllerMetric{
		TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_9800",
		Name: "controller_metric_wireless_client_count", Value: run, Unit: "clients",
		Time: now, Tags: map[string]string{"integration": integrationID},
	})
	for ap, n := range perAP {
		b.Metrics = append(b.Metrics, ControllerMetric{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_9800",
			Name: "controller_metric_wireless_ap_client_count", Value: n, Unit: "clients",
			Time: now, Tags: map[string]string{"integration": integrationID, "device": ap},
		})
	}
	return b, nil
}

// ── rrm-measurement → per-radio channel utilization ────────────────────────
//
// Model: Cisco-IOS-XE-wireless-rrm-oper, list rrm-measurement. Leaves used:
// wtp-mac, radio-slot-id, load/cca-util-percentage, load/rx-noise-channel-
// utilization (noise floor is release-variant — omitted where absent).

func (Catalyst9800Transformer) transformRRM(tenant, integrationID string, body []byte) (Batch, error) {
	var rows []struct {
		WtpMAC string `json:"wtp-mac"`
		SlotID int    `json:"radio-slot-id"`
		Load   struct {
			CCAUtilPct float64 `json:"cca-util-percentage"`
			RxUtilPct  float64 `json:"rx-noise-channel-utilization"`
		} `json:"load"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return Batch{}, err
	}
	now := time.Now().UTC()
	var b Batch
	for _, r := range rows {
		apID := wireless.APID(tenant, "cisco", "", r.WtpMAC)
		tags := map[string]string{
			"integration": integrationID,
			"device":      wireless.APEntityID(apID),
			"slot":        fmt.Sprintf("%d", r.SlotID),
		}
		b.Metrics = append(b.Metrics, ControllerMetric{
			TenantID: tenant, IntegrationID: integrationID, SourceSystem: "catalyst_9800",
			Name: "controller_metric_wireless_channel_util_pct", Value: r.Load.CCAUtilPct,
			Unit: "percent", Time: now, Tags: tags,
		})
	}
	return b, nil
}
