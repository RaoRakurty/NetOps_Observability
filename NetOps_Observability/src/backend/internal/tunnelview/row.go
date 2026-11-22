// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tunnelview

import "time"

// EndView is one end on the wire. DeviceID and Site are null when the end is
// hidden from the caller or resolves to no device; Device then carries the
// system-ip, never another tenant's device name.
type EndView struct {
	DeviceID *string `json:"device_id"`
	Device   string  `json:"device"`
	SystemIP string  `json:"system_ip"`
	Color    string  `json:"color"`
	// State is up | down, or "" when this end did not report.
	State    string `json:"state"`
	Sessions int    `json:"sessions"`
	Up       int    `json:"up"`
	Site     *Site  `json:"site"`
}

// Row is one /api/tunnels row for an SD-WAN tunnel. The legacy fields
// (local_device … uptime_s, measured, ts) keep their meaning for the widgets
// that read them; latency/jitter/loss/qoe are the quality reading, which is
// 30–60 minutes old (quality.as_of says how old), and 0 with measured=false
// when there is none.
type Row struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	TunnelID     string   `json:"tunnel_id"`
	Status       string   `json:"status"`
	State        string   `json:"state"`
	EndsReported int      `json:"ends_reported"`
	A            EndView  `json:"a"`
	B            EndView  `json:"b"`
	LocalDevice  string   `json:"local_device"`
	LocalAddr    string   `json:"local_addr"`
	RemoteDevice string   `json:"remote_device"`
	RemoteAddr   string   `json:"remote_addr"`
	LatencyMs    float64  `json:"latency_ms"`
	JitterMs     float64  `json:"jitter_ms"`
	LossPct      float64  `json:"loss_pct"`
	QoE          float64  `json:"qoe"`
	UptimeS      int      `json:"uptime_s"`
	Measured     bool     `json:"measured"`
	TS           string   `json:"ts"`
	Quality      *Quality `json:"quality"`
	Case         *Case    `json:"case"`
	Sources      []string `json:"sources"`
}

// NameOf names a visible device id for display.
type NameOf func(deviceID string) string

// RowOf renders a tunnel. stateAt is when the overlay state was read.
func RowOf(t Tunnel, nameOf NameOf, siteOf SiteOf, q *Quality, c *Case, stateAt time.Time) Row {
	a, b := endView(t.A, nameOf, siteOf), endView(t.B, nameOf, siteOf)
	r := Row{
		ID: t.ID(), Type: "sdwan", TunnelID: t.TunnelID,
		Status: t.Status(), State: t.State(), EndsReported: t.EndsReported(),
		A: a, B: b,
		LocalDevice: a.Device, LocalAddr: t.A.Color,
		RemoteDevice: b.Device, RemoteAddr: firstNonEmpty(t.B.Addr, t.B.Color),
		TS:      stateAt.UTC().Format(time.RFC3339),
		Quality: q, Case: c, Sources: []string{},
	}
	if q != nil {
		r.LatencyMs, r.JitterMs, r.LossPct, r.QoE, r.Measured = q.LatencyMs, q.JitterMs, q.LossPct, q.QoE, true
	}
	seen := map[string]bool{}
	for _, e := range []End{t.A, t.B} {
		if e.Reported && e.Source != "" && !seen[e.Source] {
			seen[e.Source] = true
			r.Sources = append(r.Sources, e.Source)
		}
	}
	return r
}

// AttachSiteRefs stamps each placed end's site with the matrix's opaque key,
// so a matrix cell filters rows exactly. t is the tunnel the row was rendered
// from (its tenant scopes the key). A nil matrix leaves the row unchanged.
func (r *Row) AttachSiteRefs(t Tunnel, m *Matrix) {
	if m == nil {
		return
	}
	for _, v := range []*EndView{&r.A, &r.B} {
		if v.Site != nil {
			v.Site.Ref = m.SiteRef(t.Tenant, *v.Site)
		}
	}
}

func endView(e End, nameOf NameOf, siteOf SiteOf) EndView {
	v := EndView{SystemIP: e.SystemIP, Color: e.Color, State: e.State(), Sessions: e.Sessions, Up: e.Up,
		Device: e.SystemIP}
	if e.DeviceID != "" {
		id := e.DeviceID
		v.DeviceID = &id
		if nameOf != nil {
			v.Device = firstNonEmpty(nameOf(id), id)
		} else {
			v.Device = id
		}
		if s, ok := endSite(e, siteOf); ok {
			v.Site = &s
		}
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
