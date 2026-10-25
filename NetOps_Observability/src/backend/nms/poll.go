// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// poll.go — pollers. A Poller fetches raw payloads for one stream and advances
// the checkpoint; it does NOT normalize (the Transformer does). The runtime
// hands it a rate-limited/retried Doer + the authenticated Session.

// streamPath maps (vendor stream) → the REST path template. Kept here so a
// vendor's endpoints live in one place. "{since}" is replaced by the checkpoint
// epoch-millis when present.
type restPoller struct {
	paths map[string]string // stream → path (may contain {since})
}

func (p restPoller) Poll(ctx context.Context, in PollInput) ([][]byte, Checkpoint, error) {
	tmpl, ok := p.paths[in.Stream]
	if !ok {
		return nil, in.Checkpoint, fmt.Errorf("stream %q not supported", in.Stream)
	}
	// Resolve the {since} cursor: checkpoint, or backfill window on first run.
	since := in.Checkpoint.LastEventTime
	if since.IsZero() && in.Backfill > 0 {
		since = nowUTC().Add(-in.Backfill)
	}
	path := tmpl
	if strings.Contains(tmpl, "{since}") {
		ms := "0"
		if !since.IsZero() {
			ms = formatInt(since.UnixMilli())
		}
		path = strings.ReplaceAll(tmpl, "{since}", ms)
	}
	// Vendor path placeholders (e.g. Meraki {org}) resolve from Params. An
	// unresolved placeholder is a config error — fail loud, never send it raw.
	for k, v := range in.Params {
		path = strings.ReplaceAll(path, "{"+k+"}", url.PathEscape(v))
	}
	if i := strings.IndexByte(path, '{'); i >= 0 {
		if j := strings.IndexByte(path[i:], '}'); j > 0 {
			return nil, in.Checkpoint, fmt.Errorf("stream %q: unresolved path parameter %s (set it in the integration credentials)", in.Stream, path[i:i+j+1])
		}
	}
	body, err := fetch(ctx, in, path)
	if err != nil {
		return nil, in.Checkpoint, err
	}
	// Advance the checkpoint to now (event-time advancement is refined by the
	// transformer's max event_time in the runtime; this is the coarse cursor).
	next := Checkpoint{LastEventTime: nowUTC(), LastSeq: in.Checkpoint.LastSeq + 1}
	return [][]byte{body}, next, nil
}

// fetch GETs base+path with the session's headers. 401 → ErrUnauthorized (the
// runtime re-authenticates); any other non-2xx is an error naming the stream.
func fetch(ctx context.Context, in PollInput, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(in.Base, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range in.Session.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := in.Do.Do(req)
	if err != nil {
		return nil, err
	}
	defer drainClose(resp)
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized // runtime re-authenticates
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPStatusError{Op: "poll " + in.Stream, Code: resp.StatusCode}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

// vManage poll endpoints (verified paths). Cursor streams, fleet-wide
// aggregations and slow snapshots are dispatched in vmanagePoll.Poll; what is
// left is a plain GET.
func vmanagePoller() Poller {
	return vmanagePoll{rest: restPoller{paths: map[string]string{
		"inventory": "/dataservice/device",
	}}}
}

// vmanageCursorStreams are read with an entry_time cursor. A bare GET of
// /dataservice/event returned 17 h / 7,188 rows (5.5 MB) on every cycle (lab,
// 2026-10-18) — more than the de-duplication window holds, so nearly every
// event was re-emitted each poll. The query asks only for what is new.
var vmanageCursorStreams = map[string]string{
	"alarms": "/dataservice/alarms",
	"events": "/dataservice/event",
	"audit":  "/dataservice/auditlog",
}

// vmanageCursorOverlap re-reads a short window behind the cursor so a row that
// lands late is not missed; the row id de-duplicates the overlap.
const vmanageCursorOverlap = 2 * time.Minute

// pollVManageSince GETs path?query=<entry_time greater than the cursor>. The
// 20.x query grammar accepts epoch-ms for "greater" (verified on 20.6.1).
func pollVManageSince(ctx context.Context, in PollInput, path string) ([][]byte, Checkpoint, error) {
	since := in.Checkpoint.LastEventTime
	if since.IsZero() {
		back := in.Backfill
		if back <= 0 {
			back = DefaultBackfill
		}
		since = nowUTC().Add(-back)
	}
	since = since.Add(-vmanageCursorOverlap)
	q, _ := json.Marshal(map[string]any{"query": map[string]any{ // discard: marshalling an in-memory value cannot fail
		"condition": "AND",
		"rules": []map[string]any{{
			"value": []string{strconv.FormatInt(since.UnixMilli(), 10)}, "field": "entry_time",
			"type": "date", "operator": "greater",
		}},
	}})
	started := nowUTC()
	body, err := fetch(ctx, in, path+"?query="+url.QueryEscape(string(q)))
	if err != nil {
		return nil, in.Checkpoint, err
	}
	return [][]byte{body}, Checkpoint{LastEventTime: started, LastSeq: in.Checkpoint.LastSeq + 1}, nil
}

// vmanagePerDevice are vManage's REAL-TIME device APIs. Every release answers
// them 400 without ?deviceId=<system-ip> (verified on 20.6.1, 2026-10-18), so
// they are polled once per reachable device found in /dataservice/device.
var vmanagePerDevice = map[string]string{
	"tunnels":             "/dataservice/device/tunnel/statistics",
	"control_connections": "/dataservice/device/control/connections",
	"bfd":                 "/dataservice/device/bfd/sessions",
}

// vmanageMaxDevicesPerCycle bounds one stream's fan-out per poll; a larger
// fabric is covered across cycles (the window rotates with the checkpoint).
const vmanageMaxDevicesPerCycle = 200

type vmanagePoll struct{ rest restPoller }

func (p vmanagePoll) Poll(ctx context.Context, in PollInput) ([][]byte, Checkpoint, error) {
	if path, ok := vmanageCursorStreams[in.Stream]; ok {
		return pollVManageSince(ctx, in, path)
	}
	if agg, ok := vmanageAggregations[in.Stream]; ok {
		return pollVManageAggregation(ctx, in, agg)
	}
	if slow, ok := vmanageSlowStreams[in.Stream]; ok {
		return pollVManageSlow(ctx, in, slow.every, slow.paths)
	}
	path, perDevice := vmanagePerDevice[in.Stream]
	if !perDevice {
		return p.rest.Poll(ctx, in)
	}
	inv, err := fetch(ctx, in, "/dataservice/device")
	if err != nil {
		return nil, in.Checkpoint, err
	}
	ids, err := vmanageDeviceIDs(inv, in.Stream)
	if err != nil {
		return nil, in.Checkpoint, err
	}
	window := rotateWindow(ids, int(in.Checkpoint.LastSeq), vmanageMaxDevicesPerCycle)
	var out [][]byte
	var failed []string
	for _, id := range window {
		body, err := fetch(ctx, in, path+"?deviceId="+url.QueryEscape(id))
		if errors.Is(err, ErrUnauthorized) {
			return nil, in.Checkpoint, err // the whole session is gone — re-authenticate
		}
		if err != nil {
			failed = append(failed, id) // one unhealthy device must not blank the fabric
			continue
		}
		out = append(out, body)
	}
	if len(out) == 0 && len(failed) > 0 {
		return nil, in.Checkpoint, fmt.Errorf("poll %s: every device failed (%d), first %s", in.Stream, len(failed), failed[0])
	}
	next := Checkpoint{LastEventTime: nowUTC(), LastSeq: in.Checkpoint.LastSeq + 1}
	return out, next, nil
}

// vmanageDeviceIDs extracts the system-ips worth querying from a
// /dataservice/device response. Controller output is untrusted input: only a
// syntactically valid IP becomes a query parameter. BFD and tunnel statistics
// exist on edges only; control connections on every reachable device.
func vmanageDeviceIDs(raw []byte, stream string) ([]string, error) {
	var resp struct {
		Data []struct {
			SystemIP     string `json:"system-ip"`
			DeviceType   string `json:"device-type"`
			Reachability string `json:"reachability"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("vmanage inventory unreadable: %w", err)
	}
	seen := map[string]bool{}
	var ids []string
	for _, d := range resp.Data {
		if !strings.EqualFold(d.Reachability, "reachable") || net.ParseIP(d.SystemIP) == nil || seen[d.SystemIP] {
			continue
		}
		edge := strings.EqualFold(d.DeviceType, "vedge") // cEdges report "vedge" too
		if stream != "control_connections" && !edge {
			continue
		}
		seen[d.SystemIP] = true
		ids = append(ids, d.SystemIP)
	}
	sort.Strings(ids)
	return ids, nil
}

// rotateWindow returns up to max ids starting at a cycle-dependent offset, so
// successive cycles walk a fabric larger than max.
func rotateWindow(ids []string, cycle, max int) []string {
	if len(ids) <= max {
		return ids
	}
	start := (cycle * max) % len(ids)
	out := make([]string, 0, max)
	for i := 0; i < max; i++ {
		out = append(out, ids[(start+i)%len(ids)])
	}
	return out
}

func catalystPoller() Poller {
	return restPoller{paths: map[string]string{
		"assurance_issues": "/dna/intent/api/v1/issues",
		"inventory":        "/dna/intent/api/v1/network-device",
		"events":           "/dna/intent/api/v1/event",
	}}
}

func ndfcPoller() Poller {
	return restPoller{paths: map[string]string{
		"fabric_alarms":    "/appcenter/cisco/ndfc/api/v1/alarms",
		"switch_health":    "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/switches",
		"interface_alarms": "/appcenter/cisco/ndfc/api/v1/interface/alarms",
		"inventory":        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/inventory/allswitches",
	}}
}

func primePoller() Poller {
	return restPoller{paths: map[string]string{
		"alarms":    "/webacs/api/v4/data/Alarms.json",
		"inventory": "/webacs/api/v4/data/Devices.json",
	}}
}

func versaPoller() Poller {
	return restPoller{paths: map[string]string{
		"alarms":     "/vnms/alarm/alarms",
		"appliances": "/vnms/appliance/appliance",
		"events":     "/vnms/dashboard/events",
	}}
}

func genericPoller() Poller {
	return restPoller{paths: map[string]string{"events": "/events"}}
}

// meraki organization poll (alerts via the API rather than webhook).
func merakiPoller() Poller {
	return restPoller{paths: map[string]string{
		"alarms":    "/api/v1/organizations/{org}/assurance/alerts",
		"inventory": "/api/v1/organizations/{org}/devices",
	}}
}

// ErrUnauthorized signals the runtime to re-authenticate and retry the poll once.
var ErrUnauthorized = fmt.Errorf("nms: unauthorized (re-auth required)")
