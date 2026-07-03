package nms

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(in.Base, "/")+path, nil)
	if err != nil {
		return nil, in.Checkpoint, err
	}
	for k, vs := range in.Session.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := in.Do.Do(req)
	if err != nil {
		return nil, in.Checkpoint, err
	}
	defer drainClose(resp)
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, in.Checkpoint, ErrUnauthorized // runtime re-authenticates
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, in.Checkpoint, fmt.Errorf("poll %s: status %d", in.Stream, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, in.Checkpoint, err
	}
	// Advance the checkpoint to now (event-time advancement is refined by the
	// transformer's max event_time in the runtime; this is the coarse cursor).
	next := Checkpoint{LastEventTime: nowUTC(), LastSeq: in.Checkpoint.LastSeq + 1}
	return [][]byte{body}, next, nil
}

// vManage poll endpoints (verified paths). Alarms since a cursor; approute
// statistics for the metric lane.
func vmanagePoller() Poller {
	return restPoller{paths: map[string]string{
		"alarms":              "/dataservice/alarms",
		"events":              "/dataservice/event",
		"tunnels":             "/dataservice/device/tunnel/statistics",
		"control_connections": "/dataservice/device/control/connections",
		"bfd":                 "/dataservice/device/bfd/sessions",
		"statistics":          "/dataservice/statistics/approute",
		"inventory":           "/dataservice/device",
	}}
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

// pollInterval clamps a configured interval to a sane floor.
func pollInterval(d time.Duration, def time.Duration) time.Duration {
	if d < 30*time.Second {
		return def
	}
	return d
}
