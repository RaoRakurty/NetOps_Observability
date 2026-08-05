package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GNMI reports the live state of streaming gNMI telemetry.
//
// Real gNMI is a gRPC Subscribe stream (protobuf over HTTP/2) that needs a
// client library outside the stdlib zero-dependency budget, so the actual
// subscription is run by the `gnmic` sidecar, which streams the fabric's
// OpenConfig/SR-Linux counters into VictoriaMetrics (metric prefix "gnmi_",
// every sample tagged with a `source` label = the target name). Probing device
// TCP ports here counted nothing useful (the lab devices prefer SNMP), so this
// collector instead asks VictoriaMetrics how many distinct gNMI sources have
// produced telemetry in the recent window — i.e. the targets actually streaming
// right now. That count rises as gnmic brings subscriptions up, which is exactly
// the "gNMI targets" signal operators expect to see climb.
//
// Targets == Reachable here: a source that reported within the freshness window
// is, by definition, an established, healthy gNMI stream. Stays stdlib
// (net/http + encoding/json) — it reads telemetry, it doesn't speak gRPC.
type gnmiCollector struct {
	interval time.Duration
	window   string // PromQL lookback for "recently streamed", e.g. "5m"

	mu     sync.RWMutex
	status Status
}

// NewGNMI builds the gNMI streaming-telemetry status collector. The targets
// func is unused — liveness comes from the telemetry gnmic has already written.
func NewGNMI(_ TargetFunc) Collector {
	return &gnmiCollector{
		interval: 60 * time.Second,
		window:   "5m",
		status:   Status{Name: "gnmi", Healthy: true, Kind: "protocol"},
	}
}

func (g *gnmiCollector) Name() string { return "gnmi" }

func (g *gnmiCollector) Status() Status {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.status
}

func (g *gnmiCollector) Run(ctx context.Context) error {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	g.pollOnce(ctx) // populate status within seconds of boot
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			g.pollOnce(ctx)
		}
	}
}

func (g *gnmiCollector) pollOnce(ctx context.Context) {
	start := time.Now()
	// Distinct gNMI sources that streamed ANY telemetry within the window.
	// Match all gnmi_* metrics so both the Arista OpenConfig models and the
	// Nokia SR Linux native models count toward the live-target total.
	q := `count(count by (source) (last_over_time({__name__=~"gnmi_.+"}[` + g.window + `])))`
	n, err := g.vmScalar(ctx, q)

	g.mu.Lock()
	g.status.LastTick = start.UTC()
	g.status.LastPollMillis = time.Since(start).Milliseconds()
	// This collector's entire job is to read gNMI liveness out of VictoriaMetrics.
	// If VM does not answer, it knows NOTHING — reporting "healthy" then is the
	// platform asserting sight it does not have. A loop that is merely running is
	// not a healthy collector.
	g.status.Healthy = err == nil
	if err != nil {
		// Couldn't reach VictoriaMetrics — report the error rather than a
		// misleading zero, and leave the last known counts in place.
		g.status.LastError = err.Error()
	} else {
		g.status.Targets = n
		g.status.Reachable = n // in-window => an established, healthy stream
		g.status.LastError = ""
	}
	g.mu.Unlock()
}

// vmScalar runs an instant PromQL query against VictoriaMetrics and returns the
// first result's value as an int (0 when the result set is empty).
func (g *gnmiCollector) vmScalar(ctx context.Context, query string) (int, error) {
	base := os.Getenv("VICTORIA_URL")
	if base == "" {
		base = os.Getenv("METRICS_URL")
	}
	if base == "" {
		base = "http://victoria:8428"
	}
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape(query)
	// #nosec G704 -- endpoint is the operator-configured VICTORIA_URL/METRICS_URL backend, not user input
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	resp, err := meshHTTPClient(5 * time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// A non-2xx reply is a failure to LOOK, not an observation of zero streams —
	// without this check a 500 from the metric store decoded to an empty result
	// and was published as "no gNMI sources are streaming".
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("victoria %d for %s", resp.StatusCode, endpoint)
	}

	var out struct {
		Data struct {
			Result []struct {
				Value [2]any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	// F-27 class: the reply size is the peer's business, not ours.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return 0, err
	}
	if len(out.Data.Result) == 0 {
		return 0, nil // nothing streaming yet
	}
	// value is [ <ts float>, "<number string>" ]
	if s, ok := out.Data.Result[0].Value[1].(string); ok {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, err
		}
		return int(f), nil
	}
	return 0, nil
}
