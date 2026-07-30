package backend

// cloud_metrics_series.go — tenant-scoped cloud metric time-series (Wave 5 #14
// slice 1). The provider metric lane (CloudWatch / Azure Monitor / GCP
// Monitoring → Vector :8690 → netops.metrics → VictoriaMetrics) has carried
// real values since #12 — this endpoint finally renders them: bounded
// query_range reads for the charts on the resource drawer / App Detail.
//
//	GET /api/cloud/metrics/series?resource=<id>[&resource=<id>…]&metric=<name>&window_minutes=<n>
//
// Isolation (§3a): the VM series carry resource_id, and resource ownership
// lives in the cloud inventory — so the handler resolves the CALLER's
// principal-tenant inventory first and refuses any resource id outside it with
// 404 (never reveal another tenant's id). The PromQL selector is built
// server-side from those validated ids only; no caller-supplied PromQL exists
// on this surface.
//
// Bounded (§9): window clamped to 5m..7d, ≤ cloudSeriesMaxResources resources
// per request, step sized so a series never exceeds cloud.SeriesMaxPoints
// points, 10s upstream timeout, 4 MiB response read cap.
//
// Honesty: a resource with no samples returns an EMPTY points array — the UI
// renders "no metrics ingested", never a fabricated flatline.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/cloud"
)

const (
	cloudSeriesMaxResources    = 6 // resources per request (drawer shows 1; App Detail a handful)
	cloudSeriesQueryTimeout    = 10 * time.Second
	cloudSeriesMaxResponseByte = 4 << 20
)

// cloud.MetricMeta is one entry of the CLOSED cloud-metric vocabulary — exactly
// the canonical names the ingest producers emit (cloudmetrics.py CW_METRICS,
// azure.py AZ_METRICS, gcp.py GCP_METRICS). A metric outside this list is
// refused: the endpoint is a cloud-lane chart feed, not a raw PromQL proxy.
type cloudSeriesPoint [2]float64

// vmQueryRangeBy runs one range PromQL query against VictoriaMetrics and
// returns keyLabel → bounded point list. Same upstream + failure contract as
// vmQueryBy (cloud_enrich.go): an unreachable store degrades to nil — the
// handler turns that into an explicit "metric store unreachable" error rather
// than an empty chart pretending the resource is silent.
func vmQueryRangeBy(ctx context.Context, q string, start, end int64, stepSec int, keyLabel string) (map[string][]cloudSeriesPoint, error) {
	base := os.Getenv("VM_QUERY_URL")
	if base == "" {
		base = "http://victoria:8428"
	}
	v := url.Values{}
	v.Set("query", q)
	v.Set("start", strconv.FormatInt(start, 10))
	v.Set("end", strconv.FormatInt(end, 10))
	v.Set("step", strconv.Itoa(stepSec)+"s")
	u := strings.TrimRight(base, "/") + "/api/v1/query_range?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	cl := &http.Client{Timeout: cloudSeriesQueryTimeout}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cloudSeriesMaxResponseByte))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metric store returned %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][2]any          `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	res := map[string][]cloudSeriesPoint{}
	for _, r := range out.Data.Result {
		id := r.Metric[keyLabel]
		if id == "" {
			continue
		}
		pts := make([]cloudSeriesPoint, 0, len(r.Values))
		for _, v := range r.Values {
			ts, tok := v[0].(float64)
			sv, sok := v[1].(string)
			if !tok || !sok {
				continue
			}
			f, err := strconv.ParseFloat(sv, 64)
			if err != nil {
				continue
			}
			pts = append(pts, cloudSeriesPoint{ts, f})
			if len(pts) >= cloud.SeriesMaxPoints {
				break // hard cap even if the upstream over-delivers
			}
		}
		// A resource can appear under several device-name relabels; keep the
		// densest series rather than silently overwriting.
		if prev, ok := res[id]; !ok || len(pts) > len(prev) {
			res[id] = pts
		}
	}
	return res, nil
}

// cloudSeriesEntry is one resource's series in the response.
type cloudSeriesEntry struct {
	ResourceID   string             `json:"resource_id"`
	ResourceName string             `json:"resource_name,omitempty"`
	Points       []cloudSeriesPoint `json:"points"`
}

// handleCloudMetricSeries serves GET /api/cloud/metrics/series.
func (s *server) handleCloudMetricSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	q := r.URL.Query()
	meta, ok := cloud.MetricInfo(strings.TrimSpace(q.Get("metric")))
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("metric must be one of the cloud metric catalog (e.g. cloud_cpu_util)"))
		return
	}
	reqIDs := q["resource"]
	if len(reqIDs) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("at least one resource=<id> is required"))
		return
	}
	if len(reqIDs) > cloudSeriesMaxResources {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at most %d resources per request", cloudSeriesMaxResources))
		return
	}
	windowMin := 0
	if v := strings.TrimSpace(q.Get("window_minutes")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("window_minutes must be a whole number"))
			return
		}
		windowMin = n
	}
	windowMin = cloud.ClampSeriesWindow(windowMin)
	stepSec := cloud.SeriesStepSeconds(windowMin)

	// §3a: resolve the CALLER's inventory and refuse anything outside it with
	// 404 — an id the tenant does not own must be indistinguishable from one
	// that does not exist.
	visible, _, _, err := s.cloudResources(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	names := make(map[string]string, len(visible))
	for _, res := range visible {
		names[res.ResourceID] = res.ResourceName
	}
	ids := make([]string, 0, len(reqIDs))
	seen := map[string]bool{}
	for _, raw := range reqIDs {
		id := strings.TrimSpace(raw)
		if !cloud.ValidResourceID(id) {
			writeError(w, http.StatusBadRequest, errors.New("invalid resource id"))
			return
		}
		if _, ok := names[id]; !ok {
			writeError(w, http.StatusNotFound, errors.New("resource not found"))
			return
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	end := time.Now().UTC().Unix()
	start := end - int64(windowMin)*60
	promql := meta.Name + `{resource_id=~"` + regexAlternation(ids) + `"}`
	ctx, cancel := context.WithTimeout(r.Context(), cloudSeriesQueryTimeout)
	defer cancel()
	byID, err := vmQueryRangeBy(ctx, promql, start, end, stepSec, "resource_id")
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("metric store unreachable: %w", err))
		return
	}
	series := make([]cloudSeriesEntry, 0, len(ids))
	for _, id := range ids {
		pts := byID[id]
		if pts == nil {
			pts = []cloudSeriesPoint{} // absent = honest empty, never fabricated
		}
		series = append(series, cloudSeriesEntry{ResourceID: id, ResourceName: names[id], Points: pts})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"metric":         meta.Name,
		"label":          meta.Label,
		"unit":           meta.Unit,
		"window_minutes": windowMin,
		"step_seconds":   stepSec,
		"start":          start,
		"end":            end,
		"series":         series,
		"catalog":        cloud.MetricCatalog(),
	})
}
