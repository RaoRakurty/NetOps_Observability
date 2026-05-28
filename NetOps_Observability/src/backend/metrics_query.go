package main

import (
	"io"
	"net/http"
	"net/url"
	"time"
)

// Native metrics querying: a thin pass-through to a Prometheus-compatible
// time-series backend so the UI can render charts itself instead of iframing
// Prometheus. VictoriaMetrics and Prometheus share the /api/v1 query API.
//
// METRICS_URL selects the upstream. It defaults to Prometheus because that's
// where data lands out of the box (self + Vector scrapes); point it at
// http://victoria:8428 once Telegraf/SNMP remote_write is feeding VM.

func (s *server) proxyMetrics(w http.ResponseWriter, r *http.Request, path string, allowed ...string) {
	base := envOr("METRICS_URL", "http://prometheus:9090")
	u, err := url.Parse(base + path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Forward only the query params this endpoint expects.
	q := url.Values{}
	for _, key := range allowed {
		for _, v := range r.URL.Query()[key] {
			if v != "" {
				q.Add(key, v)
			}
		}
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// GET /api/metrics/query?query=<promql>&time=<unix>
func (s *server) handleMetricsQuery(w http.ResponseWriter, r *http.Request) {
	s.proxyMetrics(w, r, "/api/v1/query", "query", "time")
}

// GET /api/metrics/query_range?query=<promql>&start=&end=&step=
func (s *server) handleMetricsQueryRange(w http.ResponseWriter, r *http.Request) {
	s.proxyMetrics(w, r, "/api/v1/query_range", "query", "start", "end", "step")
}

// GET /api/metrics/names — list metric names for the query autocomplete.
func (s *server) handleMetricsNames(w http.ResponseWriter, r *http.Request) {
	s.proxyMetrics(w, r, "/api/v1/label/__name__/values", "match[]", "start", "end")
}
