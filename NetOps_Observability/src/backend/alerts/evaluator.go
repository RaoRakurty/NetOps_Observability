package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Evaluate decides whether a rule should currently be firing.
//
// We treat the rule's Expr as a PromQL instant query and ask
// VictoriaMetrics (drop-in for Prometheus on /api/v1/query). The rule
// fires when the query returns at least one series whose latest sample
// is truthy: PromQL's "comparison operators" already filter to series
// where the predicate holds, so any non-empty result counts.
//
// For rules without an obvious PromQL form (e.g. those backed by log
// patterns), we'll plug a separate Evaluator implementation in later
// and dispatch on rule prefix; for now everything goes through
// VictoriaMetrics.
// Sample is one firing series: its label set and instant value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// clientFn resolves the HTTP client per evaluation. Main injects the
// platform's hardened backend client (mesh-CA verify + URL-userinfo auth,
// SEC-010) via SetHTTPClientFunc; the default keeps the package
// self-contained for tests. LAZY on purpose: the hardened transport is built
// AFTER the internal CA mints the trust bundle, later in boot than the
// engine's construction — a frozen client would miss it (hit live: every
// rule failed x509 against vmauth, 2026-08-04).
var clientFn = func() *http.Client { return &http.Client{Timeout: 8 * time.Second} }

// SetHTTPClientFunc injects the lazy client provider. Call once at wiring
// time, before the engine starts evaluating.
func SetHTTPClientFunc(fn func() *http.Client) {
	if fn != nil {
		clientFn = fn
	}
}

// Evaluate runs the rule's PromQL as an instant query against VictoriaMetrics
// and returns every series that matched — the firing instances, each with its
// labels and value. An empty slice means the rule is not firing (PromQL
// comparison operators already filter to series where the predicate holds).
// Callers render one alert per Sample, so summaries can resolve $labels/$value.
func Evaluate(r Rule) ([]Sample, error) {
	if strings.TrimSpace(r.Expr) == "" {
		return nil, errors.New("empty expression")
	}
	endpoint := envOr("VICTORIA_URL", "http://victoria:8428")
	u, err := url.Parse(strings.TrimRight(endpoint, "/") + "/api/v1/query")
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("query", r.Expr)
	q.Set("time", strconv.FormatInt(time.Now().Unix(), 10))
	u.RawQuery = q.Encode()

	client := clientFn()
	// Build the request explicitly so it carries a context (request builder is
	// ready for a caller-supplied ctx; Evaluate's signature can take one later).
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("victoria %d", resp.StatusCode)
	}

	var body struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	// F-27 class: bound the reply. A query that accidentally selects a huge
	// series set would otherwise be read into memory without limit, on a 30s
	// tick, inside the process that serves the API.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&body); err != nil {
		return nil, err
	}
	if body.Status != "success" {
		return nil, fmt.Errorf("victoria reply status=%q", body.Status)
	}

	// Vector result: [{"metric":{...}, "value":[ts, "value"]}, ...].
	var raw []struct {
		Metric map[string]string `json:"metric"`
		Value  []any             `json:"value"`
	}
	if err := json.Unmarshal(body.Data.Result, &raw); err != nil {
		return nil, err
	}
	out := make([]Sample, 0, len(raw))
	for _, m := range raw {
		s := Sample{Labels: m.Metric}
		if len(m.Value) == 2 {
			if vs, ok := m.Value[1].(string); ok {
				v, finite := parseSampleValue(vs)
				if !finite {
					// F-21 companion, worse consequence than the empty-200:
					// strconv.ParseFloat("NaN", 64) SUCCEEDS, and NaN compares
					// false against every threshold — so the sample was carried
					// into the alert and the rule built on it silently never
					// fired. A metric going NaN (stddev over one sample, a 0/0
					// rate) used to disable its alert with no signal anywhere.
					// A non-finite sample is MISSING data: drop it and say so.
					nonFiniteSamples.Add(1)
					log.Printf("alerts: rule %q dropped a non-finite sample (value=%q) — the series is producing NaN/Inf, so any threshold on it evaluates false", r.Name, vs)
					continue
				}
				s.Value = v
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// nonFiniteSamples counts samples dropped for being NaN/±Inf. Exported to the
// API's /metrics through NonFiniteSamples() — the defect was that this
// condition had no signal at all.
var nonFiniteSamples atomic.Uint64

// NonFiniteSamples reports how many NaN/±Inf samples have been dropped.
func NonFiniteSamples() uint64 { return nonFiniteSamples.Load() }

// parseSampleValue parses a VictoriaMetrics sample value, reporting finite=false
// for malformed AND for non-finite values (NaN, ±Inf) — which ParseFloat
// otherwise accepts happily.
func parseSampleValue(s string) (v float64, finite bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
