package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(u.String())
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
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
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
				s.Value, _ = strconv.ParseFloat(vs, 64)
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
