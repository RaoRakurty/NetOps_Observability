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
func Evaluate(r Rule) (bool, error) {
	if strings.TrimSpace(r.Expr) == "" {
		return false, errors.New("empty expression")
	}
	endpoint := envOr("VICTORIA_URL", "http://victoria:8428")
	u, err := url.Parse(strings.TrimRight(endpoint, "/") + "/api/v1/query")
	if err != nil {
		return false, err
	}
	q := url.Values{}
	q.Set("query", r.Expr)
	q.Set("time", strconv.FormatInt(time.Now().Unix(), 10))
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return false, fmt.Errorf("victoria %d", resp.StatusCode)
	}

	var body struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, err
	}
	if body.Status != "success" {
		return false, fmt.Errorf("victoria reply status=%q", body.Status)
	}

	// result is a JSON array. Vector-type result: [{"metric":{...},
	// "value":[ts, "value"]}, ...]. Empty array = no series matched the
	// predicate = rule shouldn't fire.
	var arr []any
	if err := json.Unmarshal(body.Data.Result, &arr); err != nil {
		return false, err
	}
	return len(arr) > 0, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
