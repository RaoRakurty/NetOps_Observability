package backend

// cloud_enrich.go — Service View live enrichment (task #12).
//
// The inventory says WHAT exists; three live feeds say HOW IT IS DOING:
//
//	provider metrics   (CloudWatch / Azure Monitor → VictoriaMetrics)
//	                   cloud_status_check_failed → the provider's own verdict
//	                   cloud_net_in/out_bytes    → real traffic on the resource
//	active checks      (probes to the resource's addresses → corr_signals)
//	app health lane    (cloud_health from the workload's own logs)
//
// Honesty rules, same as everywhere else: a value we did not measure is ABSENT
// (rendered "—"), never a fabricated zero; "unknown" is a first-class state and
// never silently becomes "healthy".

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"netops/backend/internal/rca"
	"os"
	"strconv"
	"strings"
	"time"

	"netops/backend/cloud"
)

// cloudLiveState is what the live feeds know about ONE cloud resource.
type cloudLiveState struct {
	Health       string   // healthy | degraded | down | unknown
	HealthBasis  string   // why — never a bare adjective
	TrafficBytes *float64 // network in+out over the sample; nil = not measured
	CPUPct       *float64 // nil = not measured
}

// vmQuery runs one instant PromQL query against VictoriaMetrics and returns
// resource_id → value. Failure is degradation, never an error the UI sees:
// an unreachable metric store means "unknown", not "healthy".
func vmQuery(ctx context.Context, q string) map[string]float64 {
	return vmQueryBy(ctx, q, "resource_id")
}

// vmQueryBy is vmQuery keyed by an arbitrary result label (e.g. "provider"
// for the ingestion matrix's per-provider freshness).
func vmQueryBy(ctx context.Context, q, keyLabel string) map[string]float64 {
	base := os.Getenv("VM_QUERY_URL")
	if base == "" {
		base = "http://victoria:8428"
	}
	u := fmt.Sprintf("%s/api/v1/query?query=%s", strings.TrimRight(base, "/"), url.QueryEscape(q))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	cl := &http.Client{Timeout: 4 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	// Minimal parse — VM's Prometheus-compatible response.
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil
	}
	res := map[string]float64{}
	for _, r := range out.Data.Result {
		// The key label ONLY — no device-name fallback: names collide across
		// clouds (both providers run a "correlix-vpn-nat-01"), and joining on
		// one would let a cloud's series masquerade as another's resource.
		id := r.Metric[keyLabel]
		if id == "" || len(r.Value) < 2 {
			continue
		}
		sv, _ := r.Value[1].(string)
		if f, err := strconv.ParseFloat(sv, 64); err == nil {
			res[id] = f
		}
	}
	return res
}

// cloudLiveStates builds the live view for every resource: provider verdict
// first (the cloud itself saying the instance is impaired outranks our guesses),
// then our active checks, then the workload's own health lane.
func (s *server) cloudLiveStates(ctx context.Context, scope string, res []cloud.CloudResource) map[string]cloudLiveState {
	out := make(map[string]cloudLiveState, len(res))

	// The metric lane's 5-min provider resolution means an instant query can miss
	// the latest point; last_over_time over a window is the honest read.
	statusCheck := vmQuery(ctx, `last_over_time(cloud_status_check_failed[30m])`)
	netIn := vmQuery(ctx, `last_over_time(cloud_net_in_bytes[30m])`)
	netOut := vmQuery(ctx, `last_over_time(cloud_net_out_bytes[30m])`)
	cpu := vmQuery(ctx, `last_over_time(cloud_cpu_util[30m])`)

	// Active-check failures per target address in the recent window.
	// entity_id comes in TWO shapes for the same executions: per-vantage rows
	// ("vantage->target") and a bare rollup row ("target") the pipeline derives
	// FROM them. Summing both double-counts every failure (audit D: 150 real
	// failures printed as 300). Per-vantage rows are the ground truth; the bare
	// row is used only when no per-vantage row exists for that target.
	probeFail := map[string]int{}  // per-vantage sums (real executions)
	rollupFail := map[string]int{} // bare rollup rows (fallback only)
	sql := fmt.Sprintf(`
SELECT entity_id, count() AS n
  FROM netops.corr_signals
 WHERE modality_class = 'active_probe' AND severity IN ('high','crit')
   AND ts > now() - INTERVAL 15 MINUTE
 GROUP BY entity_id
 SETTINGS tenant_scope = '%s'
 FORMAT TSV`, scope)
	for _, line := range chQuery(sql) {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.Atoi(strings.TrimSpace(f[1]))
		if _, dst, ok := strings.Cut(f[0], "->"); ok {
			probeFail[strings.TrimSpace(dst)] += n
		} else {
			rollupFail[strings.TrimSpace(f[0])] += n
		}
	}

	for _, r := range res {
		st := cloudLiveState{Health: "unknown", HealthBasis: "no provider telemetry or active check reached this resource"}
		if v, ok := cpu[r.ResourceID]; ok {
			cp := v
			st.CPUPct = &cp
		}
		if in, ok := netIn[r.ResourceID]; ok {
			total := in
			if o, ok2 := netOut[r.ResourceID]; ok2 {
				total += o
			}
			st.TrafficBytes = &total
		}

		// 1) the provider's own verdict wins — it can see what we cannot.
		if v, ok := statusCheck[r.ResourceID]; ok {
			if v > 0 {
				st.Health = "down"
				st.HealthBasis = "the cloud provider reports a failed status check on this instance"
			} else {
				st.Health = "healthy"
				st.HealthBasis = "the cloud provider reports passing status checks"
			}
		}

		// 2) our active checks: failing probes to this resource's own addresses
		//    degrade it even when the provider says the instance is up (the app
		//    can be dead on a healthy VM).
		fails := 0
		for _, ip := range append(append([]string{}, r.PrivateIPs...), r.PublicIPs...) {
			if n := probeFail[ip]; n > 0 {
				fails += n
			} else {
				fails += rollupFail[ip]
			}
		}
		if fails > 0 {
			switch st.Health {
			case "healthy":
				st.Health = "degraded"
				st.HealthBasis = fmt.Sprintf("provider status checks pass, but %s failed against this resource's address", rca.CountNoun(fails, "active check"))
			case "unknown":
				st.Health = "degraded"
				st.HealthBasis = fmt.Sprintf("%s failed against this resource's address; no provider telemetry to corroborate", rca.CountNoun(fails, "active check"))
			}
		}
		out[r.ResourceID] = st
	}
	return out
}

// cloudAppNamesFor resolves an object's affected addresses to the applications
// the DECLARED inventory says live there — so an RCA case names apps, not raw
// IPs. Evidence-based: an address no inventory claims resolves to nothing.
func cloudAppNamesFor(res []cloud.CloudResource, affected []string) []string {
	if len(res) == 0 || len(affected) == 0 {
		return nil
	}
	byIP := map[string]string{}
	for _, r := range res {
		name := r.AppName
		if name == "" {
			name = r.ResourceName // no app tag: the workload's own name is still an answer
		}
		if name == "" {
			continue
		}
		for _, ip := range append(append([]string{}, r.PrivateIPs...), r.PublicIPs...) {
			byIP[ip] = name
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range affected {
		addr := strings.TrimSpace(a)
		if _, dst, ok := strings.Cut(addr, "->"); ok {
			addr = strings.TrimSpace(dst)
		}
		if n, ok := byIP[addr]; ok && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
