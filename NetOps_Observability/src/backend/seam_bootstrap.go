package backend

// seam_bootstrap.go — the seam bootstrap engine (#67 build ⑤, design
// cloud-ingestion.md §4.1, P1-required). An empty seam inventory makes the
// correlation engine's grounding gate ground against nothing (research C5), so
// this engine auto-suggests seam instances from telemetry the platform already
// collects. Owner reviews: suggest → confirm/edit → active.
//
// Four rules over today's sources, each a PURE function over fetched rows so
// the inference is unit-testable without infrastructure:
//   R1 traceroute ownership boundary  (probe paths: private→public transition)
//   R2 BGP neighbor metadata          (VictoriaMetrics device_bgp_peer_state)
//   R3 flow ingress/egress boundary   (ClickHouse netops.flows)
//   R4 tunnel discovery               (ClickHouse netops.tunnels)
// plus R5, redundancy-group inference over the resulting inventory (#68 §4:
// groups are instance-level topology — two DX at one site, a VPN shadowing a
// DX → "members of one group?").
//
// §4.1 names R1 an "ASN transition" rule: per-hop ASN data needs an external
// ASN database we deliberately do not bundle, so v0 detects the private→public
// ownership transition (which IS an ASN transition: ours → somebody else's)
// and splits DX vs DIA by destination + path stability. An ASN enrichment
// source upgrades the split later without changing the rule's contract.
//
// Suggestions are idempotent and rejections permanent — both enforced by the
// (tenant_id, suggestion_key) unique index (see seams.go Suggest). Every
// suggestion carries provenance: which rule, what evidence, what confidence.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"netops/backend/internal/seam"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netops/backend/collectors"

	"netops/backend/chhttp"
)

// startSeamBootstrap launches the periodic suggestion loop. Postgres-only
// (the inventory is lifecycle state); on by default because the inventory is a
// P1-required input to grounding — disable with ENABLE_SEAM_BOOTSTRAP=false.
func (s *server) startSeamBootstrap(ctx context.Context) {
	if s.seams == nil {
		log.Printf("seam-bootstrap: disabled (requires Postgres backend)")
		return
	}
	if os.Getenv("ENABLE_SEAM_BOOTSTRAP") == "false" {
		log.Printf("seam-bootstrap: disabled by ENABLE_SEAM_BOOTSTRAP=false")
		return
	}
	interval := 10 * time.Minute
	if v := os.Getenv("SEAM_BOOTSTRAP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
			interval = d
		} else {
			log.Printf("seam-bootstrap: ignoring invalid SEAM_BOOTSTRAP_INTERVAL=%q (want ≥1m)", v)
		}
	}
	go func() {
		// Let collectors take their first samples before the first pass; jitter
		// the tick so restarts don't synchronize the fleet's CH/VM queries.
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			s.runSeamBootstrapOnce(ctx)
			timer.Reset(interval + time.Duration(rand.Int63n(int64(interval/10)+1))) // #nosec G404 -- jitter, not crypto
		}
	}()
}

// runSeamBootstrapOnce executes all rules over current telemetry. Each source
// is best-effort but never silent: a fetch failure is logged and the other
// rules still run (a dead VictoriaMetrics must not stop flow-based seams).
func (s *server) runSeamBootstrapOnce(ctx context.Context) {
	devices := s.discovery.Devices()
	var suggestions []seam.Seam

	paths, err := seamFetchProbePaths(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: traceroute source unavailable: %v", err)
	} else {
		suggestions = append(suggestions, seam.RuleTracerouteBoundary(paths)...)
	}

	peers, err := seamFetchBGPPeers(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: bgp source unavailable: %v", err)
	} else {
		suggestions = append(suggestions, seam.RuleBGPPeers(peers, devices)...)
	}

	flowRows, err := seamFetchFlowBoundaries(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: flow source unavailable: %v", err)
	} else {
		suggestions = append(suggestions, seam.RuleFlowBoundary(flowRows)...)
	}

	tunnels, err := seamFetchTunnels(ctx)
	if err != nil {
		log.Printf("seam-bootstrap: tunnel source unavailable: %v", err)
	} else {
		tunnelSeams, tunnelGroups := seam.RuleTunnels(tunnels, devices)
		suggestions = append(suggestions, tunnelSeams...)
		for _, g := range tunnelGroups {
			if _, err := s.seams.SuggestGroup(ctx, g); err != nil {
				log.Printf("seam-bootstrap: group suggest %s: %v", g.SuggestionKey, err)
			}
		}
	}

	inserted := 0
	for _, sg := range suggestions {
		ok, err := s.seams.Suggest(ctx, sg)
		if err != nil {
			log.Printf("seam-bootstrap: suggest %s: %v", sg.SuggestionKey, err)
			continue
		}
		if ok {
			inserted++
		}
	}

	// R5 runs over the inventory AFTER this cycle's seams land, so a first run
	// can already propose groups. Rejected/retired seams never join a group.
	groupsInserted := 0
	inv, err := s.seams.List(ctx, "", true, "", "")
	if err != nil {
		log.Printf("seam-bootstrap: inventory read for grouping: %v", err)
	} else {
		for _, g := range seam.RuleRedundancyGroups(inv) {
			ok, err := s.seams.SuggestGroup(ctx, g)
			if err != nil {
				log.Printf("seam-bootstrap: group suggest %s: %v", g.SuggestionKey, err)
				continue
			}
			if ok {
				groupsInserted++
			}
		}
	}
	log.Printf("seam-bootstrap: cycle done candidates=%d new_seams=%d new_groups=%d", len(suggestions), inserted, groupsInserted)
}

// ── seam export (engine grounding context) ────────────────────────────────────

// startSeamEnrichment exports the ACTIVE seam inventory to the shared
// enrichment dir (the device_tenant.csv plane) so the correlation engine's
// grounding gate has its context without a new auth surface. Suggested/
// rejected/retired rows never export — only owner-activated seams ground.
func (s *server) startSeamEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" || s.seams == nil {
		return
	}
	write := func() {
		active, err := s.seams.List(ctx, "", true, "active", "")
		if err != nil {
			log.Printf("seam-enrichment: list: %v", err)
			return
		}
		type seamExport struct {
			SeamID            string            `json:"seam_id"`
			TenantID          string            `json:"tenant_id"`
			SeamType          string            `json:"seam_type"`
			Endpoints         map[string]string `json:"endpoints"`
			Visibility        string            `json:"visibility"`
			ControlPlaneOwner string            `json:"control_plane_owner"`
		}
		out := make([]seamExport, 0, len(active))
		for _, sm := range active {
			out = append(out, seamExport{
				SeamID: sm.SeamID, TenantID: sm.TenantID, SeamType: sm.SeamType,
				Endpoints: sm.Endpoints, Visibility: sm.Visibility,
				ControlPlaneOwner: sm.ControlPlaneOwner,
			})
		}
		data, err := json.Marshal(out)
		if err != nil {
			log.Printf("seam-enrichment: marshal: %v", err)
			return
		}
		if err := writeFileAtomic(filepath.Join(dir, "seams.json"), data, 0o644); err != nil {
			log.Printf("seam-enrichment: write: %v", err)
			return
		}
		log.Printf("seam-enrichment: exported %d active seam(s)", len(out))
	}
	go func() {
		write()
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}

// ── R1: traceroute ownership boundary ─────────────────────────────────────────

func seamFetchProbePaths(ctx context.Context) ([]collectors.PathResult, error) {
	if collectors.RedisAddr() != "" {
		if raw, err := collectors.FetchProbePaths(ctx); err == nil && raw != "" {
			var out []collectors.PathResult
			if err := json.Unmarshal([]byte(raw), &out); err != nil {
				return nil, fmt.Errorf("redis paths decode: %w", err)
			}
			return out, nil
		}
	}
	if path := os.Getenv("PROBE_PATHS_FILE"); path != "" {
		// #nosec G304 -- operator-configured shared-volume path, not user input
		if data, err := os.ReadFile(path); err == nil {
			var out []collectors.PathResult
			if err := json.Unmarshal(data, &out); err != nil {
				return nil, fmt.Errorf("paths file decode: %w", err)
			}
			return out, nil
		}
	}
	return collectors.Paths.All(), nil
}

// seamFetchBGPPeers reads the current BGP peer table from VictoriaMetrics
// (SNMP BGP4-MIB walk: device_bgp_peer_state{device, index=<peer ip>}).
func seamFetchBGPPeers(ctx context.Context) ([]seam.BGPPeer, error) {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape("device_bgp_peer_state")
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := backendHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victoriametrics status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	peers := make([]seam.BGPPeer, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		state := 0.0
		if s, ok := r.Value[1].(string); ok {
			_, _ = fmtSscanf(s, "%f", &state)
		}
		peers = append(peers, seam.BGPPeer{
			Device: r.Metric["device"],
			PeerIP: r.Metric["index"],
			State:  state,
		})
	}
	return peers, nil
}

// seamCHQueryJSON runs a read-only ClickHouse query (FORMAT JSON) and decodes
// the data rows into dst. The bootstrap is a trusted internal reader, so it
// passes tenant_scope=__all__ like the report scheduler; per-row tenancy is
// preserved by carrying tenant_id through the rules into the suggestions.
func seamCHQueryJSON(ctx context.Context, sql string, dst any) error {
	body, err := chClientFor(envOr("CLICKHOUSE_URL", "http://clickhouse:8123")).Exec(ctx, chhttp.Request{
		SQL:        sql,
		Op:         "seam bootstrap query",
		Scope:      "__all__",
		LogComment: "worker:seam-bootstrap",
		Budget:     chWorkerBudget,
		MaxBytes:   chMaxResponseBytes,
	})
	if err != nil {
		return err
	}
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return err
	}
	return json.Unmarshal(wrapper.Data, dst)
}

// seamPrivateIPSQL classifies an address column as enterprise-internal in CH
// SQL, mirroring seamPrivateIP (IPv4 RFC 1918 + CGNAT; IPv6 ULA).
func seamFetchFlowBoundaries(ctx context.Context) ([]seam.FlowBoundary, error) {
	srcPriv := seam.PrivateIPSQL("src_addr")
	dstPriv := seam.PrivateIPSQL("dst_addr")
	sql := `
SELECT sampler_address AS sampler,
       if(` + srcPriv + ` AND NOT ` + dstPriv + `, out_if, in_if) AS wan_if,
       tenant_id,
       toUInt32(count()) AS crossing
  FROM netops.flows
 WHERE ts > now() - INTERVAL 24 HOUR
   AND ` + srcPriv + ` != ` + dstPriv + `
 GROUP BY sampler, wan_if, tenant_id
HAVING crossing >= 50
 ORDER BY crossing DESC
 LIMIT 200
FORMAT JSON`
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	var rows []seam.FlowBoundary
	if err := seamCHQueryJSON(ctx, sql, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// seamFetchTunnels returns the latest netops.tunnels row per tunnel id.
func seamFetchTunnels(ctx context.Context) ([]seam.Tunnel, error) {
	sql := `
SELECT id, type, local_device, local_addr, remote_addr, status, tenant_id
  FROM netops.tunnels
 ORDER BY ts DESC
 LIMIT 1 BY id
 LIMIT 500
FORMAT JSON`
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	var rows []seam.Tunnel
	if err := seamCHQueryJSON(ctx, sql, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
