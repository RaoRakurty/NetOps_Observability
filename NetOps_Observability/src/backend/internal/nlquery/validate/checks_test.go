// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import (
	"context"
	"errors"
	"testing"

	"netops/backend/internal/nlquery/ast"
)

// checkScope is a workspace user that declared its own Digital Experience
// checks (tracker 337 N-B5): it owns checks for erp.example.com and
// login.example.com. Another workspace's check (b-only.example.com) and the
// platform's own probe destination (8.8.8.8) are not its.
type checkScope struct {
	fakeScope
	owns   map[string]bool
	broken bool
}

func (c checkScope) Visible(ctx context.Context, r ast.EntityRef) (bool, error) {
	if r.Type == "probe_target" {
		return c.OwnsChecks(ctx, []string{r.ID[len("probe:"):]})
	}
	return c.fakeScope.Visible(ctx, r)
}

func (c checkScope) OwnsChecks(_ context.Context, keys []string) (bool, error) {
	if c.broken {
		return false, errors.New("store unavailable")
	}
	if len(keys) == 0 {
		return len(c.owns) > 0, nil
	}
	for _, k := range keys {
		if !c.owns[k] {
			return false, nil
		}
	}
	return true, nil
}

var workspaceChecks = map[string]bool{"erp.example.com": true, "login.example.com": true}

func probeQ(metric, host string) string {
	return `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"` + metric +
		`","entities":[{"type":"probe_target","id":"probe:` + host + `"}]}`
}

// A workspace user naming its OWN check reads that check's series: the gated
// platform metric is swapped for its tenant-labeled equivalent, keeping the
// question's aggregation.
func TestGatedProbeMetricSwapsToTheWorkspaceChecks(t *testing.T) {
	for gated, want := range map[string]string{
		"probe_rtt_ms":   "dem_probe_latency_ms",
		"probe_loss_pct": "dem_probe_loss_pct",
	} {
		out, res := Validate(context.Background(), cat, checkScope{owns: workspaceChecks}, q(t, probeQ(gated, "erp.example.com")))
		if !res.Valid {
			t.Fatalf("%s on an owned check must validate: %s", gated, codes(res))
		}
		if out.Metric != want {
			t.Fatalf("%s: read %s, want the workspace equivalent %s", gated, out.Metric, want)
		}
	}
	// No target named: the workspace's own checks, all of them.
	all := `{"v":1,"query_type":"metric_topk","target":"probe_target","metric":"probe_loss_pct","limit":5}`
	if out, res := Validate(context.Background(), cat, checkScope{owns: workspaceChecks}, q(t, all)); !res.Valid || out.Metric != "dem_probe_loss_pct" {
		t.Fatalf("ranking the workspace's checks: valid=%v metric=%v %s", res.Valid, out, codes(res))
	}
}

// A destination the workspace does not check itself — the platform probe
// (8.8.8.8) or another workspace's check — stays unavailable; it is never
// silently answered from someone else's series or as an empty "no loss".
func TestGatedProbeMetricStaysRefusedForATargetTheWorkspaceDoesNotOwn(t *testing.T) {
	for _, host := range []string{"8.8.8.8", "b-only.example.com"} {
		mustFail(t, checkScope{owns: workspaceChecks}, probeQ("probe_rtt_ms", host), CodeScopeUnavailable)
	}
	// One owned and one foreign target in the same question: refused whole.
	mixed := `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"probe_loss_pct","entities":[` +
		`{"type":"probe_target","id":"probe:erp.example.com"},{"type":"probe_target","id":"probe:b-only.example.com"}]}`
	mustFail(t, checkScope{owns: workspaceChecks}, mixed, CodeScopeUnavailable)
	// A workspace with no checks at all asking for "the lossiest probes".
	none := `{"v":1,"query_type":"metric_topk","target":"probe_target","metric":"probe_loss_pct","limit":5}`
	mustFail(t, checkScope{owns: map[string]bool{}}, none, CodeScopeUnavailable)
}

// A metric with no workspace equivalent (one-way delay) stays refused, and a
// store error refuses rather than guessing.
func TestGatedProbeMetricWithoutAnEquivalentOrWithAStoreErrorIsRefused(t *testing.T) {
	mustFail(t, checkScope{owns: workspaceChecks}, probeQ("probe_owd_ms", "erp.example.com"), CodeScopeUnavailable)
	mustFail(t, checkScope{owns: workspaceChecks, broken: true}, probeQ("probe_rtt_ms", "erp.example.com"), CodeScopeUnavailable)
}

// The Global view keeps reading the platform probe series, never the swap.
func TestCrossTenantKeepsThePlatformProbeMetric(t *testing.T) {
	out, res := Validate(context.Background(), cat, checkScope{fakeScope: fakeScope{cross: true}, owns: workspaceChecks},
		q(t, probeQ("probe_rtt_ms", "erp.example.com")))
	if !res.Valid || out.Metric != "probe_rtt_ms" {
		t.Fatalf("cross: valid=%v metric=%v %s", res.Valid, out, codes(res))
	}
}
