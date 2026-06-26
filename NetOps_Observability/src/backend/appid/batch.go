package appid

import "time"

// batch.go — #81 Fusion Layer §9 batch rollup. FuseBatch groups a stream of
// observations by CONVERSATION scope and fuses each group into one identity — the
// rollup the pipeline worker runs per window. Pure + deterministic.
//
// Grouping uses the finest shared identifier so cross-source observations about the
// SAME conversation fuse together (and corroborate): session → flow → 5-tuple. (A
// fuller DNS↔flow join by src+dst+window is the EvidenceCollector's future work; the
// MVP corroborates sources that share a session/flow/tuple.)

// convKey is the grouping key for an observation (finest available; "" = ungroupable).
func convKey(o ApplicationObservation) string {
	switch {
	case o.SessionID != "":
		return "sess:" + o.SessionID
	case o.FlowID != "":
		return "flow:" + o.FlowID
	case o.DstIP != "":
		return "conv:" + o.SrcIP + ">" + o.DstIP + ":" + itoa(o.DstPort) + "/" + o.Proto
	default:
		return ""
	}
}

// scopeFromObs builds the identity scope carried on a fused result.
func scopeFromObs(o ApplicationObservation) IdentityScope {
	return IdentityScope{
		SessionID: o.SessionID, FlowID: o.FlowID, WorkloadID: o.Workload,
		SrcIP: o.SrcIP, DstIP: o.DstIP, DstPort: o.DstPort, Proto: o.Proto,
	}
}

// BatchContext supplies the per-call fusion context (catalog version, canonicalizer,
// and the ambiguity lookups the guardrails consult) — injected so the rollup stays pure.
type BatchContext struct {
	Now            time.Time
	CatalogVersion int
	DNSTTL         time.Duration
	Canon          func(vendor, app string) string
	SharedCDN      func(dstIP string) bool // nil ⇒ never shared
	NATSource      func(srcIP string) bool // nil ⇒ never NAT
}

// FuseBatch groups observations by conversation scope and returns one FusedIdentity
// per group (stable order: first-seen). Deterministic given the same inputs + context.
func FuseBatch(obs []ApplicationObservation, ctx BatchContext) []FusedIdentity {
	type grp struct {
		rep ApplicationObservation
		obs []ApplicationObservation
	}
	groups := map[string]*grp{}
	var order []string
	for _, o := range obs {
		k := convKey(o)
		if k == "" {
			continue
		}
		g := groups[k]
		if g == nil {
			g = &grp{rep: o}
			groups[k] = g
			order = append(order, k)
		}
		g.obs = append(g.obs, o)
	}
	out := make([]FusedIdentity, 0, len(order))
	for _, k := range order {
		g := groups[k]
		in := FuseInput{
			Scope: scopeFromObs(g.rep), Observations: g.obs, Now: ctx.Now,
			CatalogVersion: ctx.CatalogVersion, DNSTTL: ctx.DNSTTL, Canon: ctx.Canon,
		}
		if ctx.SharedCDN != nil {
			in.SharedCDN = ctx.SharedCDN(g.rep.DstIP)
		}
		if ctx.NATSource != nil {
			in.NATSource = ctx.NATSource(g.rep.SrcIP)
		}
		out = append(out, FuseObservations(in))
	}
	return out
}
