// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_bgp.go — the READ-ONLY BGP-operations tools (IRIS Phase A4).
//
// BGP Operations already answers, for a tenant, three questions an internet-edge
// investigation needs and that no other Iris tool could reach: what do we watch,
// is what we watch RPKI-valid, and what has the global table done to it lately.
// These three tools expose exactly those reads to the skills layer, through the
// SAME tenant-scoped authorization the /api/bgp/* handlers use.
//
// Posture:
//   - READ-ONLY (CapRead). The watchlist WRITE path (add/delete) is deliberately
//     absent: the model can look at what a tenant watches, never change it.
//   - TENANT-SCOPED AT THE SEAM. The watchlist is per-tenant (FORCE-RLS) and the
//     update ring is per-tenant; both are read with the caller's own tenant from
//     the token, never from an argument. A cross-tenant caller with no tenant
//     selected gets an honest "select a tenant", not another tenant's rows.
//   - HONEST. The near-live feed is off by default and the RPKI validator is a
//     remote service; each tool says plainly when its source is unavailable
//     rather than reporting an empty, clean-looking answer.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	// MaxBGPWatchItems bounds the watchlist rows one answer may carry.
	MaxBGPWatchItems = 40
	// MaxBGPRPKIResults bounds the RPKI verdicts one answer may carry.
	MaxBGPRPKIResults = 40
	// MaxBGPFeedUpdates bounds the update rows one answer may carry, and is the
	// ceiling on the tool's own `limit` argument.
	MaxBGPFeedUpdates = 30
	// defaultBGPFeedLimit is the limit used when the caller names none.
	defaultBGPFeedLimit = 15
	bgpOpsRouteHref     = "#/infrastructure/bgp"
)

// BGPWatchItem is one watched resource of the caller's own tenant.
type BGPWatchItem struct {
	Resource string // "203.0.113.0/24" or "AS64500"
	Kind     string // prefix | asn
	Note     string
	AddedBy  string
	Added    string // RFC3339 timestamp text, or ""
	// Status is the current operational reading for the resource where one is
	// available ("announced by AS64500", "not announced"); "" = not determined.
	Status string
}

// BGPWatchlistReport is the tenant's watchlist plus the honest reason it may be
// empty or unreadable.
type BGPWatchlistReport struct {
	Items []BGPWatchItem
	// Scope names the tenant the rows belong to (audit + narration).
	Scope string
	// NotWired explains an ABSENT capability (no watchlist store, no tenant
	// selected). Non-empty means Items is not an answer.
	NotWired string
}

// BGPRPKIItem is one prefix's route-origin validation verdict.
type BGPRPKIItem struct {
	Prefix    string
	Origin    string // "AS3333" or ""
	State     string // valid | invalid | not-found | unavailable (validator's own word)
	Reason    string
	Validator string
	ROAs      int
	Error     string
}

// BGPRPKIReport is the validation sweep over the caller's own watched prefixes.
type BGPRPKIReport struct {
	Items     []BGPRPKIItem
	Scope     string
	Truncated bool
	NotWired  string
}

// BGPFeedUpdate is one recent announcement or withdrawal.
type BGPFeedUpdate struct {
	Seq      uint64
	At       string
	Type     string // "A" (announce) | "W" (withdraw)
	Resource string
	Prefix   string
	Peer     string
	Origin   string
	PathLen  int
}

// BGPFeedReport is a bounded page of the caller's own update ring.
type BGPFeedReport struct {
	Updates []BGPFeedUpdate
	Scope   string
	// Resources is the watched set the ring follows (so an empty page can say
	// WHY: nothing watched vs nothing happened).
	Resources []string
	// Gap is true when the ring overwrote entries the caller never read.
	Gap bool
	// NotWired explains an absent or disabled feed.
	NotWired string
}

// ---- get_bgp_watchlist -----------------------------------------------------

type bgpWatchlistTool struct{ deps TroubleshootDeps }

func (t bgpWatchlistTool) Name() string            { return "get_bgp_watchlist" }
func (t bgpWatchlistTool) Module() string          { return "bgp_operations" }
func (t bgpWatchlistTool) Capability() Capability  { return CapRead }
func (t bgpWatchlistTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t bgpWatchlistTool) Freshness() Freshness    { return FreshnessLive }

func (t bgpWatchlistTool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	rep, err := t.deps.BGPWatchlist(ctx, p)
	if err != nil {
		return ToolResult{}, err
	}
	tr := ToolResult{}
	if rep.NotWired != "" {
		tr.Notes = append(tr.Notes, rep.NotWired)
		return tr, nil
	}
	items := rep.Items
	if len(items) > MaxBGPWatchItems {
		items = items[:MaxBGPWatchItems]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing the first %d of %d watched resources", MaxBGPWatchItems, len(rep.Items)))
	}
	if len(items) == 0 {
		tr.Notes = append(tr.Notes, "this tenant watches no BGP prefix or ASN — say the watchlist is EMPTY, not that the routing is healthy")
		return tr, nil
	}
	for _, it := range items {
		text := fmt.Sprintf("%s (%s)", it.Resource, firstNonEmpty(it.Kind, "resource"))
		if it.Status != "" {
			text += " — " + it.Status
		}
		if it.Note != "" {
			text += "; note: " + it.Note
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "bgpwatch:" + bgpResourceToken(it.Resource), Kind: "topology",
			Text: clampText(text, maxToolTextChars), Href: bgpOpsRouteHref,
		})
	}
	return tr, nil
}

// ---- get_bgp_rpki ----------------------------------------------------------

type bgpRPKITool struct{ deps TroubleshootDeps }

func (t bgpRPKITool) Name() string            { return "get_bgp_rpki" }
func (t bgpRPKITool) Module() string          { return "bgp_operations" }
func (t bgpRPKITool) Capability() Capability  { return CapRead }
func (t bgpRPKITool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t bgpRPKITool) Freshness() Freshness    { return FreshnessRecent }

func (t bgpRPKITool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	rep, err := t.deps.BGPRPKI(ctx, p)
	if err != nil {
		return ToolResult{}, err
	}
	tr := ToolResult{}
	if rep.NotWired != "" {
		tr.Notes = append(tr.Notes, rep.NotWired)
		return tr, nil
	}
	items := rep.Items
	if len(items) > MaxBGPRPKIResults {
		items = items[:MaxBGPRPKIResults]
		tr.Truncated = true
	}
	if rep.Truncated {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, "the validation sweep was capped before every watched prefix was checked — the unlisted prefixes are UNVALIDATED, not valid")
	}
	if len(items) == 0 {
		tr.Notes = append(tr.Notes, "no watched prefix was validated — say the RPKI state is UNKNOWN for this tenant rather than valid")
		return tr, nil
	}
	for _, it := range items {
		text := fmt.Sprintf("%s origin %s — RPKI %s", it.Prefix,
			firstNonEmpty(it.Origin, "undetermined"), firstNonEmpty(it.State, "unavailable"))
		if it.ROAs > 0 {
			text += fmt.Sprintf(" (%s)", plural(it.ROAs, "matching ROA"))
		}
		if it.Reason != "" {
			text += "; " + it.Reason
		}
		if it.Error != "" {
			text += "; validator error: " + it.Error
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "bgprpki:" + bgpResourceToken(it.Prefix), Kind: "finding",
			Text: clampText(text, maxToolTextChars), Href: bgpOpsRouteHref,
		})
	}
	return tr, nil
}

// ---- get_bgp_feed_recent ---------------------------------------------------

type bgpFeedTool struct{ deps TroubleshootDeps }

func (t bgpFeedTool) Name() string            { return "get_bgp_feed_recent" }
func (t bgpFeedTool) Module() string          { return "bgp_operations" }
func (t bgpFeedTool) Capability() Capability  { return CapRead }
func (t bgpFeedTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t bgpFeedTool) Freshness() Freshness    { return FreshnessLive }

func (t bgpFeedTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	prefix := ""
	if raw := strings.TrimSpace(args["prefix"]); raw != "" {
		v, err := validAddrArg("prefix", raw, 64)
		if err != nil {
			return ToolResult{}, err
		}
		prefix = v
	}
	limit := defaultBGPFeedLimit
	if raw := strings.TrimSpace(args["limit"]); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxBGPFeedUpdates {
			return ToolResult{}, fmt.Errorf("limit must be a whole number between 1 and %d", MaxBGPFeedUpdates)
		}
		limit = n
	}
	rep, err := t.deps.BGPFeedRecent(ctx, p, prefix, limit)
	if err != nil {
		return ToolResult{}, err
	}
	tr := ToolResult{}
	if rep.NotWired != "" {
		tr.Notes = append(tr.Notes, rep.NotWired)
		tr.Notes = append(tr.Notes, "no update history was read — treat recent BGP churn as UNKNOWN, not absent")
		return tr, nil
	}
	if rep.Gap {
		tr.Truncated = true
		tr.Notes = append(tr.Notes, "the update buffer overwrote entries before they were read — this page is not the complete history")
	}
	ups := rep.Updates
	if len(ups) > limit {
		ups = ups[:limit]
		tr.Truncated = true
	}
	if len(ups) == 0 {
		switch {
		case len(rep.Resources) == 0:
			tr.Notes = append(tr.Notes, "the update feed follows no resource for this tenant (nothing is on the watchlist) — say that, not that the table is stable")
		default:
			tr.Notes = append(tr.Notes, "no update was recorded for the watched resources in the retained buffer")
		}
		return tr, nil
	}
	for _, u := range ups {
		verb := "announced"
		if strings.EqualFold(u.Type, "W") {
			verb = "withdrawn"
		}
		text := fmt.Sprintf("%s %s %s", u.At, firstNonEmpty(u.Prefix, u.Resource), verb)
		if u.Origin != "" {
			text += " by " + u.Origin
		}
		if u.Peer != "" {
			text += ", seen from peer " + u.Peer
		}
		if u.PathLen > 0 {
			text += fmt.Sprintf(", %s", plural(u.PathLen, "AS hop"))
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("bgpfeed:%d", u.Seq), Kind: "topology",
			Text: clampText(text, maxToolTextChars), Href: bgpOpsRouteHref,
		})
	}
	return tr, nil
}

// bgpResourceToken makes a resource safe and bounded inside a citation id.
func bgpResourceToken(res string) string {
	res = strings.TrimSpace(res)
	if res == "" {
		return "resource"
	}
	if len(res) > 48 {
		res = res[:48]
	}
	return strings.NewReplacer(" ", "_", "[", "", "]", "").Replace(res)
}
