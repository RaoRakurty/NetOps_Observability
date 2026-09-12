// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_path_attribution.go — the report-facing view of the path-causality RCA P2
// on-path device attribution (design §2.4). It is a PURE passthrough decode of the
// corr_objects.attribution column the correlation engine writes (engine
// ObjectSnapshot.attribution_blob): the engine already made the causal decision and
// applied the honesty caps; the report NEVER re-decides here, it only renders.
//
// Honesty carried straight through: an object with no on-path cause has an empty
// column ('{}') → nil block → the section is omitted, never rendered as a healthy or
// invented attribution. A capped verdict keeps its cap_reason so a partial/opaque
// span reads as suspected, never confirmed.

import "encoding/json"

// PathAttribution is the render contract (the P3 slice reads this): the named
// upstream-most on-path cause, its verdict lift over the symptom-only baseline, the
// explained-away downstream victims, the discounted off-path faults, the honesty-cap
// reason, and the DISCOVERED typed path (segments + key devices + head) the cause
// sits on. Absent (nil) when the engine attributed no on-path cause.
type PathAttribution struct {
	Src               string               `json:"src,omitempty"`
	Dst               string               `json:"dst,omitempty"`
	Headline          string               `json:"headline,omitempty"`
	Attributed        *rcaAttributedFault  `json:"attributed,omitempty"`
	ExplainedAway     []rcaAttributedFault `json:"explained_away,omitempty"`
	Discounted        []rcaDiscountedFault `json:"discounted,omitempty"`
	VerdictTier       string               `json:"verdict_tier"`
	BaselineTier      string               `json:"baseline_verdict_tier"`
	ConfidenceLifted  bool                 `json:"confidence_lifted"`
	Capped            bool                 `json:"capped"`
	CapReason         string               `json:"cap_reason,omitempty"`
	OnPathDeviceCount int                  `json:"on_path_device_count"`
	Path              *rcaTypedPath        `json:"path,omitempty"`
}

type rcaOnPathDevice struct {
	Address      string `json:"address,omitempty"`
	Role         string `json:"role"`
	Label        string `json:"label,omitempty"`
	SegmentIndex int    `json:"segment_index"`
	SegmentType  string `json:"segment_type,omitempty"`
	UpstreamRank int    `json:"upstream_rank"`
	Ambiguous    bool   `json:"ambiguous"`
}

type rcaAttributedFault struct {
	Device   rcaOnPathDevice `json:"device"`
	Kind     string          `json:"kind"`
	Modality string          `json:"modality,omitempty"`
	Headline string          `json:"headline,omitempty"`
}

type rcaDiscountedFault struct {
	Identity string `json:"identity"`
	Kind     string `json:"kind"`
	Reason   string `json:"reason"`
}

type rcaPathKeyDevice struct {
	Address    string `json:"address,omitempty"`
	Role       string `json:"role"`
	Label      string `json:"label,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	// Discovery-driven canonical device role + word-tier confidence
	// (topology/roles.go vocabulary) — passthrough when the engine stamped it.
	DeviceRole     string `json:"device_role,omitempty"`
	RoleConfidence string `json:"role_confidence,omitempty"`
}

type rcaTypedSegment struct {
	Index       int                `json:"index"`
	SegmentType string             `json:"segment_type"`
	Boundary    string             `json:"boundary,omitempty"`
	Provider    string             `json:"provider,omitempty"`
	Confidence  string             `json:"confidence,omitempty"`
	KeyDevices  []rcaPathKeyDevice `json:"key_devices,omitempty"`
	UnknownHops []int              `json:"unknown_hops,omitempty"`
	Ambiguous   bool               `json:"ambiguous"`
	Reason      string             `json:"reason,omitempty"`
	// Cloud attachment flavor (dia | direct_connect | expressroute | ipsec_vpn)
	// — passthrough only; the UI renders it verbatim-mapped, never guesses.
	Attachment string `json:"attachment,omitempty"`
}

type rcaPathHead struct {
	QueryName       string `json:"query_name,omitempty"`
	ResolvedAddress string `json:"resolved_address,omitempty"`
}

type rcaTypedPath struct {
	Src       string            `json:"src,omitempty"`
	Dst       string            `json:"dst,omitempty"`
	Ambiguous bool              `json:"ambiguous"`
	Head      *rcaPathHead      `json:"head,omitempty"`
	Segments  []rcaTypedSegment `json:"segments,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
}

// DecodePathAttribution reads the corr_objects.attribution column and returns the
// render view, or nil when no on-path cause was attributed. Best-effort: an
// absent/empty/malformed blob → nil (the section is omitted honestly, never faked).
func DecodePathAttribution(meta map[string]any) *PathAttribution {
	s := asString(meta["attribution"])
	if s == "" || s == "{}" {
		return nil
	}
	// The engine blob nests the tier inside verdict/baseline_verdict objects; decode
	// through a raw shape, then flatten to the (already tier-only) render view.
	var raw struct {
		Src           string               `json:"src"`
		Dst           string               `json:"dst"`
		Headline      string               `json:"headline"`
		Attributed    *rcaAttributedFault  `json:"attributed"`
		ExplainedAway []rcaAttributedFault `json:"explained_away"`
		Discounted    []rcaDiscountedFault `json:"discounted"`
		Verdict       struct {
			Tier string `json:"verdict_tier"`
		} `json:"verdict"`
		Baseline struct {
			Tier string `json:"verdict_tier"`
		} `json:"baseline_verdict"`
		ConfidenceLifted  bool          `json:"confidence_lifted"`
		Capped            bool          `json:"capped"`
		CapReason         string        `json:"cap_reason"`
		OnPathDeviceCount int           `json:"on_path_device_count"`
		Path              *rcaTypedPath `json:"path"`
	}
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return nil
	}
	// No named cause ⇒ nothing to render (the engine leaves it un-attributed).
	if raw.Attributed == nil {
		return nil
	}
	return &PathAttribution{
		Src: raw.Src, Dst: raw.Dst, Headline: raw.Headline,
		Attributed: raw.Attributed, ExplainedAway: raw.ExplainedAway,
		Discounted: raw.Discounted, VerdictTier: raw.Verdict.Tier,
		BaselineTier: raw.Baseline.Tier, ConfidenceLifted: raw.ConfidenceLifted,
		Capped: raw.Capped, CapReason: raw.CapReason,
		OnPathDeviceCount: raw.OnPathDeviceCount, Path: raw.Path,
	}
}
