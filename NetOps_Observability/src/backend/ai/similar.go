// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// similar.go — find_similar_incidents (tracker 337 N-F4): "have we seen this
// before?" over the caller's own closed incidents (internal/incidentfp).
//
// It is HISTORY, never current state and never confirmation: every result
// carries the caveat, a match below the documented threshold is not returned,
// and it declares no Signals (a past incident must never steer an
// investigation's next step — the same rule as recall_investigations).

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SimilarMatch is one recalled incident.
type SimilarMatch struct {
	CorrelationID string
	Strength      string // similar | strong
	MatchedOn     []string
	OccurredAt    time.Time
}

// SimilarIncidents is the recall answer as the tool reads it.
type SimilarIncidents struct {
	Verdict  string // similar_incidents | no_similar_incident
	Note     string
	Caveat   string
	Matches  []SimilarMatch
	Examined int
}

var similarWindows = map[string]bool{"30d": true, "90d": true, "180d": true, "365d": true}

type similarIncidentsTool struct{ deps TroubleshootDeps }

func (t similarIncidentsTool) Name() string            { return "find_similar_incidents" }
func (t similarIncidentsTool) Module() string          { return "correlations_rca" }
func (t similarIncidentsTool) Capability() Capability  { return CapRead }
func (t similarIncidentsTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t similarIncidentsTool) Freshness() Freshness    { return FreshnessHistorical }

func (t similarIncidentsTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	id, err := validIDArg("correlation_id", strings.TrimSpace(args["correlation_id"]), 64)
	if err != nil {
		return ToolResult{}, err
	}
	window := strings.ToLower(strings.TrimSpace(args["window"]))
	if window != "" && !similarWindows[window] {
		return ToolResult{}, fmt.Errorf("window must be one of 30d, 90d, 180d, 365d")
	}
	res, err := t.deps.SimilarIncidents(ctx, p, id, window)
	if err != nil {
		return ToolResult{}, err // ErrNotFound for an unknown OR another tenant's case
	}
	tr := ToolResult{}
	// NOTE: no Signals are ever set — history never routes an investigation.
	for i, m := range res.Matches {
		if i == 5 {
			tr.Truncated = true
			break
		}
		text := fmt.Sprintf("A %s match: case %s from %s — matched on %s. Context only, not confirmation.",
			promptLine(m.Strength), shortToken(m.CorrelationID), m.OccurredAt.UTC().Format("2006-01-02"),
			promptLine(strings.Join(m.MatchedOn, ", ")))
		tr.Items = append(tr.Items, EvidenceItem{CitationID: "similar:" + m.CorrelationID, Kind: "history", Text: text,
			Href: "#/monitoring/correlations?id=" + m.CorrelationID})
	}
	if res.Note != "" {
		tr.Notes = append(tr.Notes, res.Note)
	}
	if res.Caveat != "" {
		tr.Notes = append(tr.Notes, res.Caveat)
	}
	return tr, nil
}
