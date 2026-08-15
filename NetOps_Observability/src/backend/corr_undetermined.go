package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/chschema"
)

// corr_undetermined.go — #80 signature-governance: the DYNAMIC undetermined-frequency
// feed. The static self-coverage report (correlation/coverage.py) names dead/blind
// template kinds; this is its runtime companion, living in the API layer where the
// object history is. It ranks the correlation engine's UNDETERMINED verdicts by the
// recurring shape of their evidence gap, so the team can see — from real traffic —
// which fault-family signature to write or strengthen NEXT.
//
// The key insight: for an undetermined object the engine records evidence_missing as
// "{nearest_template_id}: needs {clause}" (scoring.py) — i.e. the signature it almost
// hit and what was missing. Clustering by that nearest-signature set turns a pile of
// "we couldn't tell" into a ranked, evidence-grounded backlog. Tenant-scoped via
// chRows (the corr_objects row policy) — a tenant only ever sees its OWN gaps.

// undeterminedObj is the slice of an undetermined corr object the feed reasons over.
type undeterminedObj struct {
	CorrelationID   string
	WindowStart     time.Time
	EvidenceMissing []string
	EntityTypes     []string
	SignalCount     int
}

type undeterminedGap struct {
	Clause string `json:"clause"`
	Count  int    `json:"count"`
}

// undeterminedCluster is one recurring gap-shape across many undetermined incidents.
type undeterminedCluster struct {
	Fingerprint       string            `json:"fingerprint"`
	Label             string            `json:"label"`
	NearestSignatures []string          `json:"nearest_signatures"`
	TopGaps           []undeterminedGap `json:"top_gaps"`
	EntityTypes       []string          `json:"entity_types"`
	Count             int               `json:"count"`
	LastSeen          string            `json:"last_seen"`
	Examples          []string          `json:"examples"` // up to 3 correlation ids
	AvgSignals        float64           `json:"avg_signals"`
}

// splitGapToken parses an evidence_missing token "templateID: needs clause" into its
// nearest-signature id and the gap clause. Tokens without the "id: " shape degrade to
// (uncategorized, whole-token) so nothing is silently dropped.
func splitGapToken(tok string) (sig, clause string) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", ""
	}
	if i := strings.Index(tok, ":"); i > 0 {
		sig = strings.TrimSpace(tok[:i])
		clause = strings.TrimSpace(tok[i+1:])
		clause = strings.TrimPrefix(clause, "needs ")
		return sig, strings.TrimSpace(clause)
	}
	return "uncategorized", tok
}

// clusterUndetermined groups undetermined objects by their nearest-signature set (the
// recurring gap shape) and ranks the clusters by frequency. Pure — no IO — so the
// fingerprinting/ranking is unit-tested without ClickHouse. topN<=0 means all.
func clusterUndetermined(objs []undeterminedObj, topN int) []undeterminedCluster {
	type acc struct {
		sigs     map[string]struct{}
		entities map[string]struct{}
		gaps     map[string]int
		count    int
		last     time.Time
		examples []string
		signals  int
	}
	groups := map[string]*acc{}
	order := []string{}

	for _, o := range objs {
		sigSet := map[string]struct{}{}
		gaps := []string{}
		for _, tok := range o.EvidenceMissing {
			sig, clause := splitGapToken(tok)
			if sig != "" {
				sigSet[sig] = struct{}{}
			}
			if clause != "" {
				gaps = append(gaps, clause)
			}
		}
		sigs := keysSorted(sigSet)
		fp := strings.Join(sigs, "+")
		if fp == "" {
			// No nearest-signature signal — fall back to the affected entity shape so
			// these still cluster (and stay visible) rather than vanishing.
			fp = "shape:" + strings.Join(o.EntityTypes, "+")
		}
		a := groups[fp]
		if a == nil {
			a = &acc{sigs: map[string]struct{}{}, entities: map[string]struct{}{}, gaps: map[string]int{}}
			groups[fp] = a
			order = append(order, fp)
		}
		for s := range sigSet {
			a.sigs[s] = struct{}{}
		}
		for _, e := range o.EntityTypes {
			a.entities[e] = struct{}{}
		}
		for _, g := range gaps {
			a.gaps[g]++
		}
		a.count++
		a.signals += o.SignalCount
		if o.WindowStart.After(a.last) {
			a.last = o.WindowStart
		}
		if len(a.examples) < 3 && o.CorrelationID != "" {
			a.examples = append(a.examples, o.CorrelationID)
		}
	}

	out := make([]undeterminedCluster, 0, len(groups))
	for _, fp := range order {
		a := groups[fp]
		sigs := keysSorted(a.sigs)
		entities := keysSorted(a.entities)
		avg := 0.0
		if a.count > 0 {
			avg = float64(a.signals) / float64(a.count)
		}
		c := undeterminedCluster{
			Fingerprint:       fp,
			Label:             undeterminedLabel(sigs, entities),
			NearestSignatures: sigs,
			TopGaps:           topGaps(a.gaps, 3),
			EntityTypes:       entities,
			Count:             a.count,
			Examples:          a.examples,
			AvgSignals:        avg,
		}
		if !a.last.IsZero() {
			c.LastSeen = a.last.UTC().Format(time.RFC3339)
		}
		out = append(out, c)
	}
	// Most-recurring first; ties broken by most-recent so a fresh gap surfaces.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// undeterminedLabel renders an operator-facing one-liner for a cluster.
func undeterminedLabel(sigs, entities []string) string {
	var b strings.Builder
	if len(sigs) > 0 && sigs[0] != "uncategorized" {
		b.WriteString("Near: " + strings.Join(sigs, ", "))
	} else {
		b.WriteString("Unclassified gap")
	}
	if len(entities) > 0 {
		b.WriteString(" · " + strings.Join(entities, "+"))
	}
	return b.String()
}

// topGaps returns the most common gap clauses (descending), capped at n.
func topGaps(m map[string]int, n int) []undeterminedGap {
	out := make([]undeterminedGap, 0, len(m))
	for k, v := range m {
		out = append(out, undeterminedGap{Clause: k, Count: v})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Clause < out[j].Clause
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// entityTypesFromAffected derives the distinct entity TYPES present in the affected
// JSON ({devices,interfaces,paths}) — the gap's structural shape.
func entityTypesFromAffected(blob string) []string {
	var a struct {
		Devices    []string `json:"devices"`
		Interfaces []string `json:"interfaces"`
		Paths      []string `json:"paths"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(blob)), &a) != nil {
		return nil
	}
	out := []string{}
	if len(a.Devices) > 0 {
		out = append(out, "device")
	}
	if len(a.Interfaces) > 0 {
		out = append(out, "interface")
	}
	if len(a.Paths) > 0 {
		out = append(out, "path")
	}
	return out
}

// handleUndeterminedFrequency: GET /api/correlations/undetermined-frequency
// Ranks recurring undetermined gap-shapes over a window. Tenant-scoped via chRows.
func (s *server) handleUndeterminedFrequency(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	since := durationQuery(r, "since", 7*24*time.Hour)
	win := intToString(int(since.Seconds()))
	// Fail closed (F-71/F-74 rule): `?top=abc` used to become 20 and `?top=500`
	// used to become 200, both behind a 200 the caller read as their answer.
	topN, terr := intQuery(r, "top", 20, 1, 200)
	if terr != nil {
		writeError(w, http.StatusBadRequest, terr)
		return
	}
	sql := `
SELECT toString(correlation_id) AS correlation_id,
       ` + chschema.ISO("window_start") + ` AS window_start,
       evidence_missing         AS evidence_missing,
       affected                 AS affected,
       signal_count             AS signal_count
  FROM netops.corr_objects_latest
 WHERE verdict_tier = 'undetermined'
   AND window_start >= now() - INTERVAL ` + win + ` SECOND
 ORDER BY window_start DESC
 LIMIT 5000
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	objs := make([]undeterminedObj, 0, len(rows))
	for _, ro := range rows {
		var missing []string
		_ = json.Unmarshal([]byte(asString(ro["evidence_missing"])), &missing) // best-effort: engine-authored JSON; malformed decodes to zero value
		objs = append(objs, undeterminedObj{
			CorrelationID:   asString(ro["correlation_id"]),
			WindowStart:     parseCHTime(ro["window_start"]),
			EvidenceMissing: missing,
			EntityTypes:     entityTypesFromAffected(asString(ro["affected"])),
			SignalCount:     int(asFloat(ro["signal_count"])),
		})
	}
	clusters := clusterUndetermined(objs, topN)
	writeJSON(w, http.StatusOK, map[string]any{
		"window":             since.String(),
		"total_undetermined": len(objs),
		"clusters":           clusters,
	})
}
