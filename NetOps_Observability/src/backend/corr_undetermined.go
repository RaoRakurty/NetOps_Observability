// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// undeterminedFrequencySQL builds the window read the feed clusters over.
// windowSeconds is an integer literal the caller derived from ?since.
//
// The projected aliases are deliberately NON-SHADOWING (correlation_id_s /
// window_start_iso). ClickHouse resolves a SELECT alias INSIDE the WHERE and
// ORDER BY of the SAME query, so the previous projection —
//
//	SELECT toString(correlation_id) AS correlation_id,
//	       <ISO text of window_start> AS window_start
//	 WHERE window_start >= now() - INTERVAL n SECOND
//	 ORDER BY window_start DESC
//
// bound the ISO *String* expression in the window predicate and the server
// refused every call with
//
//	Code: 386. DB::Exception: There is no supertype for types String, DateTime
//	because some of them are String/FixedString/Enum and some of them are not.
//	(NO_COMMON_TYPE)
//
// This was never data-dependent: the analyzer types the predicate before a row
// is read, so the endpoint answered 502 on an empty window too. It shipped that
// way (#80, 2026-06-30) and the S3 log-time conversion only changed WHICH String
// expression was shadowing.
//
// ORDER BY moves with the predicate: ISO text and DateTime64 happen to sort
// alike, but the ordering must be the typed one for the same reason the
// timeintel pick's ORDER BY had to (tracker 186 hotfix) — the sort and the
// window bound must be the same domain, and only the raw column is that domain.
// The row scan below reads the renamed result columns.
//
// COST (tracker 201). The read used to source netops.corr_objects_latest, whose
// body is `SELECT * FROM corr_objects ORDER BY … LIMIT 1 BY tenant_id,
// correlation_id`. A LIMIT BY cannot have a predicate pushed through it without
// changing the result, so ClickHouse folded the WHOLE HISTORY table first and
// filtered afterwards: EXPLAIN indexes=1 reported 6672/6672 granules — no
// MinMax, Partition or PrimaryKey pruning of any kind — and the endpoint's cost
// scaled with VERSIONS, which a storm multiplies (s11: 10,371 versions for 1,624
// objects). Measured on the live 2.57 M-row corpus: 4,606 ms, 2,572,440 rows,
// 1.50 GiB read, 349 MiB peak. The tracker recorded 18.9–28.3 s against the 20 s
// API budget when a full storm corpus was resident.
//
// corr_current is the sanctioned hot projection (#100 / tracker 197): ONE narrow
// row per live object, carrying every column this feed needs and NONE of the
// wide blobs (hypotheses/layer_coverage/app_impact are not in it at all, so they
// cannot be re-widened into the scan by a later edit). Its cost scales with
// OBJECTS, not versions — the axis a storm does not multiply. FINAL, not a fold:
// the table is ReplacingMergeTree keyed (tenant_id, correlation_id), so FINAL is
// the collapse, and a PREWHERE would filter BEFORE that collapse and could
// resurrect a stale verdict_tier. Same measurement, same corpus: 390 ms,
// 923,184 rows, 497 MiB read, 35.6 MiB peak — 11.8x faster, 3.1x fewer bytes,
// 9.8x less memory, and 12x under the < 5 s target.
//
// SCAN CAP. max_bytes_to_read is the containment the tracker asked for: a corpus
// that outgrows this read fails LOUD and ALONE (code 307 TOO_MANY_BYTES, which
// chhttp already classifies) instead of spending the whole 20 s API budget on
// its way to the same answer. Deliberately NOT read_overflow_mode='break': a
// silently truncated scan would serve a ranking computed from an arbitrary
// subset of the corpus, and this feed's entire purpose is telling the team WHICH
// signature gap recurs most — a quietly wrong ranking is worse than a loud
// failure (CLAUDE.md §10, no silent failures). 2 GiB is ~4x the measured read.
// max_memory_usage mirrors chWorkerReadMemoryBytes so the read is contained on
// both axes; SQL-level SETTINGS bind after the URL/profile settings chhttp
// sends, so these are the values that take effect.
func undeterminedFrequencySQL(windowSeconds string) string {
	return `
SELECT toString(correlation_id) AS correlation_id_s,
       ` + chschema.ISO("window_start") + ` AS window_start_iso,
       evidence_missing         AS evidence_missing,
       affected                 AS affected,
       signal_count             AS signal_count
  FROM netops.corr_current FINAL
 WHERE verdict_tier = 'undetermined'
   AND window_start >= now() - INTERVAL ` + windowSeconds + ` SECOND
 ORDER BY window_start DESC
 LIMIT 5000
 SETTINGS max_bytes_to_read = 2000000000, max_memory_usage = 1073741824
 FORMAT JSON`
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
	rows, err := s.chRows(r, undeterminedFrequencySQL(win))
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	objs := make([]undeterminedObj, 0, len(rows))
	for _, ro := range rows {
		var missing []string
		_ = json.Unmarshal([]byte(asString(ro["evidence_missing"])), &missing) // best-effort: engine-authored JSON; malformed decodes to zero value
		objs = append(objs, undeterminedObj{
			CorrelationID:   asString(ro["correlation_id_s"]),
			WindowStart:     parseCHTime(ro["window_start_iso"]),
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
