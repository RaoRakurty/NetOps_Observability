// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// knowledge_eval_test.go — the N-F3 retrieval evaluation (plan §5 Phase F:
// recall / precision / wrong-source / stale) with a CI ratchet. The corpus is
// testdata/knowledge_eval.json; the floors are testdata/knowledge_eval_floor
// .json. A change that lowers any metric below its floor fails the build; a
// change that raises one should raise the floor in the same PR.
//
// Wrong-source is not a ratchet: it is an invariant. One retrieved document
// of another tenant fails the test outright.

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type kbEvalCorpus struct {
	Now  time.Time `json:"now"`
	Docs []struct {
		ID        string `json:"id"`
		Layer     string `json:"layer"`
		Tenant    string `json:"tenant"`
		Authority int    `json:"authority"`
		AgeDays   int    `json:"age_days"`
		Title     string `json:"title"`
		Text      string `json:"text"`
	} `json:"docs"`
	Cases []struct {
		Q        string   `json:"q"`
		Tenant   string   `json:"tenant"`
		Relevant []string `json:"relevant"`
		Stale    []string `json:"stale"`
	} `json:"cases"`
}

type kbEvalMetrics struct {
	RecallAt3      float64 `json:"recall_at_3"`
	PrecisionAt3   float64 `json:"precision_at_3"`
	AbstainCorrect float64 `json:"abstain_correct"`
	StaleFlagged   float64 `json:"stale_flagged"`
	WrongSource    int     `json:"wrong_source"`
}

// KnowledgeEval runs the corpus and returns its metrics.
func knowledgeEval(t *testing.T) kbEvalMetrics {
	t.Helper()
	raw, err := os.ReadFile("testdata/knowledge_eval.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c kbEvalCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	docs := make([]KnowledgeDoc, 0, len(c.Docs))
	owner := map[string]string{}
	for _, d := range c.Docs {
		docs = append(docs, KnowledgeDoc{ID: d.ID, Layer: KnowledgeLayer(d.Layer), Tenant: d.Tenant, Authority: Authority(d.Authority),
			Updated: c.Now.Add(-time.Duration(d.AgeDays) * 24 * time.Hour), Title: d.Title, Text: d.Text})
		owner[d.ID] = d.Tenant
	}
	var m kbEvalMetrics
	var answerable, abstain, staleCases int
	var recall, precision, abstained, stale float64
	for _, cs := range c.Cases {
		// The corpus holds BOTH tenants: the pre-filter is part of what is
		// measured, exactly as a seam bug would present it.
		r := RankKnowledge(cs.Tenant, cs.Q, docs, []KnowledgeLayer{LayerRunbook, LayerIncident}, c.Now, 3)
		got := map[string]KnowledgeHit{}
		for _, h := range r.Hits {
			got[h.Doc.ID] = h
			if owner[h.Doc.ID] != cs.Tenant {
				m.WrongSource++
				t.Errorf("WRONG SOURCE: %q for %s retrieved %s (tenant %s)", cs.Q, cs.Tenant, h.Doc.ID, owner[h.Doc.ID])
			}
		}
		if len(cs.Relevant) == 0 {
			abstain++
			if len(r.Hits) == 0 {
				abstained++
			} else {
				t.Logf("should abstain: %q retrieved %d", cs.Q, len(r.Hits))
			}
			continue
		}
		answerable++
		rel := map[string]bool{}
		hit := 0
		for _, id := range cs.Relevant {
			rel[id] = true
			if _, ok := got[id]; ok {
				hit++
			}
		}
		want := min(len(cs.Relevant), 3)
		recall += float64(hit) / float64(want)
		if len(r.Hits) > 0 {
			ok := 0
			for _, h := range r.Hits {
				if rel[h.Doc.ID] {
					ok++
				}
			}
			precision += float64(ok) / float64(len(r.Hits))
		}
		if hit < want {
			t.Logf("recall miss: %q got %d/%d", cs.Q, hit, want)
		}
		for _, id := range cs.Stale {
			staleCases++
			if h, ok := got[id]; ok && h.Stale {
				stale++
			} else {
				t.Logf("stale not flagged: %q %s", cs.Q, id)
			}
		}
	}
	if answerable > 0 {
		m.RecallAt3 = recall / float64(answerable)
		m.PrecisionAt3 = precision / float64(answerable)
	}
	if abstain > 0 {
		m.AbstainCorrect = abstained / float64(abstain)
	}
	if staleCases > 0 {
		m.StaleFlagged = stale / float64(staleCases)
	}
	return m
}

func TestKnowledgeRetrievalEvaluation(t *testing.T) {
	m := knowledgeEval(t)
	t.Logf("N-F3 retrieval: recall@3 %.3f · precision@3 %.3f · abstain %.3f · stale flagged %.3f · wrong source %d",
		m.RecallAt3, m.PrecisionAt3, m.AbstainCorrect, m.StaleFlagged, m.WrongSource)
	if m.WrongSource != 0 {
		t.Fatalf("wrong-source retrieval must be zero, got %d", m.WrongSource)
	}
	raw, err := os.ReadFile("testdata/knowledge_eval_floor.json")
	if err != nil {
		t.Fatalf("read floor: %v", err)
	}
	var floor kbEvalMetrics
	if err := json.Unmarshal(raw, &floor); err != nil {
		t.Fatalf("parse floor: %v", err)
	}
	for _, c := range []struct {
		name      string
		got, want float64
	}{
		{"recall_at_3", m.RecallAt3, floor.RecallAt3},
		{"precision_at_3", m.PrecisionAt3, floor.PrecisionAt3},
		{"abstain_correct", m.AbstainCorrect, floor.AbstainCorrect},
		{"stale_flagged", m.StaleFlagged, floor.StaleFlagged},
	} {
		if c.got+1e-9 < c.want {
			t.Errorf("%s fell below its floor: %.3f < %.3f (testdata/knowledge_eval_floor.json)", c.name, c.got, c.want)
		}
	}
}
