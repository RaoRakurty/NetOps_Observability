// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_release_gate_audit_test.go — the N-H5 "audit completeness" gate: asks
// across the performance classes, over the JSON and the streamed path, each
// leave ONE complete decision in the ledger — QUESTION_RECEIVED first,
// ANSWER_RETURNED last, a contiguous sequence, every entry stamped with the
// decision, the asker and the surface.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/internal/aidecision"
	"netops/backend/internal/irisgate"
)

var auditGateQuestions = []string{
	"show cpu on edge-a for the last hour", // data
	"how do I add a device",                // product
	"what can you do",                      // capability
	"what incidents are open right now",    // incidents
}

func decisionIDFrom(t *testing.T, w *httptest.ResponseRecorder, stream bool) string {
	t.Helper()
	body := w.Body.String()
	if stream {
		for _, ev := range parseSSE(t, body) {
			if ev.name == "answer" {
				body = ev.data
			}
		}
	}
	var out struct {
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return ""
	}
	return out.DecisionID
}

func ledgerComplete(t *testing.T, s *server, c jwtClaims, id string) []string {
	t.Helper()
	if !aidecision.ValidID(id) {
		return []string{"the answer names no decision"}
	}
	es := ledgerEntries(t, s, c, "?decision_id="+id)
	var bad []string
	if len(es) < 2 {
		return []string{"fewer than two ledger entries"}
	}
	if es[0]["event_type"] != aidecision.QuestionReceived {
		bad = append(bad, "first entry is not QUESTION_RECEIVED")
	}
	if es[len(es)-1]["event_type"] != aidecision.AnswerReturned {
		bad = append(bad, "last entry is not ANSWER_RETURNED")
	}
	for i, e := range es {
		if int(e["seq"].(float64)) != i || e["decision_id"] != id || e["principal"] != c.Sub || e["surface"] != "ask" {
			bad = append(bad, "an entry is out of sequence or not stamped with its decision")
			break
		}
	}
	return bad
}

func TestIrisReleaseGateAuditCompleteness(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	var ok, total int64
	for _, q := range auditGateQuestions {
		for _, stream := range []bool{false, true} {
			accept := ""
			if stream {
				accept = "text/event-stream"
			}
			total++
			w := httptest.NewRecorder()
			s.handleAIAsk(w, askReq(a, q, accept))
			if w.Code != http.StatusOK {
				t.Errorf("%q (stream=%v): %d %s", q, stream, w.Code, w.Body.String())
				continue
			}
			if bad := ledgerComplete(t, s, a, decisionIDFrom(t, w, stream)); len(bad) > 0 {
				t.Errorf("%q (stream=%v): incomplete decision: %v", q, stream, bad)
				continue
			}
			ok++
		}
	}
	if err := irisgate.Record("root.audit", irisgate.Measure{Gate: irisgate.GateAudit, OK: ok, Total: total,
		Note: "asks (JSON + stream) leaving one complete ledgered decision"}); err != nil {
		t.Fatal(err)
	}
}
