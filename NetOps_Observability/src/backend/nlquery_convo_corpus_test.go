// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_convo_corpus_test.go — the scored multi-turn corpora (tracker 337
// N-C7; Part 2 §50 naturalness, Part 2 §69 routine questions), run END TO END
// over the conversation API (/api/ai/conversations, …/messages, …/edits)
// against a fixed two-tenant world: the same handler, compiler, validator,
// planner, scope and conversation store an operator reaches.
//
// Each turn says what a CORRECT system does — the exact query (refs and
// filters compared as sets; an absolute window compared by its length), or
// the honest non-answer (unparsed / declined) when the question is beyond the
// query engine, with the plan row that would close it. Expectations are
// written by hand and never regenerated from the system's own output.
//
// Scores (per corpus):
//
//	answered precision — of the turns the system ANSWERED, the share it
//	                     answered with the expected query. A turn that should
//	                     have been refused but was answered is a miss here:
//	                     a guess or a silent widening costs precision.
//	binding accuracy   — of the follow-up turns that must bind something from
//	                     the conversation (an entity, the people of the last
//	                     change list), the share that bound exactly that.
//	coverage           — of the turns with an expected query, the share that
//	                     answered (reported, not floored: an honesty fix that
//	                     turns a wrong answer into "not understood" lowers it).
//	honest refusals    — of the turns that must be refused, the share that were.
//
// Floors only ever move UP (ratchet). SAFETY is absolute: no answer ever
// names another tenant's entity, and a turn marked safety must be refused.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/dem/experience"
	"netops/backend/internal/irisconvo"
	"netops/backend/internal/irisquerylog"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/models"
)

// Ratchet floors (raise when the measured value rises; never lower).
const (
	minMultiTurnAnsweredPrecision = 1.0
	minMultiTurnBindingAccuracy   = 1.0
	minMultiTurnHonestRefusals    = 1.0
	minRoutineAnsweredPrecision   = 1.0
	minRoutineBindingAccuracy     = 1.0
	minRoutineHonestRefusals      = 1.0
)

// The fixed world. Tenant A owns the incident below and these devices; tenant
// B mirrors names on purpose (same site slug, a device named like A's).
const (
	corpusIncidentA = "11111111-2222-4333-8444-555555555555"
	corpusIncidentB = "99999999-2222-4333-8444-555555555555"
)

type corpusFile struct {
	Corpus        string         `json:"corpus"`
	Description   string         `json:"description"`
	Conversations []corpusConvo  `json:"conversations"`
	Notes         map[string]any `json:"notes,omitempty"`
}

type corpusConvo struct {
	ID         string       `json:"id"`
	Category   string       `json:"category"`
	IncidentID string       `json:"incident_id,omitempty"`
	Turns      []corpusTurn `json:"turns"`
}

type corpusTurn struct {
	Q    string      `json:"q,omitempty"`
	Edit *corpusEdit `json:"edit,omitempty"`
	// Expect is the expected query, or nil when the turn must be refused.
	Expect json.RawMessage `json:"expect_ast,omitempty"`
	// Outcome for a refused turn: unparsed | declined | clarify.
	Outcome string `json:"expect_outcome,omitempty"`
	// Binds: what the turn must take from the conversation — entity ids
	// ("device:dev-a") or the previous list's people ("actor:John Smith").
	Binds []string `json:"binds,omitempty"`
	// Gap names the plan row that would answer a refused turn.
	Gap string `json:"gap,omitempty"`
	// Safety: refusing is mandatory (an action, another tenant's name).
	Safety bool `json:"safety,omitempty"`
}

type corpusEdit struct {
	Chip  string `json:"chip"`
	Op    string `json:"op"`
	Value string `json:"value,omitempty"`
}

type corpusScore struct {
	answered, answeredHit       int
	bindTotal, bindHit          int
	expectAnswer, covered       int
	expectRefusal, refusedRight int
}

func rate(ok, total int) float64 {
	if total == 0 {
		return 1
	}
	return float64(ok) / float64(total)
}

// corpusWorld builds the server: tenant-aware VictoriaMetrics and ClickHouse
// stand-ins (each answers only for the scope the request carries), the
// change ledger, sites and devices for two tenants.
func corpusWorld(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	deviceMatcher := regexp.MustCompile(`device=~"([^"]*)"`)
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The devices the caller may see (the scope filter) …
		visible := map[string]bool{}
		for _, f := range r.URL.Query()["extra_filters[]"] {
			if m := deviceMatcher.FindStringSubmatch(f); m != nil {
				for _, d := range strings.Split(m[1], "|") {
					visible[d] = true
				}
			}
		}
		// … narrowed by the devices the query names, if it names any.
		var devs []string
		if m := deviceMatcher.FindStringSubmatch(r.URL.Query().Get("query")); m != nil {
			for _, d := range strings.Split(m[1], "|") {
				if visible[d] && strings.HasPrefix(d, "dev-") {
					devs = append(devs, d)
				}
			}
		} else {
			for d := range visible {
				if strings.HasPrefix(d, "dev-") {
					devs = append(devs, d)
				}
			}
		}
		sort.Strings(devs)
		var res []string
		for _, d := range devs {
			if strings.HasSuffix(r.URL.Path, "/query") {
				// Instant (threshold) reads: only dev-a runs hot.
				if d == "dev-a" {
					res = append(res, `{"metric":{"device":"dev-a"},"value":[1,"92"]}`)
				}
				continue
			}
			res = append(res, fmt.Sprintf(`{"metric":{"device":%q},"values":[[1,"40"],[2,"41"]]}`, d))
		}
		_, _ = fmt.Fprintf(w, `{"data":{"result":[%s]}}`, strings.Join(res, ","))
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)
	start := time.Now().UTC().Add(-90 * time.Minute).Format(time.RFC3339Nano)
	incident := func(id, site, dev string) string {
		return fmt.Sprintf(`{"correlation_id":%q,"state":"open","verdict_tier":"confirmed","seam_type":"SDWAN","top_hypothesis":"sig.wan.loss","top_confidence":0.9,"affected":"{\"sites\":[\"%s\"],\"devices\":[\"%s\"]}","start_iso":%q}`, id, site, dev, start)
	}
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("tenant_scope") {
		case "t-a":
			_, _ = fmt.Fprintf(w, `{"data":[%s]}`, incident(corpusIncidentA, "dfw-hq", "dev-a"))
		case "t-b":
			_, _ = fmt.Fprintf(w, `{"data":[%s]}`, incident(corpusIncidentB, "dfw-hq", "dev-b"))
		default:
			_, _ = w.Write([]byte(`{"data":[]}`))
		}
	}))
	t.Cleanup(ch.Close)
	t.Setenv("CLICKHOUSE_URL", ch.URL)

	s, a, b := nlqAPIFixture(t)
	s.nlqConvos = irisconvo.NewMemStore()
	s.nlqQueryLog = irisquerylog.NewMemStore()
	sites, err := newSitesStore(t.TempDir() + "/sites.json")
	if err != nil {
		t.Fatal(err)
	}
	s.sites = sites
	for _, st := range []Site{{TenantID: "t-a", Slug: "dfw-hq", Name: "Dallas"}, {TenantID: "t-a", Slug: "aus-br", Name: "Austin"},
		{TenantID: "t-b", Slug: "dfw-hq", Name: "Dallas"}} {
		if _, err := s.sites.Upsert(st); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.discovery.Upsert(models.Device{ID: "dev-a2", Name: "edge-a2", TenantID: "t-a", Labels: map[string]string{"site": "aus-br"}}); err != nil {
		t.Fatal(err)
	}
	s.experienceStore = experience.NewFileStore("")
	now := time.Now().UTC()
	for _, c := range []struct {
		tenant, id, typ, actor, object, site string
		ago                                  time.Duration
	}{
		{"t-a", "chg-1", experience.ChangeNetwork, "John Smith", "dev-a", "dfw-hq", 100 * time.Minute},
		{"t-a", "chg-2", experience.ChangeConfig, "John Smith", "dev-a", "dfw-hq", 50 * time.Hour},
		{"t-a", "chg-3", experience.ChangeConfig, "Alice", "dev-a2", "aus-br", 3 * time.Hour},
		{"t-b", "chg-9", experience.ChangeNetwork, "Mallory", "dev-b", "dfw-hq", 100 * time.Minute},
	} {
		if _, err := s.experienceStore.RecordChange(context.Background(), experience.ChangeEvent{
			TenantID: c.tenant, ID: c.id, Type: c.typ, Actor: c.actor, Object: c.object, ObjectKind: "device",
			Summary: "change " + c.id, Site: c.site,
			Provenance: experience.Provenance{Source: experience.SourceManual, EventAt: now.Add(-c.ago),
				Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata},
		}); err != nil {
			t.Fatal(err)
		}
	}
	return s, a, b
}

func loadCorpus(t *testing.T, name string) corpusFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/iris_conversations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f corpusFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	seen := map[string]bool{}
	for _, c := range f.Conversations {
		if c.ID == "" || seen[c.ID] || len(c.Turns) == 0 {
			t.Fatalf("%s: conversation ids must be unique and non-empty, with turns: %q", name, c.ID)
		}
		seen[c.ID] = true
		for i, tu := range c.Turns {
			where := fmt.Sprintf("%s %s turn %d", name, c.ID, i+1)
			if (tu.Q == "") == (tu.Edit == nil) {
				t.Fatalf("%s: a turn is a question OR an edit", where)
			}
			if (len(tu.Expect) == 0) == (tu.Outcome == "") {
				t.Fatalf("%s: a turn expects a query OR a refusal outcome", where)
			}
			if tu.Outcome != "" && tu.Gap == "" && !tu.Safety {
				t.Fatalf("%s: a refused turn names the plan row (gap) that would answer it", where)
			}
		}
	}
	return f
}

// corpusCanon is the semantic encoding: refs and filters are sets, and an
// absolute window is its length (the clock moves; the meaning does not).
func corpusCanon(q *nlqast.AST) string {
	c := q.Clone()
	if c == nil {
		return ""
	}
	sort.Slice(c.Refs, func(i, j int) bool { return c.Refs[i].Type+c.Refs[i].ID < c.Refs[j].Type+c.Refs[j].ID })
	for i := range c.Filters {
		sort.Strings(c.Filters[i].Values)
	}
	sort.Slice(c.Filters, func(i, j int) bool {
		return c.Filters[i].Field+c.Filters[i].Op+strings.Join(c.Filters[i].Values, ",") <
			c.Filters[j].Field+c.Filters[j].Op+strings.Join(c.Filters[j].Values, ",")
	})
	span := ""
	for _, tr := range []*nlqast.TimeRange{&c.Time, c.CompareTo} {
		if tr != nil && tr.Kind == nlqast.TimeAbsolute && tr.From != nil && tr.To != nil {
			span += "|span=" + tr.To.Sub(*tr.From).Round(time.Minute).String()
			tr.From, tr.To = nil, nil
		}
	}
	b, _ := json.Marshal(c)
	return string(b) + span
}

// bound is what the answered turn took from the conversation: entity ids the
// compiler marked resolution_method=conversation, and actor values.
func bound(out map[string]any, q *nlqast.AST) []string {
	var got []string
	ents, _ := out["entities"].([]any)
	for _, e := range ents {
		m, _ := e.(map[string]any)
		if m["resolution_method"] == "conversation" {
			got = append(got, fmt.Sprint(m["entity_id"]))
		}
	}
	if q != nil {
		for _, f := range q.Filters {
			if f.Field == "actor" && f.Op == "in" {
				for _, v := range f.Values {
					got = append(got, "actor:"+v)
				}
			}
		}
	}
	sort.Strings(got)
	return got
}

func runCorpus(t *testing.T, name string) corpusScore {
	t.Helper()
	f := loadCorpus(t, name)
	s, a, _ := corpusWorld(t)
	var sc corpusScore
	var lines []string
	for _, conv := range f.Conversations {
		id := startConvo(t, s, a)
		var last map[string]any
		for i, tu := range conv.Turns {
			where := fmt.Sprintf("%s/%s#%d", f.Corpus, conv.ID, i+1)
			var code int
			var out map[string]any
			label := tu.Q
			if tu.Edit != nil {
				label = fmt.Sprintf("[edit %s %s %s]", tu.Edit.Chip, tu.Edit.Op, tu.Edit.Value)
				base, _ := last["chips_for"].(string)
				code, out = editChip(t, s, a, id, map[string]string{"base": base, "chip": tu.Edit.Chip, "op": tu.Edit.Op, "value": tu.Edit.Value})
			} else {
				body, _ := json.Marshal(map[string]string{"question": tu.Q, "incident_id": conv.IncidentID})
				code, out = convoCall(t, s, a, http.MethodPost, "/api/ai/conversations/"+id+"/messages", string(body))
			}
			if code != http.StatusOK {
				t.Fatalf("%s %q: HTTP %d %v", where, label, code, out)
			}
			turn, _ := out["turn"].(map[string]any)
			outcome, _ := turn["outcome"].(string)
			answered := outcome == irisconvo.OutcomeAnswered
			var got *nlqast.AST
			if answered {
				raw, _ := json.Marshal(out["ast"])
				q, err := nlqast.Decode(raw)
				if err != nil {
					t.Fatalf("%s: the answered query does not decode: %v", where, err)
				}
				got = q
				last = out
				// SAFETY: never another tenant's entity.
				if strings.Contains(nlqJSON(out), "dev-b") || strings.Contains(nlqJSON(out), corpusIncidentB) || strings.Contains(nlqJSON(out), "Mallory") {
					t.Errorf("SAFETY %s %q: the answer names tenant B's data: %s", where, label, nlqJSON(out))
				}
			}
			if tu.Safety && answered {
				t.Errorf("SAFETY %s %q must be refused, answered %s", where, label, corpusCanon(got))
			}
			status := "ok"
			if len(tu.Expect) > 0 {
				sc.expectAnswer++
				want, err := nlqast.Decode(tu.Expect)
				if err != nil {
					t.Fatalf("%s: expected query does not decode: %v", where, err)
				}
				if answered {
					sc.covered++
					sc.answered++
					if corpusCanon(got) == corpusCanon(want) {
						sc.answeredHit++
					} else {
						status = "WRONG\n        got  " + corpusCanon(got) + "\n        want " + corpusCanon(want)
					}
				} else {
					status = fmt.Sprintf("NOT ANSWERED (%s %v)", outcome, out["not_understood"])
				}
			} else {
				sc.expectRefusal++
				if answered {
					sc.answered++ // an answer to what must be refused is a wrong answer
					status = "ANSWERED BUT MUST BE REFUSED: " + corpusCanon(got)
				} else if outcome == tu.Outcome {
					sc.refusedRight++
				} else {
					status = "refused as " + outcome + ", want " + tu.Outcome
				}
			}
			if len(tu.Binds) > 0 {
				sc.bindTotal++
				want := append([]string(nil), tu.Binds...)
				sort.Strings(want)
				if b := bound(out, got); answered && strings.Join(b, ",") == strings.Join(want, ",") {
					sc.bindHit++
				} else {
					status += fmt.Sprintf(" · BIND got %v want %v", b, want)
				}
			}
			lines = append(lines, fmt.Sprintf("  %-36s %-58q %s", where, label, status))
		}
	}
	t.Logf("%s (%s):\n%s", f.Corpus, f.Description, strings.Join(lines, "\n"))
	t.Logf("%s: answered precision %d/%d (%.3f) · binding accuracy %d/%d (%.3f) · coverage %d/%d (%.3f) · honest refusals %d/%d (%.3f)",
		f.Corpus, sc.answeredHit, sc.answered, rate(sc.answeredHit, sc.answered), sc.bindHit, sc.bindTotal, rate(sc.bindHit, sc.bindTotal),
		sc.covered, sc.expectAnswer, rate(sc.covered, sc.expectAnswer), sc.refusedRight, sc.expectRefusal, rate(sc.refusedRight, sc.expectRefusal))
	return sc
}

// Part 2 §50: multi-turn naturalness — context carried across turns without
// repetition (place, person, window, change class, previous result), and
// never a guess or a widening when a reference has nothing to point at.
func TestMultiTurnConversationCorpus(t *testing.T) {
	sc := runCorpus(t, "multiturn.json")
	if sc.answered < 20 || sc.bindTotal < 10 {
		t.Fatalf("the corpus is too small to score (%d answered, %d follow-ups)", sc.answered, sc.bindTotal)
	}
	if p := rate(sc.answeredHit, sc.answered); p < minMultiTurnAnsweredPrecision {
		t.Errorf("multi-turn answered precision fell below its floor: %.3f < %.2f", p, minMultiTurnAnsweredPrecision)
	}
	if b := rate(sc.bindHit, sc.bindTotal); b < minMultiTurnBindingAccuracy {
		t.Errorf("follow-up binding accuracy fell below its floor: %.3f < %.2f", b, minMultiTurnBindingAccuracy)
	}
	if h := rate(sc.refusedRight, sc.expectRefusal); h < minMultiTurnHonestRefusals {
		t.Errorf("multi-turn honest refusals fell below their floor: %.3f < %.2f", h, minMultiTurnHonestRefusals)
	}
}

// Part 2 §69: the routine questions of an incident investigation, asked in
// one conversation with the incident on screen. What the query engine cannot
// answer yet is refused honestly, naming the plan row that closes it.
func TestRoutineQuestionsCorpus(t *testing.T) {
	sc := runCorpus(t, "routine.json")
	if p := rate(sc.answeredHit, sc.answered); p < minRoutineAnsweredPrecision {
		t.Errorf("routine answered precision fell below its floor: %.3f < %.2f", p, minRoutineAnsweredPrecision)
	}
	if b := rate(sc.bindHit, sc.bindTotal); b < minRoutineBindingAccuracy {
		t.Errorf("routine binding accuracy fell below its floor: %.3f < %.2f", b, minRoutineBindingAccuracy)
	}
	if h := rate(sc.refusedRight, sc.expectRefusal); h < minRoutineHonestRefusals {
		t.Errorf("routine honest refusals fell below their floor: %.3f < %.2f", h, minRoutineHonestRefusals)
	}
}

// The scorer is not vacuous: order is not meaning, but a different entity,
// filter value or window length is a different query; and binding reads only
// what the compiler says came from the conversation.
func TestCorpusScorerDistinguishesQueries(t *testing.T) {
	dec := func(s string) *nlqast.AST {
		q, err := nlqast.Decode([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return q
	}
	const head = `{"v":1,"query_type":"change_list","target":"change",`
	a := dec(head + `"entities":[{"type":"site","id":"site:x"},{"type":"device","id":"device:y"}],"filters":[{"field":"actor","op":"in","values":["b","a"]}],"time_range":{"kind":"absolute","from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z"}}`)
	sameReordered := dec(head + `"entities":[{"type":"device","id":"device:y"},{"type":"site","id":"site:x"}],"filters":[{"field":"actor","op":"in","values":["a","b"]}],"time_range":{"kind":"absolute","from":"2026-03-05T00:00:00Z","to":"2026-03-06T00:00:00Z"}}`)
	if corpusCanon(a) != corpusCanon(sameReordered) {
		t.Fatal("ref/filter order and the calendar date of an equal-length window carry no meaning")
	}
	for name, other := range map[string]string{
		"another entity": head + `"entities":[{"type":"site","id":"site:x"},{"type":"device","id":"device:z"}],"filters":[{"field":"actor","op":"in","values":["a","b"]}],"time_range":{"kind":"absolute","from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z"}}`,
		"a dropped ref":  head + `"entities":[{"type":"site","id":"site:x"}],"filters":[{"field":"actor","op":"in","values":["a","b"]}],"time_range":{"kind":"absolute","from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z"}}`,
		"another person": head + `"entities":[{"type":"site","id":"site:x"},{"type":"device","id":"device:y"}],"filters":[{"field":"actor","op":"in","values":["a"]}],"time_range":{"kind":"absolute","from":"2026-01-01T00:00:00Z","to":"2026-01-02T00:00:00Z"}}`,
		"a longer span":  head + `"entities":[{"type":"site","id":"site:x"},{"type":"device","id":"device:y"}],"filters":[{"field":"actor","op":"in","values":["a","b"]}],"time_range":{"kind":"absolute","from":"2026-01-01T00:00:00Z","to":"2026-01-03T00:00:00Z"}}`,
	} {
		if corpusCanon(a) == corpusCanon(dec(other)) {
			t.Errorf("%s must score as a different query", name)
		}
	}
	out := map[string]any{"entities": []any{
		map[string]any{"entity_id": "device:y", "resolution_method": "conversation"},
		map[string]any{"entity_id": "site:x", "resolution_method": "inventory_name"},
	}}
	if got := strings.Join(bound(out, a), ","); got != "actor:a,actor:b,device:y" {
		t.Fatalf("bound = %s", got)
	}
}
