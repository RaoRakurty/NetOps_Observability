// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package routinerollup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/oslog"
)

var now = time.Date(2026, 11, 19, 10, 30, 20, 0, time.UTC)

// fakeStore answers like OpenSearch for the three calls the job makes. Composite
// pages are scripted per index; counts and sums per (index, hour).
type fakeStore struct {
	mu       sync.Mutex
	indices  []string
	pages    map[string][]string // index → composite responses, served in order (then empty)
	served   map[string]int
	counts   map[string]int64 // index|hourRFC3339 → originals
	sums     map[string]int64 // rollupIndex|hourRFC3339 → rolled sum
	bulks    []string
	searches []string
	bulkResp string
	failOn   string
}

func newFake() *fakeStore {
	return &fakeStore{pages: map[string][]string{}, served: map[string]int{}, counts: map[string]int64{}, sums: map[string]int64{}}
}

func (f *fakeStore) Indices(_ context.Context, pattern string) ([]string, error) {
	if pattern != OriginalsBase+"-*" {
		return nil, fmt.Errorf("unexpected pattern %q", pattern)
	}
	return append([]string(nil), f.indices...), nil
}

func (f *fakeStore) Search(_ context.Context, index string, body map[string]any) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(body)
	f.searches = append(f.searches, index+" "+string(b))
	if f.failOn != "" && strings.Contains(index, f.failOn) {
		return nil, errors.New("opensearch unavailable")
	}
	rng := body["query"].(map[string]any)["range"].(map[string]any)["timestamp"].(map[string]any)
	hour := rng["gte"].(string)
	switch {
	case body["aggs"] != nil && strings.Contains(string(b), `"composite"`):
		i := f.served[index]
		f.served[index]++
		if i < len(f.pages[index]) {
			return []byte(f.pages[index][i]), nil
		}
		return []byte(`{"aggregations":{"k":{"buckets":[]}}}`), nil
	case body["aggs"] != nil: // rolled sum
		return []byte(fmt.Sprintf(`{"aggregations":{"n":{"value":%d}}}`, f.sums[index+"|"+hour])), nil
	default: // count
		return []byte(fmt.Sprintf(`{"hits":{"total":{"value":%d}}}`, f.counts[index+"|"+hour])), nil
	}
}

func (f *fakeStore) Bulk(_ context.Context, ndjson []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bulks = append(f.bulks, string(ndjson))
	if f.bulkResp != "" {
		return []byte(f.bulkResp), nil
	}
	return []byte(`{"errors":false,"items":[]}`), nil
}

func bucketJSON(tenant, host, user string, minute time.Time, count int) string {
	key := map[string]any{"device_id": host, "host": host, "hostname": nil, "source_ip": "10.0.0.1",
		"audit_source": "10.9.9.9:830", "audit_user": user, "minute": minute.UnixMilli()}
	if tenant == "" {
		key["tenant_id"] = nil
	} else {
		key["tenant_id"] = tenant
	}
	b, _ := json.Marshal(map[string]any{"key": key, "doc_count": count,
		"first": map[string]any{"value": minute.Add(3 * time.Second).UnixMilli()},
		"last":  map[string]any{"value": minute.Add(57 * time.Second).UnixMilli()}})
	return string(b)
}

func page(after string, buckets ...string) string {
	a := "null"
	if after != "" {
		a = after
	}
	return `{"aggregations":{"k":{"after_key":` + a + `,"buckets":[` + strings.Join(buckets, ",") + `]}}}`
}

func newJob(f *fakeStore) *Job {
	return &Job{Store: f, Now: func() time.Time { return now }, Metrics: NewMetrics(),
		Config: Config{ReconcileEvery: 24 * time.Hour}}
}

type bulkLine struct {
	Index map[string]string `json:"index"`
}

func parseBulk(t *testing.T, body string) (metas []map[string]string, docs []map[string]any) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines)%2 != 0 {
		t.Fatalf("bulk body has an odd number of lines:\n%s", body)
	}
	for i := 0; i < len(lines); i += 2 {
		var m bulkLine
		var d map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &m); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(lines[i+1]), &d); err != nil {
			t.Fatal(err)
		}
		metas, docs = append(metas, m.Index), append(docs, d)
	}
	return metas, docs
}

func TestCompositeBodyFoldsClosedMinutesByIdentity(t *testing.T) {
	from, to := now.Truncate(time.Minute).Add(-15*time.Minute), now.Truncate(time.Minute)
	b, _ := json.Marshal(CompositeBody(from, to, 500, nil))
	s := string(b)
	for _, want := range []string{
		`"gte":"2026-11-19T10:15:00Z"`, `"lt":"2026-11-19T10:30:00Z"`, // closed minutes only
		`"fixed_interval":"1m"`, `"missing_bucket":true`, `"size":500`,
		`"tenant_id"`, `"device_id"`, `"host"`, `"hostname"`, `"source_ip"`, `"audit_source"`, `"audit_user"`,
		`"min":{"field":"timestamp"}`, `"max":{"field":"timestamp"}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("composite body missing %s\n%s", want, s)
		}
	}
	if strings.Contains(s, `"after"`) {
		t.Error("a first page carries no after key")
	}
}

func TestIndexNaming(t *testing.T) {
	if got, ok := RollupIndexFor("netops-syslogroutine-acme-corp-2026.11.19"); !ok || got != "netops-syslogrollup-acme-corp-2026.11.19" {
		t.Errorf("RollupIndexFor = %q %v", got, ok)
	}
	if _, ok := RollupIndexFor("netops-syslog-acme-2026.11.19"); ok {
		t.Error("a main-syslog index is not an originals index")
	}
	if seg, ok := Segment("netops-syslogroutine-acme-corp-2026.11.19"); !ok || seg != "acme-corp" {
		t.Errorf("Segment = %q %v", seg, ok)
	}
	if seg, ok := Segment("netops-syslogrollup-untagged-2026.11.19"); !ok || seg != "untagged" {
		t.Errorf("Segment = %q %v", seg, ok)
	}
}

// segFor must be the read-side derivation exactly, or a tenant's roll-ups would
// be written under a segment its own read pattern never names.
func TestSegForMatchesTheReadDerivation(t *testing.T) {
	for _, tenant := range []string{"", "  ", "acme", "Acme Corp", "a.b/c:d", "tenant_1-2", "t-ü"} {
		if got, want := segFor(tenant), oslog.IndexTenantSeg(tenant); got != want {
			t.Errorf("segFor(%q) = %q, oslog.IndexTenantSeg = %q", tenant, got, want)
		}
	}
}

func TestBucketIDIsStableAndDistinct(t *testing.T) {
	m := now.Truncate(time.Minute)
	a := Bucket{Key: map[string]string{"tenant_id": "acme", "host": "e1", "audit_user": "admin"}, Minute: m}
	b := Bucket{Key: map[string]string{"tenant_id": "acme", "host": "e1", "audit_user": "admin"}, Minute: m, Count: 99}
	if a.ID() != b.ID() {
		t.Error("the same key and minute must map to the same document (re-roll upserts)")
	}
	for _, other := range []Bucket{
		{Key: map[string]string{"tenant_id": "globex", "host": "e1", "audit_user": "admin"}, Minute: m},
		{Key: map[string]string{"tenant_id": "acme", "host": "e1", "audit_user": "oper"}, Minute: m},
		{Key: map[string]string{"tenant_id": "acme", "host": "e1", "audit_user": "admin"}, Minute: m.Add(time.Minute)},
		// field boundaries are delimited: "e1"+"admin" must not equal "e1a"+"dmin"
		{Key: map[string]string{"tenant_id": "acme", "host": "e1a", "audit_user": "dmin"}, Minute: m},
	} {
		if other.ID() == a.ID() {
			t.Errorf("distinct buckets share an id: %+v", other)
		}
	}
}

func TestTickRollsOwnTenantPagesAndSkipsAMismatchedTenant(t *testing.T) {
	f := newFake()
	acme := "netops-syslogroutine-acme-2026.11.19"
	old := "netops-syslogroutine-acme-2026.11.17" // outside the lookback: never read
	f.indices = []string{acme, old}
	m1, m2 := now.Truncate(time.Minute).Add(-3*time.Minute), now.Truncate(time.Minute).Add(-2*time.Minute)
	f.pages[acme] = []string{
		page(`{"tenant_id":"acme","minute":1}`, bucketJSON("acme", "edge-1", "vmanage", m1, 41),
			bucketJSON("globex", "edge-9", "x", m1, 5)), // a globex record inside acme's index
		page("", bucketJSON("acme", "edge-1", "vmanage", m2, 40)),
	}
	j := newJob(f)
	if err := j.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.searches {
		if strings.HasPrefix(s, old+" ") && strings.Contains(s, "composite") {
			t.Errorf("an index outside the lookback was aggregated: %s", s)
		}
	}
	if len(f.bulks) != 2 {
		t.Fatalf("want one bulk per non-empty page, got %d", len(f.bulks))
	}
	var metas []map[string]string
	var docs []map[string]any
	for _, b := range f.bulks {
		m, d := parseBulk(t, b)
		metas, docs = append(metas, m...), append(docs, d...)
	}
	if len(docs) != 2 {
		t.Fatalf("want 2 acme roll-ups (the globex bucket skipped), got %d", len(docs))
	}
	for i, m := range metas {
		if m["_index"] != "netops-syslogrollup-acme-2026.11.19" {
			t.Errorf("roll-up written to %q", m["_index"])
		}
		if docs[i]["tenant_id"] != "acme" || docs[i]["audit_user"] != "vmanage" || docs[i]["host"] != "edge-1" {
			t.Errorf("roll-up lost its identity: %v", docs[i])
		}
		if _, has := docs[i]["hostname"]; has {
			t.Errorf("an absent key field must stay absent, got %v", docs[i])
		}
	}
	if docs[0]["occurrence_count"] != float64(41) || docs[1]["occurrence_count"] != float64(40) {
		t.Errorf("counts = %v / %v", docs[0]["occurrence_count"], docs[1]["occurrence_count"])
	}
	if docs[0]["first_seen"] != float64(m1.Add(3*time.Second).UnixMilli()) || docs[0]["last_seen"] != float64(m1.Add(57*time.Second).UnixMilli()) {
		t.Errorf("first/last seen = %v / %v", docs[0]["first_seen"], docs[0]["last_seen"])
	}
	s := j.Metrics.Snapshot()
	if s.TenantMismatch != 5 || s.Written != 2 || s.RunsOK != 1 || s.LastSuccess != now {
		t.Errorf("metrics = %+v", s)
	}
}

func TestReRollUpsertsTheSameDocuments(t *testing.T) {
	ids := func() []string {
		f := newFake()
		idx := "netops-syslogroutine-untagged-2026.11.19"
		f.indices = []string{idx}
		f.pages[idx] = []string{page("", bucketJSON("", "edge-2", "admin", now.Truncate(time.Minute).Add(-time.Minute), 7))}
		if err := newJob(f).Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		metas, docs := parseBulk(t, f.bulks[0])
		if _, has := docs[0]["tenant_id"]; has {
			t.Errorf("an untagged record's roll-up must stay untagged: %v", docs[0])
		}
		if metas[0]["_index"] != "netops-syslogrollup-untagged-2026.11.19" {
			t.Errorf("untagged roll-up written to %q", metas[0]["_index"])
		}
		return []string{metas[0]["_id"]}
	}
	a, b := ids(), ids()
	if a[0] != b[0] || len(a[0]) != 64 {
		t.Errorf("re-rolling the same minute must upsert the same _id (sha256 hex): %v vs %v", a, b)
	}
}

// §3a: two tenants' originals in two indices land in two roll-up indices and
// never share one, whatever the documents say.
func TestTwoTenantsAreNeverMixed(t *testing.T) {
	f := newFake()
	acme, globex := "netops-syslogroutine-acme-2026.11.19", "netops-syslogroutine-globex-2026.11.19"
	f.indices = []string{acme, globex}
	m := now.Truncate(time.Minute).Add(-time.Minute)
	f.pages[acme] = []string{page("", bucketJSON("acme", "edge-1", "vmanage", m, 3))}
	f.pages[globex] = []string{page("", bucketJSON("globex", "edge-1", "vmanage", m, 9))}
	if err := newJob(f).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, b := range f.bulks {
		metas, docs := parseBulk(t, b)
		for i, meta := range metas {
			seen[meta["_index"]] = fmt.Sprint(docs[i]["tenant_id"])
			if meta["_index"] == "netops-syslogrollup-acme-2026.11.19" && docs[i]["occurrence_count"] != float64(3) {
				t.Errorf("acme's roll-up carries another tenant's count: %v", docs[i])
			}
		}
	}
	if seen["netops-syslogrollup-acme-2026.11.19"] != "acme" || seen["netops-syslogrollup-globex-2026.11.19"] != "globex" || len(seen) != 2 {
		t.Fatalf("roll-ups by index = %v", seen)
	}
	// Same device name, same user, same minute in two tenants: two documents.
	a := Bucket{Key: map[string]string{"tenant_id": "acme", "host": "edge-1", "audit_user": "vmanage"}, Minute: m}
	g := Bucket{Key: map[string]string{"tenant_id": "globex", "host": "edge-1", "audit_user": "vmanage"}, Minute: m}
	if a.ID() == g.ID() {
		t.Error("two tenants' identical keys collapse onto one document id")
	}
}

// A record that arrives late (after its minute was first rolled) is folded in
// by the next tick's lookback: the same document, the higher count.
func TestLateArrivalUpsertsTheHigherCount(t *testing.T) {
	f := newFake()
	idx := "netops-syslogroutine-acme-2026.11.19"
	f.indices = []string{idx}
	m := now.Truncate(time.Minute).Add(-5 * time.Minute)
	f.pages[idx] = []string{page("", bucketJSON("acme", "edge-1", "u", m, 10))}
	j := newJob(f)
	if err := j.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.pages[idx] = append(f.pages[idx], page("", bucketJSON("acme", "edge-1", "u", m, 12)))
	if err := j.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	m1, d1 := parseBulk(t, f.bulks[0])
	m2, d2 := parseBulk(t, f.bulks[1])
	if m1[0]["_id"] != m2[0]["_id"] {
		t.Fatal("the late re-roll wrote a new document instead of upserting the minute's")
	}
	if d1[0]["occurrence_count"] != float64(10) || d2[0]["occurrence_count"] != float64(12) {
		t.Errorf("counts %v → %v, want 10 → 12", d1[0]["occurrence_count"], d2[0]["occurrence_count"])
	}
}

// A restarted job (a fresh Job: no lastReconcile) reconciles on its first tick,
// so an outage's gap is repaired without waiting an hour.
func TestARestartedJobReconcilesAtOnce(t *testing.T) {
	f := newFake()
	idx := "netops-syslogroutine-acme-2026.11.19"
	f.indices = []string{idx}
	h := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	f.counts[idx+"|"+h] = 50 // the roll-up sum for that hour is 0: the job was down
	j := newJob(f)
	j.Config.ReconcileHorizon = 2 * time.Hour
	if err := j.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := j.Metrics.Snapshot().MismatchHours; got != 1 {
		t.Fatalf("a fresh job must reconcile at once and find the down hour; mismatch hours = %d", got)
	}
}

func TestReconcileReRollsOnlyHoursThatDisagree(t *testing.T) {
	f := newFake()
	idx := "netops-syslogroutine-acme-2026.11.19"
	f.indices = []string{idx}
	h1 := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC).Format(time.RFC3339)
	h2 := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC).Format(time.RFC3339)
	f.counts[idx+"|"+h1], f.sums["netops-syslogrollup-acme-2026.11.19|"+h1] = 100, 100 // agrees
	f.counts[idx+"|"+h2], f.sums["netops-syslogrollup-acme-2026.11.19|"+h2] = 100, 60  // a gap
	j := newJob(f)
	j.Config.ReconcileHorizon = 3 * time.Hour
	if err := j.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	var rerolled []string
	for _, s := range f.searches {
		if strings.Contains(s, "composite") && strings.Contains(s, `"lt":"2026-11-19T`) && !strings.Contains(s, `"gte":"2026-11-19T10:15:00Z"`) {
			rerolled = append(rerolled, s)
		}
	}
	if len(rerolled) != 1 || !strings.Contains(rerolled[0], `"gte":"`+h2+`"`) {
		t.Fatalf("want exactly the 09:00 hour re-rolled, got %v", rerolled)
	}
	if got := j.Metrics.Snapshot().MismatchHours; got != 1 {
		t.Errorf("mismatch hours = %d, want 1", got)
	}
}

func TestPageBudgetDefersInsteadOfDropping(t *testing.T) {
	f := newFake()
	idx := "netops-syslogroutine-acme-2026.11.19"
	f.indices = []string{idx}
	m := now.Truncate(time.Minute).Add(-time.Minute)
	f.pages[idx] = []string{
		page(`{"minute":1}`, bucketJSON("acme", "e1", "u", m, 1)),
		page("", bucketJSON("acme", "e2", "u", m, 1)),
	}
	j := newJob(f)
	j.Config.MaxPages = 1
	if err := j.Tick(context.Background()); err != nil {
		t.Fatalf("a spent page budget is a deferral, not a failure: %v", err)
	}
	s := j.Metrics.Snapshot()
	if s.Deferrals != 1 || s.Written != 1 || !s.LastSuccess.IsZero() {
		t.Errorf("metrics = %+v (a deferred tick is not a completed one)", s)
	}
}

func TestStoreFailuresAreReturnedNotSwallowed(t *testing.T) {
	f := newFake()
	f.indices = []string{"netops-syslogroutine-acme-2026.11.19"}
	f.failOn = "acme"
	if err := newJob(f).Tick(context.Background()); err == nil {
		t.Fatal("an OpenSearch failure must fail the tick")
	}
	f2 := newFake()
	idx := "netops-syslogroutine-acme-2026.11.19"
	f2.indices = []string{idx}
	f2.pages[idx] = []string{page("", bucketJSON("acme", "e1", "u", now.Truncate(time.Minute).Add(-time.Minute), 1))}
	f2.bulkResp = `{"errors":true,"items":[{"index":{"status":400}}]}`
	if err := newJob(f2).Tick(context.Background()); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("a rejected roll-up document must fail the tick, got %v", err)
	}
}

func TestMetricsWrite(t *testing.T) {
	m := NewMetrics()
	var b bytes.Buffer
	m.Write(&b)
	if strings.Contains(b.String(), "last_success_timestamp_seconds") {
		t.Error("never rolled must not render a last-success gauge")
	}
	m.success(now, now)
	m.written(3)
	b.Reset()
	m.Write(&b)
	for _, want := range []string{
		`netops_routine_rollup_runs_total{result="ok"} 1`,
		"netops_routine_rollup_documents_written_total 3",
		fmt.Sprintf("netops_routine_rollup_last_success_timestamp_seconds %d", now.Unix()),
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics missing %q:\n%s", want, b.String())
		}
	}
	var nilM *Metrics
	nilM.Write(&b) // nil-safe
}
