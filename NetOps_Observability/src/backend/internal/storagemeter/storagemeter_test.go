package storagemeter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func clock() time.Time { return fixedNow }

// fakeDeps builds a Meter whose every store answers from memory. Nothing here
// touches a network, a database or the clock, which is the whole point of the
// Deps seam.
func fakeDeps() Deps {
	return Deps{
		Now:      clock,
		Database: "netops",
		DataRoot: "/data",
		CatPattern: func(tenant string, cross bool) string {
			if cross {
				return "netops-*"
			}
			return "netops-syslog-" + tenant + "-*,netops-syslog-untagged-*"
		},
		IndexTenant: func(index string) (string, bool) {
			rest, ok := strings.CutPrefix(index, "netops-")
			if !ok {
				return "", false
			}
			parts := strings.Split(rest, "-")
			if len(parts) < 3 {
				return "", false
			}
			return strings.Join(parts[1:len(parts)-1], "-"), true
		},
	}
}

func osRows(rows []catIndexRow) OpenSearchGet {
	return func(_ context.Context, path string, out any) error {
		if strings.HasPrefix(path, "/_cat/indices/") {
			blob, err := json.Marshal(rows)
			if err != nil {
				return err
			}
			return json.Unmarshal(blob, out)
		}
		return errors.New("unexpected path " + path)
	}
}

func find(t *testing.T, rs []Reading, store Store, scope string) Reading {
	t.Helper()
	for _, r := range rs {
		if r.Store == store && r.Scope == scope {
			return r
		}
	}
	t.Fatalf("no reading for %s/%s in %+v", store, scope, rs)
	return Reading{}
}

// ── the honesty contract ─────────────────────────────────────────────────────

// The whole reason this package exists (tracker 204): a store that could not be
// measured must be a NIL with a reason, never a zero.
func TestUnmeasuredStoreIsNilWithAReasonNeverZero(t *testing.T) {
	m := New(fakeDeps()) // every client nil
	got := m.Probe(context.Background(), Principal{CrossTenant: true})
	if len(got) == 0 {
		t.Fatal("a meter with no clients must still report every store")
	}
	for _, r := range got {
		if r.BytesOnDisk != nil {
			t.Fatalf("%s measured nothing but reported a number: %+v", r.Store, r)
		}
		if !strings.HasPrefix(r.Detail, "not measured — ") {
			t.Fatalf("%s: an unmeasured reading must say why, got %q", r.Store, r.Detail)
		}
		if strings.TrimSpace(strings.TrimPrefix(r.Detail, "not measured — ")) == "" {
			t.Fatalf("%s: the reason is empty", r.Store)
		}
	}
}

// Zero bytes is a legitimate MEASUREMENT and must not be confused with "not
// measured" — the two render differently and mean different things.
func TestZeroBytesIsAMeasurementNotAnAbsence(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = osRows(nil)
	m := New(d)
	r := find(t, m.Probe(context.Background(), Principal{CrossTenant: true}), StoreOpenSearch, ScopePlatform)
	if !r.Measured() || *r.BytesOnDisk != 0 {
		t.Fatalf("an empty cluster must measure as zero bytes, got %+v", r)
	}
	if !strings.Contains(r.Detail, "MEASUREMENT") {
		t.Fatalf("the zero must be labelled a measurement: %q", r.Detail)
	}
}

// Kafka is the one store that genuinely cannot be measured from the api. The
// reason must name all three blockers so nobody re-opens the question blind.
func TestKafkaIsHonestlyUnmeasurable(t *testing.T) {
	m := New(fakeDeps())
	r := find(t, m.Probe(context.Background(), Principal{CrossTenant: true}), StoreKafka, ScopePlatform)
	if r.Measured() {
		t.Fatal("Kafka must not report a measured size")
	}
	for _, want := range []string{"no Kafka client", "kafka-exporter", "does not mount"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("the Kafka reason must name %q: %q", want, r.Detail)
		}
	}
}

// ── OpenSearch: per-tenant attribution off the index name ────────────────────

func TestOpenSearchAttributesBytesByTheTenantSegmentInTheIndexName(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = osRows([]catIndexRow{
		{Index: "netops-syslog-acme-2026.09.06", Store: "1000", Docs: "10"},
		{Index: "netops-syslog-acme-2026.09.05", Store: "500", Docs: "5"},
		{Index: "netops-syslog-globex-2026.09.06", Store: "7000", Docs: "70"},
		{Index: "netops-syslog-untagged-2026.09.06", Store: "300", Docs: "3"},
	})
	m := New(d)
	got := m.Probe(context.Background(), Principal{CrossTenant: true})
	if b := *find(t, got, StoreOpenSearch, "acme").BytesOnDisk; b != 1500 {
		t.Errorf("acme = %d, want 1500", b)
	}
	if b := *find(t, got, StoreOpenSearch, "globex").BytesOnDisk; b != 7000 {
		t.Errorf("globex = %d, want 7000", b)
	}
	// The shared untagged indices are their OWN scope, never folded into a
	// tenant's total: splitting them would be a derivation.
	un := find(t, got, StoreOpenSearch, ScopeUntagged)
	if *un.BytesOnDisk != 300 {
		t.Errorf("untagged = %d, want 300", *un.BytesOnDisk)
	}
	if !strings.Contains(un.Detail, "NOT folded into any tenant") {
		t.Errorf("the untagged reading must say it is not attributed: %q", un.Detail)
	}
}

// An index whose size the cluster did not report must not be counted as zero:
// that would silently understate the total.
func TestOpenSearchSkipsAnIndexWithNoReportedSizeRatherThanCountingItZero(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = osRows([]catIndexRow{
		{Index: "netops-syslog-acme-2026.09.06", Store: "1000", Docs: "10"},
		{Index: "netops-syslog-acme-2026.09.04", Store: "", Docs: ""},
	})
	r := find(t, New(d).Probe(context.Background(), Principal{CrossTenant: true}), StoreOpenSearch, "acme")
	if *r.BytesOnDisk != 1000 {
		t.Errorf("acme = %d, want 1000", *r.BytesOnDisk)
	}
	if !strings.Contains(r.Detail, "reported NO size") {
		t.Errorf("the exclusion must be stated, not silent: %q", r.Detail)
	}
}

// The fallback: an account without indices:monitor/stats gets a PLATFORM TOTAL
// and is told, in the reading itself, that there is no per-tenant attribution.
func TestOpenSearchFallsBackToNodeStatsAndSaysItCannotAttribute(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = func(_ context.Context, path string, out any) error {
		if strings.HasPrefix(path, "/_cat/indices/") {
			return errors.New("no permissions for [indices:monitor/stats]")
		}
		return json.Unmarshal([]byte(
			`{"nodes":{"n1":{"name":"opensearch","indices":{"store":{"size_in_bytes":4242}}}}}`), out)
	}
	m := New(d)
	r := find(t, m.Probe(context.Background(), Principal{CrossTenant: true}), StoreOpenSearch, ScopePlatform)
	if !r.Measured() || *r.BytesOnDisk != 4242 {
		t.Fatalf("fallback total = %+v, want 4242", r)
	}
	if !strings.Contains(r.Detail, "PLATFORM TOTAL ONLY") ||
		!strings.Contains(r.Detail, "indices:monitor/stats") {
		t.Errorf("the fallback must name its limitation and the fix: %q", r.Detail)
	}
}

// Defense in depth (§3a.4): if the cluster ever answers a scoped pattern with
// another tenant's index, its bytes stop here. The untagged lane is the one
// exception, because it IS in a scoped caller's pattern.
func TestOpenSearchDropsAnotherTenantsIndexEvenIfTheClusterReturnsIt(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = osRows([]catIndexRow{
		{Index: "netops-syslog-acme-2026.09.06", Store: "1000", Docs: "1"},
		{Index: "netops-syslog-globex-2026.09.06", Store: "999999", Docs: "9"},
		{Index: "netops-syslog-untagged-2026.09.06", Store: "300", Docs: "3"},
	})
	got := New(d).Probe(context.Background(), Principal{Tenant: "acme"})
	for _, r := range got {
		if r.Scope == "globex" {
			t.Fatalf("another tenant's index bytes reached a scoped caller: %+v", r)
		}
	}
	if *find(t, got, StoreOpenSearch, "acme").BytesOnDisk != 1000 {
		t.Error("the caller's own bytes are wrong")
	}
	if *find(t, got, StoreOpenSearch, ScopeUntagged).BytesOnDisk != 300 {
		t.Error("the untagged lane is in a scoped caller's own pattern and must be reported")
	}
}

// A SCOPED caller gets no fallback at all: a platform total is not that
// tenant's bytes and must never be shown as if it were.
func TestOpenSearchGivesAScopedCallerNoPlatformFallback(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = func(_ context.Context, path string, out any) error {
		if strings.HasPrefix(path, "/_cat/indices/") {
			return errors.New("no permissions for [indices:monitor/stats]")
		}
		return json.Unmarshal([]byte(
			`{"nodes":{"n1":{"name":"opensearch","indices":{"store":{"size_in_bytes":4242}}}}}`), out)
	}
	m := New(d)
	r := find(t, m.Probe(context.Background(), Principal{Tenant: "acme"}), StoreOpenSearch, "acme")
	if r.Measured() {
		t.Fatalf("a scoped caller must not receive the platform total: %+v", r)
	}
}

// ── ClickHouse: the partition IS the tenant ──────────────────────────────────

func TestPartitionTenantReadsBothPartitionKeyShapes(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"t_abc", "t_abc", true},
		{"global", "global", true},
		{`('t_abc',202609)`, "t_abc", true},
		{`('global',20260906)`, "global", true},
		{"", "", false},
		{"(202609)", "", false},
		{"('unterminated", "", false},
	}
	for _, c := range cases {
		got, ok := partitionTenant(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("partitionTenant(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// The SQL scope is the storage-layer enforcement for this read (system.parts has
// no tenant column, so no row policy can reach it). Pin its shape.
func TestClickHouseSQLScopesToTheCallersTenant(t *testing.T) {
	cross := chPartsSQL("netops", "", true)
	if strings.Contains(cross, "partition =") {
		t.Errorf("a cross-tenant read must not be narrowed: %s", cross)
	}
	scoped := chPartsSQL("netops", "t_abc", false)
	for _, want := range []string{"partition = 't_abc'", `startsWith(partition, '(\'t_abc\'')`} {
		if !strings.Contains(scoped, want) {
			t.Errorf("scoped SQL must contain %q, got %s", want, scoped)
		}
	}
}

// Zero trust (§3): a tenant id outside the accepted alphabet is REFUSED, not
// escaped, and no query is run at all.
func TestClickHouseRefusesToInterpolateAHostileTenantID(t *testing.T) {
	d := fakeDeps()
	called := false
	d.ClickHouse = func(context.Context, string) ([]map[string]any, error) {
		called = true
		return nil, nil
	}
	m := New(d)
	r := find(t, m.Probe(context.Background(), Principal{Tenant: "t'; DROP TABLE parts--"}),
		StoreClickHouse, "t'; DROP TABLE parts--")
	if r.Measured() {
		t.Fatal("a hostile tenant id must not produce a measurement")
	}
	if called {
		t.Fatal("no SQL may be run for a tenant id this probe refuses")
	}
	if !strings.Contains(r.Detail, "SQL literal") {
		t.Errorf("the refusal must say why: %q", r.Detail)
	}
}

func TestClickHouseGroupsBytesByTenantAndReportsAMeasuredCompressionRatio(t *testing.T) {
	d := fakeDeps()
	d.ClickHouse = func(_ context.Context, _ string) ([]map[string]any, error) {
		return []map[string]any{
			{"database": "netops", "table": "corr_signals", "partition": `('t_abc',20260906)`,
				"bytes": "1000", "rows": "100", "uncompressed": "5000"},
			{"database": "netops", "table": "corr_signals", "partition": `('t_abc',20260905)`,
				"bytes": "500", "rows": "50", "uncompressed": "2500"},
			{"database": "netops", "table": "flows", "partition": `('t_xyz',20260906)`,
				"bytes": "9000", "rows": "900", "uncompressed": "9000"},
		}, nil
	}
	m := New(d)
	got := m.Probe(context.Background(), Principal{CrossTenant: true})
	abc := find(t, got, StoreClickHouse, "t_abc")
	if *abc.BytesOnDisk != 1500 {
		t.Errorf("t_abc = %d, want 1500", *abc.BytesOnDisk)
	}
	// Components are keyed by (table, period): the table is the evidence CLASS
	// and the period is the DAY, which is what tracker 204 asks for.
	byDay := map[string]Component{}
	for _, c := range abc.Components {
		if c.Name != "netops.corr_signals" {
			t.Fatalf("unexpected component %q", c.Name)
		}
		byDay[c.Period] = c
	}
	if len(byDay) != 2 {
		t.Fatalf("expected one component per day, got %+v", abc.Components)
	}
	day := byDay["20260906"]
	if day.BytesOnDisk != 1000 {
		t.Errorf("20260906 = %d, want 1000", day.BytesOnDisk)
	}
	ratio := day.CompressionRatio()
	if ratio == nil || *ratio != 5.0 {
		t.Errorf("compression ratio = %v, want 5.0 (5000/1000)", ratio)
	}
	if *find(t, got, StoreClickHouse, "t_xyz").BytesOnDisk != 9000 {
		t.Error("t_xyz total wrong")
	}
}

// Defense in depth (§3a.4): a row the SQL scope should never have returned is
// dropped again on the way out.
func TestClickHouseDropsAnotherTenantsRowEvenIfTheQueryReturnsIt(t *testing.T) {
	d := fakeDeps()
	d.ClickHouse = func(_ context.Context, _ string) ([]map[string]any, error) {
		return []map[string]any{
			{"table": "corr_signals", "partition": `('t_abc',20260906)`, "bytes": "1000"},
			{"table": "corr_signals", "partition": `('t_other',20260906)`, "bytes": "999999"},
		}, nil
	}
	got := New(d).Probe(context.Background(), Principal{Tenant: "t_abc"})
	for _, r := range got {
		if r.Scope == "t_other" {
			t.Fatalf("another tenant's scope reached a scoped caller: %+v", r)
		}
	}
	if *find(t, got, StoreClickHouse, "t_abc").BytesOnDisk != 1000 {
		t.Error("the caller's own bytes are wrong")
	}
}

// A component with no reported uncompressed size has NO ratio — not a ratio of
// one, which would read as "this data does not compress".
// Per-DAY attribution: the period comes off the store's own addressing (the
// partition value, the daily index name), never from a division of a total.
func TestPeriodExtractionIsAFactAboutTheStoreNotAGuess(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`('t_abc',20260906)`, "20260906"},
		{`('t_abc',202609)`, "202609"},
		{"t_abc", ""},               // partitioned by tenant only — no period
		{`('t_abc','eu-west')`, ""}, // a second key column that is not a date
		{`('t_abc',2026)`, ""},      // not a YYYYMM/YYYYMMDD shape
		{"", ""},
	} {
		if got := partitionPeriod(c.in); got != c.want {
			t.Errorf("partitionPeriod(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"netops-syslog-acme-2026.09.06", "2026.09.06"},
		{"netops-audit-2026.09", ""},
		{"netops-saved-objects", ""},
		{"", ""},
	} {
		if got := indexPeriod(c.in); got != c.want {
			t.Errorf("indexPeriod(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCompressionRatioIsNilWhenTheStoreDoesNotReportOne(t *testing.T) {
	if (Component{Name: "x", BytesOnDisk: 10}).CompressionRatio() != nil {
		t.Fatal("a missing uncompressed size must yield no ratio")
	}
}

// ── the platform-only stores refuse to derive a tenant share ────────────────

func TestPlatformOnlyStoresRefuseToSplitBytesPerTenant(t *testing.T) {
	d := fakeDeps()
	d.Victoria = func(context.Context, string) ([]VMSample, error) {
		return []VMSample{{Labels: map[string]string{"type": "storage/small"}, Value: 100}}, nil
	}
	d.Postgres = func(context.Context) (int64, []Component, bool, string, error) {
		return 42, nil, true, "", nil
	}
	d.Dir = func(context.Context, string) (int64, []Component, error) { return 7, nil, nil }
	got := New(d).Probe(context.Background(), Principal{Tenant: "acme"})
	for _, s := range []Store{StoreVictoria, StorePostgres, StoreFiles} {
		r := find(t, got, s, "acme")
		if r.Measured() {
			t.Errorf("%s must not report a per-tenant number: %+v", s, r)
		}
		if !strings.Contains(r.Detail, "not measured — ") {
			t.Errorf("%s: %q", s, r.Detail)
		}
	}
}

func TestVictoriaMeasuresThePlatformFromItsOwnSelfMetric(t *testing.T) {
	d := fakeDeps()
	d.Victoria = func(context.Context, string) ([]VMSample, error) {
		return []VMSample{
			{Labels: map[string]string{"type": "storage/small"}, Value: 100},
			{Labels: map[string]string{"type": "indexdb/file"}, Value: 20},
		}, nil
	}
	r := find(t, New(d).Probe(context.Background(), Principal{CrossTenant: true}), StoreVictoria, ScopePlatform)
	if !r.Measured() || *r.BytesOnDisk != 120 {
		t.Fatalf("vm total = %+v, want 120", r)
	}
}

// "The query worked but the series does not exist" is NOT zero bytes.
func TestVictoriaWithNoSeriesIsNotMeasuredRatherThanZero(t *testing.T) {
	d := fakeDeps()
	d.Victoria = func(context.Context, string) ([]VMSample, error) { return nil, nil }
	r := find(t, New(d).Probe(context.Background(), Principal{CrossTenant: true}), StoreVictoria, ScopePlatform)
	if r.Measured() {
		t.Fatalf("no series must not measure as zero: %+v", r)
	}
	if !strings.Contains(r.Detail, "NOT zero bytes") {
		t.Errorf("the reason must say so explicitly: %q", r.Detail)
	}
}

// "This installation runs the file backend" is a DEPLOYMENT FACT, not a failure.
func TestPostgresDistinguishesNoDatabaseFromAFailedQuery(t *testing.T) {
	d := fakeDeps()
	d.Postgres = func(context.Context) (int64, []Component, bool, string, error) {
		return 0, nil, false, "this installation does not use the PostgreSQL app-state backend", nil
	}
	r := find(t, New(d).Probe(context.Background(), Principal{CrossTenant: true}), StorePostgres, ScopePlatform)
	if r.Measured() || !strings.Contains(r.Detail, "does not use the PostgreSQL") {
		t.Fatalf("deployment fact not reported: %+v", r)
	}

	d.Postgres = func(context.Context) (int64, []Component, bool, string, error) {
		return 0, nil, false, "", errors.New("connection refused")
	}
	r = find(t, New(d).Probe(context.Background(), Principal{CrossTenant: true}), StorePostgres, ScopePlatform)
	if !strings.Contains(r.Detail, "refused the size query") {
		t.Fatalf("a query failure must read as one: %+v", r)
	}
}

// A cancelled probe reads differently from a refused one (§10: no silent
// failures, and no failures that all look alike either).
func TestProbeReasonTellsATimeoutApartFromARefusal(t *testing.T) {
	if !strings.Contains(probeReason("x", context.DeadlineExceeded), "inside the probe's deadline") {
		t.Error("a deadline must read as a deadline")
	}
	if !strings.Contains(probeReason("x", errors.New("boom")), "refused the size query: boom") {
		t.Error("a refusal must carry the store's own words")
	}
}

// ── the file walk ────────────────────────────────────────────────────────────

func TestWalkDirMeasuresApparentSizePerTopLevelChild(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "deep"), 0o750); err != nil {
		t.Fatal(err)
	}
	write := func(p string, n int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, p), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join("a", "deep", "x.bin"), 100)
	write(filepath.Join("a", "y.bin"), 50)
	write("top.json", 7)
	total, comps, err := WalkDir(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if total != 157 {
		t.Errorf("total = %d, want 157", total)
	}
	got := map[string]int64{}
	for _, c := range comps {
		got[c.Name] = c.BytesOnDisk
	}
	if got["a/"] != 150 || got["top.json"] != 7 {
		t.Errorf("breakdown = %v, want a/=150 top.json=7", got)
	}
}

func TestWalkDirOnAMissingRootIsAnErrorNotAZero(t *testing.T) {
	if _, _, err := WalkDir(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("a missing data root must be an error, so the reading renders as not-measured")
	}
}

// ── the /metrics contract ────────────────────────────────────────────────────

func TestMetricsEmitNoByteSeriesForAnUnmeasuredStoreButAlwaysTheMeasuredGauge(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = osRows([]catIndexRow{{Index: "netops-syslog-acme-2026.09.06", Store: "1000", Docs: "1"}})
	m := New(d)
	m.Sample(context.Background())
	var sb strings.Builder
	m.Metrics().Write(&sb)
	out := sb.String()
	if !strings.Contains(out, `netops_storage_bytes_measured{store="opensearch",tenant="acme"} 1000`) {
		t.Errorf("missing the measured series:\n%s", out)
	}
	if strings.Contains(out, `netops_storage_bytes_measured{store="kafka"`) {
		t.Error("an unmeasured store must emit NO bytes series")
	}
	for _, s := range Stores {
		want := `netops_storage_measured{store="` + string(s) + `"}`
		if !strings.Contains(out, want) {
			t.Errorf("every store must emit its measured gauge on every scrape; missing %s", want)
		}
	}
	if !strings.Contains(out, `netops_storage_measured{store="kafka"} 0`) {
		t.Error("kafka must report measured=0")
	}
	if !strings.Contains(out, "netops_storage_measurement_passes_total 1") {
		t.Error("the pass counter must advance")
	}
}

// "Never sampled" is -1, not 0: a zero would render as "measured this instant".
func TestStalenessSentinelForANeverSampledMeter(t *testing.T) {
	var sb strings.Builder
	New(fakeDeps()).Metrics().Write(&sb)
	if !strings.Contains(sb.String(), "netops_storage_measurement_age_seconds -1") {
		t.Errorf("never-sampled must be -1:\n%s", sb.String())
	}
}

// ── the HTTP surface ─────────────────────────────────────────────────────────

func gate(p Principal) Gate {
	return func(http.ResponseWriter, *http.Request) (Principal, bool) { return p, true }
}

func getReport(t *testing.T, m *Meter) Report {
	t.Helper()
	w := httptest.NewRecorder()
	m.HandleMeasured(w, httptest.NewRequest(http.MethodGet, RouteMeasured, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var rep Report
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestReportTotalIsALowerBoundAndSaysSoWhileAnythingIsUnmeasured(t *testing.T) {
	d := fakeDeps()
	d.OpenSearch = osRows([]catIndexRow{{Index: "netops-syslog-acme-2026.09.06", Store: "1000", Docs: "1"}})
	d.Gate = gate(Principal{Subject: "root", CrossTenant: true})
	rep := getReport(t, New(d))
	if rep.TotalMeasuredBytes != 1000 {
		t.Errorf("total = %d, want 1000", rep.TotalMeasuredBytes)
	}
	if len(rep.UnmeasuredStores) == 0 {
		t.Fatal("kafka at minimum is unmeasured and must be listed")
	}
	if !strings.HasPrefix(rep.MeasurementNote, "PARTIAL.") {
		t.Errorf("the note must warn that the total is a lower bound: %q", rep.MeasurementNote)
	}
}

// A principal bound to no tenant and holding no cross grant reads NOTHING.
// Default-closed, §3a rule 1.
func TestAPrincipalWithNoTenantAndNoCrossGrantReadsNothing(t *testing.T) {
	d := fakeDeps()
	probed := false
	d.OpenSearch = func(context.Context, string, any) error { probed = true; return nil }
	d.Gate = gate(Principal{Subject: "nobody"})
	rep := getReport(t, New(d))
	if len(rep.Readings) != 0 || rep.TotalMeasuredBytes != 0 {
		t.Fatalf("an unscoped principal must read nothing: %+v", rep)
	}
	if probed {
		t.Fatal("no store may be probed for a principal with no scope")
	}
}

func TestHandlerRefusesANonGETAndAnUnwiredMeter(t *testing.T) {
	d := fakeDeps()
	d.Gate = gate(Principal{CrossTenant: true})
	w := httptest.NewRecorder()
	New(d).HandleMeasured(w, httptest.NewRequest(http.MethodPost, RouteMeasured, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST → %d, want 405", w.Code)
	}
	w = httptest.NewRecorder()
	New(fakeDeps()).HandleMeasured(w, httptest.NewRequest(http.MethodGet, RouteMeasured, nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("unwired gate → %d, want 503", w.Code)
	}
}

// A refused gate must not be followed by a body.
func TestARefusedGateEndsTheRequest(t *testing.T) {
	d := fakeDeps()
	d.Gate = func(w http.ResponseWriter, _ *http.Request) (Principal, bool) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return Principal{}, false
	}
	w := httptest.NewRecorder()
	New(d).HandleMeasured(w, httptest.NewRequest(http.MethodGet, RouteMeasured, nil))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "measurement_note") {
		t.Fatalf("a refused gate must end the request: %d %s", w.Code, w.Body.String())
	}
}

// ── nil-safety, the way every other module here behaves ──────────────────────

func TestNilMeterIsSafeEverywhere(t *testing.T) {
	var m *Meter
	if got := m.Probe(context.Background(), Principal{}); got != nil {
		t.Error("nil Probe")
	}
	m.Sample(context.Background())
	m.RunSampler(context.Background())
	if _, at, n := m.Snapshot(); !at.IsZero() || n != 0 {
		t.Error("nil Snapshot")
	}
	var sb strings.Builder
	m.Metrics().Write(&sb)
}
