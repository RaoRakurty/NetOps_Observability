package storagemeter

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ── OpenSearch ───────────────────────────────────────────────────────────────

// catIndexRow is one `_cat/indices?format=json` row. Every field arrives as a
// STRING, including the byte counts — that is the API, not a mistake here.
type catIndexRow struct {
	Index string `json:"index"`
	Store string `json:"store.size"`
	Docs  string `json:"docs.count"`
}

// nodesStoreStats is the `_nodes/stats/indices/store` reply, reduced to the one
// number it is read for: total on-disk index bytes per node.
type nodesStoreStats struct {
	Nodes map[string]struct {
		Name    string `json:"name"`
		Indices struct {
			Store struct {
				SizeInBytes int64 `json:"size_in_bytes"`
			} `json:"store"`
		} `json:"indices"`
	} `json:"nodes"`
}

// probeOpenSearch measures index bytes, per tenant where the index name says so.
//
// PRIMARY: `_cat/indices?bytes=b` over the pattern the caller may enumerate.
// The index name carries the tenant segment, so the total attributes exactly and
// the shared `untagged` indices are reported under their own scope rather than
// being folded into anybody's number.
//
// FALLBACK: an installation whose api service account lacks
// `indices:monitor/stats` gets a 403 on `_cat/indices` (SEC-008's role model did
// not grant it until this change). Rather than reporting nothing, the probe then
// asks for the node-level `indices.store.size_in_bytes`, which the account CAN
// read, and says plainly that the number is a PLATFORM TOTAL with no per-tenant
// attribution — and why. A tenant caller gets no fallback at all: a platform
// total is not that tenant's bytes and must not be shown as if it were.
func (m *Meter) probeOpenSearch(ctx context.Context, p Principal) []Reading {
	at := m.deps.now()
	if m.deps.OpenSearch == nil || m.deps.CatPattern == nil || m.deps.IndexTenant == nil {
		return []Reading{notMeasured(StoreOpenSearch, scopeOf(p),
			"this installation wires no search-cluster client", at)}
	}
	pattern := m.deps.CatPattern(p.Tenant, p.CrossTenant)
	var rows []catIndexRow
	err := m.deps.OpenSearch(ctx,
		"/_cat/indices/"+pattern+"?bytes=b&h=index,store.size,docs.count&format=json&expand_wildcards=all", &rows)
	if err == nil {
		return m.openSearchReadings(rows, p, at, pattern)
	}
	// The primary path failed. On a scoped caller there is nothing honest to
	// fall back to.
	reason := probeReason("the search cluster", err)
	if !p.CrossTenant {
		return []Reading{notMeasured(StoreOpenSearch, scopeOf(p),
			reason+" — per-tenant index bytes need `indices:monitor/stats` on the api's"+
				" service account (deployment/docker/opensearch/security/roles.yml);"+
				" the security config must be re-applied for a role edit to take effect", at)}
	}
	var stats nodesStoreStats
	if ferr := m.deps.OpenSearch(ctx, "/_nodes/stats/indices/store", &stats); ferr != nil {
		return []Reading{notMeasured(StoreOpenSearch, ScopePlatform,
			reason+"; the node-level fallback also failed: "+probeReason("the search cluster", ferr), at)}
	}
	var total int64
	comps := make([]Component, 0, len(stats.Nodes))
	for _, n := range stats.Nodes {
		total += n.Indices.Store.SizeInBytes
		b := n.Indices.Store.SizeInBytes
		comps = append(comps, Component{Name: "node " + n.Name, BytesOnDisk: b})
	}
	if len(stats.Nodes) == 0 {
		return []Reading{notMeasured(StoreOpenSearch, ScopePlatform,
			reason+"; the node-level fallback returned no nodes", at)}
	}
	return []Reading{measured(StoreOpenSearch, ScopePlatform, total,
		"GET /_nodes/stats/indices/store → indices.store.size_in_bytes, summed over nodes",
		"PLATFORM TOTAL ONLY, with NO per-tenant attribution: "+reason+
			" — grant `indices:monitor/stats` on the api's service account and re-apply the"+
			" security config to get the per-index breakdown", at, comps)}
}

// openSearchReadings groups `_cat/indices` rows by the tenant segment in the
// index name. A row whose name this process cannot parse is NOT silently
// dropped and NOT attributed to a guess: it lands under ScopePlatform with its
// own component line, so the platform total stays exact.
func (m *Meter) openSearchReadings(rows []catIndexRow, p Principal, at time.Time, pattern string) []Reading {
	byScope := map[string][]Component{}
	// Rows the cluster listed but reported no size for (a CLOSED or relocating
	// index). They are excluded from the total rather than counted as zero —
	// and the count is carried into the detail, because a total that is
	// silently low is the same failure as a derived number labelled measured.
	sizeless := 0
	for _, r := range rows {
		idx := strings.TrimSpace(r.Index)
		if idx == "" {
			continue
		}
		bytes, ok := parseInt64(r.Store)
		if !ok {
			sizeless++
			continue
		}
		scope := ScopePlatform
		if seg, found := m.deps.IndexTenant(idx); found {
			scope = seg
		}
		if !p.CrossTenant && scope != p.Tenant && scope != ScopeUntagged {
			// Defense in depth under the index pattern (§3a.4). The pattern this
			// caller was given cannot name another tenant's indices — but if the
			// cluster ever answers with one anyway, its bytes stop HERE. The
			// untagged lane is the one exception, and it is in the scoped
			// caller's pattern by the same rule log search uses.
			continue
		}
		comp := Component{Name: idx, BytesOnDisk: bytes, Period: indexPeriod(idx)}
		if docs, dok := parseInt64(r.Docs); dok {
			d := docs
			comp.Rows = &d
		}
		byScope[scope] = append(byScope[scope], comp)
	}
	if len(byScope) == 0 {
		return []Reading{measured(StoreOpenSearch, scopeOf(p), 0,
			"GET /_cat/indices/"+pattern+"?bytes=b → store.size",
			"measured: the pattern this caller may enumerate matched no index, so zero bytes is the MEASUREMENT, not a missing value", at, nil)}
	}
	out := make([]Reading, 0, len(byScope))
	for scope, comps := range byScope {
		var total int64
		for _, c := range comps {
			total += c.BytesOnDisk
		}
		detail := "measured from the search cluster's own per-index store size; the index name carries the tenant segment, so these bytes attribute exactly"
		if scope == ScopeUntagged {
			detail = "measured: the SHARED untagged indices, which hold documents that carried no tenant claim. Deliberately NOT folded into any tenant's total — splitting them would be a derivation, not a measurement"
		} else if scope == ScopePlatform {
			detail = "measured: indices whose name carries no tenant segment (platform-owned lanes)"
		}
		if sizeless > 0 {
			detail += ". " + itoa(sizeless) + " index(es) in this caller's pattern reported NO size" +
				" (closed or relocating) and are excluded from the total rather than counted as zero"
		}
		out = append(out, measured(StoreOpenSearch, scope, total,
			"GET /_cat/indices/"+pattern+"?bytes=b → store.size", detail, at, comps))
	}
	sortReadings(out)
	return out
}

// ── ClickHouse ───────────────────────────────────────────────────────────────

// tenantIDRe is what this package is willing to interpolate into SQL. Zero
// trust (§3): a tenant id that does not match is REFUSED rather than escaped —
// there is no legitimate tenant id outside this alphabet, and "escape it
// carefully" is how injection bugs are written.
var tenantIDRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// partitionTenant extracts the owning tenant from a `system.parts.partition`
// value. Every netops table is partitioned by tenant_id first, so the value is
// either the bare id (single-column key, rendered unquoted) or a tuple literal
// `('t_abc',202609)`. Returns ok=false for anything else, which the caller
// reports under ScopePlatform rather than guessing at.
func partitionTenant(partition string) (string, bool) {
	s := strings.TrimSpace(partition)
	if s == "" {
		return "", false
	}
	if !strings.HasPrefix(s, "(") {
		return s, true
	}
	rest := s[1:]
	if !strings.HasPrefix(rest, "'") {
		return "", false
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '\'')
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// partitionPeriod extracts the DATE element of a partition value, when the
// partition key has one. Every netops table is partitioned by (tenant_id,
// toYYYYMM…(ts)) or by tenant_id alone; the second tuple element is therefore
// the period, and a bare tenant partition has none. Returns "" rather than
// guessing — a missing period is a fact about the table's partition key.
func partitionPeriod(partition string) string {
	s := strings.TrimSpace(partition)
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return ""
	}
	i := strings.LastIndexByte(s, ',')
	if i < 0 {
		return ""
	}
	v := strings.Trim(strings.TrimSpace(s[i+1:len(s)-1]), "'")
	// Only YYYYMM or YYYYMMDD are a period. Anything else is some other second
	// key column and must not be labelled a date.
	if len(v) != 6 && len(v) != 8 {
		return ""
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return v
}

// indexPeriod extracts the %Y.%m.%d suffix vector-router writes onto every
// daily index (deployment/docker/vector-router/vector.yaml). Returns "" for an
// index that is not daily — again a fact, not a gap.
func indexPeriod(index string) string {
	i := strings.LastIndexByte(index, '-')
	if i < 0 {
		return ""
	}
	v := index[i+1:]
	if len(v) != 10 || v[4] != '.' || v[7] != '.' {
		return ""
	}
	for k, r := range v {
		if k == 4 || k == 7 {
			continue
		}
		if r < '0' || r > '9' {
			return ""
		}
	}
	return v
}

// chPartsSQL is the size query, scoped in the SQL itself for a tenant caller.
// `system.parts` is cluster metadata with no tenant column, so the ClickHouse
// row policies cannot reach it — the WHERE clause below IS the storage-layer
// scope for this read, which is why it is built here and pinned by a test.
func chPartsSQL(database, tenant string, cross bool) string {
	b := &strings.Builder{}
	b.WriteString("SELECT database, table, partition, ")
	b.WriteString("sum(bytes_on_disk) AS bytes, sum(rows) AS rows, ")
	b.WriteString("sum(data_uncompressed_bytes) AS uncompressed ")
	b.WriteString("FROM system.parts WHERE active AND database = '")
	b.WriteString(database)
	b.WriteString("'")
	if !cross {
		// Both partition-key shapes, named explicitly: the bare id and the
		// leading element of a tuple literal.
		b.WriteString(" AND (partition = '")
		b.WriteString(tenant)
		b.WriteString("' OR startsWith(partition, '(\\'")
		b.WriteString(tenant)
		b.WriteString("\\''))")
	}
	b.WriteString(" GROUP BY database, table, partition FORMAT JSON")
	return b.String()
}

// probeClickHouse measures bytes_on_disk per tenant, per table.
func (m *Meter) probeClickHouse(ctx context.Context, p Principal) []Reading {
	at := m.deps.now()
	if m.deps.ClickHouse == nil || strings.TrimSpace(m.deps.Database) == "" {
		return []Reading{notMeasured(StoreClickHouse, scopeOf(p),
			"this installation wires no ClickHouse client", at)}
	}
	if !p.CrossTenant && !tenantIDRe.MatchString(p.Tenant) {
		return []Reading{notMeasured(StoreClickHouse, scopeOf(p),
			"the caller's tenant id is not a shape this probe will put in a SQL literal, so no scoped query was run", at)}
	}
	sql := chPartsSQL(m.deps.Database, p.Tenant, p.CrossTenant)
	rows, err := m.deps.ClickHouse(ctx, sql)
	if err != nil {
		return []Reading{notMeasured(StoreClickHouse, scopeOf(p),
			probeReason("ClickHouse", err), at)}
	}
	type acc struct {
		bytes int64
		comps map[string]*Component
	}
	byScope := map[string]*acc{}
	for _, r := range rows {
		part, _ := chStr(r["partition"])
		table, _ := chStr(r["table"])
		bytes, ok := chInt(r["bytes"])
		if !ok {
			continue
		}
		scope := ScopePlatform
		if t, found := partitionTenant(part); found {
			scope = t
		}
		if !p.CrossTenant && scope != p.Tenant {
			// Defense in depth under the WHERE clause (§3a.4): a row the SQL
			// scope should never have returned is dropped here too.
			continue
		}
		a := byScope[scope]
		if a == nil {
			a = &acc{comps: map[string]*Component{}}
			byScope[scope] = a
		}
		a.bytes += bytes
		// Keyed by (table, period), not by table alone: the table names the
		// evidence CLASS and the period names the DAY (or month, for the
		// monthly-partitioned archive), which together are what tracker 204
		// asks for. Both come off the partition value the server reported.
		period := partitionPeriod(part)
		key := table + "\x00" + period
		c := a.comps[key]
		if c == nil {
			c = &Component{Name: m.deps.Database + "." + table, Period: period}
			a.comps[key] = c
		}
		c.BytesOnDisk += bytes
		if n, ok := chInt(r["rows"]); ok {
			cur := int64(0)
			if c.Rows != nil {
				cur = *c.Rows
			}
			cur += n
			c.Rows = &cur
		}
		if n, ok := chInt(r["uncompressed"]); ok {
			cur := int64(0)
			if c.UncompressedBytes != nil {
				cur = *c.UncompressedBytes
			}
			cur += n
			c.UncompressedBytes = &cur
		}
	}
	if len(byScope) == 0 {
		return []Reading{measured(StoreClickHouse, scopeOf(p), 0,
			"SELECT sum(bytes_on_disk) FROM system.parts WHERE active",
			"measured: the scope this caller may read holds no active part, so zero bytes is the MEASUREMENT, not a missing value", at, nil)}
	}
	out := make([]Reading, 0, len(byScope))
	for scope, a := range byScope {
		comps := make([]Component, 0, len(a.comps))
		for _, c := range a.comps {
			comps = append(comps, *c)
		}
		out = append(out, measured(StoreClickHouse, scope, a.bytes,
			"SELECT sum(bytes_on_disk), sum(rows), sum(data_uncompressed_bytes) FROM system.parts WHERE active GROUP BY table, partition",
			"measured from ClickHouse's own part metadata; every netops table is partitioned by tenant_id first, so the partition names the owner and these bytes attribute exactly. The compression ratio beside each table is uncompressed/on-disk as the server reports it — not the assumed constant the sizing model uses",
			at, comps))
	}
	sortReadings(out)
	return out
}

// ── VictoriaMetrics ──────────────────────────────────────────────────────────

// probeVictoria reads the engine's OWN storage self-metric. Platform-only: the
// series carries no tenant label and there is no per-tenant data directory, so
// a tenant's share of it cannot be measured — only calculated, which is the
// thing this whole package exists to stop presenting as a measurement.
func (m *Meter) probeVictoria(ctx context.Context, p Principal) []Reading {
	at := m.deps.now()
	if !p.CrossTenant {
		return []Reading{notMeasured(StoreVictoria, scopeOf(p),
			"VictoriaMetrics stores every tenant's samples in one data directory and its size metric carries no tenant label, so a single tenant's bytes cannot be MEASURED here; any per-tenant figure would be a series-count derivation", at)}
	}
	if m.deps.Victoria == nil {
		return []Reading{notMeasured(StoreVictoria, ScopePlatform,
			"this installation wires no VictoriaMetrics client", at)}
	}
	samples, err := m.deps.Victoria(ctx, "vm_data_size_bytes")
	if err != nil {
		return []Reading{notMeasured(StoreVictoria, ScopePlatform,
			probeReason("VictoriaMetrics", err), at)}
	}
	if len(samples) == 0 {
		return []Reading{notMeasured(StoreVictoria, ScopePlatform,
			"VictoriaMetrics answered the query but published no vm_data_size_bytes series, so there is nothing to read — this is NOT zero bytes", at)}
	}
	var total int64
	comps := make([]Component, 0, len(samples))
	for _, s := range samples {
		b := int64(s.Value)
		total += b
		name := s.Labels["type"]
		if name == "" {
			name = "storage"
		}
		comps = append(comps, Component{Name: name, BytesOnDisk: b})
	}
	return []Reading{measured(StoreVictoria, ScopePlatform, total,
		"PromQL vm_data_size_bytes (VictoriaMetrics' own storage self-metric), summed over part types",
		"measured by the engine itself and read back over the metrics API; the breakdown is its storage/indexdb part types", at, comps)}
}

// ── PostgreSQL ───────────────────────────────────────────────────────────────

func (m *Meter) probePostgres(ctx context.Context, p Principal) []Reading {
	at := m.deps.now()
	if !p.CrossTenant {
		return []Reading{notMeasured(StorePostgres, scopeOf(p),
			"the application database holds every tenant's rows in shared, FORCE-RLS tables; PostgreSQL sizes RELATIONS, not row subsets, so a single tenant's bytes cannot be measured here", at)}
	}
	if m.deps.Postgres == nil {
		return []Reading{notMeasured(StorePostgres, ScopePlatform,
			"this installation wires no PostgreSQL pool", at)}
	}
	total, rels, ok, reason, err := m.deps.Postgres(ctx)
	if err != nil {
		return []Reading{notMeasured(StorePostgres, ScopePlatform, probeReason("PostgreSQL", err), at)}
	}
	if !ok {
		return []Reading{notMeasured(StorePostgres, ScopePlatform, reason, at)}
	}
	return []Reading{measured(StorePostgres, ScopePlatform, total,
		"SELECT pg_database_size(current_database()) and pg_total_relation_size() per relation",
		"measured by PostgreSQL itself; pg_total_relation_size includes each table's indexes and TOAST, so the parts sum to the whole", at, rels)}
}

// ── the api's own file store ─────────────────────────────────────────────────

func (m *Meter) probeFiles(ctx context.Context, p Principal) []Reading {
	at := m.deps.now()
	if !p.CrossTenant {
		return []Reading{notMeasured(StoreFiles, scopeOf(p),
			"the api's file store holds platform state (device registry, audit, sessions), not per-tenant data directories, so there is no per-tenant size to measure", at)}
	}
	if m.deps.Dir == nil || strings.TrimSpace(m.deps.DataRoot) == "" {
		return []Reading{notMeasured(StoreFiles, ScopePlatform,
			"this installation wires no data directory for the api's file store", at)}
	}
	total, children, err := m.deps.Dir(ctx, m.deps.DataRoot)
	if err != nil {
		return []Reading{notMeasured(StoreFiles, ScopePlatform,
			probeReason("the api's data directory", err), at)}
	}
	return []Reading{measured(StoreFiles, ScopePlatform, total,
		"recursive walk of "+m.deps.DataRoot+" as the api container sees it (os.Lstat size per regular file)",
		"measured by this process with a syscall — the one store it does not have to ask a server about. Apparent size, so a sparse or hole-punched file counts as its logical length", at, children)}
}

// ── Kafka ────────────────────────────────────────────────────────────────────

// kafkaNotMeasuredReason is a CONSTANT, deliberately. Kafka's log-directory size
// is the one store on this platform that genuinely cannot be measured from the
// api today, and the reason is structural rather than transient:
//
//   - the Go backend ships NO Kafka client (CLAUDE.md §6 allowlist — emit goes
//     over the Vector HTTP bus bridge), so `DescribeLogDirs` is not reachable
//     without adding a wire-protocol implementation;
//   - kafka-exporter publishes consumer lag and partition offsets, not log-dir
//     bytes (checked against its live /metrics, 2026-09-06);
//   - the api container does not mount data/kafka, so it cannot walk it either.
//
// The bound that DOES exist is the configured one, and this sentence names it
// rather than pretending the number is unknowable in every sense.
const kafkaNotMeasuredReason = "no size source is reachable from the api: the Go backend ships no Kafka client (CLAUDE.md §6), " +
	"kafka-exporter publishes consumer lag and offsets but no log-directory bytes, and the api container does not mount the broker's data volume. " +
	"The only figure available is the CONFIGURED bound (KAFKA_LOG_RETENTION_BYTES), which is a ceiling, not a measurement"

func (m *Meter) probeKafka(_ context.Context, p Principal) []Reading {
	return []Reading{notMeasured(StoreKafka, scopeOf(p), kafkaNotMeasuredReason, m.deps.now())}
}

// ── decoding helpers ─────────────────────────────────────────────────────────

// parseInt64 parses a `_cat` string field. Explicitly NOT fmt.Sscanf: Sscanf
// stops at the first non-digit and reports success, so "12x" would parse as 12.
func parseInt64(s string) (int64, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// chInt reads a ClickHouse JSON value that may be a quoted 64-bit integer
// (which is how ClickHouse renders UInt64/Int64 in FORMAT JSON) or a number.
func chInt(v any) (int64, bool) {
	switch t := v.(type) {
	case string:
		return parseInt64(t)
	case float64:
		return int64(t), true
	case int64:
		return t, true
	default:
		return 0, false
	}
}

func chStr(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// scopeOf is the scope label a reading gets for this principal.
func scopeOf(p Principal) string {
	if p.CrossTenant {
		return ScopePlatform
	}
	return p.Tenant
}
