// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package routinerollup keeps the per-minute roll-ups of routine
// management-session syslog (tracker 410, owner decision 2026-11-19).
//
// The router writes routine originals to netops-syslogroutine-<tenant>-<date>,
// which expire after a short window (>= 72 h per record). Before they go, this
// job folds them into netops-syslogrollup-<tenant>-<date>: one document per
// (tenant, device, source, user, minute) carrying first_seen / last_seen /
// occurrence_count and the identity, kept for the full telemetry window — so
// D2 ("no record dropped silently; first/last/count + identity survive") and D7
// (usernames for attribution) hold after the originals are gone.
//
// Design, and why:
//   - It reads the STORED originals (an OpenSearch composite aggregation per
//     closed minute), not the Kafka stream. Exact, stateless and idempotent:
//     each document's _id is the sha256 of its key, so re-rolling a minute
//     upserts the same documents with the full count, and several api replicas
//     can run it at once. It repairs any outage shorter than the originals'
//     life on its own.
//   - Tenancy comes from the INDEX NAME (the roll-up index is the original's
//     with the family base swapped), never from a document field; a bucket
//     whose tenant_id disagrees with its index is skipped and counted, never
//     written into the wrong tenant's index (§3a).
//   - Every tick re-rolls a short lookback of closed minutes (late arrivals);
//     an hourly reconcile recounts each closed hour of the horizon and
//     re-rolls only hours whose roll-up sum differs from the originals' count.
//   - Every list is bounded (§9): pages per tick, page size, the reconcile
//     horizon; a cut is counted, never silent (§10).
//
// Nothing here knows about principals or HTTP: the api root supplies a Store
// at the platform scope (the job is platform plumbing; every document keeps its
// own tenant) and renders Metrics on /metrics.
package routinerollup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// The two index families (mirrors internal/oslog; duplicated so this package
// imports nothing from the api's log projection).
const (
	OriginalsBase = "netops-syslogroutine"
	RollupBase    = "netops-syslogrollup"
	// SchemaVersion stamps every roll-up document (rollup_v). "2" (tracker 410
	// (d)): audit_source is keyed WITHOUT its ephemeral client port. Readers and
	// the reconcile sum count only the current version, so the v1 documents
	// (one per session, not per source) are ignored and their hours re-rolled.
	// logroutine.RollupSchemaVersion must equal this (pinned by a test).
	SchemaVersion = "2"
)

// Store is the OpenSearch surface the job needs.
type Store interface {
	// Indices lists the names of the indices matching pattern.
	Indices(ctx context.Context, pattern string) ([]string, error)
	// Search runs one _search on index and returns the raw response.
	Search(ctx context.Context, index string, body map[string]any) ([]byte, error)
	// Bulk sends one NDJSON _bulk body and returns the raw response.
	Bulk(ctx context.Context, ndjson []byte) ([]byte, error)
}

// Config bounds the job. Zero values take the defaults below.
type Config struct {
	Lookback         time.Duration // catch-up reach of the first tick after a start
	Settle           time.Duration // a minute is rolled once it closed this long ago
	ReconcileEvery   time.Duration // how often closed hours are recounted
	ReconcileHorizon time.Duration // how far back the recount reaches (< the originals' life)
	PageSize         int           // composite buckets per page
	MaxPages         int           // pages per tick across all indices
}

func (c Config) withDefaults() Config {
	if c.Lookback <= 0 {
		c.Lookback = 15 * time.Minute
	}
	if c.Settle <= 0 {
		c.Settle = 2 * time.Minute
	}
	if c.ReconcileEvery <= 0 {
		c.ReconcileEvery = time.Hour
	}
	if c.ReconcileHorizon <= 0 {
		// 48 h: well inside the >= 72 h the originals live, so an hour is
		// never recounted after its originals began to expire.
		c.ReconcileHorizon = 48 * time.Hour
	}
	if c.PageSize <= 0 || c.PageSize > 2000 {
		c.PageSize = 500
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 400
	}
	return c
}

// Job is one roll-up worker.
type Job struct {
	Store   Store
	Config  Config
	Now     func() time.Time
	Metrics *Metrics

	mu            sync.Mutex
	lastReconcile time.Time
	pagesLeft     int
	// rolledTo is the end of the last window every index was rolled through.
	// Each minute is rolled ONCE (tracker 410 (e): re-rolling a 15-minute
	// lookback every tick rewrote each roll-up ~7 times, so the index held
	// ~6 deleted documents per live one). A record that lands after its minute
	// was rolled is the hourly reconcile's to fix.
	rolledTo time.Time
}

// errPageCap ends a tick early when its page budget is spent: the rest is
// rolled on the next tick (counted as a deferral, never dropped).
var errPageCap = errors.New("routinerollup: page budget spent for this tick")

// keyFields are the composite sources, in key order. Every one is a mapped
// keyword on the originals (the netops-syslog template) and on the roll-ups.
var keyFields = []string{"tenant_id", "device_id", "host", "hostname", "source_ip", "audit_source", "audit_user"}

// Bucket is one rolled-up (tenant, device, source, user, minute).
type Bucket struct {
	Key       map[string]string
	Minute    time.Time
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// ID is the document id: sha256 over the key fields and the minute, so the
// same bucket always lands on the same document.
func (b Bucket) ID() string {
	h := sha256.New()
	for _, f := range keyFields {
		h.Write([]byte(f))
		h.Write([]byte{0x1f})
		h.Write([]byte(b.Key[f]))
		h.Write([]byte{0x1e})
	}
	fmt.Fprintf(h, "%d", b.Minute.UTC().Unix())
	return hex.EncodeToString(h.Sum(nil))
}

// Doc is the roll-up document body.
func (b Bucket) Doc() map[string]any {
	ms := b.Minute.UTC().UnixMilli()
	d := map[string]any{
		"ts": ms, "timestamp": b.Minute.UTC().Format(time.RFC3339), "minute": ms,
		"first_seen": b.FirstSeen.UTC().UnixMilli(), "last_seen": b.LastSeen.UTC().UnixMilli(),
		"occurrence_count": b.Count, "event_category": "management_audit",
		"signal": "syslog_rollup", "rollup_v": SchemaVersion,
	}
	for _, f := range keyFields {
		if v := b.Key[f]; v != "" {
			d[f] = v
		}
	}
	return d
}

// RollupIndexFor is the roll-up index that holds an originals index's minutes:
// the same tenant segment and date, the family base swapped. ok=false for a
// name that is not an originals index.
func RollupIndexFor(originals string) (string, bool) {
	rest, ok := strings.CutPrefix(originals, OriginalsBase+"-")
	if !ok || rest == "" {
		return "", false
	}
	return RollupBase + "-" + rest, true
}

// Segment is the tenant segment of an originals or roll-up index name
// (<base>-<segment>-<YYYY.MM.DD>); the segment may itself contain "-".
func Segment(index string) (string, bool) {
	for _, base := range []string{OriginalsBase, RollupBase} {
		rest, ok := strings.CutPrefix(index, base+"-")
		if !ok {
			continue
		}
		i := strings.LastIndex(rest, "-")
		if i <= 0 || i == len(rest)-1 {
			return "", false
		}
		return rest[:i], true
	}
	return "", false
}

// indexDay is the UTC day an index name's date suffix names.
func indexDay(index string) (time.Time, bool) {
	i := strings.LastIndex(index, "-")
	if i < 0 {
		return time.Time{}, false
	}
	d, err := time.Parse("2006.01.02", index[i+1:])
	if err != nil {
		return time.Time{}, false
	}
	return d.UTC(), true
}

// overlaps reports whether an index's day intersects [from, to).
func overlaps(index string, from, to time.Time) bool {
	day, ok := indexDay(index)
	if !ok {
		return false
	}
	return day.Before(to) && day.Add(24*time.Hour).After(from)
}

// segFor is the index segment a document's tenant_id must map to — the router's
// derivation (lower-case, illegal characters to "-", "" → untagged). It MUST
// match oslog.IndexTenantSeg; TestSegForMatchesTheReadDerivation pins it.
func segFor(tenant string) string {
	seg := strings.ToLower(strings.TrimSpace(tenant))
	if seg == "" {
		return "untagged"
	}
	var b strings.Builder
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// Tick rolls the lookback window of closed minutes and, when due, reconciles
// the horizon. A tick that ran out of page budget returns nil after counting
// the deferral; a store failure returns its error.
func (j *Job) Tick(ctx context.Context) error {
	cfg := j.Config.withDefaults()
	now := j.now()
	closed := now.UTC().Truncate(time.Minute) // closed minutes only
	to := closed.Add(-cfg.Settle)             // ...that have had time to arrive
	from := to.Add(-cfg.Lookback)
	j.mu.Lock()
	if !j.rolledTo.IsZero() && j.rolledTo.After(from) {
		from = j.rolledTo
	}
	j.mu.Unlock()
	indices, err := j.Store.Indices(ctx, OriginalsBase+"-*")
	if err != nil {
		return fmt.Errorf("list routine indices: %w", err)
	}
	j.mu.Lock()
	j.pagesLeft = cfg.MaxPages
	j.mu.Unlock()
	for _, idx := range indices {
		if !from.Before(to) {
			break // nothing newly settled since the last tick
		}
		if !overlaps(idx, from, to) {
			continue
		}
		if err := j.rollWindow(ctx, idx, from, to); err != nil {
			if errors.Is(err, errPageCap) {
				j.Metrics.deferral()
				return nil // rolledTo not advanced: the window is rolled again
			}
			return err
		}
	}
	j.mu.Lock()
	if to.After(j.rolledTo) {
		j.rolledTo = to
	}
	j.mu.Unlock()
	j.mu.Lock()
	due := j.lastReconcile.IsZero() || now.Sub(j.lastReconcile) >= cfg.ReconcileEvery
	j.mu.Unlock()
	if due {
		if err := j.reconcile(ctx, indices, to, cfg); err != nil {
			if errors.Is(err, errPageCap) {
				j.Metrics.deferral()
				return nil
			}
			return err
		}
		j.mu.Lock()
		j.lastReconcile = now
		j.mu.Unlock()
	}
	j.Metrics.success(now, to)
	return nil
}

func (j *Job) now() time.Time {
	if j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// reconcile recounts each closed hour of the horizon and re-rolls the hours
// whose roll-up sum differs from the originals' count.
func (j *Job) reconcile(ctx context.Context, indices []string, to time.Time, cfg Config) error {
	end := to.Truncate(time.Hour) // the current hour is still being rolled by ticks
	start := end.Add(-cfg.ReconcileHorizon)
	mismatched := 0
	for _, idx := range indices {
		rollup, ok := RollupIndexFor(idx)
		if !ok {
			continue
		}
		for h := start; h.Before(end); h = h.Add(time.Hour) {
			if !overlaps(idx, h, h.Add(time.Hour)) {
				continue
			}
			orig, err := j.count(ctx, idx, h, h.Add(time.Hour))
			if err != nil {
				return err
			}
			sum, err := j.rolledSum(ctx, rollup, h, h.Add(time.Hour))
			if err != nil {
				return err
			}
			if orig == sum {
				continue
			}
			mismatched++
			if err := j.rollWindow(ctx, idx, h, h.Add(time.Hour)); err != nil {
				j.Metrics.mismatchHours(mismatched)
				return err
			}
		}
	}
	j.Metrics.mismatchHours(mismatched)
	return nil
}

func rangeQuery(field string, from, to time.Time) map[string]any {
	return map[string]any{"range": map[string]any{field: map[string]any{
		"gte": from.UTC().Format(time.RFC3339), "lt": to.UTC().Format(time.RFC3339),
	}}}
}

// count is the number of originals with a timestamp in [from, to).
func (j *Job) count(ctx context.Context, index string, from, to time.Time) (int64, error) {
	raw, err := j.Store.Search(ctx, index, map[string]any{
		"size": 0, "track_total_hits": true, "query": rangeQuery("timestamp", from, to),
	})
	if err != nil {
		return 0, fmt.Errorf("count %s: %w", index, err)
	}
	var out struct {
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("count %s: decode: %w", index, err)
	}
	return out.Hits.Total.Value, nil
}

// rolledSum is sum(occurrence_count) of the roll-ups whose minute is in
// [from, to). A roll-up index that does not exist yet sums to 0.
func (j *Job) rolledSum(ctx context.Context, index string, from, to time.Time) (int64, error) {
	raw, err := j.Store.Search(ctx, index, map[string]any{
		"size": 0, "query": map[string]any{"bool": map[string]any{"filter": []any{
			rangeQuery("timestamp", from, to),
			map[string]any{"term": map[string]any{"rollup_v": SchemaVersion}}, // only the current key
		}}},
		"aggs": map[string]any{"n": map[string]any{"sum": map[string]any{"field": "occurrence_count"}}},
	})
	if err != nil {
		return 0, fmt.Errorf("sum %s: %w", index, err)
	}
	return parseSum(raw)
}

func parseSum(raw []byte) (int64, error) {
	var out struct {
		Aggregations struct {
			N struct {
				Value float64 `json:"value"`
			} `json:"n"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("sum: decode: %w", err)
	}
	return int64(out.Aggregations.N.Value), nil
}

// CompositeBody is the aggregation that folds [from, to) into one bucket per
// key and minute. Exported for the tests that pin its shape.
func CompositeBody(from, to time.Time, size int, after map[string]any) map[string]any {
	sources := make([]any, 0, len(keyFields)+1)
	for _, f := range keyFields {
		if f == "audit_source" {
			// Keyed WITHOUT the ephemeral client port (tracker 410 (d)): the packs
			// write `{src}[:{port}]` and every vManage/ConfD session comes from a
			// new port, so a port-keyed bucket held one session, not one source.
			sources = append(sources, map[string]any{f: map[string]any{"terms": map[string]any{
				"script": map[string]any{"lang": "painless", "source": auditSourceAddrScript}, "missing_bucket": true,
			}}})
			continue
		}
		sources = append(sources, map[string]any{f: map[string]any{"terms": map[string]any{"field": f, "missing_bucket": true}}})
	}
	sources = append(sources, map[string]any{"minute": map[string]any{"date_histogram": map[string]any{
		"field": "timestamp", "fixed_interval": "1m",
	}}})
	comp := map[string]any{"size": size, "sources": sources}
	if after != nil {
		comp["after"] = after
	}
	return map[string]any{
		"size": 0, "query": rangeQuery("timestamp", from, to),
		"aggs": map[string]any{"k": map[string]any{
			"composite": comp,
			"aggs": map[string]any{
				"first": map[string]any{"min": map[string]any{"field": "timestamp"}},
				"last":  map[string]any{"max": map[string]any{"field": "timestamp"}},
			},
		}},
	}
}

// auditSourceAddrScript strips a trailing ":<digits>" port from audit_source
// when what precedes it is an IPv4 address/hostname (no ':') or a bracketed
// IPv6 address ("[2001:db8::1]:830" -> "[2001:db8::1]"). An unbracketed IPv6
// value is kept whole: its last group cannot be told from a port. The result
// is what logroutine.addrMatch's exact terms match, so the read clause still
// selects the roll-ups. StripAuditSourcePort is its Go twin (tests pin both).
const auditSourceAddrScript = `if (doc['audit_source'].size() == 0) { return null; }
String s = doc['audit_source'].value;
int i = s.lastIndexOf(':');
if (i <= 0 || i == s.length() - 1) { return s; }
for (int k = i + 1; k < s.length(); k++) { if (!Character.isDigit(s.charAt(k))) { return s; } }
String h = s.substring(0, i);
if (h.endsWith(']') || h.indexOf(':') < 0) { return h; }
return s;`

// StripAuditSourcePort is auditSourceAddrScript in Go, for the tests and for
// any Go-side reader that must derive the same key.
func StripAuditSourcePort(s string) string {
	i := strings.LastIndex(s, ":")
	if i <= 0 || i == len(s)-1 {
		return s
	}
	for _, r := range s[i+1:] {
		if r < '0' || r > '9' {
			return s
		}
	}
	h := s[:i]
	if strings.HasSuffix(h, "]") || !strings.Contains(h, ":") {
		return h
	}
	return s
}

type compositeResp struct {
	Aggregations struct {
		K struct {
			AfterKey map[string]any `json:"after_key"`
			Buckets  []struct {
				Key      map[string]any `json:"key"`
				DocCount int64          `json:"doc_count"`
				First    struct {
					Value *float64 `json:"value"`
				} `json:"first"`
				Last struct {
					Value *float64 `json:"value"`
				} `json:"last"`
			} `json:"buckets"`
		} `json:"k"`
	} `json:"aggregations"`
}

// ParseBuckets decodes one composite page.
func ParseBuckets(raw []byte) ([]Bucket, map[string]any, error) {
	var r compositeResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, fmt.Errorf("composite: decode: %w", err)
	}
	out := make([]Bucket, 0, len(r.Aggregations.K.Buckets))
	for _, b := range r.Aggregations.K.Buckets {
		key := map[string]string{}
		for _, f := range keyFields {
			if v, ok := b.Key[f].(string); ok {
				key[f] = v
			}
		}
		mf, ok := b.Key["minute"].(float64)
		if !ok {
			return nil, nil, errors.New("composite: a bucket carries no minute")
		}
		minute := time.UnixMilli(int64(mf)).UTC()
		bk := Bucket{Key: key, Minute: minute, Count: b.DocCount, FirstSeen: minute, LastSeen: minute}
		if b.First.Value != nil {
			bk.FirstSeen = time.UnixMilli(int64(*b.First.Value)).UTC()
		}
		if b.Last.Value != nil {
			bk.LastSeen = time.UnixMilli(int64(*b.Last.Value)).UTC()
		}
		out = append(out, bk)
	}
	return out, r.Aggregations.K.AfterKey, nil
}

// rollWindow folds [from, to) of one originals index into its roll-up index,
// page by page, each page written before the next is read.
func (j *Job) rollWindow(ctx context.Context, index string, from, to time.Time) error {
	rollup, ok := RollupIndexFor(index)
	if !ok {
		return nil
	}
	seg, ok := Segment(index)
	if !ok {
		return nil
	}
	cfg := j.Config.withDefaults()
	var after map[string]any
	for {
		j.mu.Lock()
		if j.pagesLeft <= 0 {
			j.mu.Unlock()
			return errPageCap
		}
		j.pagesLeft--
		j.mu.Unlock()
		raw, err := j.Store.Search(ctx, index, CompositeBody(from, to, cfg.PageSize, after))
		if err != nil {
			return fmt.Errorf("aggregate %s: %w", index, err)
		}
		buckets, next, err := ParseBuckets(raw)
		if err != nil {
			return fmt.Errorf("aggregate %s: %w", index, err)
		}
		var body bytes.Buffer
		written := 0
		for _, b := range buckets {
			if segFor(b.Key["tenant_id"]) != seg {
				// A document whose tenant disagrees with the index it sits
				// in: never written into this tenant's roll-ups (§3a).
				j.Metrics.tenantMismatch(b.Count)
				continue
			}
			meta, err := json.Marshal(map[string]any{"index": map[string]any{"_index": rollup, "_id": b.ID()}})
			if err != nil {
				return err
			}
			doc, err := json.Marshal(b.Doc())
			if err != nil {
				return err
			}
			body.Write(meta)
			body.WriteByte('\n')
			body.Write(doc)
			body.WriteByte('\n')
			written++
		}
		if written > 0 {
			resp, err := j.Store.Bulk(ctx, body.Bytes())
			if err != nil {
				return fmt.Errorf("write %s: %w", rollup, err)
			}
			if failed, err := BulkFailures(resp); err != nil || failed > 0 {
				if err == nil {
					err = fmt.Errorf("%d roll-up documents were rejected", failed)
				}
				return fmt.Errorf("write %s: %w", rollup, err)
			}
			j.Metrics.written(written)
		}
		if len(buckets) == 0 || next == nil {
			return nil
		}
		after = next
	}
}

// BulkFailures counts the rejected items of a _bulk response.
func BulkFailures(raw []byte) (int, error) {
	var r struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return 0, fmt.Errorf("bulk: decode: %w", err)
	}
	if !r.Errors {
		return 0, nil
	}
	n := 0
	for _, it := range r.Items {
		for _, v := range it {
			if v.Status >= 300 {
				n++
			}
		}
	}
	return n, nil
}

// Run ticks every interval until ctx ends, backing off after failures (up to
// 10 minutes), and logs each change between healthy and failing once.
func (j *Job) Run(ctx context.Context, interval time.Duration, logf func(msg string, err error)) {
	if j == nil || j.Store == nil {
		return
	}
	if interval <= 0 {
		interval = time.Minute
	}
	wait := interval
	t := time.NewTimer(wait)
	defer t.Stop()
	var lastErr error
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		tctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err := j.Tick(tctx)
		cancel()
		changed := first || (err == nil) != (lastErr == nil)
		first, lastErr = false, err
		if err != nil && !errors.Is(err, context.Canceled) {
			j.Metrics.failure()
			if changed && logf != nil {
				logf("routine-syslog roll-up could not roll; the originals are kept and the next tick retries", err)
			}
			if wait < 10*time.Minute {
				wait *= 2
			}
		} else {
			if changed && logf != nil && err == nil {
				logf("routine-syslog roll-up is rolling", nil)
			}
			wait = interval
		}
		t.Reset(wait)
	}
}
