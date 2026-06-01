package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ----------------------------------------------------------------------------
// Structured logger — emits one JSON line per event to stdout. Vector's
// docker_logs source picks them up, parses the JSON, ships to Redpanda
// (topic netops.applogs), and vector-router then writes them into the
// `netops-applogs-YYYY.MM.DD` OpenSearch index.
// ----------------------------------------------------------------------------

type jsonLogger struct {
	mu sync.Mutex
	w  io.Writer
}

var appLog = &jsonLogger{w: os.Stdout}

func (l *jsonLogger) log(level, component, msg string, fields map[string]any) {
	event := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level,
		"component": component,
		"msg":       msg,
	}
	for k, v := range fields {
		event[k] = v
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = json.NewEncoder(l.w).Encode(event)
}

func logInfo(component, msg string, fields map[string]any)  { appLog.log("info", component, msg, fields) }
func logWarn(component, msg string, fields map[string]any)  { appLog.log("warn", component, msg, fields) }
func logError(component, msg string, fields map[string]any) { appLog.log("error", component, msg, fields) }

// ----------------------------------------------------------------------------
// Log search — OpenSearch query proxy.
//
// The Logs tab posts a small JSON body with { query, from, to, size,
// signal }. We build a real OpenSearch _search request and return the
// response untouched so the frontend can render hits + aggregations.
//
// `signal` selects which index pattern to hit:
//   - "applogs" → netops-applogs-*    (container/API logs)
//   - "syslog"  → netops-syslog-*     (network device syslog)
//   - "flows"   → netops-flows-*      (NetFlow / IPFIX / sFlow records)
//   - ""        → netops-*            (everything)
// ----------------------------------------------------------------------------

type logSearchReq struct {
	Query  string `json:"query"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Size   int    `json:"size,omitempty"`
	Signal string `json:"signal,omitempty"`
}

func (s *server) handleLogsSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req logSearchReq
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		q := r.URL.Query()
		req.Query = q.Get("query")
		req.From = q.Get("from")
		req.To = q.Get("to")
		req.Signal = q.Get("signal")
		if n, err := strconv.Atoi(q.Get("size")); err == nil {
			req.Size = n
		}
	}
	if req.Size <= 0 || req.Size > 5000 {
		req.Size = 200
	}

	end := time.Now().UTC()
	start := end.Add(-15 * time.Minute)
	if req.From != "" {
		if t, err := parseTimeFlexible(req.From); err == nil {
			start = t
		}
	}
	if req.To != "" {
		if t, err := parseTimeFlexible(req.To); err == nil {
			end = t
		}
	}

	index := indexFor(req.Signal)

	// Compose a query string DSL body. We use query_string so callers
	// can pass either bare text ("error") or full Lucene syntax
	// ("severity:err AND host:router-01").
	// All netops-* indices (applogs/syslog/flows) timestamp their docs with the
	// field `timestamp` (Vector's default), not the ECS `@timestamp`. Sort and
	// range-filter on that. unmapped_type keeps the sort from failing on any
	// index whose mapping happens to lack the field rather than erroring the
	// whole multi-index search.
	filters := []any{
		map[string]any{
			"range": map[string]any{
				"timestamp": map[string]string{
					"gte": start.Format(time.RFC3339),
					"lte": end.Format(time.RFC3339),
				},
			},
		},
	}

	// Tenant isolation: a scoped principal may only see logs emitted by devices
	// in its own tenant — matched on the log's host/hostname (device name) or
	// source_ip (device address). A tenant with no devices sees no logs; the
	// cross-tenant platform owner is unrestricted. (Logs aren't yet tagged with a
	// tenant_id at ingestion, so we scope by the caller's visible device set.)
	if claims, ok := userFrom(r.Context()); ok {
		if names, cross := s.visibleDeviceKeys(claims); !cross {
			addrs, _ := s.visibleDeviceAddrs(claims)
			var should []any
			if len(names) > 0 {
				should = append(should,
					map[string]any{"terms": map[string]any{"host": names}},
					map[string]any{"terms": map[string]any{"hostname": names}},
				)
			}
			if len(addrs) > 0 {
				should = append(should, map[string]any{"terms": map[string]any{"source_ip": addrs}})
			}
			if len(should) == 0 {
				// No visible devices → no logs are in this tenant's namespace.
				should = append(should, map[string]any{"match_none": map[string]any{}})
			}
			filters = append(filters, map[string]any{
				"bool": map[string]any{"should": should, "minimum_should_match": 1},
			})
		}
	}

	body := map[string]any{
		"size": req.Size,
		"sort": []any{map[string]any{"timestamp": map[string]string{"order": "desc", "unmapped_type": "date"}}},
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"query_string": map[string]any{
							"query":            queryOrAll(req.Query),
							"analyze_wildcard": true,
						},
					},
				},
				"filter": filters,
			},
		},
	}

	resp, err := openSearch("POST", "/"+index+"/_search", body)
	if err != nil {
		logError("logs", "opensearch search failed", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("logs: copy response: %v", err)
	}
}

func (s *server) handleLogsIndices(w http.ResponseWriter, _ *http.Request) {
	resp, err := openSearch("GET", "/_cat/indices/netops-*?format=json", nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func indexFor(signal string) string {
	switch strings.ToLower(signal) {
	case "applogs", "app":
		return "netops-applogs-*"
	case "syslog":
		return "netops-syslog-*"
	case "flows", "netflow", "flow":
		return "netops-flows-*"
	default:
		return "netops-*"
	}
}

func queryOrAll(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return "*"
	}
	return q
}

// openSearch is a tiny HTTP client wrapper for the OpenSearch cluster.
// Auth would go here once DISABLE_SECURITY_PLUGIN is flipped off.
func openSearch(method, path string, body any) (*http.Response, error) {
	base := envOr("OPENSEARCH_URL", "http://opensearch:9200")
	u, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// parseTimeFlexible accepts RFC3339, Unix seconds, or Unix nanoseconds.
func parseTimeFlexible(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1_000_000_000_000_000 {
			return time.Unix(0, n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized time format: %q", s)
}
