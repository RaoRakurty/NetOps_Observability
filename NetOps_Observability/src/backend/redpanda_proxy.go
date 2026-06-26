package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// redpanda_proxy.go — #81 P5b. A minimal, stdlib-only Kafka producer over Redpanda's
// HTTP REST gateway (pandaproxy, :8082). The Go backend is stdlib-only with NO Kafka
// client (allowlist §6) — the established pattern (see netbox_sync.go) is "REST, not
// the Kafka bus" for low-volume, control-plane-ish emit. Fused application identities
// are exactly that: a small, periodic enrichment stream the Python correlation engine
// consumes off netops.app.identities.v1. Vendor logs keep flowing via syslog/Vector.

// pandaProxyURL is the base URL of the Redpanda HTTP proxy. Inside the compose network
// the api container reaches it at http://redpanda:8082; override via env for other
// topologies. Empty/disabled by config → emit is a no-op (offline-safe).
func pandaProxyURL() string {
	return strings.TrimRight(envOr("REDPANDA_PROXY_URL", "http://redpanda:8082"), "/")
}

// produceJSON publishes records to a topic via pandaproxy's JSON produce API. Each
// record is a (key, value) pair; key drives partitioning (here: tenant — same tenant's
// identities stay ordered). Bounded by an IO timeout (§9). At-least-once by design;
// the consumer is idempotent (deterministic signal_id), so a retto is safe.
//
// Returns the number of records the broker reported. A non-2xx response or transport
// error is returned to the caller, which decides whether to retry or carry on (the
// fusion worker treats emit as best-effort — the ClickHouse persist is the source of
// truth; the topic is only the correlation feed).
func produceJSON(ctx context.Context, topic string, records []proxyRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	base := pandaProxyURL()
	if base == "" {
		return 0, nil // disabled — offline-safe no-op
	}
	u, err := url.Parse(base + "/topics/" + url.PathEscape(topic))
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(struct {
		Records []proxyRecord `json:"records"`
	}{Records: records})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	// pandaproxy content negotiation: JSON-encoded record values, v2 API.
	req.Header.Set("Content-Type", "application/vnd.kafka.json.v2+json")
	req.Header.Set("Accept", "application/vnd.kafka.v2+json")
	resp, err := backendHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("pandaproxy produce %s: status %d: %s", topic, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return len(records), nil
}

// proxyRecord is one Kafka record for the pandaproxy JSON produce API. Value is the
// event object (serialized as JSON); Key (optional) sets the partition key.
type proxyRecord struct {
	Key   string `json:"key,omitempty"`
	Value any    `json:"value"`
}
