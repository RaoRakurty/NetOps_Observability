package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/collectors"
)

// bus_producer.go — #81 P5b / #97. A minimal, stdlib-only bus producer over the
// Vector aggregator's HTTP bus-bridge source (bus_in, :8692). The Go backend is
// stdlib-only with NO Kafka client (allowlist §6) — the established pattern
// (see netbox_sync.go) is "REST, not the Kafka bus" for low-volume,
// control-plane-ish emit. Vector forwards each envelope to its netops.* topic
// (kafka_bus sink, templated topic, netops.* prefix enforced in the remap).
// Replaced the Redpanda pandaproxy when the bus moved to Apache Kafka, which
// has no HTTP produce API (#97 licensing swap).

// busBridgeURL is the base URL of the Vector bus bridge. Inside the compose
// network the api container reaches it at http://vector-aggregator:8692;
// override via env for other topologies. Empty ("BUS_BRIDGE_URL=") → emit is
// a no-op (offline-safe).
func busBridgeURL() string {
	// LookupEnv, not envOr: envOr treats an EMPTY value as "unset" and returns
	// the fallback, so `BUS_BRIDGE_URL=` silently kept dialling
	// vector-aggregator instead of disabling emit. The documented offline-safe
	// switch did not exist — on a dev box every emit attempted a DNS lookup and
	// failed. An explicitly-empty value now means disabled, as documented; only
	// an ABSENT variable takes the compose default.
	if v, ok := os.LookupEnv("BUS_BRIDGE_URL"); ok {
		return strings.TrimRight(v, "/")
	}
	return "http://vector-aggregator:8692"
}

// produceJSON publishes records to a netops.* topic via the bus bridge. Each
// record is a (key, value) pair; key drives partitioning (here: tenant — same
// tenant's identities stay ordered). Bounded by an IO timeout (§9).
// At-least-once by design; the consumer is idempotent (deterministic
// signal_id), so a redelivery is safe.
//
// Returns the number of records accepted by the bridge. A non-2xx response or
// transport error is returned to the caller, which decides whether to retry or
// carry on (the fusion worker treats emit as best-effort — the ClickHouse
// persist is the source of truth; the topic is only the correlation feed).
func produceJSON(ctx context.Context, topic string, records []proxyRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	base := busBridgeURL()
	if base == "" {
		return 0, nil // disabled — offline-safe no-op
	}
	// One envelope per record: {topic, key, event}. Vector's json codec turns
	// a JSON array body into one event per element.
	envs := make([]busEnvelope, 0, len(records))
	for _, r := range records {
		envs = append(envs, busEnvelope{Topic: topic, Key: r.Key, Event: r.Value})
	}
	payload, err := json.Marshal(envs)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	// F-08: the bus bridge is authenticated now. Its netops.* prefix check is
	// a ROUTING guard, never an identity guard — without this header anything
	// on the compose network could produce onto any tenant's topic.
	collectors.SetIngestAuth(req)
	resp, err := backendHTTPClient(20 * time.Second).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("bus bridge produce %s: status %d: %s", topic, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return len(records), nil
}

// busEnvelope is one record on the wire to the Vector bus bridge. The remap
// unwraps Event onto the topic named by Topic; Key (optional) becomes the
// Kafka message key.
type busEnvelope struct {
	Topic string `json:"topic"`
	Key   string `json:"key,omitempty"`
	Event any    `json:"event"`
}

// proxyRecord is one bus record from a producer's point of view: Value is the
// event object (serialized as JSON); Key (optional) sets the partition key.
type proxyRecord struct {
	Key   string `json:"key,omitempty"`
	Value any    `json:"value"`
}
