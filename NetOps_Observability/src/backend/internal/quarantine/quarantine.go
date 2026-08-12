// Package quarantine is the operator half of F-11 seal-or-quarantine (design
// doc docs/design/f11-seal-or-quarantine.md, D5): the pure logic behind
// GET /api/quarantine and POST /api/quarantine/reattribute.
//
// The edge (generated router config, processors/quarantine.go) replaces every
// TENANT-UNATTRIBUTABLE event with a metadata envelope whose payload — the
// whole original event — is sealed under the dedicated `quarantine` key
// scope. This package resolves an envelope's hashed identity against the LIVE
// device inventory (the authoritative source; a caller-supplied tenant is
// never accepted), unseals the payload, and re-injects the original event
// onto its lane's bus topic so the normal pipeline attributes, seals and
// stores it under the resolved tenant's own rules.
//
// Every effectful dependency (unseal, bus produce, doc delete, the OpenSearch
// fetch behind the metrics sampler) is injected — the package itself performs
// no IO, holds no globals and imports no HTTP-handler code (CLAUDE.md §1/§2).
package quarantine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"netops/backend/processors"
	"netops/backend/sealing"
)

// IdentityRow is one (identity, tenant) projection of a device — the SAME
// identities the ingest tier looks up (device name and management address,
// mirroring buildEnrichmentRows): the envelope's identity_sha was computed
// over exactly one of these strings.
type IdentityRow struct {
	Identity string
	Tenant   string
}

// The three resolution refusals, kept distinct so the API can tell the
// operator WHAT to fix. All map to 409 (the state of the inventory conflicts
// with the request; the request itself is well-formed).
var (
	// ErrIdentityUnknown — no device in the live inventory carries this
	// identity. Re-attribution would be guessing.
	ErrIdentityUnknown = errors.New("identity not in inventory — assign the device first")
	// ErrIdentityUnassigned — the identity is a known device that maps to the
	// platform tenant (""). Quarantined events need a REAL tenant to restore
	// into; assign the device to one first.
	ErrIdentityUnassigned = errors.New("identity resolves only to the platform tenant — assign the device to a tenant first")
	// ErrIdentityAmbiguous — the identity maps to more than one tenant (e.g.
	// NAT collapsing two devices onto one address). Fail-safe refusal, same as
	// the enrichment export's ambiguity rule.
	ErrIdentityAmbiguous = errors.New("identity resolves to more than one tenant — resolve the inventory conflict first")
)

// ResolveIdentity finds which inventory identities hash to shaHex and returns
// the single non-empty tenant they resolve to, plus the count of distinct
// matched identity strings. The sha comparison is case-insensitive (hex).
//
// The result is authoritative BY CONSTRUCTION: it is recomputed from the live
// inventory on every call, never from the quarantine doc or the request.
func ResolveIdentity(rows []IdentityRow, shaHex string) (tenant string, matched int, err error) {
	want := strings.ToLower(strings.TrimSpace(shaHex))
	identities := map[string]bool{}
	tenants := map[string]bool{}
	for _, r := range rows {
		if r.Identity == "" {
			continue
		}
		sum := sha256.Sum256([]byte(r.Identity))
		if hex.EncodeToString(sum[:]) != want {
			continue
		}
		identities[r.Identity] = true
		tenants[strings.ToLower(strings.TrimSpace(r.Tenant))] = true
	}
	if len(identities) == 0 {
		return "", 0, ErrIdentityUnknown
	}
	delete(tenants, "")
	switch len(tenants) {
	case 0:
		return "", len(identities), ErrIdentityUnassigned
	case 1:
		for t := range tenants {
			tenant = t
		}
		return tenant, len(identities), nil
	default:
		return "", len(identities), ErrIdentityAmbiguous
	}
}

// laneTopics maps each quarantining lane to its original bus topic — the
// topic the event would have arrived on, so re-injection replays the normal
// path end to end. Closed set on purpose: an unknown lane in an envelope is
// refused, never guessed.
var laneTopics = map[string]string{
	"syslog":   "netops.syslog",
	"snmptrap": "netops.snmptrap",
	"flows":    "netops.flows",
}

// TopicForLane returns the re-injection topic for a quarantine lane.
func TopicForLane(lane string) (string, bool) {
	t, ok := laneTopics[lane]
	return t, ok
}

// SealContext is the exact authenticated context the router sealed quarantine
// payloads under (processors/quarantine.go). The MAC covers every field, so
// any drift here makes every envelope unrecoverable — which is why the
// constants are shared, not retyped.
func SealContext() sealing.Context {
	return sealing.Context{
		Tenant:      processors.QuarantineScope,
		ProcessorID: processors.QuarantineProcessorID,
		Field:       processors.QuarantinePayloadField,
		DataType:    "quarantine",
	}
}

// Doc is one quarantine envelope as read back from OpenSearch. Its JSON shape
// IS the list-response row: metadata only. Payload deliberately carries
// `json:"-"` — the sealed token must be structurally unable to reach a list
// response, whatever the handler does.
type Doc struct {
	Index       string `json:"_index"`
	ID          string `json:"-"` // OS doc id; transport detail, not metadata
	EventID     string `json:"cx_event_id"`
	ReceivedAt  string `json:"received_at"`
	Lane        string `json:"lane"`
	IdentitySha string `json:"identity_sha"`
	SourceIP    string `json:"source_ip,omitempty"`
	Reason      string `json:"reason"`
	Payload     string `json:"-"` // sealed token — NEVER serialized
}

// quarantineIndexPrefix guards the tombstone path: a DELETE is issued only
// against indices that are provably quarantine indices, whatever the search
// response claims (§3: never trust upstream services).
const quarantineIndexPrefix = "netops-quarantine-"

// metadataFields is the _source projection for the list query — the payload
// is not even transferred from OpenSearch for a metadata listing.
var metadataFields = []string{"cx_event_id", "received_at", "lane", "identity_sha", "source_ip", "reason"}

// ListQuery is the metadata-list search body: newest first, exact totals, and
// a min aggregation over received_at for the summary.
func ListQuery(offset, limit int) map[string]any {
	return map[string]any{
		"from":             offset,
		"size":             limit,
		"track_total_hits": true,
		"_source":          metadataFields,
		"sort": []any{
			map[string]any{"received_at": map[string]any{"order": "desc", "unmapped_type": "date"}},
		},
		"aggs": map[string]any{
			"oldest_received": map[string]any{"min": map[string]any{"field": "received_at"}},
		},
	}
}

// ShaQuery is the re-attribution search body: every envelope whose identity
// hashed to sha, oldest first, bounded to limit per call (the caller reports
// the remainder).
func ShaQuery(sha string, limit int) map[string]any {
	return map[string]any{
		"size":             limit,
		"track_total_hits": true,
		"query":            map[string]any{"term": map[string]any{"identity_sha": sha}},
		"sort": []any{
			map[string]any{"received_at": map[string]any{"order": "asc", "unmapped_type": "date"}},
		},
	}
}

// osSearchResponse is the subset of an OpenSearch search reply this package
// reads.
type osSearchResponse struct {
	Hits struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []struct {
			Index  string         `json:"_index"`
			ID     string         `json:"_id"`
			Source map[string]any `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
	Aggregations struct {
		OldestReceived struct {
			Value         *float64 `json:"value"`
			ValueAsString string   `json:"value_as_string"`
		} `json:"oldest_received"`
	} `json:"aggregations"`
}

// ParseSearch decodes a quarantine search reply into docs, the exact total,
// and the oldest received_at (RFC3339 string; "" when the index is empty or
// the aggregation was not requested).
func ParseSearch(r io.Reader) (docs []Doc, total int64, oldest string, err error) {
	var body osSearchResponse
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		return nil, 0, "", fmt.Errorf("quarantine: decode search response: %w", err)
	}
	docs = make([]Doc, 0, len(body.Hits.Hits))
	for _, h := range body.Hits.Hits {
		str := func(key string) string {
			v, _ := h.Source[key].(string)
			return v
		}
		docs = append(docs, Doc{
			Index:       h.Index,
			ID:          h.ID,
			EventID:     str("cx_event_id"),
			ReceivedAt:  str("received_at"),
			Lane:        str("lane"),
			IdentitySha: str("identity_sha"),
			SourceIP:    str("source_ip"),
			Reason:      str("reason"),
			Payload:     str(processors.QuarantinePayloadField),
		})
	}
	if body.Aggregations.OldestReceived.Value != nil {
		oldest = body.Aggregations.OldestReceived.ValueAsString
	}
	return docs, body.Hits.Total.Value, oldest, nil
}

// RestoreEvent turns an unsealed payload back into the event to re-inject:
// the original object with the resolved tenant stamped, the registry-miss
// marker cleared (so the router's quarantine guard does not re-fire), the
// original envelope id carried for id_key idempotency, and an explicit
// provenance marker.
func RestoreEvent(plaintext []byte, tenant, eventID string) (map[string]any, error) {
	var ev map[string]any
	if err := json.Unmarshal(plaintext, &ev); err != nil {
		return nil, fmt.Errorf("quarantine: payload is not a JSON object: %w", err)
	}
	if ev == nil {
		return nil, errors.New("quarantine: payload decoded to null")
	}
	ev["tenant_id"] = tenant
	delete(ev, "tenant_registry")
	ev["cx_event_id"] = eventID
	ev["cx_restored_from"] = "quarantine"
	return ev, nil
}

// RestoreDeps are the injected effects of one restore run. Produce must be
// DURABLE acceptance by the bus (a disabled/no-op bridge is an error, not a
// success): Delete is only ever called after Produce succeeds.
type RestoreDeps struct {
	// Unseal opens one sealed payload token under the quarantine context.
	Unseal func(ctx context.Context, token string) (string, error)
	// Produce publishes the restored event onto its lane's original topic,
	// keyed by tenant.
	Produce func(ctx context.Context, topic, tenant string, event map[string]any) error
	// Delete tombstones one quarantine doc after successful re-injection.
	Delete func(ctx context.Context, index, id string) error
}

// RestoreResult counts one run's outcomes. Restored counts events accepted by
// the bus; DeleteFailed counts restored events whose tombstone failed (the
// doc lingers as noise — the restore itself is idempotent, see Restore).
type RestoreResult struct {
	Restored     int
	Failed       int
	Deleted      int
	DeleteFailed int
}

// Restore unseals and re-injects each doc, then tombstones it. Per-doc
// failures are counted and never abort the batch.
//
// REPLAY-SAFE by construction: the re-injected event carries the envelope's
// original cx_event_id and the OpenSearch event sinks use `id_key:
// cx_event_id`, so running the same restore twice UPSERTS the same document
// ids instead of duplicating tenant data — which is also why a failed
// tombstone is noise rather than corruption.
func Restore(ctx context.Context, deps RestoreDeps, docs []Doc, tenant string) RestoreResult {
	var res RestoreResult
	for _, d := range docs {
		topic, ok := TopicForLane(d.Lane)
		if !ok {
			res.Failed++
			continue
		}
		// Zero trust on the search response: tombstones may only reach
		// quarantine indices, and an envelope without its original event id
		// cannot be re-injected idempotently — refuse both.
		if !strings.HasPrefix(d.Index, quarantineIndexPrefix) || d.EventID == "" || d.Payload == "" {
			res.Failed++
			continue
		}
		plaintext, err := deps.Unseal(ctx, d.Payload)
		if err != nil {
			res.Failed++
			continue
		}
		ev, err := RestoreEvent([]byte(plaintext), tenant, d.EventID)
		if err != nil {
			res.Failed++
			continue
		}
		if err := deps.Produce(ctx, topic, tenant, ev); err != nil {
			res.Failed++
			continue
		}
		res.Restored++
		if err := deps.Delete(ctx, d.Index, d.ID); err != nil {
			res.DeleteFailed++
		} else {
			res.Deleted++
		}
	}
	return res
}
