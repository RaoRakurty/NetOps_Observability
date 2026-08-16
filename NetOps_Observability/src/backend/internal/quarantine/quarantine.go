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

// laneReplayGuarded reports whether a lane's CANONICAL store cannot
// deduplicate a replayed event by id. The OS event sinks upsert by `id_key:
// cx_event_id`, so a syslog/snmptrap replay is an upsert; the flows lane's
// canonical store is the ClickHouse netops.flows table (plain MergeTree, no
// id column at all — the sink's skip_unknown_fields silently drops
// cx_event_id), so every re-produce lands a DUPLICATE canonical row. Guarded
// lanes get at-most-once produce semantics instead: the envelope is claimed
// (CAS on the OS doc, see RestoreDeps.Claim) before its single produce, and
// an envelope carrying a claim is never produced again — only its tombstone
// is retried.
func laneReplayGuarded(lane string) bool { return lane == "flows" }

// ErrClaimConflict is returned by RestoreDeps.Claim when the CAS lost: another
// restore run claimed the envelope between our search and our claim. The
// winner produces and tombstones; this run must do neither.
var ErrClaimConflict = errors.New("quarantine: envelope already claimed by a concurrent restore")

// RestoredAtField is the envelope field a successful claim stamps
// (RestoreDeps.Claim) and ParseSearch reads back — the persistent "produce was
// attempted" marker that survives a failed tombstone.
const RestoredAtField = "cx_restored_at"

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
	// RestoredAt is the replay-guard claim stamp (RestoredAtField): non-empty
	// means an earlier restore already ATTEMPTED the produce and only the
	// tombstone remains. Listed so a lingering claimed envelope is visible to
	// the operator, not a mystery row.
	RestoredAt string `json:"cx_restored_at,omitempty"`
	Payload    string `json:"-"` // sealed token — NEVER serialized
	// Optimistic-concurrency coordinates of the doc at search time; the claim
	// CAS (RestoreDeps.Claim) conditions on them so two concurrent restores
	// cannot both win the same envelope. Transport detail, never serialized.
	SeqNo       int64 `json:"-"`
	PrimaryTerm int64 `json:"-"`
}

// quarantineIndexPrefix guards the tombstone path: a DELETE is issued only
// against indices that are provably quarantine indices, whatever the search
// response claims (§3: never trust upstream services).
const quarantineIndexPrefix = "netops-quarantine-"

// metadataFields is the _source projection for the list query — the payload
// is not even transferred from OpenSearch for a metadata listing.
var metadataFields = []string{"cx_event_id", "received_at", "lane", "identity_sha", "source_ip", "reason", RestoredAtField}

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
		// The replay-guard claim (RestoreDeps.Claim) is a CAS conditioned on
		// each hit's _seq_no/_primary_term — request them with the hits.
		"seq_no_primary_term": true,
		"query":               map[string]any{"term": map[string]any{"identity_sha": sha}},
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
			Index       string         `json:"_index"`
			ID          string         `json:"_id"`
			SeqNo       int64          `json:"_seq_no"`
			PrimaryTerm int64          `json:"_primary_term"`
			Source      map[string]any `json:"_source"`
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
		// The quarantine sink's `id_key: cx_event_id` CONSUMES the field into
		// the document _id (verified on the live index, 2026-08-12) — so the
		// _id IS the original event id, and _source usually has no copy.
		eventID := str("cx_event_id")
		if eventID == "" {
			eventID = h.ID
		}
		docs = append(docs, Doc{
			Index:       h.Index,
			ID:          h.ID,
			EventID:     eventID,
			ReceivedAt:  str("received_at"),
			Lane:        str("lane"),
			IdentitySha: str("identity_sha"),
			SourceIP:    str("source_ip"),
			Reason:      str("reason"),
			RestoredAt:  str(RestoredAtField),
			Payload:     str(processors.QuarantinePayloadField),
			SeqNo:       h.SeqNo,
			PrimaryTerm: h.PrimaryTerm,
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
	// Claim stamps RestoredAtField on the envelope doc BEFORE a replay-guarded
	// lane's produce, conditioned on the doc's (seqNo, primaryTerm) as seen at
	// search time — a CAS, so exactly one concurrent restore run wins each
	// envelope. Must return an error wrapping ErrClaimConflict when the CAS
	// lost. Required for guarded lanes: Restore fails such docs closed when
	// Claim is nil, because producing a flow without the guard reopens the
	// canonical-store duplication path.
	Claim func(ctx context.Context, index, id string, seqNo, primaryTerm int64) error
	// Unclaim clears the claim stamp after the bus REFUSED the produce (the
	// event is provably not in the canonical store), so the envelope stays
	// restorable. Best-effort: a failed rollback leaves the claim in place and
	// the next run refuses the replay — the deliberate at-most-once loss
	// window, and it takes a produce failure AND a rollback failure to hit it.
	Unclaim func(ctx context.Context, index, id string) error
}

// RestoreResult counts one run's outcomes. Restored counts events accepted by
// the bus; DeleteFailed counts restored events whose tombstone failed (the
// doc lingers as noise — replays are refused or upsert, see Restore).
// ReplayRefused counts envelopes skipped by the replay guard (already claimed
// by an earlier or concurrent run); UnclaimFailed counts claim rollbacks that
// failed after a refused produce (the envelope will be refused, not retried).
// Aborted counts envelopes never attempted because ctx was cancelled mid-batch
// — they stay untouched (no claim, no tombstone) and restore on the next run.
type RestoreResult struct {
	Restored      int
	Failed        int
	Deleted       int
	DeleteFailed  int
	ReplayRefused int
	UnclaimFailed int
	Aborted       int
}

// Restore unseals and re-injects each doc, then tombstones it. Per-doc
// failures are counted and never abort the batch; a cancelled/expired ctx DOES
// abort it (counted in Aborted) — the guarded claim is a persistent
// side-effect, and taking it with a ctx the remaining steps will refuse is how
// an envelope gets stranded as "already restored" and later tombstoned without
// its event ever reaching the bus (H9). Callers therefore run Restore on a
// context detached from the client connection (see handleQuarantineReattribute).
//
// REPLAY SAFETY — two dedup contracts, by lane, both promising "re-running
// the same restore never duplicates tenant data":
//
//   - OS-canonical lanes (syslog, snmptrap): the re-injected event carries the
//     envelope's original cx_event_id and the OpenSearch event sinks use
//     `id_key: cx_event_id`, so a replay UPSERTS the same document ids — a
//     failed tombstone is noise, not corruption.
//   - flows (laneReplayGuarded): the canonical store is ClickHouse (plain
//     MergeTree, no id dedup), so the same outcome is enforced restore-side
//     with at-most-once produce: each envelope is claimed via CAS before its
//     single produce, an envelope already carrying a claim only gets its
//     tombstone retried, and a claim is rolled back only when the bus refused
//     the event outright.
func Restore(ctx context.Context, deps RestoreDeps, docs []Doc, tenant string) RestoreResult {
	var res RestoreResult
	for i, d := range docs {
		// H9: a cancelled ctx must stop the batch BEFORE the next claim. The
		// effectful deps honour ctx, so claiming here would stamp the
		// persistent restored-at marker and then have Produce refused — the
		// next run would see the claim, refuse the replay and tombstone an
		// envelope whose event never reached the bus: silent data loss from
		// nothing more than a client disconnect. Stop instead; untouched
		// envelopes restore cleanly on the next run.
		if ctx.Err() != nil {
			res.Aborted += len(docs) - i
			break
		}
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
		guarded := laneReplayGuarded(d.Lane)
		if guarded && d.RestoredAt != "" {
			// An earlier run claimed this envelope: its produce was at least
			// ATTEMPTED and may have landed in ClickHouse (the common way
			// here is a produce that succeeded but a tombstone that failed).
			// At-most-once for canonical flow data: never produce again —
			// finish the tombstone instead.
			res.ReplayRefused++
			if err := deps.Delete(ctx, d.Index, d.ID); err != nil {
				res.DeleteFailed++
			} else {
				res.Deleted++
			}
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
		if guarded {
			if deps.Claim == nil {
				// Fail closed: a guarded produce without the replay guard
				// would reopen the duplication path.
				res.Failed++
				continue
			}
			if err := deps.Claim(ctx, d.Index, d.ID, d.SeqNo, d.PrimaryTerm); err != nil {
				if errors.Is(err, ErrClaimConflict) {
					// A concurrent run won the CAS — it produces and
					// tombstones; this run must do neither.
					res.ReplayRefused++
				} else {
					res.Failed++
				}
				continue
			}
		}
		if err := deps.Produce(ctx, topic, tenant, ev); err != nil {
			res.Failed++
			// H9: a ctx-shaped produce error is NOT "the bus refused" — the
			// event may or may not have reached the bus, so a guarded claim
			// must STAY (unclaiming could double-produce a flow that did
			// land; keeping it is the documented at-most-once window). Either
			// way the ctx is dead: stop before claiming more envelopes.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				if guarded {
					res.UnclaimFailed++ // the claim sticks; refused, not retried
				}
				res.Aborted += len(docs) - i - 1
				break
			}
			if guarded {
				// The bus refused, so the event is NOT in ClickHouse — roll
				// the claim back so the envelope stays restorable. If the
				// rollback also fails, the claim sticks and the next run
				// refuses the replay: the accepted at-most-once loss window
				// (it takes BOTH failures), surfaced via UnclaimFailed.
				if deps.Unclaim == nil || deps.Unclaim(ctx, d.Index, d.ID) != nil {
					res.UnclaimFailed++
				}
			}
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
