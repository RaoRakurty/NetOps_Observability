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
// lanes get at-most-once produce semantics instead, via a two-phase mark: the
// envelope is claimed (CAS on the OS doc, see RestoreDeps.Claim) before its
// single produce, and the bus's acceptance is stamped back onto the doc
// (RestoreDeps.MarkProduced) before the tombstone. An envelope carrying a
// claim is never produced again; whether its tombstone is retried or the
// envelope is preserved depends on the produced-stamp (see Restore).
func laneReplayGuarded(lane string) bool { return lane == "flows" }

// ErrClaimConflict is returned by RestoreDeps.Claim when the CAS lost: another
// restore run claimed the envelope between our search and our claim. The
// winner produces and tombstones; this run must do neither.
var ErrClaimConflict = errors.New("quarantine: envelope already claimed by a concurrent restore")

// RestoredAtField is the envelope field a successful claim stamps
// (RestoreDeps.Claim) and ParseSearch reads back — the persistent "a produce
// MAY have been attempted" marker that survives a crash or a failed tombstone.
// On its own it is deliberately ambiguous: a process killed between the claim
// landing and the produce landing leaves exactly this stamp and nothing else,
// so the claim alone must never justify a tombstone (that was the pre-fix
// silent-loss window: crash after Claim, before Produce → next run tombstoned
// an envelope whose event never reached the bus). RestoredProducedField is the
// disambiguator.
const RestoredAtField = "cx_restored_at"

// RestoredProducedField is the second half of the two-phase replay mark: it is
// stamped (RestoreDeps.MarkProduced) only AFTER the bus durably accepted the
// guarded produce, and before the tombstone. Persistent doc states, and what a
// later Restore does with each:
//
//   - neither field: never attempted → restore normally.
//   - claim only: INDETERMINATE — the previous run died between the claim
//     landing and this stamp landing, so the produce may or may not have
//     reached the bus. Never re-produce (could duplicate a canonical
//     ClickHouse row), never tombstone (could delete a flow that never
//     arrived): the envelope is preserved (ClaimStranded).
//   - both fields: produce provably succeeded, only the tombstone remains →
//     refuse the replay and retry the delete (ReplayRefused).
const RestoredProducedField = "cx_restored_produced"

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
	// means an earlier restore claimed the envelope and MAY have produced it.
	// Listed so a lingering claimed envelope is visible to the operator, not a
	// mystery row.
	RestoredAt string `json:"cx_restored_at,omitempty"`
	// RestoredProduced is the produced-stamp (RestoredProducedField): non-empty
	// means the bus provably accepted the produce and only the tombstone
	// remains. A doc with RestoredAt set but RestoredProduced empty is a
	// STRANDED claim (see Restore) — listed so the operator can tell the two
	// lingering states apart.
	RestoredProduced string `json:"cx_restored_produced,omitempty"`
	Payload          string `json:"-"` // sealed token — NEVER serialized
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
var metadataFields = []string{"cx_event_id", "received_at", "lane", "identity_sha", "source_ip", "reason", RestoredAtField, RestoredProducedField}

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
			Index:            h.Index,
			ID:               h.ID,
			EventID:          eventID,
			ReceivedAt:       str("received_at"),
			Lane:             str("lane"),
			IdentitySha:      str("identity_sha"),
			SourceIP:         str("source_ip"),
			Reason:           str("reason"),
			RestoredAt:       str(RestoredAtField),
			RestoredProduced: str(RestoredProducedField),
			Payload:          str(processors.QuarantinePayloadField),
			SeqNo:            h.SeqNo,
			PrimaryTerm:      h.PrimaryTerm,
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
	// MarkProduced stamps RestoredProducedField on the envelope doc AFTER the
	// bus durably accepted a guarded produce and BEFORE the tombstone — the
	// persistent fact that lets a later run distinguish "produce landed, only
	// the tombstone remains" (safe to finish) from a stranded claim (preserved,
	// never tombstoned). Required for guarded lanes, same fail-closed rule as
	// Claim: without it every crash-after-produce would strand its envelope.
	// No CAS needed — the claim CAS already made this run the doc's sole owner.
	MarkProduced func(ctx context.Context, index, id string) error
	// Unclaim clears the claim stamp after the bus REFUSED the produce (the
	// event is provably not in the canonical store), so the envelope stays
	// restorable. Best-effort: a failed rollback leaves a bare claim in place
	// and the next run STRANDS the envelope (preserved, neither re-produced
	// nor tombstoned — see ClaimStranded); it takes a produce failure AND a
	// rollback failure to reach that state.
	Unclaim func(ctx context.Context, index, id string) error
}

// RestoreResult counts one run's outcomes. Restored counts events accepted by
// the bus; DeleteFailed counts restored events whose tombstone failed (the
// doc lingers as noise — replays are refused or upsert, see Restore).
// ReplayRefused counts envelopes skipped by the replay guard (claimed AND
// provably produced by an earlier run, or lost to a concurrent run's CAS);
// ClaimStranded counts envelopes carrying a bare claim with no produced-stamp
// — a previous run died between the claim landing and the produce being
// proven, so they are preserved untouched (neither re-produced nor tombstoned;
// see Restore). UnclaimFailed counts claim rollbacks that failed after a
// refused produce (the envelope will strand, not retry). MarkProducedFailed
// counts produced-stamps that failed after a successful produce (harmless if
// the tombstone right after succeeds; otherwise the envelope strands instead
// of auto-tombstoning). Aborted counts envelopes never attempted because ctx
// was cancelled mid-batch — they stay untouched (no claim, no tombstone) and
// restore on the next run.
type RestoreResult struct {
	Restored           int
	Failed             int
	Deleted            int
	DeleteFailed       int
	ReplayRefused      int
	ClaimStranded      int
	UnclaimFailed      int
	MarkProducedFailed int
	Aborted            int
}

// Restore unseals and re-injects each doc, then tombstones it. Per-doc
// failures are counted and never abort the batch; a cancelled/expired ctx DOES
// abort it (counted in Aborted) — the guarded claim is a persistent
// side-effect, and taking it with a ctx the remaining steps will refuse is how
// an envelope gets stranded with a bare claim, needing manual adjudication
// (H9). Callers therefore run Restore on a context detached from the client
// connection (see handleQuarantineReattribute).
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
//     with at-most-once produce and a two-phase mark: each envelope is claimed
//     via CAS before its single produce, the bus's acceptance is stamped back
//     (MarkProduced) before the tombstone, an envelope carrying claim+stamp
//     only gets its tombstone retried, an envelope carrying a BARE claim is
//     preserved untouched (ClaimStranded — the produce outcome is unknowable,
//     so neither re-producing nor tombstoning is safe), and a claim is rolled
//     back only when the bus refused the event outright.
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
			if d.RestoredProduced == "" {
				// BARE claim: the run that claimed this envelope died before
				// the produced-stamp landed — anywhere from "never called
				// Produce" (a crash right after the claim CAS) to "the bus
				// accepted but the stamp write was lost". The produce outcome
				// is UNKNOWABLE from here: re-producing could duplicate a
				// canonical ClickHouse row (no id dedup — irreversible), and
				// tombstoning could delete a flow that never reached the bus
				// (the pre-fix silent-loss bug: a crash between Claim and
				// Produce lost the event with zero failures recorded). Do
				// NEITHER — preserve the envelope, sealed payload intact and
				// operator-visible (the list shows cx_restored_at with no
				// cx_restored_produced), for manual adjudication via the
				// reveal path. At-most-once holds; custody holds.
				res.ClaimStranded++
				continue
			}
			// Claim + produced-stamp: the bus provably accepted this event
			// and only the tombstone failed. At-most-once for canonical flow
			// data: never produce again — finish the tombstone instead.
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
			if deps.Claim == nil || deps.MarkProduced == nil {
				// Fail closed: a guarded produce without the full two-phase
				// replay guard would reopen the duplication path (no Claim)
				// or strand every crash-after-produce envelope (no
				// MarkProduced).
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
					// The claim sticks with no produced-stamp: the next run
					// preserves the envelope as ClaimStranded (indeterminate
					// produce — neither re-produced nor tombstoned).
					res.UnclaimFailed++
				}
				res.Aborted += len(docs) - i - 1
				break
			}
			if guarded {
				// The bus refused, so the event is NOT in ClickHouse — roll
				// the claim back so the envelope stays restorable. If the
				// rollback also fails, the bare claim sticks and the next run
				// preserves the envelope as ClaimStranded (it takes BOTH
				// failures to get there), surfaced via UnclaimFailed.
				if deps.Unclaim == nil || deps.Unclaim(ctx, d.Index, d.ID) != nil {
					res.UnclaimFailed++
				}
			}
			continue
		}
		res.Restored++
		if guarded {
			// Second phase of the replay mark: persist "the bus accepted it"
			// BEFORE the tombstone, so a failed/crashed tombstone leaves a
			// doc a later run can safely finish (ReplayRefused + delete)
			// instead of stranding it as indeterminate. A failed stamp is
			// deliberately non-fatal: if the delete below succeeds the stamp
			// is moot, and if both fail the envelope strands — operator
			// noise, never loss or duplication. Counted (§10) so neither
			// outcome is silent.
			if err := deps.MarkProduced(ctx, d.Index, d.ID); err != nil {
				res.MarkProducedFailed++
			}
		}
		if err := deps.Delete(ctx, d.Index, d.ID); err != nil {
			res.DeleteFailed++
		} else {
			res.Deleted++
		}
	}
	return res
}
