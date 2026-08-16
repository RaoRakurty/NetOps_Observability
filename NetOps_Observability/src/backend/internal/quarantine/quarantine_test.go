package quarantine

// quarantine_test.go — F-11 slice 4 (design doc D5): the pure logic behind the
// operator quarantine workflow. The invariants pinned here:
//
//   - identity resolution is AUTHORITATIVE (live inventory only) and refuses
//     unknown, platform-only and ambiguous identities distinctly;
//   - the restore loop is fail-safe per document: an unsealable/foreign/
//     unroutable doc is counted failed and NEVER tombstoned, and a produce
//     failure never deletes the quarantine doc (delete only after the event is
//     durably re-injected);
//   - the sealed payload can never appear in a serialized Doc.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"netops/backend/processors"
)

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestResolveIdentity(t *testing.T) {
	rows := []IdentityRow{
		{Identity: "edge-1", Tenant: "acme"},
		{Identity: "10.9.9.9", Tenant: "acme"},
		{Identity: "shared-nat", Tenant: "acme"},
		{Identity: "shared-nat", Tenant: "globex"},
		{Identity: "lab-sw", Tenant: ""},
	}

	tenant, matched, err := ResolveIdentity(rows, shaOf("edge-1"))
	if err != nil {
		t.Fatalf("known identity: %v", err)
	}
	if tenant != "acme" || matched != 1 {
		t.Fatalf("known identity: tenant=%q matched=%d, want acme/1", tenant, matched)
	}

	// The sha is hex — accept either case (operators paste from different UIs).
	if _, _, err := ResolveIdentity(rows, strings.ToUpper(shaOf("edge-1"))); err != nil {
		t.Fatalf("uppercase sha refused: %v", err)
	}

	if _, _, err := ResolveIdentity(rows, shaOf("never-seen")); !errors.Is(err, ErrIdentityUnknown) {
		t.Fatalf("unknown identity: err=%v, want ErrIdentityUnknown", err)
	}
	if _, _, err := ResolveIdentity(rows, shaOf("shared-nat")); !errors.Is(err, ErrIdentityAmbiguous) {
		t.Fatalf("ambiguous identity: err=%v, want ErrIdentityAmbiguous", err)
	}
	// A registry hit onto the platform tenant ("") is NOT a re-attribution
	// target: the caller must assign the device to a real tenant first.
	if _, _, err := ResolveIdentity(rows, shaOf("lab-sw")); !errors.Is(err, ErrIdentityUnassigned) {
		t.Fatalf("platform-only identity: err=%v, want ErrIdentityUnassigned", err)
	}
}

func TestTopicForLane(t *testing.T) {
	want := map[string]string{
		"syslog":   "netops.syslog",
		"snmptrap": "netops.snmptrap",
		"flows":    "netops.flows",
	}
	for lane, topic := range want {
		got, ok := TopicForLane(lane)
		if !ok || got != topic {
			t.Errorf("TopicForLane(%q) = %q,%v want %q,true", lane, got, ok, topic)
		}
	}
	// Only the device-attribution lanes quarantine; anything else must refuse
	// rather than guess a topic.
	for _, lane := range []string{"applogs", "cloudlogs", "", "SYSLOG; DROP"} {
		if _, ok := TopicForLane(lane); ok {
			t.Errorf("TopicForLane(%q) resolved a topic for a non-quarantine lane", lane)
		}
	}
}

// The unseal context must be byte-identical to the one the generated router
// config sealed under (processors/quarantine.go) — the MAC binds it.
func TestSealContextMatchesTheEdge(t *testing.T) {
	c := SealContext()
	if c.Tenant != processors.QuarantineScope {
		t.Errorf("Tenant = %q, want %q", c.Tenant, processors.QuarantineScope)
	}
	if c.ProcessorID != processors.QuarantineProcessorID {
		t.Errorf("ProcessorID = %q, want %q", c.ProcessorID, processors.QuarantineProcessorID)
	}
	if c.Field != processors.QuarantinePayloadField {
		t.Errorf("Field = %q, want %q", c.Field, processors.QuarantinePayloadField)
	}
	if c.DataType != "quarantine" {
		t.Errorf("DataType = %q, want quarantine", c.DataType)
	}
}

func TestRestoreEvent(t *testing.T) {
	ev, err := RestoreEvent([]byte(`{"message":"m","hostname":"edge-1","tenant_id":"","tenant_registry":"miss"}`), "acme", "e1")
	if err != nil {
		t.Fatal(err)
	}
	if ev["tenant_id"] != "acme" {
		t.Errorf("tenant_id = %v, want acme", ev["tenant_id"])
	}
	if _, present := ev["tenant_registry"]; present {
		t.Error("tenant_registry survived the restore — the re-injected event would re-quarantine")
	}
	if ev["cx_event_id"] != "e1" {
		t.Errorf("cx_event_id = %v, want e1 (id_key idempotency)", ev["cx_event_id"])
	}
	if ev["cx_restored_from"] != "quarantine" {
		t.Errorf("cx_restored_from = %v, want quarantine", ev["cx_restored_from"])
	}
	if ev["message"] != "m" || ev["hostname"] != "edge-1" {
		t.Errorf("original fields were not preserved: %v", ev)
	}

	// Non-object plaintext is refused, never wrapped or guessed at.
	if _, err := RestoreEvent([]byte(`"just a string"`), "acme", "e1"); err == nil {
		t.Error("non-object plaintext accepted")
	}
	if _, err := RestoreEvent([]byte(`{broken`), "acme", "e1"); err == nil {
		t.Error("malformed plaintext accepted")
	}
}

const searchReply = `{
  "hits": {
    "total": {"value": 3, "relation": "eq"},
    "hits": [
      {"_index": "netops-quarantine-2026.08.12", "_id": "d1", "_source": {
        "cx_event_id": "e1", "received_at": "2026-08-12T01:00:00Z", "lane": "syslog",
        "identity_sha": "aa", "source_ip": "10.0.0.9", "reason": "TENANT_UNATTRIBUTABLE",
        "cx_quarantine_payload": "<enc:v1:quarantine:1:aa:bb:cc>"}},
      {"_index": "netops-quarantine-2026.08.11", "_id": "d2", "_source": {
        "cx_event_id": "e2", "received_at": "2026-08-11T01:00:00Z", "lane": "flows",
        "identity_sha": "bb", "reason": "TENANT_UNATTRIBUTABLE"}}
    ]
  },
  "aggregations": {"oldest_received": {"value": 1754960400000, "value_as_string": "2026-08-11T01:00:00.000Z"}}
}`

func TestParseSearch(t *testing.T) {
	docs, total, oldest, err := ParseSearch(strings.NewReader(searchReply))
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if oldest != "2026-08-11T01:00:00.000Z" {
		t.Errorf("oldest = %q", oldest)
	}
	if len(docs) != 2 {
		t.Fatalf("docs = %d, want 2", len(docs))
	}
	d := docs[0]
	if d.Index != "netops-quarantine-2026.08.12" || d.ID != "d1" || d.EventID != "e1" ||
		d.Lane != "syslog" || d.IdentitySha != "aa" || d.SourceIP != "10.0.0.9" ||
		d.Reason != "TENANT_UNATTRIBUTABLE" || d.ReceivedAt != "2026-08-12T01:00:00Z" {
		t.Errorf("doc[0] parsed wrong: %+v", d)
	}
	if d.Payload != "<enc:v1:quarantine:1:aa:bb:cc>" {
		t.Errorf("payload not captured for the restore path: %q", d.Payload)
	}
	if docs[1].Payload != "" || docs[1].SourceIP != "" {
		t.Errorf("absent fields must stay empty: %+v", docs[1])
	}
}

// The metadata list serializes Doc directly, so the type itself must be unable
// to leak the sealed payload.
func TestDocJSONNeverCarriesThePayload(t *testing.T) {
	b, err := json.Marshal(Doc{
		Index: "netops-quarantine-2026.08.12", ID: "d1", EventID: "e1",
		ReceivedAt: "2026-08-12T01:00:00Z", Lane: "syslog", IdentitySha: "aa",
		Reason: "TENANT_UNATTRIBUTABLE", Payload: "<enc:v1:quarantine:1:iv:ct:mac>",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "enc:") || strings.Contains(strings.ToLower(s), "payload") {
		t.Fatalf("serialized Doc leaks the sealed payload: %s", s)
	}
	for _, want := range []string{"cx_event_id", "received_at", "lane", "identity_sha", "reason", "_index"} {
		if !strings.Contains(s, want) {
			t.Errorf("serialized Doc missing metadata field %q: %s", want, s)
		}
	}
}

func TestRestoreOrchestration(t *testing.T) {
	docs := []Doc{
		{Index: "netops-quarantine-2026.08.12", ID: "d1", EventID: "e1", Lane: "syslog", Payload: "tok-good"},
		{Index: "netops-quarantine-2026.08.12", ID: "d2", EventID: "e2", Lane: "syslog", Payload: "tok-bad"},
		// A doc claiming a non-quarantine index must never be tombstoned — the
		// delete path would otherwise reach arbitrary indices (zero trust on
		// the search response).
		{Index: "netops-syslog-acme-2026.08.12", ID: "d3", EventID: "e3", Lane: "syslog", Payload: "tok-good"},
		{Index: "netops-quarantine-2026.08.12", ID: "d4", EventID: "e4", Lane: "not-a-lane", Payload: "tok-good"},
		// Without the original cx_event_id a replay could not upsert — refuse
		// rather than break idempotency.
		{Index: "netops-quarantine-2026.08.12", ID: "d5", EventID: "", Lane: "syslog", Payload: "tok-good"},
	}
	var produced []string
	var deleted []string
	deps := RestoreDeps{
		Unseal: func(_ context.Context, tok string) (string, error) {
			if tok == "tok-good" {
				return `{"message":"m"}`, nil
			}
			return "", errors.New("mac refused")
		},
		Produce: func(_ context.Context, topic, key string, ev map[string]any) error {
			produced = append(produced, topic+"|"+key+"|"+ev["cx_event_id"].(string))
			return nil
		},
		Delete: func(_ context.Context, index, id string) error {
			deleted = append(deleted, index+"/"+id)
			return nil
		},
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if res.Restored != 1 || res.Failed != 4 {
		t.Fatalf("restored=%d failed=%d, want 1/4", res.Restored, res.Failed)
	}
	if res.Deleted != 1 || res.DeleteFailed != 0 {
		t.Fatalf("deleted=%d delete_failed=%d, want 1/0", res.Deleted, res.DeleteFailed)
	}
	if len(produced) != 1 || produced[0] != "netops.syslog|acme|e1" {
		t.Fatalf("produced = %v", produced)
	}
	if len(deleted) != 1 || deleted[0] != "netops-quarantine-2026.08.12/d1" {
		t.Fatalf("deleted = %v", deleted)
	}
}

// A produce failure means the event is NOT re-injected — deleting the
// quarantine doc then would be data loss, so the tombstone must not happen.
func TestRestoreProduceFailureKeepsTheDoc(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "d1", EventID: "e1", Lane: "syslog", Payload: "tok"}}
	deleteCalled := false
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"a":1}`, nil },
		Produce: func(context.Context, string, string, map[string]any) error { return errors.New("bus down") },
		Delete:  func(context.Context, string, string) error { deleteCalled = true; return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if res.Restored != 0 || res.Failed != 1 {
		t.Fatalf("restored=%d failed=%d, want 0/1", res.Restored, res.Failed)
	}
	if deleteCalled {
		t.Fatal("DELETE was issued for an event that never reached the bus — that is data loss")
	}
}

// FAILING-FIRST (2026-08-14 verification): ClickHouse is the canonical flow
// store (vector-router clickhouse_flows sink → netops.flows, ENGINE=MergeTree,
// no cx_event_id column — skip_unknown_fields drops it — and no id-based
// dedup analogue to the OS sinks' id_key). Re-producing a flows event is
// therefore NOT an upsert: every extra Produce lands a duplicate canonical
// row. A lingering envelope (tombstone delete failed) must never be produced
// a second time, however many times the operator re-runs the restore.
func TestRestoreFlowsNeverProducesTheSameEventTwice(t *testing.T) {
	doc := Doc{Index: "netops-quarantine-2026.08.12", ID: "d1", EventID: "e1", Lane: "flows", Payload: "tok"}
	produced := 0
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Produce: func(context.Context, string, string, map[string]any) error { produced++; return nil },
		// The tombstone fails, so the SAME doc is still in the index when the
		// operator retries the restore.
		Delete: func(context.Context, string, string) error { return errors.New("os hiccup") },
	}
	_ = Restore(context.Background(), deps, []Doc{doc}, "acme")
	_ = Restore(context.Background(), deps, []Doc{doc}, "acme")
	if produced > 1 {
		t.Fatalf("a quarantined FLOW was produced %d times — duplicate rows in the canonical ClickHouse store", produced)
	}
}

// The flows replay guard, happy path: claim (CAS on the doc's search-time
// seq_no/primary_term) strictly BEFORE the produce, tombstone after — and the
// OS lanes' behavior is untouched (no claim calls at all).
func TestRestoreFlowsClaimProtocol(t *testing.T) {
	docs := []Doc{
		{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok", SeqNo: 7, PrimaryTerm: 2},
		{Index: "netops-quarantine-2026.08.12", ID: "s1", EventID: "e2", Lane: "syslog", Payload: "tok"},
	}
	var calls []string
	deps := RestoreDeps{
		Unseal: func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Claim: func(_ context.Context, index, id string, seqNo, primaryTerm int64) error {
			if index != "netops-quarantine-2026.08.12" || id != "f1" || seqNo != 7 || primaryTerm != 2 {
				t.Errorf("claim coordinates wrong: %s/%s %d/%d", index, id, seqNo, primaryTerm)
			}
			calls = append(calls, "claim:"+id)
			return nil
		},
		Unclaim: func(_ context.Context, _, id string) error { calls = append(calls, "unclaim:"+id); return nil },
		Produce: func(_ context.Context, topic, _ string, ev map[string]any) error {
			calls = append(calls, "produce:"+topic+":"+ev["cx_event_id"].(string))
			return nil
		},
		Delete: func(_ context.Context, _, id string) error { calls = append(calls, "delete:"+id); return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if res.Restored != 2 || res.Deleted != 2 || res.Failed != 0 || res.ReplayRefused != 0 || res.UnclaimFailed != 0 {
		t.Fatalf("counts: %+v", res)
	}
	want := []string{
		"claim:f1", "produce:netops.flows:e1", "delete:f1", // guarded lane: claim strictly first
		"produce:netops.syslog:e2", "delete:s1", // OS lane: NO claim — id_key upsert is the guard
	}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("call order = %v, want %v", calls, want)
	}
}

// An envelope already carrying the claim stamp (an earlier run produced but
// its tombstone failed) is never produced again — only the tombstone is
// retried. This is the at-most-once contract that keeps the canonical
// ClickHouse store duplicate-free.
func TestRestoreFlowsAlreadyClaimedOnlyTombstones(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows",
		Payload: "tok", RestoredAt: "2026-08-14T01:00:00Z"}}
	var produced, unsealed bool
	var deleted []string
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { unsealed = true; return `{"bytes":42}`, nil },
		Claim:   func(context.Context, string, string, int64, int64) error { return nil },
		Produce: func(context.Context, string, string, map[string]any) error { produced = true; return nil },
		Delete:  func(_ context.Context, index, id string) error { deleted = append(deleted, index+"/"+id); return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if produced {
		t.Fatal("a claimed flows envelope was produced AGAIN — duplicate canonical row")
	}
	if unsealed {
		t.Error("no reason to unseal an envelope that will not be produced")
	}
	if res.ReplayRefused != 1 || res.Restored != 0 || res.Failed != 0 || res.Deleted != 1 {
		t.Fatalf("counts: %+v", res)
	}
	if len(deleted) != 1 || deleted[0] != "netops-quarantine-2026.08.12/f1" {
		t.Fatalf("tombstone not retried: %v", deleted)
	}
}

// A lost claim CAS means a CONCURRENT restore owns the envelope: this run must
// neither produce (duplicate) nor delete (stealing the winner's tombstone
// while its produce may still be in flight).
func TestRestoreFlowsClaimConflictDoesNothingElse(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok"}}
	var produced, deleted bool
	deps := RestoreDeps{
		Unseal: func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Claim: func(context.Context, string, string, int64, int64) error {
			return fmt.Errorf("wrapped: %w", ErrClaimConflict)
		},
		Produce: func(context.Context, string, string, map[string]any) error { produced = true; return nil },
		Delete:  func(context.Context, string, string) error { deleted = true; return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if produced || deleted {
		t.Fatalf("conflict must be a full stop: produced=%v deleted=%v", produced, deleted)
	}
	if res.ReplayRefused != 1 || res.Failed != 0 {
		t.Fatalf("counts: %+v", res)
	}
}

// A claim error that is NOT a CAS conflict (OS down, etc.) is a plain failure
// — no produce, no tombstone, envelope intact for a later run.
func TestRestoreFlowsClaimErrorFails(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok"}}
	var produced bool
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Claim:   func(context.Context, string, string, int64, int64) error { return errors.New("os down") },
		Produce: func(context.Context, string, string, map[string]any) error { produced = true; return nil },
		Delete:  func(context.Context, string, string) error { t.Error("tombstone without produce"); return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if produced || res.Failed != 1 || res.ReplayRefused != 0 {
		t.Fatalf("produced=%v counts=%+v", produced, res)
	}
}

// A refused produce rolls the claim back (the event is provably not in
// ClickHouse, so the envelope must stay restorable), and the doc is kept.
func TestRestoreFlowsProduceFailureRollsBackClaim(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok"}}
	var unclaimed, deleted bool
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Claim:   func(context.Context, string, string, int64, int64) error { return nil },
		Unclaim: func(context.Context, string, string) error { unclaimed = true; return nil },
		Produce: func(context.Context, string, string, map[string]any) error { return errors.New("bus down") },
		Delete:  func(context.Context, string, string) error { deleted = true; return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if !unclaimed {
		t.Fatal("claim was not rolled back after a refused produce — the envelope would be stranded")
	}
	if deleted {
		t.Fatal("DELETE was issued for an event that never reached the bus — data loss")
	}
	if res.Failed != 1 || res.UnclaimFailed != 0 {
		t.Fatalf("counts: %+v", res)
	}
}

// The double-failure window (produce refused AND rollback failed) must be
// loud: the envelope will be replay-refused next run, and the operator sees
// exactly how many envelopes are in that state.
func TestRestoreFlowsUnclaimFailureIsCounted(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok"}}
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Claim:   func(context.Context, string, string, int64, int64) error { return nil },
		Unclaim: func(context.Context, string, string) error { return errors.New("os down too") },
		Produce: func(context.Context, string, string, map[string]any) error { return errors.New("bus down") },
		Delete:  func(context.Context, string, string) error { t.Error("tombstone without produce"); return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if res.Failed != 1 || res.UnclaimFailed != 1 {
		t.Fatalf("counts: %+v", res)
	}
}

// A guarded lane without a Claim dependency fails CLOSED: producing a flow
// without the replay guard would reopen the duplication path.
func TestRestoreFlowsFailsClosedWithoutClaimDep(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok"}}
	var produced bool
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"bytes":42}`, nil },
		Produce: func(context.Context, string, string, map[string]any) error { produced = true; return nil },
		Delete:  func(context.Context, string, string) error { return nil },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if produced || res.Failed != 1 {
		t.Fatalf("produced=%v counts=%+v", produced, res)
	}
}

// The re-attribution search must request the CAS coordinates the claim
// conditions on.
func TestShaQueryRequestsSeqNoPrimaryTerm(t *testing.T) {
	q := ShaQuery("ab", 10)
	if v, ok := q["seq_no_primary_term"].(bool); !ok || !v {
		t.Fatalf("seq_no_primary_term missing from ShaQuery: %v", q)
	}
}

// A delete failure after a successful produce is reported, not hidden — the
// restore itself is idempotent (id_key upsert), so the leftover doc is noise,
// but the operator must see it.
func TestRestoreDeleteFailureIsCounted(t *testing.T) {
	docs := []Doc{{Index: "netops-quarantine-2026.08.12", ID: "d1", EventID: "e1", Lane: "syslog", Payload: "tok"}}
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"a":1}`, nil },
		Produce: func(context.Context, string, string, map[string]any) error { return nil },
		Delete:  func(context.Context, string, string) error { return errors.New("os down") },
	}
	res := Restore(context.Background(), deps, docs, "acme")
	if res.Restored != 1 || res.Deleted != 0 || res.DeleteFailed != 1 {
		t.Fatalf("got %+v, want restored=1 deleted=0 delete_failed=1", res)
	}
}

// ── H9: a client disconnect must never strand a claim ────────────────────────

// FAILING-FIRST (H9, 2026-08-15 review): Claim ignored ctx while Produce and
// Unclaim honoured it. When the request ctx died mid-batch (nginx's 120s read
// timeout, a closed tab) the claim landed, the produce was refused with
// context.Canceled, and the rollback was refused too — so the envelope sat
// "already restored". The NEXT restore run then replay-refused it and
// tombstoned it: the flow event was lost forever. A pre-cancelled ctx must
// touch NOTHING — no claim, no produce, no tombstone — so the next run
// restores the envelope normally.
func TestRestoreH9PreCancelledCtxTouchesNothing(t *testing.T) {
	doc := Doc{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok", SeqNo: 3, PrimaryTerm: 1}
	claims, produces, deletes := 0, 0, 0
	deps := RestoreDeps{
		Unseal:  func(context.Context, string) (string, error) { return `{"bytes":1}`, nil },
		Produce: func(ctx context.Context, _, _ string, _ map[string]any) error { produces++; return ctx.Err() },
		Delete:  func(context.Context, string, string) error { deletes++; return nil },
		Claim:   func(context.Context, string, string, int64, int64) error { claims++; return nil },
		Unclaim: func(ctx context.Context, _, _ string) error { return ctx.Err() },
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	res := Restore(cancelled, deps, []Doc{doc}, "acme")
	if claims != 0 || produces != 0 || deletes != 0 {
		t.Fatalf("cancelled ctx still had effects: claims=%d produces=%d deletes=%d", claims, produces, deletes)
	}
	if res.Aborted != 1 || res.Restored != 0 || res.Failed != 0 || res.ReplayRefused != 0 {
		t.Fatalf("res = %+v, want aborted=1 and nothing else", res)
	}
	// The next run (live ctx, same doc — RestoredAt still empty because no
	// claim ever landed) must restore normally, NOT tombstone a replay refusal.
	res = Restore(context.Background(), deps, []Doc{doc}, "acme")
	if res.ReplayRefused != 0 {
		t.Fatalf("next run replay-refused a never-claimed envelope: %+v", res)
	}
	if res.Restored != 1 || claims != 1 || produces != 1 || deletes != 1 {
		t.Fatalf("next run did not restore cleanly: res=%+v claims=%d produces=%d deletes=%d", res, claims, produces, deletes)
	}
}

// H9, second half: a ctx that dies DURING the batch. The ctx-shaped produce
// error is not "the bus refused" — the event may have reached the bus, so the
// claim must stay (no rollback that could double-produce) and the batch must
// stop before claiming any further envelope.
func TestRestoreH9ProduceCtxCancelAbortsBatch(t *testing.T) {
	docs := []Doc{
		{Index: "netops-quarantine-2026.08.12", ID: "f1", EventID: "e1", Lane: "flows", Payload: "tok", SeqNo: 1, PrimaryTerm: 1},
		{Index: "netops-quarantine-2026.08.12", ID: "f2", EventID: "e2", Lane: "flows", Payload: "tok", SeqNo: 2, PrimaryTerm: 1},
	}
	ctx, cancel := context.WithCancel(context.Background())
	claims, unclaims := 0, 0
	deps := RestoreDeps{
		Unseal: func(context.Context, string) (string, error) { return `{"bytes":1}`, nil },
		Produce: func(context.Context, string, string, map[string]any) error {
			cancel() // the client disconnects while the produce is in flight
			return context.Canceled
		},
		Delete:  func(context.Context, string, string) error { return nil },
		Claim:   func(context.Context, string, string, int64, int64) error { claims++; return nil },
		Unclaim: func(context.Context, string, string) error { unclaims++; return nil },
	}
	res := Restore(ctx, deps, docs, "acme")
	if unclaims != 0 {
		t.Fatal("rolled back a claim after a ctx-cancelled produce — the event may be in ClickHouse; unclaiming reopens the duplication path")
	}
	if claims != 1 {
		t.Fatalf("claimed %d envelopes after the ctx died, want 1 (the in-flight one only)", claims)
	}
	if res.Failed != 1 || res.UnclaimFailed != 1 || res.Aborted != 1 {
		t.Fatalf("res = %+v, want failed=1 unclaim_failed=1 aborted=1", res)
	}
}
