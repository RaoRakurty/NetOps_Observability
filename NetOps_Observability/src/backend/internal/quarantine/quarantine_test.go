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
