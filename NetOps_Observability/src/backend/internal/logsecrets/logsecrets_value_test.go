// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logsecrets

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/credscrub"
)

// A fabricated community, built at run time.
var configured = "fixture-comm-" + strings.Repeat("q", 6)

func scrubberFor(t *testing.T, values ...string) *credscrub.Scrubber {
	t.Helper()
	s := credscrub.New(func(context.Context) ([]string, error) { return values, nil })
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// The three ConfD session records of one SNMP poll, as the packs stored them
// before the parse fix: the community is the session's "user" everywhere.
func confdSessionDoc(user string) string {
	return `{"hostname":"vEdge-20","appname":"confd","time_received_ns":1762657500123456789,` +
		`"event_type":"audit_session_groups","event_category":"management_audit",` +
		`"audit_user":"` + user + `","audit_action":"groups_assigned","session_id":"49119",` +
		`"title":"Session groups assigned on vEdge-20 to ` + user + `",` +
		`"summary":"Session of ` + user + ` given groups basic",` +
		`"correlation_key":"audit:vEdge-20:groups:49119","dedup_key":"vEdge-20|confd|audit_session_groups",` +
		`"message":"audit user: ` + user + `/49119 assigned to groups: basic",` +
		`"message_original":"<190>Nov 11 09:00:01 vEdge-20 confd[812]: audit user: ` + user + `/49119 assigned to groups: basic",` +
		`"structured_data":{"meta":[{"who":"` + user + `"}]}}`
}

func TestStripSourceMasksAConfiguredCommunityInEveryField(t *testing.T) {
	out, err := StripSource(json.RawMessage(confdSessionDoc(configured)), scrubberFor(t, configured))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, configured) {
		t.Fatalf("the community survived: %s", s)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for field, want := range map[string]string{
		"audit_user":       "***",
		"title":            "Session groups assigned on vEdge-20 to ***",
		"summary":          "Session of *** given groups basic",
		"message":          "audit user: ***/49119 assigned to groups: basic",
		"message_original": "<190>Nov 11 09:00:01 vEdge-20 confd[812]: audit user: ***/49119 assigned to groups: basic",
		"hostname":         "vEdge-20",
		"session_id":       "49119",
	} {
		if doc[field] != want {
			t.Errorf("%s = %q, want %q", field, doc[field], want)
		}
	}
	if !strings.Contains(s, `"time_received_ns":1762657500123456789`) {
		t.Errorf("a number lost its precision: %s", s)
	}
	if !strings.Contains(s, `"who":"***"`) {
		t.Errorf("a nested value was not masked: %s", s)
	}
}

// The same record for a person keeps the person (owner D7): only a configured
// value is masked.
func TestStripSourceKeepsAHumanSessionUser(t *testing.T) {
	doc := confdSessionDoc("fixture-person")
	out, err := StripSource(json.RawMessage(doc), scrubberFor(t, configured))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != doc {
		t.Fatalf("a document without a configured value changed:\n got %s\nwant %s", out, doc)
	}
}

func TestStripSearchResponseMasksHitsAndAggregationBuckets(t *testing.T) {
	body := `{"took":2,"hits":{"total":{"value":1},"hits":[{"_index":"netops-syslog-acme-2026.11.11","_id":"1","_source":` +
		confdSessionDoc(configured) + `}]},"aggregations":{"users":{"buckets":[{"key":"` + configured + `","doc_count":3},{"key":"fixture-person","doc_count":1}]},"routine":{"doc_count":12}}}`
	out, err := StripSearchResponse([]byte(body), scrubberFor(t, configured))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, configured) {
		t.Fatalf("the community survived: %s", s)
	}
	for _, want := range []string{`"took":2`, `"value":1`, `"fixture-person"`, `"doc_count":12`, `netops-syslog-acme-2026.11.11`} {
		if !strings.Contains(s, want) {
			t.Errorf("lost %s: %s", want, s)
		}
	}
}

func TestStripSearchResponseMasksAggregationsWithoutHits(t *testing.T) {
	body := `{"aggregations":{"u":{"buckets":[{"key":"` + configured + `"}]}}}`
	out, err := StripSearchResponse([]byte(body), scrubberFor(t, configured))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), configured) {
		t.Fatalf("the community survived: %s", out)
	}
}

// Nothing to mask: the very bytes the store sent, so no caller can learn the set
// by watching other text change.
func TestStripWithAScrubberLeavesOtherDocumentsByteIdentical(t *testing.T) {
	vm := scrubberFor(t, configured, "public")
	for _, doc := range []string{
		`{ "z":1.0,  "a":"<b>", "message":"publicity is not a community" }`,
		`{"message":"fixture-comm-qqqqq is one q short"}`,
	} {
		out, err := StripSource(json.RawMessage(doc), vm)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != doc {
			t.Errorf("got %s want %s", out, doc)
		}
	}
	body := `{"took":3,  "hits":{"hits":[{"_source":{"message":"x"}}]}}`
	out, err := StripSearchResponse([]byte(body), vm)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != body {
		t.Errorf("rewrote a clean body: %s", out)
	}
}

// Default-closed holds for the by-value pass too.
func TestStripRefusesAValueBearingBodyItCannotParse(t *testing.T) {
	vm := scrubberFor(t, configured)
	if _, err := StripSource(json.RawMessage(`{"message":"`+configured), vm); err == nil {
		t.Error("truncated _source must be refused")
	}
	if _, err := StripSearchResponse([]byte(`{"hits":{"hits":[{"_source":{"m":"`+configured), vm); err == nil {
		t.Error("truncated response must be refused")
	}
}

// The pattern layer reaches the ConfD SNMP session line even with no scrubber
// and a community configured nowhere: the fast path must not skip it.
func TestStripSourceMasksTheConfdSNMPSessionUserWithoutAScrubber(t *testing.T) {
	unconfigured := "fixture-other-" + strings.Repeat("z", 4)
	raw := json.RawMessage(`{"hostname":"vEdge-20","message":"audit user: ` + unconfigured +
		`/49119 created new session via snmp from 127.0.0.1:54873 with udp"}`)
	out, err := StripSource(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), unconfigured) {
		t.Fatalf("the via-snmp session user survived: %s", out)
	}
	if !strings.Contains(string(out), "audit user: ***/49119 created new session via snmp") {
		t.Fatalf("unexpected masking: %s", out)
	}
}

// A typed-nil scrubber (no credential store wired) is a no-op, not a panic.
func TestStripWithATypedNilScrubber(t *testing.T) {
	var vm *credscrub.Scrubber
	doc := confdSessionDoc(configured)
	out, err := StripSource(json.RawMessage(doc), vm)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != doc {
		t.Fatalf("a nil scrubber changed the document: %s", out)
	}
}
