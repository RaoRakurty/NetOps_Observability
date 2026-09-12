// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package processors

// reallogs_test.go — the Sensitive Data Scanner acceptance suite, run against
// the ACTUAL document shapes this platform indexes.
//
// The fixtures below were captured from the running stack on 2026-07-31
// (netops-syslog-*, netops-applogs-*, netops-snmptrap-*) and then seeded with
// the sensitive values a customer environment carries. That combination is the
// point: synthetic samples proved the regexes worked in isolation, but the
// FIRST bug a real document exposed was that sensitive values do not live in
// `message` — a trap's MAC sits in nested `fields.mac`, an address in `host`.
// A detector that only reads `message` therefore did nothing, which is exactly
// what "the managed rules don't match anything" looked like from the UI.
//
// Every managed rule, every matcher and every action is exercised here.

import (
	"encoding/json"
	"strings"
	"testing"
)

// realSyslog is a live Cisco-IOS-style document (parser_id ios_style.v1).
const realSyslog = `{
  "tenant_id": "acme",
  "appname": "SYS",
  "event_type": "logginghost_startstop",
  "facility": "SYS",
  "host": "homedepot-hq-core-sw01",
  "hostname": "homedepot-hq-core-sw01",
  "message": "- - - %SYS-6-LOGGINGHOST_STARTSTOP: admin jsmith@homedepot.com from 10.70.245.12 community=public",
  "normalized_severity": "notice",
  "parser_id": "ios_style.v1",
  "severity": "notice",
  "ts": 1785500000000
}`

// realTrap is a live Arista MAC-move trap: note the NESTED fields.mac and the
// IPv4 in `host` — neither is in `message`.
const realTrap = `{
  "tenant_id": "acme",
  "_signal": "snmptrap",
  "category": "layer2",
  "device": "leaf1",
  "event_type": "arista_bridge_ext_mac_move",
  "fields": {"bridge_port": "1", "mac": "AA:C1:AB:E2:57:01", "vlan": "1006"},
  "host": "172.40.40.21",
  "hostname": "leaf1",
  "message": "aristaBridgeExtMacMove 1.3.6.1.4.1.30065.3.2.0.2 sysUpTime=14072613 dot1qTpFdbPort=1",
  "ts": 1785500000000
}`

// realApplog is a live container log line, seeded with the secrets an
// application actually leaks into logs.
const realApplog = `{
  "tenant_id": "acme",
  "component": "http",
  "container_name": "netops-api-1",
  "image": "netops-api",
  "level": "info",
  "message": "POST /v1/pay card=4111 1111 1111 1111 ssn=123-45-6789 auth=Bearer sk-live-9f8e7d6c5b4a3f2e1d",
  "password": "hunter2",
  "upstream": "https://svc:s3cr3tpw@billing.internal/charge",
  "ts": 1785500000000
}`

func mustEvent(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return m
}

// run applies one processor to a fixture and returns the shaped event.
func run(t *testing.T, r Processor, lane, raw string) SimResult {
	t.Helper()
	r.TenantID, r.Lane, r.Enabled = "acme", lane, true
	if err := r.Validate(); err != nil {
		t.Fatalf("processor must validate: %v (%+v)", err, r)
	}
	return SimulateChain([]Processor{r}, lane, "acme", mustEvent(t, raw))
}

func str(t *testing.T, ev map[string]any, path string) string {
	t.Helper()
	v, _ := getPath(ev, path)
	return toStr(v)
}

// ── every managed rule, against data that actually contains its target ──────

func TestManagedRulesAgainstRealLogs(t *testing.T) {
	cases := []struct {
		rule    string // managed rule id
		lane    string
		fixture string
		field   string // "" → FieldAll (the clone default)
		// wantGone must NOT survive; wantToken must appear.
		wantGone  string
		wantToken string
	}{
		{"email", "syslog", realSyslog, "", "jsmith@homedepot.com", "[EMAIL]"},
		{"ipv4", "syslog", realSyslog, "", "10.70.245.12", "[IP]"},
		{"snmp_community", "syslog", realSyslog, "", "community=public", "[REDACTED]"},
		// The trap's MAC is in fields.mac — only a whole-event sweep finds it.
		{"mac", "snmptrap", realTrap, "", "AA:C1:AB:E2:57:01", "[MAC]"},
		{"ipv4", "snmptrap", realTrap, "", "172.40.40.21", "[IP]"},
		{"credit_card", "applogs", realApplog, "", "4111 1111 1111 1111", "[CARD]"},
		{"us_ssn", "applogs", realApplog, "", "123-45-6789", "[SSN]"},
		{"bearer_token", "applogs", realApplog, "", "sk-live-9f8e7d6c5b4a3f2e1d", "[TOKEN]"},
		{"password_field", "applogs", realApplog, "", "hunter2", "[REDACTED]"},
		{"basic_auth_url", "applogs", realApplog, "", "s3cr3tpw", "[REDACTED]"},
	}
	for _, c := range cases {
		t.Run(c.rule+"/"+c.lane, func(t *testing.T) {
			mr, ok := ManagedRuleByID(c.rule)
			if !ok {
				t.Fatalf("managed rule %q is missing from the catalog", c.rule)
			}
			p, ok := CloneManagedRule(mr.ID, c.lane, c.field)
			if !ok {
				t.Fatalf("clone failed for %q", c.rule)
			}
			res := run(t, p, c.lane, c.fixture)
			blob, _ := json.Marshal(res.Event)
			got := string(blob)
			if strings.Contains(got, c.wantGone) {
				t.Errorf("%s LEAKED %q\nevent: %s", c.rule, c.wantGone, got)
			}
			if !strings.Contains(got, c.wantToken) {
				t.Errorf("%s did not write its token %q\nevent: %s", c.rule, c.wantToken, got)
			}
			if len(res.Applied) == 0 {
				t.Errorf("%s reported nothing applied — the preview would look broken", c.rule)
			}
		})
	}
}

// A sweep must never rewrite the fields the pipeline itself owns.
func TestSweepPreservesPipelineFields(t *testing.T) {
	// ipv4 would happily match a tenant id or a routing field if allowed near one.
	ev := mustEvent(t, realTrap)
	ev["tenant_seg"] = "10.0.0.1"
	ev["log_index_base"] = "syslog"
	p, _ := CloneManagedRule("ipv4", "snmptrap", "")
	p.TenantID, p.Enabled = "acme", true
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	res := SimulateChain([]Processor{p}, "snmptrap", "acme", ev)
	if res.Event["tenant_id"] != "acme" {
		t.Fatalf("tenant_id must survive a sweep: %v", res.Event["tenant_id"])
	}
	if res.Event["tenant_seg"] != "10.0.0.1" {
		t.Fatalf("pipeline-owned tenant_seg must survive a sweep: %v", res.Event["tenant_seg"])
	}
	if res.Event["log_index_base"] != "syslog" {
		t.Fatalf("index routing must survive a sweep: %v", res.Event["log_index_base"])
	}
	// …while the payload IS redacted.
	if strings.Contains(str(t, res.Event, "host"), "172.40.40.21") {
		t.Fatal("the sweep must still redact the payload")
	}
}

// ── every ACTION, on a real document ────────────────────────────────────────

func TestEveryActionOnRealLogs(t *testing.T) {
	t.Run("redact_field", func(t *testing.T) {
		res := run(t, Processor{Type: TypeRedactField, Field: "hostname", Replacement: "[HOST]"}, "syslog", realSyslog)
		if res.Event["hostname"] != "[HOST]" {
			t.Fatalf("got %v", res.Event["hostname"])
		}
	})
	t.Run("redact_pattern", func(t *testing.T) {
		res := run(t, Processor{Type: TypeRedactPattern, Field: "message",
			PatternKind: PatternBuiltin, Pattern: "email", Replacement: "[EMAIL]"}, "syslog", realSyslog)
		if strings.Contains(str(t, res.Event, "message"), "jsmith@") {
			t.Fatalf("got %v", res.Event["message"])
		}
	})
	t.Run("mask", func(t *testing.T) {
		res := run(t, Processor{Type: TypeMask, Field: "password", KeepLast: 2}, "applogs", realApplog)
		got := str(t, res.Event, "password")
		if got != "*****r2" && !strings.HasSuffix(got, "r2") {
			t.Fatalf("mask must keep the last 2: %q", got)
		}
		if strings.Contains(got, "hunte") {
			t.Fatalf("mask leaked the head: %q", got)
		}
	})
	t.Run("hash", func(t *testing.T) {
		res := run(t, Processor{Type: TypeHash, Field: "hostname"}, "syslog", realSyslog)
		got := str(t, res.Event, "hostname")
		if len(got) != 16 || got == "homedepot-hq-core-sw01" {
			t.Fatalf("hash must produce a 16-char digest, got %q", got)
		}
		// Stable: the same input always yields the same token (joinable).
		res2 := run(t, Processor{Type: TypeHash, Field: "hostname"}, "syslog", realSyslog)
		if str(t, res2.Event, "hostname") != got {
			t.Fatal("hash must be stable so operators can still correlate")
		}
	})
	t.Run("tag", func(t *testing.T) {
		res := run(t, Processor{Type: TypeTag, Field: FieldAll,
			PatternKind: PatternBuiltin, Pattern: "credit_card", Replacement: "PCI"}, "applogs", realApplog)
		tags, _ := res.Event[TagField].([]any)
		if len(tags) != 1 || tags[0] != "PCI" {
			t.Fatalf("tag must stamp a marker: %v", res.Event[TagField])
		}
		// DETECT-ONLY: the value must be untouched.
		if !strings.Contains(str(t, res.Event, "message"), "4111 1111 1111 1111") {
			t.Fatal("tag must NOT modify the value — it is the detect-only mode")
		}
	})
	t.Run("drop_field", func(t *testing.T) {
		res := run(t, Processor{Type: TypeDropField, Field: "password"}, "applogs", realApplog)
		if _, ok := res.Event["password"]; ok {
			t.Fatal("drop_field must remove the key")
		}
	})
	t.Run("set_field", func(t *testing.T) {
		res := run(t, Processor{Type: TypeSetField, Field: "severity", Value: "audited"}, "syslog", realSyslog)
		if res.Event["severity"] != "audited" {
			t.Fatalf("got %v", res.Event["severity"])
		}
	})
	t.Run("drop_event", func(t *testing.T) {
		res := run(t, Processor{Type: TypeDropEvent,
			Match: &Match{Field: "severity", Op: MatchEquals, Value: "notice"}}, "syslog", realSyslog)
		if !res.Dropped {
			t.Fatal("a matching drop_event must drop the real document")
		}
	})
}

// ── every MATCHER, on a real document ───────────────────────────────────────

func TestEveryMatcherOnRealLogs(t *testing.T) {
	cases := []struct {
		name  string
		m     Match
		fires bool
	}{
		{"equals hit", Match{Field: "severity", Op: MatchEquals, Value: "notice"}, true},
		{"equals miss", Match{Field: "severity", Op: MatchEquals, Value: "critical"}, false},
		{"attribute hit", Match{Field: "facility", Op: MatchAttribute, Value: "SYS"}, true},
		{"contains hit", Match{Field: "message", Op: MatchContains, Value: "LOGGINGHOST"}, true},
		{"contains miss", Match{Field: "message", Op: MatchContains, Value: "BGP"}, false},
		{"prefix hit", Match{Field: "hostname", Op: MatchPrefix, Value: "homedepot"}, true},
		{"prefix miss", Match{Field: "hostname", Op: MatchPrefix, Value: "leaf"}, false},
		{"regex hit", Match{Field: "parser_id", Op: MatchRegex, Value: `^ios_style\.v[0-9]+$`}, true},
		{"regex miss", Match{Field: "parser_id", Op: MatchRegex, Value: `^junos`}, false},
		{"nested field hit", Match{Field: "fields.vlan", Op: MatchEquals, Value: "1006"}, false}, // wrong fixture on purpose
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := run(t, Processor{Type: TypeSetField, Field: "marker", Value: "yes", Match: &c.m}, "syslog", realSyslog)
			got := res.Event["marker"] == "yes"
			if got != c.fires {
				t.Errorf("matcher %+v fired=%v, want %v", c.m, got, c.fires)
			}
		})
	}
	// The nested matcher DOES fire on the document that has the nested field.
	res := run(t, Processor{Type: TypeSetField, Field: "marker", Value: "yes",
		Match: &Match{Field: "fields.vlan", Op: MatchEquals, Value: "1006"}}, "snmptrap", realTrap)
	if res.Event["marker"] != "yes" {
		t.Fatal("a JSON-path matcher must reach a nested field")
	}
}

// ── the full chain, ordered, on a real document ─────────────────────────────

func TestFullChainOnRealApplog(t *testing.T) {
	chain := []Processor{}
	for i, id := range []string{"credit_card", "us_ssn", "bearer_token", "password_field", "basic_auth_url"} {
		p, ok := CloneManagedRule(id, "applogs", "")
		if !ok {
			t.Fatalf("clone %s", id)
		}
		p.ID, p.TenantID, p.Enabled, p.Order = id, "acme", true, (i+1)*10
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		chain = append(chain, p)
	}
	res := SimulateChain(chain, "applogs", "acme", mustEvent(t, realApplog))
	blob, _ := json.Marshal(res.Event)
	got := string(blob)
	for _, secret := range []string{"4111 1111 1111 1111", "123-45-6789", "sk-live-9f8e7d6c5b4a3f2e1d", "hunter2", "s3cr3tpw"} {
		if strings.Contains(got, secret) {
			t.Errorf("chain LEAKED %q\nevent: %s", secret, got)
		}
	}
	if len(res.Applied) != len(chain) {
		t.Errorf("every processor in the chain should report: %+v", res.Applied)
	}
	// Applied order must equal execution order.
	for i, a := range res.Applied {
		if a.RuleID != chain[i].ID {
			t.Errorf("applied[%d]=%s, want %s (execution order)", i, a.RuleID, chain[i].ID)
		}
	}
}

// Every catalog entry must compile in RE2 AND be reachable from a clone. This
// is the guard that would have caught the negative-lookahead panic (RE2 has no
// lookaround) before it reached a running process.
func TestEveryManagedRuleIsUsable(t *testing.T) {
	for _, mr := range ManagedRules() {
		if mr.Pattern != "" && compiled(mr.Pattern) == nil {
			t.Errorf("managed rule %s has a pattern RE2 cannot compile: %s", mr.ID, mr.Pattern)
		}
		if mr.Pattern == "" && len(mr.Keys) == 0 {
			t.Errorf("managed rule %s detects nothing (no pattern, no keys)", mr.ID)
		}
		if mr.Replacement == "" || mr.Version < 1 || mr.Category == "" || mr.Description == "" {
			t.Errorf("managed rule %s is incompletely specified: %+v", mr.ID, mr)
		}
		p, ok := CloneManagedRule(mr.ID, "syslog", "")
		if !ok {
			t.Fatalf("managed rule %s cannot be cloned", mr.ID)
		}
		p.TenantID = "acme"
		if err := p.Validate(); err != nil {
			t.Errorf("a clone of %s does not validate: %v", mr.ID, err)
		}
		// Content detectors sweep everything; key detectors carry a key list.
		if len(mr.Keys) == 0 && p.Field != FieldAll {
			t.Errorf("a content detector should sweep every field by default, %s targets %q", mr.ID, p.Field)
		}
		if len(mr.Keys) > 0 && len(p.Keys) == 0 {
			t.Errorf("a key detector must clone its key list, %s cloned none", mr.ID)
		}
	}
	if n := len(ManagedRules()); n < 10 {
		t.Errorf("the catalog should cover at least 10 common cases, has %d", n)
	}
}
