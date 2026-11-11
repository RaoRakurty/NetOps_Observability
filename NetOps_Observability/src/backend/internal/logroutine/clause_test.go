// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The clause is proven by EVALUATING it, not by looking for strings in it: a
// small evaluator of the query DSL subset it uses runs the JSON OpenSearch
// would receive against documents shaped like the pack fixtures
// (telemetry-catalog/vendor-packs/standard.yaml, cisco_sdwan.yaml) and the lab
// records of 2026-11-11.

const (
	ctlIP      = "10.255.255.1"   // the lab vManage's system IP
	platformIP = "10.70.245.122"  // the appliance (CX_PLATFORM_ADDRESSES)
	humanIP    = "192.0.2.7"      // an operator's laptop
	ctlIPv6    = "2001:db8:ff::1" // a controller on IPv6
)

func labSources() Sources {
	return Sources{Platform: []string{platformIP}, Controllers: []string{ctlIP, ctlIPv6}}
}

type doc = map[string]string

func mgmt(eventType string, kv ...string) doc {
	d := doc{"event_category": Category, "event_type": eventType}
	for i := 0; i+1 < len(kv); i += 2 {
		d[kv[i]] = kv[i+1]
	}
	return d
}

func TestClauseClassifiesTheLabRecords(t *testing.T) {
	cases := []struct {
		name string
		d    doc
		want string // the rule that classes it routine; "" = always shown
	}{
		// Routine: what the lab measured.
		{"our SNMP poll through the edge's snmpd proxy", mgmt("audit_session_created_snmp", "audit_via", "snmp", "audit_source", "127.0.0.1:54511", "audit_user", "svc-user"), RulePoll},
		{"SNMP poll with no source at all", mgmt("audit_session_created_snmp", "audit_via", "snmp"), RulePoll},
		{"SNMP agent poll trace", mgmt("snmp_agent_table_error"), RulePoll},
		{"SNMP genErr answering our poll", mgmt("snmp_get_response_generr"), RulePoll},
		{"session groups", mgmt("audit_session_groups", "audit_user", "svc-user"), RuleSessionDetail},
		{"session closed", mgmt("audit_session_terminated", "audit_user", "svc-user"), RuleSessionDetail},
		{"NETCONF RPC step", mgmt("netconf_rpc", "audit_via", "netconf", "audit_action", "rpc"), RuleSessionDetail},
		{"NETCONF notification", mgmt("netconf_notification", "audit_via", "netconf"), RuleSessionDetail},
		{"NETCONF action", mgmt("netconf_action_clear", "audit_via", "netconf"), RuleSessionDetail},
		{"PAM session opened", mgmt("ssh_session_opened", "audit_via", "ssh", "audit_user", "admin"), RuleSessionDetail},
		{"PAM session closed", mgmt("ssh_session_closed", "audit_via", "ssh"), RuleSessionDetail},
		{"vManage NETCONF transport session", mgmt("netconf_session", "audit_via", "netconf", "audit_source", ctlIP), RuleControllerSource},
		{"vManage NETCONF session with port", mgmt("audit_session_created_netconf", "audit_via", "netconf", "audit_source", ctlIP+":41424"), RuleControllerSource},
		{"vManage sshd login for NETCONF over SSH", mgmt("ssh_login_accepted", "audit_via", "ssh", "audit_source", ctlIP+":41424"), RuleControllerSource},
		{"vManage DMI login on IOS XE", mgmt("dmi_auth_passed", "audit_via", "netconf over ssh", "audit_source", ctlIP+":41424"), RuleControllerSource},
		{"controller on IPv6, bracketed with port", mgmt("netconf_session", "audit_via", "netconf", "audit_source", "["+ctlIPv6+"]:830"), RuleControllerSource},
		{"controller on IPv6, plain", mgmt("netconf_session", "audit_via", "netconf", "audit_source", ctlIPv6), RuleControllerSource},
		{"Correlix's own NETCONF", mgmt("netconf_session", "audit_via", "netconf", "audit_source", platformIP), RuleMonitoringSource},
		{"Correlix's own RESTCONF via DMI", mgmt("dmi_auth_passed", "audit_via", "RESTCONF over HTTPS", "audit_source", platformIP+":5000"), RuleMonitoringSource},

		// Always shown.
		{"refused SNMP community", doc{"event_category": "security_audit", "event_type": "snmp_auth_failed_community", "audit_via": "snmp", "audit_action": "auth_failed", "audit_source": "127.0.0.1"}, ""},
		{"a failure filed as management_audit by a future row", mgmt("audit_session_created_snmp", "audit_via", "snmp", "audit_action", "auth_failed"), ""},
		{"a failure word in the event type", mgmt("ssh_login_failed", "audit_via", "ssh", "audit_source", ctlIP), ""},
		{"a denial", mgmt("netconf_rpc", "audit_action", "access_denied"), ""},
		{"a person's CLI session, even from the controller", mgmt("audit_session_created_cli", "audit_via", "cli", "audit_source", ctlIP+":51234"), ""},
		{"a person's CLI session from a laptop", mgmt("audit_session_created_cli", "audit_via", "cli", "audit_source", humanIP+":51234"), ""},
		{"an SSH login from a laptop", mgmt("ssh_login_accepted", "audit_via", "ssh", "audit_source", humanIP+":22"), ""},
		{"an SSH login from Correlix (its device terminal is a person)", mgmt("ssh_login_accepted", "audit_via", "ssh", "audit_source", platformIP+":40000"), ""},
		{"a NETCONF session from an unknown address", mgmt("netconf_session", "audit_via", "netconf", "audit_source", humanIP), ""},
		{"a DMI login with no service named", mgmt("dmi_auth_passed", "audit_source", ctlIP+":41424"), ""},
		{"a neighbour of the controller address", mgmt("netconf_session", "audit_via", "netconf", "audit_source", "10.255.255.10:830"), ""},
		{"a longer address starting with the controller's", mgmt("netconf_session", "audit_via", "netconf", "audit_source", "10.255.255.100"), ""},
		{"an SSH banner probe", mgmt("ssh_banner_probe", "audit_via", "ssh"), ""},
		{"a document stored before the packs classified it", doc{"message": "audit user: svc/1 created new session via snmp from 127.0.0.1:1 with udp"}, ""},
		{"an interface going down", doc{"event_type": "link_down", "event_category": "", "severity": "err"}, ""},
	}
	q := roundTrip(t, Clause(labSources()))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, names := eval(t, q, c.d)
			if c.want == "" {
				if ok {
					t.Fatalf("classed routine (%v), must stay visible: %v", names, c.d)
				}
				return
			}
			if !ok {
				t.Fatalf("not classed routine, want %s: %v", c.want, c.d)
			}
			if !contains(names, c.want) {
				t.Fatalf("matched rules %v, want %s", names, c.want)
			}
			// No OTHER rule may claim it: the panel names exactly one reason.
			for _, n := range names {
				if strings.HasPrefix(n, "routine_mgmt.") && n != c.want {
					t.Errorf("rule %s also matched; the record has one reason", n)
				}
			}
		})
	}
}

// Without addresses the source rules are absent: nothing is guessed, the
// controller's sessions stay visible, and polls and in-session steps still fold.
func TestClauseWithoutAddressesHidesOnlyWhatNeedsNoAddress(t *testing.T) {
	q := roundTrip(t, Clause(Sources{}))
	raw, _ := json.Marshal(q)
	for _, absent := range []string{RuleMonitoringSource, RuleControllerSource, "audit_source"} {
		if strings.Contains(string(raw), absent) {
			t.Errorf("unconfigured clause still names %s:\n%s", absent, raw)
		}
	}
	if ok, _ := eval(t, q, mgmt("netconf_session", "audit_via", "netconf", "audit_source", ctlIP)); ok {
		t.Error("a controller session was hidden with no controller known")
	}
	if ok, _ := eval(t, q, mgmt("audit_session_created_snmp", "audit_via", "snmp")); !ok {
		t.Error("an SNMP poll session must fold without any address")
	}
}

// Configuration text never reaches the query: only parsed addresses do.
func TestCleanAddrsKeepsOnlyAddresses(t *testing.T) {
	got := CleanAddrs([]string{" 10.0.0.1 ", "10.0.0.1", "[2001:db8::1]", "10.9.0.0/16", `x"}},{"match_all`, "", "2001:DB8::1"})
	want := []string{"10.0.0.1", "2001:db8::1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("CleanAddrs = %v, want %v", got, want)
	}
	many := make([]string, 0, MaxAddrs+10)
	for i := 0; i < MaxAddrs+10; i++ {
		many = append(many, fmt.Sprintf("10.1.%d.%d", i/250, i%250+1))
	}
	if n := len(CleanAddrs(many)); n != MaxAddrs {
		t.Fatalf("CleanAddrs kept %d, bound is %d", n, MaxAddrs)
	}
	raw, _ := json.Marshal(Clause(Sources{Platform: []string{`1.2.3.4"} OR {"match_all`}}))
	if strings.Contains(string(raw), "match_all") {
		t.Fatalf("configuration text reached the query: %s", raw)
	}
}

// The exclusion is exactly "not routine" and the aggregation counts exactly the
// routine records: one class, two uses.
func TestExclusionAndAggAreTheSameClass(t *testing.T) {
	src := labSources()
	excl := roundTrip(t, Exclusion(src))
	agg := roundTrip(t, Agg(src))
	filter, _ := agg["filter"].(map[string]any)
	for _, d := range []doc{
		mgmt("audit_session_created_snmp", "audit_via", "snmp"),
		mgmt("audit_session_created_cli", "audit_via", "cli", "audit_source", humanIP),
		{"event_category": "security_audit", "event_type": "snmp_auth_failed_community"},
	} {
		routine, _ := eval(t, filter, d)
		kept, _ := eval(t, excl, d)
		if routine == kept {
			t.Errorf("exclusion and aggregation disagree on %v (routine=%v kept=%v)", d, routine, kept)
		}
	}
}

// ---- a minimal evaluator of the DSL subset the clause uses ------------------

func roundTrip(t *testing.T, q map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// eval reports whether q matches d and which named clauses matched (the
// matched_queries OpenSearch would report).
func eval(t *testing.T, q map[string]any, d doc) (bool, []string) {
	t.Helper()
	names := map[string]bool{}
	ok := evalQ(t, q, d, names)
	var out []string
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return ok, out
}

func evalQ(t *testing.T, q map[string]any, d doc, names map[string]bool) bool {
	t.Helper()
	if len(q) != 1 {
		t.Fatalf("a query object must have exactly one kind: %v", q)
	}
	for kind, body := range q {
		switch kind {
		case "bool":
			return evalBool(t, body.(map[string]any), d, names)
		case "term":
			field, v, ci := leaf(t, body)
			return eq(d[field], v.(string), ci)
		case "terms":
			for field, vs := range body.(map[string]any) {
				for _, v := range vs.([]any) {
					if d[field] == v.(string) {
						return true
					}
				}
				return false
			}
		case "prefix":
			field, v, ci := leaf(t, body)
			val, has := d[field]
			if !has {
				return false
			}
			if ci {
				return strings.HasPrefix(strings.ToLower(val), strings.ToLower(v.(string)))
			}
			return strings.HasPrefix(val, v.(string))
		case "wildcard":
			field, v, ci := leaf(t, body)
			val, has := d[field]
			if !has {
				return false
			}
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(v.(string)), `\*`, ".*") + "$"
			if ci {
				pat = "(?i)" + pat
			}
			return regexp.MustCompile(pat).MatchString(val)
		default:
			t.Fatalf("evaluator does not know query kind %q", kind)
		}
	}
	return false
}

func evalBool(t *testing.T, b map[string]any, d doc, names map[string]bool) bool {
	t.Helper()
	list := func(k string) []any {
		v, _ := b[k].([]any)
		return v
	}
	ok := true
	for _, c := range append(list("filter"), list("must")...) {
		if !evalQ(t, c.(map[string]any), d, names) {
			ok = false
		}
	}
	for _, c := range list("must_not") {
		if evalQ(t, c.(map[string]any), d, map[string]bool{}) {
			ok = false
		}
	}
	should := list("should")
	if len(should) > 0 {
		min := 0
		if len(list("filter"))+len(list("must")) == 0 {
			min = 1
		}
		if m, has := b["minimum_should_match"]; has {
			min = int(m.(float64))
		}
		n := 0
		for _, c := range should {
			if evalQ(t, c.(map[string]any), d, names) {
				n++
			}
		}
		if n < min {
			ok = false
		}
	}
	if name, has := b["_name"].(string); has && ok {
		names[name] = true
	}
	return ok
}

func leaf(t *testing.T, body any) (string, any, bool) {
	t.Helper()
	for field, v := range body.(map[string]any) {
		if m, isObj := v.(map[string]any); isObj {
			ci, _ := m["case_insensitive"].(bool)
			return field, m["value"], ci
		}
		return field, v, false
	}
	t.Fatalf("empty leaf query")
	return "", nil, false
}

func eq(a, b string, ci bool) bool {
	if ci {
		return strings.EqualFold(a, b)
	}
	return a == b
}
