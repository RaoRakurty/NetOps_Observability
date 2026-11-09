// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The trap receiver turns a decoded trap into meaning from data alone. These
// tests hold that: the recorded lab trap decodes end to end, the packs agree with
// the index they were written against, and a vendor nobody has heard of works by
// adding data and nothing else.

// A community is required on the wire and means nothing here: fabricated.
const fabricatedCommunity = "fixture-community"

// tvb is one binding of a fabricated trap: the dotted OID and its BER value.
type tvb struct {
	oid string
	ber []byte
}

func arcs(t *testing.T, dotted string) []int {
	t.Helper()
	parts := strings.Split(dotted, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("bad oid %q: %v", dotted, err)
		}
		out[i] = n
	}
	return out
}

func berOctets(s string) []byte { return berTLV(0x04, []byte(s)) }

// buildTrapV2c builds a v2c trap with sysUpTime.0, snmpTrapOID.0 and the bindings.
func buildTrapV2c(t *testing.T, trapOID string, bindings ...tvb) []byte {
	t.Helper()
	vb := func(oid string, val []byte) []byte { return berTLV(0x30, append(berOID(arcs(t, oid)), val...)) }
	vbs := vb("1.3.6.1.2.1.1.3.0", berTLV(0x43, []byte{0x00, 0x01, 0x00, 0x00}))
	vbs = append(vbs, vb("1.3.6.1.6.3.1.1.4.1.0", berOID(arcs(t, trapOID)))...)
	for _, b := range bindings {
		vbs = append(vbs, vb(b.oid, b.ber)...)
	}
	pduBody := berInt(7)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berTLV(0x30, vbs)...)
	msg := berInt(1)
	msg = append(msg, berOctets(fabricatedCommunity)...)
	msg = append(msg, berTLV(0xA7, pduBody)...)
	return berTLV(0x30, msg)
}

func decodeForTest(t *testing.T, pkt []byte) *TrapEvent {
	t.Helper()
	ev, err := decodeTrap(pkt, "192.0.2.102", nil)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	deriveEnvelope(ev)
	return ev
}

const (
	vf = "1.3.6.1.4.1.41916.100.1." // VIPTELA-TRAPS fields
	vt = "1.3.6.1.4.1.41916.100.2." // VIPTELA-TRAPS traps
)

// vEdgeDateAndTime is 2026-11-09T01:35:01.1Z as RFC 2579 octets.
var vEdgeDateAndTime = berTLV(0x04, []byte{0x07, 0xEA, 0x0B, 0x09, 0x01, 0x23, 0x01, 0x01, '+', 0, 0})

func cpuTrap(t *testing.T, severity int, warning string) []byte {
	return buildTrapV2c(t, vt+"114",
		tvb{vf + "1.0", vEdgeDateAndTime},
		tvb{vf + "2.0", berInt(severity)},
		tvb{vf + "54.0", berOctets(warning)},
		tvb{vf + "190.0", berOctets("12.23")},
		tvb{vf + "191.0", berOctets("7.98")},
		tvb{vf + "192.0", berOctets("79.79")})
}

// The shape recorded on the lab on 2026-11-09 from vedge-52: OID, varbind arcs,
// native minor(3), wording and values. Only the community is fabricated.
func TestTrapSemantics_RecordedLabCPURecovery(t *testing.T) {
	ev := decodeForTest(t, cpuTrap(t, 3, "System cpu usage back to normal level"))

	if ev.TrapName != "viptelaSystemCpuUsage" || ev.MIBModule != "VIPTELA-TRAPS" {
		t.Fatalf("name/module = %q/%q", ev.TrapName, ev.MIBModule)
	}
	if ev.MIBBundleVersion == "" || ev.MIBBundleVersion != oidIdx.Version {
		t.Fatalf("mib_bundle_version = %q, index %q", ev.MIBBundleVersion, oidIdx.Version)
	}
	if ev.NativeSeverityText != "minor" || ev.NativeSeverityCode == nil || *ev.NativeSeverityCode != 3 {
		t.Fatalf("native severity = %q/%v", ev.NativeSeverityText, ev.NativeSeverityCode)
	}
	// Three separate ideas: natively minor, a clear, and normalized as info.
	if ev.EventState != "clear" || ev.EventStateFidelity != "lab_validated" {
		t.Fatalf("event_state = %q (%s)", ev.EventState, ev.EventStateFidelity)
	}
	if ev.Severity != "info" {
		t.Fatalf("normalized severity = %q, want info", ev.Severity)
	}
	if ev.DeviceEventTime != "2026-11-09T01:35:01.1Z" {
		t.Fatalf("device_event_time = %q", ev.DeviceEventTime)
	}
	for field, want := range map[string]float64{"cpu_user_percent": 12.23, "cpu_system_percent": 7.98, "cpu_idle_percent": 79.79} {
		if ev.Values[field] != want {
			t.Errorf("values[%s] = %v, want %v", field, ev.Values[field], want)
		}
	}
	if ev.Summary != "System cpu usage back to normal level" {
		t.Errorf("summary = %q", ev.Summary)
	}
	if ev.Category != "platform_health" || ev.Family != "cpu" || ev.Vendor != "cisco" {
		t.Errorf("category/family/vendor = %q/%q/%q", ev.Category, ev.Family, ev.Vendor)
	}

	// Never reinterpret: every binding keeps its numeric OID and raw value.
	byName := map[string]TrapVarbind{}
	for _, vb := range ev.Varbinds {
		if vb.OID == "" {
			t.Fatalf("binding lost its OID: %+v", vb)
		}
		byName[vb.Name] = vb
	}
	sev := byName["netconfNotificationSeverity"]
	if sev.OID != vf+"2.0" || sev.Raw != "3" || sev.Label != "minor" || sev.Value != "minor(3)" {
		t.Errorf("severity binding = %+v", sev)
	}
	et := byName["eventTime"]
	if et.Type != "DateAndTime" || !strings.HasPrefix(et.Raw, "0x07ea") || et.Time != "2026-11-09T01:35:01.1Z" {
		t.Errorf("eventTime binding = %+v", et)
	}
	if u := byName["viptelaSystemCpuUserPercentage"]; u.Raw != "12.23" || u.OID != vf+"190.0" {
		t.Errorf("cpu user binding = %+v", u)
	}

	// The wire names the JSON promises.
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"severity_native_text":"minor"`, `"severity_native_code":3`, `"event_state":"clear"`,
		`"mib_module":"VIPTELA-TRAPS"`, `"mib_bundle_version":"`, `"raw_value":"12.23"`, `"enum_label":"minor"`} {
		if !strings.Contains(string(body), key) {
			t.Errorf("event JSON has no %s", key)
		}
	}
}

// The engine's rules are tested against this same recording
// (src/correlation/test_trap_packs_387.py), so the receiver and the rules cannot
// disagree about the event's shape without one of the two going red.
func TestTrapSemantics_MatchesTheEngineFixture(t *testing.T) {
	b, err := os.ReadFile("../../correlation/fixtures/source_parity/trap_vedge52_cpu_recovery_20261109.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	var bindings []tvb
	for _, raw := range want["varbinds"].([]any) {
		vb := raw.(map[string]any)
		val := berOctets(vb["raw_value"].(string))
		if vb["type"] == "INTEGER" {
			n, err := strconv.Atoi(vb["raw_value"].(string))
			if err != nil {
				t.Fatal(err)
			}
			val = berInt(n)
		}
		bindings = append(bindings, tvb{vb["oid"].(string), val})
	}
	ev := decodeForTest(t, buildTrapV2c(t, want["trap_oid"].(string), bindings...))
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	// Set by the deployment, not by the decode. The uptime binding is the wire's own.
	for _, k := range []string{"_signal", "timestamp", "host", "device", "snmp_version"} {
		delete(want, k)
	}
	gotVbs := got["varbinds"].([]any)[1:]
	wantVbs := want["varbinds"].([]any)
	if len(gotVbs) != len(wantVbs) {
		t.Fatalf("varbinds = %d, want %d", len(gotVbs), len(wantVbs))
	}
	for i := range wantVbs {
		a, _ := json.Marshal(gotVbs[i])
		w, _ := json.Marshal(wantVbs[i])
		if string(a) != string(w) {
			t.Errorf("varbind %d:\n got %s\nwant %s", i, a, w)
		}
	}
	delete(want, "varbinds")
	for k, w := range want {
		a, _ := json.Marshal(got[k])
		e, _ := json.Marshal(w)
		if string(a) != string(e) {
			t.Errorf("%s = %s, fixture says %s", k, a, e)
		}
	}
}

func TestTrapSemantics_StateNeedsEvidence(t *testing.T) {
	cases := []struct {
		name       string
		pkt        []byte
		state, sev string
		fidelity   string
		nativeText string
	}{
		{name: "critical raise by wording", pkt: cpuTrap(t, 1, "System cpu usage is above 90% (critically high)"),
			state: "raise", sev: "crit", fidelity: "doc_claimed", nativeText: "critical"},
		{name: "minor raise by wording", pkt: cpuTrap(t, 3, "System cpu usage is above 75%"),
			state: "raise", sev: "warning", fidelity: "doc_claimed", nativeText: "minor"},
		{name: "wording nobody documented claims nothing", pkt: cpuTrap(t, 1, "cpu feels odd"),
			state: "point", sev: "notice", nativeText: "critical"},
		{name: "state object down", pkt: buildTrapV2c(t, vt+"4", tvb{vf + "2.0", berInt(2)}, tvb{vf + "13.0", berInt(1)}),
			state: "raise", sev: "err", fidelity: "doc_claimed", nativeText: "major"},
		{name: "state object up", pkt: buildTrapV2c(t, vt+"4", tvb{vf + "2.0", berInt(3)}, tvb{vf + "13.0", berInt(0)}),
			state: "clear", sev: "info", fidelity: "doc_claimed", nativeText: "minor"},
		{name: "state object value outside the row", pkt: buildTrapV2c(t, vt+"4", tvb{vf + "13.0", berInt(9)}),
			state: "point", sev: "notice"},
		{name: "state object absent", pkt: buildTrapV2c(t, vt+"4", tvb{vf + "2.0", berInt(1)}),
			state: "point", sev: "notice", nativeText: "critical"},
		{name: "retry leg is not a claim", pkt: buildTrapV2c(t, vt+"54", tvb{vf + "2.0", berInt(1)}, tvb{vf + "69.0", berInt(1)}),
			state: "point", sev: "notice", nativeText: "critical"},
		{name: "fixed by identity", pkt: buildTrapV2c(t, vt+"27", tvb{vf + "2.0", berInt(1)}),
			state: "raise", sev: "crit", fidelity: "doc_claimed", nativeText: "critical"},
		{name: "TLOC change has no state object", pkt: buildTrapV2c(t, vt+"21", tvb{vf + "2.0", berInt(3)}),
			state: "point", sev: "notice", fidelity: "doc_claimed", nativeText: "minor"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := decodeForTest(t, c.pkt)
			if ev.EventState != c.state || ev.Severity != c.sev || ev.EventStateFidelity != c.fidelity || ev.NativeSeverityText != c.nativeText {
				t.Fatalf("state=%q sev=%q fidelity=%q native=%q, want %q %q %q %q",
					ev.EventState, ev.Severity, ev.EventStateFidelity, ev.NativeSeverityText, c.state, c.sev, c.fidelity, c.nativeText)
			}
		})
	}
}

// An unreviewed notification keeps its MIB hint, whatever the vendor calls it:
// a native `critical` on something nobody has read must not reach the engine as
// a critical. The native words are still there for the operator.
func TestTrapSemantics_UnlistedNotificationStaysBelowTheFloor(t *testing.T) {
	ev := decodeForTest(t, buildTrapV2c(t, vt+"43", tvb{vf + "2.0", berInt(1)})) // viptelaSystemDiskUsage
	if ev.TrapName != "viptelaSystemDiskUsage" {
		t.Fatalf("name = %q", ev.TrapName)
	}
	if ev.NativeSeverityText != "critical" || ev.Severity != "notice" || ev.EventState != "point" {
		t.Fatalf("native=%q sev=%q state=%q", ev.NativeSeverityText, ev.Severity, ev.EventState)
	}
}

func TestTrapSemantics_StandardLayerAcrossVendors(t *testing.T) {
	for oid, want := range map[string]string{
		"1.3.6.1.2.1.222.0.1": "clear", "1.3.6.1.2.1.222.0.2": "raise",
		"1.3.6.1.6.3.1.1.5.3": "raise", "1.3.6.1.6.3.1.1.5.4": "clear",
	} {
		ev := decodeForTest(t, buildTrapV2c(t, oid))
		if ev.EventState != want || ev.EventStateFidelity != "doc_claimed" {
			t.Errorf("%s: state=%q fidelity=%q, want %q doc_claimed", oid, ev.EventState, ev.EventStateFidelity, want)
		}
	}
	ev := decodeForTest(t, buildTrapV2c(t, "1.3.6.1.2.1.222.0.2", tvb{"1.3.6.1.2.1.222.1.2.1.13.4", berInt(1)}))
	if ev.TrapName != "bfdSessDown" || ev.MIBModule != "BFD-STD-MIB" || ev.Family != "bfd" || ev.Severity != "warning" {
		t.Errorf("bfdSessDown = %q %q %q %q", ev.TrapName, ev.MIBModule, ev.Family, ev.Severity)
	}
}

// An OID nobody indexed stays honest: raw, named by nothing, and no state claim.
func TestTrapSemantics_UnknownEnterpriseStaysRaw(t *testing.T) {
	ev := decodeForTest(t, buildTrapV2c(t, "1.3.6.1.4.1.64999.9.9", tvb{"1.3.6.1.4.1.64999.1.1.0", berInt(5)}))
	if ev.TrapName != "enterpriseSpecific" || ev.EventState != "point" || ev.EventStateFidelity != "" ||
		ev.MIBModule != "" || ev.MIBBundleVersion != "" || ev.NativeSeverityText != "" {
		t.Fatalf("%+v", ev)
	}
	vb := ev.Varbinds[len(ev.Varbinds)-1]
	if vb.Name != "" || vb.Raw != "5" || vb.OID != "1.3.6.1.4.1.64999.1.1.0" || vb.Num != nil {
		t.Fatalf("binding = %+v", vb)
	}
}

// THE PROOF THE RECEIVER IS GENERIC. A vendor that exists nowhere in this repo
// (enterprise 64999) arrives through data alone: index nodes and a pack, each
// with its own severity vocabulary, state object, wording and typed fields.
// No Go changes, and the same path as every real vendor.
func TestTrapSemantics_SecondEnterpriseThroughDataOnly(t *testing.T) {
	const (
		root   = "1.3.6.1.4.1.64999."
		notif  = root + "0.1"
		notif2 = root + "0.2"
		sev    = root + "1.1"
		state  = root + "1.2"
		temp   = root + "1.3"
		note   = root + "1.4"
		when   = root + "1.5"
		count  = root + "1.6"
	)
	nodes := map[string]OIDNode{
		notif:  {Name: "acmePortChange", MIB: "ACME-TRAPS", Kind: "notification"},
		notif2: {Name: "acmeHeat", MIB: "ACME-TRAPS", Kind: "notification"},
		sev:    {Name: "acmeLevel", MIB: "ACME-TRAPS", Kind: "scalar", Type: "INTEGER", Enum: map[string]string{"10": "sev-high", "20": "sev-low"}},
		state:  {Name: "acmePortState", MIB: "ACME-TRAPS", Kind: "scalar", Type: "INTEGER", Enum: map[string]string{"7": "broken", "8": "healthy", "9": "testing"}},
		temp:   {Name: "acmeTemperature", MIB: "ACME-TRAPS", Kind: "scalar", Type: "DisplayString"},
		note:   {Name: "acmeNote", MIB: "ACME-TRAPS", Kind: "scalar", Type: "DisplayString"},
		when:   {Name: "acmeWhen", MIB: "ACME-TRAPS", Kind: "scalar", Type: "DateAndTime"},
		count:  {Name: "acmeCount", MIB: "ACME-TRAPS", Kind: "scalar", Type: "Unsigned32"},
	}
	for oid, n := range nodes {
		oidIdx.Nodes[oid] = n
	}
	t.Cleanup(func() {
		for oid := range nodes {
			delete(oidIdx.Nodes, oid)
		}
	})
	pack := `{
	  "schema": 1, "pack": "acme", "source": "test",
	  "objects": {
	    "` + sev + `": {"name": "acmeLevel", "role": "native_severity", "normalized": {"sev-high": "alert", "sev-low": "notice"}},
	    "` + temp + `": {"name": "acmeTemperature", "field": "temperature_c", "type": "float"},
	    "` + note + `": {"name": "acmeNote", "role": "summary", "field": "note", "type": "string"}
	  },
	  "notifications": {
	    "` + notif + `": {"name": "acmePortChange", "category": "data_plane", "family": "ports", "fidelity": "doc_claimed",
	      "state_object": "` + state + `", "raise": ["broken"], "clear": ["healthy"]},
	    "` + notif2 + `": {"name": "acmeHeat", "fidelity": "lab_validated",
	      "text_object": "` + note + `", "text": [{"contains": ["cooled"], "state": "clear", "fidelity": "live_validated"}]}
	  }
	}`
	sem, err := compileTrapPackData([]byte(pack))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	saved := trapSem
	trapSem = sem
	t.Cleanup(func() { trapSem = saved })

	raise := decodeForTest(t, buildTrapV2c(t, notif,
		tvb{sev + ".0", berInt(10)}, tvb{state + ".0", berInt(7)}, tvb{temp + ".0", berOctets("41.5")},
		tvb{note + ".0", berOctets("  port   7 broke ")}, tvb{when + ".0", vEdgeDateAndTime}, tvb{count + ".0", berInt(12)}))
	if raise.TrapName != "acmePortChange" || raise.MIBModule != "ACME-TRAPS" {
		t.Fatalf("decode = %q %q", raise.TrapName, raise.MIBModule)
	}
	if raise.NativeSeverityText != "sev-high" || *raise.NativeSeverityCode != 10 || raise.Severity != "alert" {
		t.Fatalf("severity = %q %d %q", raise.NativeSeverityText, *raise.NativeSeverityCode, raise.Severity)
	}
	if raise.EventState != "raise" || raise.Category != "data_plane" || raise.Family != "ports" {
		t.Fatalf("state/taxonomy = %q %q %q", raise.EventState, raise.Category, raise.Family)
	}
	if raise.Values["temperature_c"] != 41.5 || raise.Fields["note"] != "  port   7 broke " || raise.Summary != "port 7 broke" {
		t.Fatalf("fields = %v %v %q", raise.Values, raise.Fields, raise.Summary)
	}
	if raise.DeviceEventTime != "2026-11-09T01:35:01.1Z" {
		t.Fatalf("time = %q", raise.DeviceEventTime)
	}
	var num *float64
	for _, vb := range raise.Varbinds {
		if vb.Name == "acmeCount" {
			num = vb.Num
		}
	}
	if num == nil || *num != 12 {
		t.Fatalf("a numeric SYNTAX stays a number: %v", num)
	}

	clear := decodeForTest(t, buildTrapV2c(t, notif, tvb{sev + ".0", berInt(20)}, tvb{state + ".0", berInt(8)}))
	if clear.EventState != "clear" || clear.Severity != "info" || clear.NativeSeverityText != "sev-low" {
		t.Fatalf("clear = %q %q %q", clear.EventState, clear.Severity, clear.NativeSeverityText)
	}
	testing_ := decodeForTest(t, buildTrapV2c(t, notif, tvb{state + ".0", berInt(9)}))
	if testing_.EventState != "point" {
		t.Fatalf("a value outside the row = %q", testing_.EventState)
	}
	cooled := decodeForTest(t, buildTrapV2c(t, notif2, tvb{note + ".0", berOctets("it cooled down")}))
	if cooled.EventState != "clear" || cooled.EventStateFidelity != "live_validated" {
		t.Fatalf("wording = %q %q", cooled.EventState, cooled.EventStateFidelity)
	}
}

// The mechanism must not know any vendor: that is the whole design.
func TestTrapSemantics_NoVendorNamesInTheMechanism(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)viptela|41916|sdwan|vsmart|vbond|vedge|cedge`)
	for _, f := range []string{"trap_semantics.go", "oidindex.go", "snmptrap.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := forbidden.Find(b); m != nil {
			t.Errorf("%s names %q: a vendor belongs in a pack, not in the receiver", f, m)
		}
	}
}

// The shipped packs load, and every OID in them is what the index says it is.
// This is the OID-mapping validation the owner's D4 asks for: a pack can only
// name what the pinned MIB defines, under the name it defines it.
func TestTrapPacks_EmbeddedLoadClean(t *testing.T) {
	sem, err := compileTrapPacks(trapPackFS, "mibs/packs")
	if err != nil {
		t.Fatal(err)
	}
	if len(sem.notifications) == 0 || len(sem.objects) == 0 {
		t.Fatalf("empty: %d notifications %d objects", len(sem.notifications), len(sem.objects))
	}
	for oid, o := range sem.objects {
		n, found := oidIdx.Nodes[oid]
		if !found || n.Name != o.Name || n.Kind == "notification" {
			t.Errorf("object %s: pack says %q, index says %+v", oid, o.Name, n)
		}
		if o.Role == trapRoleNativeSeverity {
			if len(n.Enum) == 0 {
				t.Errorf("object %s: a native severity without an enum", oid)
			}
			labels := map[string]bool{}
			for _, l := range n.Enum {
				labels[strings.ToLower(l)] = true
			}
			for l := range o.lookup {
				if !labels[l] {
					t.Errorf("object %s: %q is not in the MIB's enum %v", oid, l, n.Enum)
				}
			}
		}
	}
	for oid, r := range sem.notifications {
		n, found := oidIdx.Nodes[oid]
		if !found || n.Name != r.Name || n.Kind != "notification" {
			t.Errorf("notification %s: pack says %q, index says %+v", oid, r.Name, n)
		}
		if r.TextObject != "" {
			if _, found := oidIdx.Nodes[r.TextObject]; !found {
				t.Errorf("notification %s: text object %s is not indexed", oid, r.TextObject)
			}
		}
		if r.StateObject == "" {
			continue
		}
		st, found := oidIdx.Nodes[r.StateObject]
		if !found {
			t.Errorf("notification %s: state object %s is not indexed", oid, r.StateObject)
			continue
		}
		labels := map[string]bool{}
		for _, l := range st.Enum {
			labels[strings.ToLower(l)] = true
		}
		for v := range r.states {
			if !labels[v] {
				t.Errorf("notification %s: %q is not in %s's enum %v", oid, v, st.Name, st.Enum)
			}
		}
	}
}

func TestCompileTrapPackData_RefusesAHalfUnderstoodTable(t *testing.T) {
	wrap := func(objects, notifs string) []byte {
		return []byte(`{"schema":1,"pack":"x","objects":{` + objects + `},"notifications":{` + notifs + `}}`)
	}
	for name, raw := range map[string][]byte{
		"unknown key":        []byte(`{"schema":1,"pack":"x","nonsense":1}`),
		"wrong schema":       []byte(`{"schema":2,"pack":"x"}`),
		"unnamed pack":       []byte(`{"schema":1}`),
		"unknown role":       wrap(`"1.1":{"name":"a","role":"mystery"}`, ``),
		"unknown type":       wrap(`"1.1":{"name":"a","field":"f","type":"blob"}`, ``),
		"field with no type": wrap(`"1.1":{"name":"a","field":"f"}`, ``),
		"normalized no role": wrap(`"1.1":{"name":"a","normalized":{"x":"crit"}}`, ``),
		"object no name":     wrap(`"1.1":{}`, ``),
		"no fidelity":        wrap(``, `"1.1":{"name":"a","event_state":"raise"}`),
		"off the ladder":     wrap(``, `"1.1":{"name":"a","fidelity":"hope","event_state":"raise"}`),
		"bad state":          wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","event_state":"maybe"}`),
		"no way to a state":  wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed"}`),
		"two ways":           wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","event_state":"raise","state_object":"1.2","raise":["x"]}`),
		"object no values":   wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","state_object":"1.2"}`),
		"both raise, clear":  wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","state_object":"1.2","raise":["x"],"clear":["X"]}`),
		"text no rows":       wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","text_object":"1.2"}`),
		"text bad row":       wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","text_object":"1.2","text":[{"contains":[],"state":"raise","fidelity":"doc_claimed"}]}`),
		"not json":           []byte(`{`),
	} {
		if _, err := compileTrapPackData(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := wrap(`"1.1":{"name":"a"}`, ``)
	if _, err := compileTrapPackData(dup, dup); err == nil {
		t.Error("an OID claimed by two packs must refuse the set")
	}
	dupN := wrap(``, `"1.1":{"name":"a","fidelity":"doc_claimed","event_state":"raise"}`)
	if _, err := compileTrapPackData(dupN, dupN); err == nil {
		t.Error("a notification claimed by two packs must refuse the set")
	}
}

func TestDecodeDateAndTime(t *testing.T) {
	for raw, want := range map[string]string{
		"0x07ea0b09012301012b0000": "2026-11-09T01:35:01.1Z",
		"0x07ea0b090123010 1":      "",
		"0x07ea0b0901230101":       "2026-11-09T01:35:01.1Z", // 8 octets: no zone
		"0x07ea0b09012301012d0500": "2026-11-09T06:35:01.1Z", // -05:00
		"0x07ea020f0000000012b00":  "",                       // odd length
		"0x07ea021f00000000":       "",                       // 31 February
		"0x07ea0d0100000000":       "",                       // month 13
		"0x07ea0b0118000000":       "",                       // hour 24
		"0x07ea0b09012301012a0000": "",                       // zone sign is neither + nor -
		"0x07ea0b09012301012b1e00": "",                       // zone hour 30
		"0x07ea0b090123010a":       "",                       // deci-seconds 10
		"System cpu":               "",                       // not hex at all
		"":                         "",
		"0xzz":                     "",
	} {
		got, ok := decodeDateAndTime(raw)
		if got != want || ok != (want != "") {
			t.Errorf("%q = %q %v, want %q", raw, got, ok, want)
		}
	}
}

// A value that does not parse fills no field: no guessed number, raw kept.
func TestTrapSemantics_FieldThatDoesNotParseFillsNothing(t *testing.T) {
	for _, bad := range []string{"high", "NaN", "Inf", "-Inf", ""} {
		ev := decodeForTest(t, buildTrapV2c(t, vt+"114", tvb{vf + "190.0", berOctets(bad)}))
		if _, set := ev.Values["cpu_user_percent"]; set {
			t.Errorf("%q filled a number: %v", bad, ev.Values)
		}
	}
	ev := decodeForTest(t, buildTrapV2c(t, vt+"44", tvb{vf + "55.0", berInt(4096)}, tvb{vf + "56.0", berOctets("1.5")}))
	if ev.Values["total_mb"] != 4096 {
		t.Errorf("total_mb = %v", ev.Values)
	}
	if _, set := ev.Values["free_mb"]; set {
		t.Errorf("an int field took a fraction: %v", ev.Values)
	}
}

// Only the first binding of an object counts, so a hostile trap cannot override
// the state or the severity by sending the object twice.
func TestTrapSemantics_FirstBindingWins(t *testing.T) {
	ev := decodeForTest(t, buildTrapV2c(t, vt+"4",
		tvb{vf + "2.0", berInt(3)}, tvb{vf + "2.0", berInt(1)},
		tvb{vf + "13.0", berInt(0)}, tvb{vf + "13.0", berInt(1)}))
	if ev.EventState != "clear" || ev.NativeSeverityText != "minor" {
		t.Fatalf("state=%q native=%q", ev.EventState, ev.NativeSeverityText)
	}
}
