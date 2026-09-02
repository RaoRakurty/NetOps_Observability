package ai

// troubleshoot_state_test.go — the `get_device_state` contract (IRIS Phase A4).
//
// Four properties are load-bearing and pinned here:
//
//   - the ARGUMENT vocabulary is closed: a bad area, a target on an area that
//     takes none, a missing target where one is required, and a non-address
//     target all fail BEFORE any seam is touched;
//   - a cross-tenant / unknown device is ErrNotFound, indistinguishably;
//   - an unavailable capability is DISCLOSED with the read-only command list —
//     never a fabricated reading, and never a "clean" silence;
//   - only signals from the CLOSED `state:` vocabulary reach the chain, one per
//     facet, and unparsed output is labelled unparsed in those words.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// stateDeps wires a state seam whose report each test shapes.
func stateDeps(rep DeviceStateReport, err error) TroubleshootDeps {
	d := tsDeps()
	d.DeviceState = func(_ context.Context, _ Principal, req DeviceStateRequest) (DeviceStateReport, error) {
		if err != nil {
			return DeviceStateReport{}, err
		}
		out := rep
		out.DeviceID, out.Area = req.DeviceID, req.Area
		return out, nil
	}
	return d
}

func stateArgs(area string) ToolArgs { return ToolArgs{"device_id": "edge-1", "area": area} }

func TestDeviceStateArgValidation(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	tool, ok := reg.Get("get_device_state")
	if !ok {
		t.Fatal("get_device_state must register with a wired seam")
	}
	cases := []struct {
		name string
		args ToolArgs
		want string // substring of the refusal
	}{
		{"device_id is required", ToolArgs{"area": "bgp"}, "device_id is required"},
		{"area is required", ToolArgs{"device_id": "edge-1"}, "area must be one of"},
		{"area is closed", ToolArgs{"device_id": "edge-1", "area": "everything"}, "area must be one of"},
		{"area is not free text", ToolArgs{"device_id": "edge-1", "area": "bgp; show run"}, "area must be one of"},
		{"platform takes no target", ToolArgs{"device_id": "edge-1", "area": "platform", "target": "Gi0/1"}, "takes no target"},
		{"logs takes no target", ToolArgs{"device_id": "edge-1", "area": "logs", "target": "x"}, "takes no target"},
		{"routes needs a target", ToolArgs{"device_id": "edge-1", "area": "routes"}, "needs a target"},
		{"a route target must look like a prefix", ToolArgs{"device_id": "edge-1", "area": "routes", "target": "the-default-route"}, "must be an IP address"},
		{"an l2 target must look like an address", ToolArgs{"device_id": "edge-1", "area": "l2", "target": "server42!"}, "must be an IP address"},
		{"an interface target is bounded", ToolArgs{"device_id": "edge-1", "area": "interfaces", "target": strings.Repeat("i", 200)}, "too long"},
		{"an interface target has no shell metacharacters", ToolArgs{"device_id": "edge-1", "area": "interfaces", "target": "Gi0/1 | show run"}, "unsupported character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tool.Run(context.Background(), tsPrincipal(), tc.args)
			if err == nil {
				t.Fatalf("%v must be refused", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not explain the refusal (want %q)", err, tc.want)
			}
		})
	}

	// Every area accepts its own legal shape.
	for _, area := range StateAreas() {
		args := stateArgs(area)
		switch area {
		case "routes":
			args["target"] = "203.0.113.0/24"
		case "l2":
			args["target"] = "0011.2233.4455"
		case "interfaces":
			args["target"] = "GigabitEthernet0/0/1"
		}
		if _, err := tool.Run(context.Background(), tsPrincipal(), args); err != nil {
			t.Errorf("area %q with a legal target was refused: %v", area, err)
		}
	}
}

// A device the caller may not see and a device that does not exist must be
// indistinguishable, and the state seam must never be reached for either.
func TestDeviceStateCrossTenantIsNotFound(t *testing.T) {
	reached := false
	d := tsDeps()
	d.DeviceState = func(context.Context, Principal, DeviceStateRequest) (DeviceStateReport, error) {
		reached = true
		return DeviceStateReport{}, nil
	}
	tool, _ := tsRegistry(t, d).Get("get_device_state")
	for _, ref := range []string{"leaf-2", "dev-b", "no-such-device"} {
		_, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device_id": ref, "area": "bgp"})
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: err = %v, want ErrNotFound", ref, err)
		}
	}
	if reached {
		t.Fatal("the state seam was reached for a device the caller cannot see")
	}
}

// The honesty floor: no capture transport ⇒ the read-only command list, an
// explicit "unknown, not healthy" note, and a `state:collect=not_wired` fact the
// chain can branch on. Never a reading.
func TestDeviceStateNotWiredIsHonest(t *testing.T) {
	rep := DeviceStateReport{
		DeviceName: "edge-1", Platform: "ios-xe", Dialect: "cisco/ios_xe", Collected: false,
		NotWired: "live device-state collection is not wired on this deployment — no command was run",
		Commands: []DiagnosticCommand{
			{SpecID: "bgp-summary", Purpose: "BGP session state", Command: "show ip bgp summary"},
		},
	}
	tool, _ := tsRegistry(t, stateDeps(rep, nil)).Get("get_device_state")
	res, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("bgp"))
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.ToLower(strings.Join(res.Notes, " | "))
	if !strings.Contains(notes, "not wired") {
		t.Errorf("the reason must be disclosed verbatim: %q", notes)
	}
	if !strings.Contains(notes, "unknown, not healthy") {
		t.Errorf("an unread device must be called UNKNOWN, not healthy: %q", notes)
	}
	if !containsSignal(res.Signals, "state:collect=not_wired") {
		t.Errorf("signals = %v, want state:collect=not_wired", res.Signals)
	}
	cmds := 0
	for _, it := range res.Items {
		if strings.Contains(it.Text, "show ip bgp summary") {
			cmds++
		}
	}
	if cmds != 1 {
		t.Errorf("the read-only command bundle must be handed back exactly once: %+v", res.Items)
	}
}

// An unassessed platform is its own answer: `unsupported`, not `not_wired`, and
// never a Cisco command rendered at an unknown box.
func TestDeviceStateUnsupportedPlatform(t *testing.T) {
	rep := DeviceStateReport{
		DeviceName: "edge-1", Platform: "someos 9", Status: "unsupported", Collected: false,
		NotWired: `platform "someos 9" does not resolve to a known CLI dialect`,
	}
	tool, _ := tsRegistry(t, stateDeps(rep, nil)).Get("get_device_state")
	res, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("igp"))
	if err != nil {
		t.Fatal(err)
	}
	if !containsSignal(res.Signals, "state:collect=unsupported") {
		t.Fatalf("signals = %v, want state:collect=unsupported", res.Signals)
	}
	head := res.Items[0].Text
	if !strings.Contains(head, "no known CLI dialect") {
		t.Errorf("the head line must say the platform is unassessed: %q", head)
	}
}

// Signals: only the closed vocabulary survives, and the citation ids are stable.
func TestDeviceStateSignalsAreClosedAndCited(t *testing.T) {
	rep := DeviceStateReport{
		DeviceName: "edge-1", Dialect: "cisco/ios_xe", Status: "ok", Collected: true,
		Rows: []StateRow{
			{Text: "BGP peer 10.0.0.1 — AS65001, state Idle", Signals: []string{"state:bgp_peer=idle"}},
			{Text: "BGP peer 10.0.0.2 — AS65002, state Established", Signals: []string{"state:bgp_peer=established"}},
			{Text: "BGP peer 10.0.0.3 — invented", Signals: []string{"state:bgp_peer=on_fire"}},   // outside the value set
			{Text: "BGP peer 10.0.0.4 — invented", Signals: []string{"state:nonsense=idle"}},      // outside the facet set
			{Text: "BGP peer 10.0.0.5 — invented", Signals: []string{"signature=bgp-fabricated"}}, // wrong namespace entirely
		},
	}
	tool, _ := tsRegistry(t, stateDeps(rep, nil)).Get("get_device_state")
	res, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("bgp"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"state:bgp_peer=established", "state:bgp_peer=idle", "state:collect=ok"}
	if len(res.Signals) != len(want) {
		t.Fatalf("signals = %v, want exactly %v", res.Signals, want)
	}
	for i, w := range want {
		if res.Signals[i] != w {
			t.Fatalf("signals = %v, want %v (sorted, closed vocabulary only)", res.Signals, want)
		}
	}
	for i, it := range res.Items {
		if want := fmt.Sprintf("state:bgp:dev-a:%d", i); it.CitationID != want {
			t.Errorf("citation %d = %q, want %q", i, it.CitationID, want)
		}
	}
}

// Caps: the per-area row cap bounds the PROMPT, and the truncation is disclosed
// — but a decisive fact past the cap is still asserted.
func TestDeviceStateRowCap(t *testing.T) {
	rep := DeviceStateReport{DeviceName: "edge-1", Status: "ok", Collected: true}
	for i := 0; i < MaxStateRowsIGP+12; i++ {
		row := StateRow{Text: fmt.Sprintf("OSPF neighbour 10.0.0.%d — state FULL/DR", i), Signals: []string{"state:igp_nbr=full"}}
		if i == MaxStateRowsIGP+5 { // past the cap
			row = StateRow{Text: "OSPF neighbour 10.0.0.250 — state EXSTART", Signals: []string{"state:igp_nbr=not_full"}}
		}
		rep.Rows = append(rep.Rows, row)
	}
	tool, _ := tsRegistry(t, stateDeps(rep, nil)).Get("get_device_state")
	res, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("igp"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Items); got != MaxStateRowsIGP+1 { // + the head line
		t.Fatalf("rendered %d items, want the head plus %d capped rows", got, MaxStateRowsIGP)
	}
	if !res.Truncated {
		t.Error("hitting the cap must be disclosed as truncation")
	}
	if !containsSignal(res.Signals, "state:igp_nbr=not_full") {
		t.Fatalf("a decisive fact past the row cap must still be asserted: %v", res.Signals)
	}
}

// An output no parser could read is quoted as UNPARSED, in those words, and is
// never turned into a typed row.
func TestDeviceStateUnparsedOutputIsLabelled(t *testing.T) {
	rep := DeviceStateReport{
		DeviceName: "edge-1", Status: "partial", Collected: true,
		Note: "1 of 2 commands failed",
		Gaps: []StateGap{{
			Command: "show isis adjacency",
			Reason:  "no parser is established for isis-neighbor on cisco/nx-os",
			Lines:   []string{"System Id       SNPA        Level  State", "core-2          N/A         L2     Up"},
		}},
	}
	tool, _ := tsRegistry(t, stateDeps(rep, nil)).Get("get_device_state")
	res, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("igp"))
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(res.Notes, " | ")
	if !strings.Contains(notes, "UNPARSED") {
		t.Errorf("an unreadable capture must say UNPARSED: %q", notes)
	}
	if !strings.Contains(notes, "1 of 2 commands failed") {
		t.Errorf("the collector's own note must be disclosed: %q", notes)
	}
	quoted := 0
	for _, it := range res.Items {
		if strings.HasPrefix(it.Text, "unparsed output of") {
			quoted++
		}
	}
	if quoted != 2 {
		t.Fatalf("both redacted raw lines must be quoted as unparsed, got %d (%+v)", quoted, res.Items)
	}
	if !containsSignal(res.Signals, "state:collect=partial") {
		t.Errorf("signals = %v, want state:collect=partial", res.Signals)
	}
}

// A completed read that returned nothing must say the device reported NOTHING —
// silence must never render as health.
func TestDeviceStateEmptyReadIsNotHealth(t *testing.T) {
	tool, _ := tsRegistry(t, stateDeps(DeviceStateReport{
		DeviceName: "edge-1", Status: "ok", Collected: true,
	}, nil)).Get("get_device_state")
	res, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("l2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Notes, " | "), "reported NOTHING") {
		t.Fatalf("an empty read must not read as healthy: %v", res.Notes)
	}
}

// A seam error propagates unchanged (the runner classifies it; the tool must not
// swallow it into a fabricated answer).
func TestDeviceStateSeamErrorPropagates(t *testing.T) {
	tool, _ := tsRegistry(t, stateDeps(DeviceStateReport{}, ErrNotImplemented)).Get("get_device_state")
	if _, err := tool.Run(context.Background(), tsPrincipal(), stateArgs("platform")); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v, want ErrNotImplemented", err)
	}
}

// The tool's closed area vocabulary must not drift from the battery's; the root
// package pins it to protocoldiag.Areas(). Here we pin its shape and order.
func TestStateAreaVocabularyIsClosed(t *testing.T) {
	want := []string{"interfaces", "igp", "bgp", "routes", "l2", "platform", "logs"}
	got := StateAreas()
	if len(got) != len(want) {
		t.Fatalf("areas = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("areas = %v, want %v", got, want)
		}
	}
	// The returned slice is a copy: a caller cannot mutate the vocabulary.
	got[0] = "mutated"
	if StateAreas()[0] != "interfaces" {
		t.Fatal("StateAreas() must return a copy")
	}
	for _, a := range want {
		if _, ok := stateTargetRules[a]; !ok {
			t.Errorf("area %q has no target rule", a)
		}
		if stateRowCap(a) <= 0 {
			t.Errorf("area %q has no positive row cap", a)
		}
	}
}

func containsSignal(sigs []string, want string) bool {
	for _, s := range sigs {
		if s == want {
			return true
		}
	}
	return false
}
