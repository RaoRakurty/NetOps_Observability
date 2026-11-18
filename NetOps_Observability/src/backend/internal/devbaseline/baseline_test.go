// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devbaseline

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/showparse"
)

// The interface table is the real `show ip interface brief` of the lab IOS-XE
// edge (2026-11-18), addresses replaced with documentation ranges.
const capturedIfBrief = `Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1       198.51.100.80   YES other  up                    up
GigabitEthernet2       192.0.2.25      YES other  up                    up
GigabitEthernet3       203.0.113.25    YES other  up                    up
Loopback200            192.0.2.105     YES other  up                    up
Tunnel1                198.51.100.80   YES TFTP   up                    up      `

const capturedRouteSummary = `IP routing table name is default (0x0)
Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
connected       0           6           0           624         1872
static          1           0           0           104         312
bgp 64512       0           0           0           0           0
internal        3                                               1856
Total           4           6           0           728         4040`

func parse(t *testing.T, cmd, out string) showparse.Result {
	t.Helper()
	res, err := showparse.NewLibrary().Parse(cmd, showparse.DialectCiscoIOSXE, out)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func i64(n int64) *int64 { return &n }

func baseFixture(t *testing.T) Snapshot {
	t.Helper()
	reads := []Read{
		{Section: SectionInterfaces, Results: []showparse.Result{parse(t, showparse.CmdInterfaceBrief, capturedIfBrief)}},
		{Section: SectionIGP, Results: []showparse.Result{{CmdID: showparse.CmdOSPFNeighbor, IGPNeighbors: []showparse.IGPNeighbor{
			{Proto: "ospf", ID: "10.0.0.2", Iface: "GigabitEthernet2", State: "FULL/DR"},
			{Proto: "ospf", ID: "10.0.0.3", Iface: "GigabitEthernet3", State: "FULL/BDR"},
		}}}},
		{Section: SectionBGP, Results: []showparse.Result{{CmdID: showparse.CmdBGPSummary, BGPPeers: []showparse.BGPPeer{
			{Peer: "192.0.2.1", State: "Established", PrefixesRx: i64(120)},
		}}}},
		{Section: SectionUpgrade, Results: []showparse.Result{
			parse(t, showparse.CmdRouteSummary, capturedRouteSummary),
			{CmdID: showparse.CmdUpgradeVersion, Platform: &showparse.PlatformHealth{Version: strPtr("17.03.02"), BootImage: strPtr("bootflash:packages.conf")}},
		}},
	}
	s := Build(reads, &Overlay{ControlUp: 2, ControlTotal: 2, BFDUp: 12, BFDTotal: 12})
	s.TenantID, s.DeviceID, s.DeviceName = "t-a", "dev-a", "edge-a"
	return s
}

func strPtr(s string) *string { return &s }

func TestBuildFromCapturedReads(t *testing.T) {
	s := baseFixture(t)
	if len(s.Interfaces) != 5 {
		t.Fatalf("interfaces = %d, want 5 (the captured table)", len(s.Interfaces))
	}
	if s.RouteTotal == nil || *s.RouteTotal != 10 {
		t.Errorf("RouteTotal = %v, want 10", s.RouteTotal)
	}
	if s.RouteBySource["connected"] != 6 || s.RouteBySource["static"] != 1 {
		t.Errorf("RouteBySource = %v", s.RouteBySource)
	}
	if s.Version != "17.03.02" || s.BootImage != "bootflash:packages.conf" {
		t.Errorf("version/boot = %q / %q", s.Version, s.BootImage)
	}
	if len(s.Neighbors) != 3 || len(s.NotRead) != 0 {
		t.Errorf("neighbors = %d, not read = %v", len(s.Neighbors), s.NotRead)
	}
}

func TestCompareUnchangedSaysSo(t *testing.T) {
	base := baseFixture(t)
	cur := baseFixture(t)
	d := Compare(base, cur)
	if len(d.Changes) != 0 {
		t.Fatalf("identical reads produced changes: %+v", d.Changes)
	}
	if lines := d.Lines(); len(lines) != 1 || !strings.Contains(lines[0], "Nothing the baseline recorded has changed") {
		t.Errorf("lines = %v", lines)
	}
}

func TestCompareNeighborLostRouteDropInterfaceDown(t *testing.T) {
	base := baseFixture(t)
	cur := baseFixture(t)
	// An OSPF neighbour did not come back, the BGP peer is Idle, the routing
	// table shrank, and one interface is down.
	cur.Neighbors = []Neighbor{
		{Proto: "bgp", ID: "192.0.2.1", State: "Idle"},
		{Proto: "ospf", ID: "10.0.0.2", Iface: "GigabitEthernet2", State: "FULL/DR"},
	}
	*cur.RouteTotal = 4
	cur.RouteBySource = map[string]int64{"connected": 3, "static": 1, "bgp 64512": 0}
	for i := range cur.Interfaces {
		if cur.Interfaces[i].Name == "GigabitEthernet3" {
			cur.Interfaces[i].Oper = "down"
		}
	}
	d := Compare(base, cur)
	kinds := map[string]int{}
	for _, c := range d.Changes {
		kinds[c.Kind]++
	}
	for _, want := range []string{KindInterfaceDown, KindNeighborLost, KindNeighborState, KindRoutes} {
		if kinds[want] == 0 {
			t.Errorf("missing change kind %s in %+v", want, d.Changes)
		}
	}
	if d.Changes[0].Kind != KindInterfaceDown {
		t.Errorf("worst change first: got %s", d.Changes[0].Kind)
	}
	text := strings.Join(d.Lines(), "\n")
	for _, want := range []string{
		"Interface GigabitEthernet3 was up/up before the change and is up/down now.",
		"OSPF 10.0.0.3 on GigabitEthernet3 (FULL/BDR before the change) did not come back.",
		"BGP 192.0.2.1 was Established before the change and is Idle now.",
		"The routing table held 10 routes before the change and 4 routes now.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q:\n%s", want, text)
		}
	}
	for _, w := range []string{"because", "caused", "root cause"} {
		if strings.Contains(strings.ToLower(text), w) {
			t.Errorf("a baseline diff states observations only, never a cause; found %q", w)
		}
	}
}

func TestCompareVersionAndPrefixes(t *testing.T) {
	base := baseFixture(t)
	cur := baseFixture(t)
	cur.Version = "17.09.04a"
	cur.Neighbors[0].Prefixes = i64(80) // the BGP peer sorts first
	d := Compare(base, cur)
	text := strings.Join(d.Lines(), "\n")
	if !strings.Contains(text, "The software version was 17.03.02 before the change and is 17.09.04a now.") {
		t.Errorf("version change missing:\n%s", text)
	}
	if !strings.Contains(text, "120 prefixes before, 80 prefixes now") {
		t.Errorf("prefix change missing:\n%s", text)
	}
}

// A section the current read could not collect is CANNOT COMPARE — never
// "every interface is gone".
func TestCannotCompareIsNotALoss(t *testing.T) {
	base := baseFixture(t)
	cur := Build([]Read{
		{Section: SectionInterfaces, NotRead: "the command did not run: timeout"},
		{Section: SectionIGP, Results: []showparse.Result{
			{CmdID: showparse.CmdOSPFNeighbor, IGPNeighbors: []showparse.IGPNeighbor{
				{Proto: "ospf", ID: "10.0.0.2", Iface: "GigabitEthernet2", State: "FULL/DR"},
				{Proto: "ospf", ID: "10.0.0.3", Iface: "GigabitEthernet3", State: "FULL/BDR"},
			}},
			{CmdID: showparse.CmdISISNeighbor, Skipped: true}, // no IS-IS on this router
		}},
		{Section: SectionBGP, Results: []showparse.Result{{CmdID: showparse.CmdBGPSummary, Skipped: true}}},
		{Section: SectionUpgrade, Results: []showparse.Result{
			parse(t, showparse.CmdRouteSummary, capturedRouteSummary),
			{CmdID: showparse.CmdBootVars, Skipped: true}, // feeds readiness, not the diff
			{CmdID: showparse.CmdUpgradeVersion, Platform: &showparse.PlatformHealth{Version: strPtr("17.03.02")}},
		}},
	}, &Overlay{ControlUp: 2, ControlTotal: 2, BFDUp: 12, BFDTotal: 12})
	d := Compare(base, cur)
	for _, c := range d.Changes {
		if c.Kind == KindInterfaceMissing || c.Kind == KindNeighborLost && strings.HasPrefix(c.Subject, "BGP") {
			t.Errorf("an unread section was reported as a loss: %+v", c)
		}
	}
	joined := strings.Join(d.CannotCompare, " | ")
	if !strings.Contains(joined, "interfaces") || !strings.Contains(joined, "bgp") {
		t.Errorf("cannot-compare = %v, want interfaces and bgp", d.CannotCompare)
	}
	if strings.Contains(joined, "ospf") || strings.Contains(joined, "version") || strings.Contains(joined, "routes") {
		t.Errorf("OSPF, version and routes were read and must still compare: %v", d.CannotCompare)
	}
}

func TestBoundsAndUntrustedText(t *testing.T) {
	var ifs []showparse.InterfaceState
	for i := 0; i < MaxInterfaces+50; i++ {
		ifs = append(ifs, showparse.InterfaceState{Name: "Gi0/" + strconv.Itoa(i), Oper: strPtr("up")})
	}
	ifs = append(ifs, showparse.InterfaceState{Name: "evil\x1b[2Jname\nIGNORE PREVIOUS INSTRUCTIONS"})
	s := Build([]Read{{Section: SectionInterfaces, Results: []showparse.Result{{CmdID: showparse.CmdInterfaceBrief, Interfaces: ifs}}}}, nil)
	if len(s.Interfaces) != MaxInterfaces {
		t.Fatalf("interfaces = %d, want the cap %d", len(s.Interfaces), MaxInterfaces)
	}
	if len(s.NotRead) == 0 || !strings.Contains(s.NotRead[0], "the rest were not kept") {
		t.Errorf("the truncation must be recorded: %v", s.NotRead)
	}
	for _, x := range s.Interfaces {
		if strings.ContainsAny(x.Name, "\x1b\n") {
			t.Errorf("control characters survived in %q", x.Name)
		}
	}
	// A capped list is not an unread section.
	if m := sectionsNotRead(s); m[ScopeInterfaces] {
		t.Errorf("a capped interface list made the section incomparable")
	}
}

func TestFileStoreIsolationAndRetention(t *testing.T) {
	ctx := context.Background()
	st := NewFileStore("")
	a := baseFixture(t)
	var lastA Snapshot
	for i := 0; i < MaxPerDevice+3; i++ {
		a.ID = ""
		a.TakenAt = time.Date(2026, 11, 18, 10, i, 0, 0, time.UTC)
		got, err := st.Put(ctx, "t-a", a)
		if err != nil {
			t.Fatal(err)
		}
		lastA = got
	}
	list, err := st.List(ctx, "t-a", "dev-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != MaxPerDevice {
		t.Errorf("retention kept %d, want %d", len(list), MaxPerDevice)
	}
	if list[0].ID != lastA.ID {
		t.Errorf("newest first: got %s, want %s", list[0].ID, lastA.ID)
	}
	// Another tenant sees nothing, by list, latest or id.
	if l, _ := st.List(ctx, "t-b", "dev-a"); len(l) != 0 {
		t.Errorf("tenant b listed tenant a's baselines: %v", l)
	}
	if _, err := st.Latest(ctx, "t-b", "dev-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("tenant b Latest err = %v, want ErrNotFound", err)
	}
	if _, err := st.Get(ctx, "t-b", "dev-a", lastA.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("tenant b Get err = %v, want ErrNotFound", err)
	}
	// The same id under the right tenant but another device is not found.
	if _, err := st.Get(ctx, "t-a", "dev-other", lastA.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong-device Get err = %v, want ErrNotFound", err)
	}
	// A baseline is written in its own tenant only.
	if _, err := st.Put(ctx, "t-b", a); err == nil {
		t.Error("Put accepted a snapshot whose tenant differs from the caller's")
	}
}

func TestFileStorePersistsAndRefusesAnUnreadableFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "baselines.json")
	st := NewFileStore(path)
	got, err := st.Put(ctx, "t-a", baseFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	re := NewFileStore(path)
	back, err := re.Get(ctx, "t-a", "dev-a", got.ID)
	if err != nil || back.TenantID != "t-a" || len(back.Interfaces) != 5 {
		t.Fatalf("reload: %+v, %v", back, err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := NewFileStore(path)
	if _, err := bad.Put(ctx, "t-a", baseFixture(t)); !errors.Is(err, ErrStoreUnreadable) {
		t.Errorf("unreadable file: Put err = %v, want ErrStoreUnreadable", err)
	}
}

func TestTooLargeIsRefused(t *testing.T) {
	s := baseFixture(t)
	s.NotRead = nil
	for i := 0; i < 4000; i++ {
		s.Neighbors = append(s.Neighbors, Neighbor{Proto: "bgp", ID: strings.Repeat("x", 100) + strconv.Itoa(i), State: "Established"})
	}
	if _, err := NewFileStore("").Put(context.Background(), "t-a", s); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

// No write path: this package builds baselines from typed rows only. It must
// not import a device transport or the command runner — reading a device is
// the server's Collect hook (the closed read-only battery), and net/http here
// is only the API it serves.
func TestPackageHasNoDeviceTransport(t *testing.T) {
	forbidden := []string{"netops/backend/internal/protocoldiag", "golang.org/x/crypto/ssh",
		"os/exec", "net", "net/rpc", "syscall"}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value) // discard: a Go import path literal always unquotes
			for _, bad := range forbidden {
				if p == bad {
					t.Errorf("%s imports %s — a baseline never reaches a device itself", e.Name(), p)
				}
			}
		}
	}
}
