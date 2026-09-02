package protocoldiag

// fanout_test.go — the parallel-collection proofs, all against an in-memory
// runner. No test here opens a socket.
//
// The property under test is the one NetClaw states in one line and we have to
// prove in code: ONE DEVICE'S FAILURE OR TIMEOUT CHANGES NOTHING FOR THE OTHERS.
// Every case below is a different way for a device to go wrong — error, hang,
// unassessed platform, no command for the area, cancellation — checked against
// the same assertion: the healthy devices still return complete, correct state.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/showparse"
)

// ── an in-memory runner with per-device behaviour ───────────────────────────

// scriptedRunner answers a battery command per device. It records concurrency
// (so the cap can be observed), can block a named device until released, and can
// fail a named device — the three shapes a real fleet produces.
type scriptedRunner struct {
	mu       sync.Mutex
	inFlight int
	maxSeen  int
	calls    map[string]int  // device id → commands run
	perDevID map[string]bool // device id → currently in flight (one-at-a-time proof)
	doubled  []string        // device ids seen twice concurrently

	output map[string]string // spec-independent canned output, by device id
	fail   map[string]error  // device id → error for every command
	hang   map[string]bool   // device id → block until ctx is done
	delay  time.Duration
}

func newScriptedRunner() *scriptedRunner {
	return &scriptedRunner{
		calls: map[string]int{}, perDevID: map[string]bool{},
		output: map[string]string{}, fail: map[string]error{}, hang: map[string]bool{},
	}
}

func (r *scriptedRunner) Run(ctx context.Context, dev Device, command string) (string, error) {
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > r.maxSeen {
		r.maxSeen = r.inFlight
	}
	if r.perDevID[dev.ID] {
		r.doubled = append(r.doubled, dev.ID)
	}
	r.perDevID[dev.ID] = true
	r.calls[dev.ID]++
	hang, failErr, out, delay := r.hang[dev.ID], r.fail[dev.ID], r.output[dev.ID], r.delay
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.inFlight--
		r.perDevID[dev.ID] = false
		r.mu.Unlock()
	}()

	if hang {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if failErr != nil {
		return "", failErr
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return out, nil
}

func (r *scriptedRunner) snapshot() (maxConcurrent int, calls map[string]int, doubled []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := map[string]int{}
	for k, v := range r.calls {
		cp[k] = v
	}
	return r.maxSeen, cp, append([]string(nil), r.doubled...)
}

// bgpSummaryOutput is a realistic Cisco BGP summary used as canned output.
const bgpSummaryOutput = `BGP router identifier 10.255.0.1, local AS number 65001

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4        65002    1234    1235     1234    0    0 02:31:11       12
10.0.0.3        4        65003       0       0        1    0    0 never    Idle
`

func devN(n int, platform string) Device {
	return Device{
		ID:       fmt.Sprintf("dev-%d", n),
		Hostname: fmt.Sprintf("core-%02d", n),
		Platform: platform,
		Address:  fmt.Sprintf("192.0.2.%d", n),
		TenantID: "acme",
	}
}

func newBatteryCollector(t *testing.T, r CommandRunner, opts ...BatteryOption) *BatteryCollector {
	t.Helper()
	c, err := NewBatteryCollector(DefaultStateBattery(), r, opts...)
	if err != nil {
		t.Fatalf("NewBatteryCollector: %v", err)
	}
	return c
}

// ── construction ────────────────────────────────────────────────────────────

func TestNewBatteryCollector_FailsClosed(t *testing.T) {
	if _, err := NewBatteryCollector(nil, newScriptedRunner()); err == nil {
		t.Error("a nil battery must be refused, not silently accepted")
	}
	if _, err := NewBatteryCollector(DefaultStateBattery(), nil); err == nil {
		t.Error("a nil runner must be refused")
	}
}

func TestRunBattery_UnknownArea(t *testing.T) {
	c := newBatteryCollector(t, newScriptedRunner())
	_, err := c.RunBattery(context.Background(), []Device{devN(1, "Cisco IOS-XE 17.9")}, Area("nope"), Target{})
	if !errors.Is(err, ErrUnknownArea) {
		t.Errorf("got %v, want ErrUnknownArea", err)
	}
}

// ── the headline property ───────────────────────────────────────────────────

// TestRunBattery_FailureIsolation puts one healthy device, one that errors on
// every command, one that hangs past its deadline and one on an unassessed
// platform in the SAME run, and asserts the healthy one is untouched.
func TestRunBattery_FailureIsolation(t *testing.T) {
	r := newScriptedRunner()
	healthy := devN(1, "Cisco IOS-XE 17.9")
	broken := devN(2, "Cisco IOS-XE 17.9")
	hung := devN(3, "Cisco IOS-XE 17.9")
	alien := devN(4, "Acme MysteryOS 1.0")
	r.output[healthy.ID] = bgpSummaryOutput
	r.fail[broken.ID] = errors.New("connect: connection refused")
	r.hang[hung.ID] = true

	c := newBatteryCollector(t, r, WithDeviceTimeout(150*time.Millisecond))
	start := time.Now()
	run, err := c.RunBattery(context.Background(), []Device{healthy, broken, hung, alien}, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	elapsed := time.Since(start)

	if len(run.Devices) != 4 {
		t.Fatalf("got %d device states, want 4", len(run.Devices))
	}
	if run.Devices[0].DeviceID != healthy.ID || run.Devices[3].DeviceID != alien.ID {
		t.Error("results must come back in the caller's device order")
	}

	// 1. the healthy device is complete and correct
	h := run.Devices[0]
	if h.Status != DeviceStatusOK {
		t.Errorf("healthy device status = %q (%s), want ok", h.Status, h.Note)
	}
	if len(h.Parsed) != 1 || h.Parsed[0].Skipped {
		t.Fatalf("healthy device parse: %+v", h.Parsed)
	}
	if n := len(h.Parsed[0].BGPPeers); n != 2 {
		t.Errorf("healthy device parsed %d peers, want 2", n)
	}
	if h.TenantID != "acme" {
		t.Errorf("TenantID = %q, must be stamped from the device (§3a)", h.TenantID)
	}
	if h.Dialect != showparse.DialectCiscoIOSXE {
		t.Errorf("dialect = %q", h.Dialect)
	}

	// 2. the broken device reports its own failure
	if b := run.Devices[1]; b.Status != DeviceStatusFailed {
		t.Errorf("broken device status = %q, want failed", b.Status)
	} else if len(b.Commands) == 0 || b.Commands[0].Err == "" {
		t.Error("the broken device must carry the transport error on its command")
	}

	// 3. the hung device times out on ITS OWN deadline
	if g := run.Devices[2]; g.Status != DeviceStatusTimedOut {
		t.Errorf("hung device status = %q (%s), want timed_out", g.Status, g.Note)
	}

	// 4. the unassessed platform is unsupported, and NO command was run on it
	a := run.Devices[3]
	if a.Status != DeviceStatusUnsupported {
		t.Errorf("alien platform status = %q, want unsupported", a.Status)
	}
	if len(a.Commands) != 0 {
		t.Errorf("a command was run at an unassessed platform: %+v", a.Commands)
	}
	if a.Dialect != "" {
		t.Errorf("an unassessed platform must resolve to NO dialect, got %q", a.Dialect)
	}

	// 5. the whole run is bounded by the per-device deadline, not by the hang
	if elapsed > 3*time.Second {
		t.Fatalf("the run took %v — a hung device blocked the others", elapsed)
	}
	counts := run.Counts()
	if counts[DeviceStatusOK] != 1 || counts[DeviceStatusFailed] != 1 ||
		counts[DeviceStatusTimedOut] != 1 || counts[DeviceStatusUnsupported] != 1 {
		t.Errorf("Counts() = %v", counts)
	}
}

// TestRunBattery_ConcurrencyCap proves the fan-out never exceeds the ceiling and
// never runs two commands at one device at once.
func TestRunBattery_ConcurrencyCap(t *testing.T) {
	r := newScriptedRunner()
	r.delay = 20 * time.Millisecond
	var devs []Device
	for i := 1; i <= 24; i++ {
		d := devN(i, "Cisco IOS-XE 17.9")
		r.output[d.ID] = bgpSummaryOutput
		devs = append(devs, d)
	}
	c := newBatteryCollector(t, r)
	run, err := c.RunBattery(context.Background(), devs, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	maxSeen, calls, doubled := r.snapshot()
	if maxSeen > MaxBatteryConcurrency {
		t.Errorf("peak concurrency %d exceeds the cap of %d", maxSeen, MaxBatteryConcurrency)
	}
	if maxSeen < 2 {
		t.Errorf("peak concurrency %d — the fan-out did not run in parallel at all", maxSeen)
	}
	if len(doubled) != 0 {
		t.Errorf("two commands were in flight at the same device: %v", doubled)
	}
	if len(calls) != 24 {
		t.Errorf("%d devices were contacted, want 24", len(calls))
	}
	for _, d := range run.Devices {
		if d.Status != DeviceStatusOK {
			t.Errorf("%s: %s (%s)", d.DeviceID, d.Status, d.Note)
		}
	}
}

// TestRunBattery_ConcurrencyCanOnlyNarrow proves WithConcurrency cannot widen
// the ceiling.
func TestRunBattery_ConcurrencyCanOnlyNarrow(t *testing.T) {
	r := newScriptedRunner()
	r.delay = 15 * time.Millisecond
	var devs []Device
	for i := 1; i <= 12; i++ {
		d := devN(i, "Cisco IOS-XE 17.9")
		r.output[d.ID] = bgpSummaryOutput
		devs = append(devs, d)
	}
	c := newBatteryCollector(t, r, WithConcurrency(1000))
	if _, err := c.RunBattery(context.Background(), devs, AreaBGP, Target{}); err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if maxSeen, _, _ := r.snapshot(); maxSeen > MaxBatteryConcurrency {
		t.Errorf("WithConcurrency(1000) widened the cap to %d", maxSeen)
	}

	r2 := newScriptedRunner()
	r2.delay = 15 * time.Millisecond
	for _, d := range devs {
		r2.output[d.ID] = bgpSummaryOutput
	}
	c2 := newBatteryCollector(t, r2, WithConcurrency(2))
	if _, err := c2.RunBattery(context.Background(), devs, AreaBGP, Target{}); err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if maxSeen, _, _ := r2.snapshot(); maxSeen > 2 {
		t.Errorf("WithConcurrency(2) allowed %d in flight", maxSeen)
	}
}

// TestRunBattery_CancellationPropagates proves a cancelled caller context ends
// the run promptly AND still returns one honest state per device.
func TestRunBattery_CancellationPropagates(t *testing.T) {
	r := newScriptedRunner()
	var devs []Device
	for i := 1; i <= 20; i++ {
		d := devN(i, "Cisco IOS-XE 17.9")
		r.hang[d.ID] = true
		devs = append(devs, d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(60 * time.Millisecond)
		cancel()
	}()
	c := newBatteryCollector(t, r, WithDeviceTimeout(10*time.Second), WithTotalTimeout(10*time.Second))
	start := time.Now()
	run, err := c.RunBattery(ctx, devs, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("cancellation took %v to take effect", d)
	}
	if len(run.Devices) != 20 {
		t.Fatalf("got %d states, want one per device even under cancellation", len(run.Devices))
	}
	for _, d := range run.Devices {
		switch d.Status {
		case DeviceStatusTimedOut, DeviceStatusFailed:
		default:
			t.Errorf("%s: status %q under cancellation", d.DeviceID, d.Status)
		}
		if d.Note == "" {
			t.Errorf("%s: a non-OK status must carry a note", d.DeviceID)
		}
	}
}

// TestRunBattery_TotalTimeoutBoundsTheRun proves the whole-run budget holds even
// when every device would hang for longer.
func TestRunBattery_TotalTimeoutBoundsTheRun(t *testing.T) {
	r := newScriptedRunner()
	var devs []Device
	for i := 1; i <= 30; i++ {
		d := devN(i, "Cisco IOS-XE 17.9")
		r.hang[d.ID] = true
		devs = append(devs, d)
	}
	c := newBatteryCollector(t, r,
		WithDeviceTimeout(10*time.Second), WithTotalTimeout(200*time.Millisecond))
	start := time.Now()
	run, err := c.RunBattery(context.Background(), devs, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the total timeout did not bound the run: %v", d)
	}
	if len(run.Devices) != 30 {
		t.Fatalf("got %d states, want 30", len(run.Devices))
	}
	if run.FinishedAt.Before(run.StartedAt) {
		t.Error("FinishedAt precedes StartedAt")
	}
}

// TestRunBattery_DedupesAndCaps proves one-in-flight-per-device is preserved by
// construction (a repeated device is scheduled once) and that an over-long
// device list is REPORTED, not silently trimmed.
func TestRunBattery_DedupesAndCaps(t *testing.T) {
	r := newScriptedRunner()
	d1 := devN(1, "Cisco IOS-XE 17.9")
	r.output[d1.ID] = bgpSummaryOutput
	c := newBatteryCollector(t, r)
	run, err := c.RunBattery(context.Background(), []Device{d1, d1, d1}, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if len(run.Devices) != 1 {
		t.Errorf("a repeated device produced %d states, want 1", len(run.Devices))
	}

	r2 := newScriptedRunner()
	var many []Device
	for i := 1; i <= MaxBatteryDevices+5; i++ {
		d := devN(i, "Cisco IOS-XE 17.9")
		r2.output[d.ID] = bgpSummaryOutput
		many = append(many, d)
	}
	c2 := newBatteryCollector(t, r2)
	run2, err := c2.RunBattery(context.Background(), many, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if !run2.Truncated {
		t.Error("an over-cap device list must be reported as truncated")
	}
	if len(run2.Devices) != MaxBatteryDevices+5 {
		t.Fatalf("got %d states, want one per input device", len(run2.Devices))
	}
	if got := run2.Counts()[DeviceStatusNotRun]; got != 5 {
		t.Errorf("%d devices reported not_run, want 5", got)
	}
	_, calls, _ := r2.snapshot()
	if len(calls) != MaxBatteryDevices {
		t.Errorf("%d devices were contacted, want the %d cap", len(calls), MaxBatteryDevices)
	}
}

// TestRunBattery_UnsupportedArea proves the no-fallback rule at the fan-out: a
// dialect with no authored command for the requested area gets NO command and an
// honest "unsupported", never another platform's command.
//
// The shipped battery covers every area on every dialect, so the gap is built
// explicitly here — which is also the exact shape a newly-onboarded platform has
// on its first day.
func TestRunBattery_UnsupportedArea(t *testing.T) {
	partial, err := NewStateBattery([]BatterySpec{
		bs(showparse.CmdBGPSummary, AreaBGP, "bgp state",
			map[showparse.Dialect]string{showparse.DialectCiscoIOSXE: "show ip bgp summary"}),
		bs(showparse.CmdOSPFNeighbor, AreaIGP, "ospf state",
			map[showparse.Dialect]string{showparse.DialectCiscoIOSXE: "show ip ospf neighbor"}),
	})
	if err != nil {
		t.Fatalf("NewStateBattery: %v", err)
	}
	r := newScriptedRunner()
	junos := devN(1, "Juniper Junos 22.4R3")
	cisco := devN(2, "Cisco IOS-XE 17.9")
	r.output[cisco.ID] = bgpSummaryOutput
	c, err := NewBatteryCollector(partial, r)
	if err != nil {
		t.Fatalf("NewBatteryCollector: %v", err)
	}
	run, err := c.RunBattery(context.Background(), []Device{junos, cisco}, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	j := run.Devices[0]
	if j.Status != DeviceStatusUnsupported {
		t.Errorf("Junos status = %q, want unsupported", j.Status)
	}
	if len(j.Commands) != 0 {
		t.Errorf("a command was rendered for an unsupported dialect: %+v", j.Commands)
	}
	if !strings.Contains(j.Note, string(AreaBGP)) {
		t.Errorf("the note must name the area: %q", j.Note)
	}
	if j.Dialect != showparse.DialectJunos {
		t.Errorf("the dialect resolved fine (%q) — only the COMMAND is missing", j.Dialect)
	}
	if run.Devices[1].Status != DeviceStatusOK {
		t.Errorf("the supported device was affected: %q", run.Devices[1].Status)
	}
	// The shipped battery has no such gap: every area renders on every dialect.
	full := DefaultStateBattery()
	tgt := Target{Interface: "GigabitEthernet0/0", Prefix: "10.0.0.0/8", Address: "10.0.0.2"}
	for _, area := range Areas() {
		for _, d := range showparse.Dialects() {
			if len(full.Battery(area, d, tgt)) == 0 {
				t.Errorf("the shipped battery renders nothing for %s on %s", area, d)
			}
		}
	}
}

// TestRunBattery_RedactsBeforeItLeaves proves the §8 rule: a secret in a
// captured line is masked in the stored output AND in everything derived from it.
func TestRunBattery_RedactsBeforeItLeaves(t *testing.T) {
	const secret = "S3cr3tK3yV4lue"
	r := newScriptedRunner()
	d := devN(1, "Cisco IOS-XE 17.9")
	r.output[d.ID] = "*Sep  2 09:58:12.345: %SEC-6-IPACCESSLOGP: key-string " + secret + "\n" +
		"*Sep  2 09:59:01.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down\n"
	c := newBatteryCollector(t, r)
	run, err := c.RunBattery(context.Background(), []Device{d}, AreaLogs, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	st := run.Devices[0]
	for _, cc := range st.Commands {
		if strings.Contains(cc.Output, secret) {
			t.Fatalf("an unredacted secret survived into the stored capture: %q", cc.Output)
		}
		if !strings.Contains(cc.Output, redactionMark) {
			t.Errorf("the secret line was not redacted at all: %q", cc.Output)
		}
	}
	// …and into the typed rows derived from it.
	for _, res := range st.Parsed {
		for _, l := range res.Logs {
			if strings.Contains(l.Raw, secret) || strings.Contains(l.Message, secret) {
				t.Fatalf("an unredacted secret reached a typed log row: %+v", l)
			}
		}
	}
	// The battery has no `show running-config`-class command in the first place.
	for _, cc := range st.Commands {
		if strings.Contains(cc.Command, "running-config") {
			t.Fatalf("the battery ran a configuration read: %q", cc.Command)
		}
	}
}

// TestRunBattery_TypedRowsAndSkips proves the evidence accounting: parsed rows
// are counted, and a capture the parser could not read surfaces its REASON
// rather than vanishing.
func TestRunBattery_TypedRowsAndSkips(t *testing.T) {
	r := newScriptedRunner()
	good := devN(1, "Cisco IOS-XE 17.9")
	junk := devN(2, "Cisco IOS-XE 17.9")
	r.output[good.ID] = bgpSummaryOutput
	r.output[junk.ID] = "% Invalid input detected at '^' marker.\n"
	c := newBatteryCollector(t, r)
	run, err := c.RunBattery(context.Background(), []Device{good, junk}, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	rows, skipped := run.Devices[0].TypedRows()
	if rows != 2 || len(skipped) != 0 {
		t.Errorf("healthy device: rows=%d skipped=%v, want 2/none", rows, skipped)
	}
	rows, skipped = run.Devices[1].TypedRows()
	if rows != 0 || len(skipped) != 1 {
		t.Fatalf("junk device: rows=%d skipped=%v, want 0/one", rows, skipped)
	}
	if !strings.Contains(skipped[0], showparse.CmdBGPSummary) || skipped[0] == "" {
		t.Errorf("the skip must name the command and say why: %q", skipped[0])
	}
	// The command still RAN and its (unparseable) output is retained honestly.
	if run.Devices[1].Status != DeviceStatusOK {
		t.Errorf("an unparseable answer is still an answer: status %q", run.Devices[1].Status)
	}
}

// TestRunBattery_AllAreasAllDialects walks every area against one device of
// every dialect and asserts nothing panics, every command that ran was a battery
// command, and every parse is either typed or honestly skipped.
func TestRunBattery_AllAreasAllDialects(t *testing.T) {
	platforms := map[showparse.Dialect]string{
		showparse.DialectCiscoIOS:   "Cisco IOS 15.2",
		showparse.DialectCiscoIOSXE: "Cisco IOS-XE 17.9",
		showparse.DialectCiscoIOSXR: "Cisco IOS-XR 7.5.2",
		showparse.DialectCiscoNXOS:  "Cisco NX-OS 10.2",
		showparse.DialectJunos:      "Juniper Junos 22.4R3",
		showparse.DialectNokiaSROS:  "Nokia SR OS 22.10.R4",
		showparse.DialectAristaEOS:  "Arista EOS 4.30.2F",
		showparse.DialectHuaweiVRP:  "Huawei VRP V800R021",
	}
	b := DefaultStateBattery()
	r := newScriptedRunner()
	var devs []Device
	i := 0
	for _, p := range platforms {
		i++
		d := devN(i, p)
		r.output[d.ID] = bgpSummaryOutput
		devs = append(devs, d)
	}
	c := newBatteryCollector(t, r)
	tgt := Target{Interface: "GigabitEthernet0/0", Prefix: "192.0.2.0/24",
		Address: "000c.29ab.cdef", Peer: "10.0.0.2", VRF: "CUST-A"}
	for _, area := range Areas() {
		run, err := c.RunBattery(context.Background(), devs, area, tgt)
		if err != nil {
			t.Fatalf("area %s: %v", area, err)
		}
		for _, st := range run.Devices {
			if st.Status == DeviceStatusUnsupported {
				continue
			}
			for _, cc := range st.Commands {
				if err := ValidateReadOnly(cc.Command); err != nil {
					t.Errorf("%s ran a non-read-only command %q", st.DeviceID, cc.Command)
				}
				if !b.Allows(st.Dialect, cc.Command) {
					t.Errorf("%s ran %q, which is not in the battery table for %s",
						st.DeviceID, cc.Command, st.Dialect)
				}
			}
			for _, res := range st.Parsed {
				if res.Skipped && res.Reason == "" {
					t.Errorf("%s: a skipped parse carries no reason", st.DeviceID)
				}
			}
		}
	}
}

// TestRunBattery_EmptyDeviceList is the degenerate case: no devices, no error,
// no work.
func TestRunBattery_EmptyDeviceList(t *testing.T) {
	c := newBatteryCollector(t, newScriptedRunner())
	run, err := c.RunBattery(context.Background(), nil, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if len(run.Devices) != 0 || run.Truncated {
		t.Errorf("empty run = %+v", run)
	}
}

// ── the live battery runner's gate ──────────────────────────────────────────

// TestSSHBatteryRunner_ClosedTable proves the live battery runner admits battery
// commands and refuses everything else — including the CATALOG's commands, which
// belong to the other table.
func TestSSHBatteryRunner_ClosedTable(t *testing.T) {
	gw := &fakeGateway{out: bgpSummaryOutput}
	r, err := NewSSHBatteryRunner(DefaultStateBattery(), gw)
	if err != nil {
		t.Fatalf("NewSSHBatteryRunner: %v", err)
	}
	dev := Device{ID: "d1", Platform: "Cisco IOS-XE 17.9", Address: "192.0.2.10"}
	if _, err := r.Run(context.Background(), dev, "show ip bgp summary"); err != nil {
		t.Errorf("a battery command was refused: %v", err)
	}
	for _, bad := range []string{
		"show running-config",
		"show ip bgp neighbors 10.0.0.2 advertised-routes", // catalog-only
		"show tech-support",
	} {
		if _, err := r.Run(context.Background(), dev, bad); !errors.Is(err, ErrCommandNotInTable) && !errors.Is(err, ErrNotReadOnly) {
			t.Errorf("%q was not refused (err=%v)", bad, err)
		}
	}
	// An unassessed platform resolves to no dialect and therefore to no command.
	alien := Device{ID: "d2", Platform: "Acme MysteryOS", Address: "192.0.2.11"}
	if _, err := r.Run(context.Background(), alien, "show ip bgp summary"); !errors.Is(err, ErrCommandNotInTable) {
		t.Errorf("an unassessed platform must be refused, got %v", err)
	}
	if _, err := NewSSHBatteryRunner(nil, gw); err == nil {
		t.Error("a nil battery must be refused")
	}
	if _, err := NewSSHBatteryRunner(DefaultStateBattery(), nil); err == nil {
		t.Error("a nil gateway must be refused")
	}
}

// TestBatteryOptions_AndHelpers covers the option surface and the small helpers
// the main scenarios do not reach: an injected clock, the placeholder resolver's
// whole vocabulary, and RedactOutput's empty case.
func TestBatteryOptions_AndHelpers(t *testing.T) {
	fixed := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	r := newScriptedRunner()
	d := devN(1, "Cisco IOS-XE 17.9")
	r.output[d.ID] = bgpSummaryOutput
	c := newBatteryCollector(t, r,
		WithBatteryClock(func() time.Time { return fixed }),
		WithBatteryClock(nil),        // ignored: there is no "no clock"
		WithConcurrency(0),           // ignored: there is no "unbounded"
		WithDeviceTimeout(0),         // ignored: there is no "no timeout"
		WithTotalTimeout(-time.Hour), // ignored
	)
	run, err := c.RunBattery(context.Background(), []Device{d}, AreaBGP, Target{})
	if err != nil {
		t.Fatalf("RunBattery: %v", err)
	}
	if !run.StartedAt.Equal(fixed) || !run.Devices[0].Commands[0].Timestamp.Equal(fixed) {
		t.Errorf("the injected clock was not used: %+v", run.StartedAt)
	}
	if c.concurrency != MaxBatteryConcurrency || c.deviceTimeout != DefaultDeviceTimeout ||
		c.totalTimeout != DefaultBatteryTimeout {
		t.Errorf("a non-positive option changed a bound: %d/%v/%v",
			c.concurrency, c.deviceTimeout, c.totalTimeout)
	}

	tgt := Target{Interface: "Gi0/0", Peer: "10.0.0.2", Prefix: "10.0.0.0/8",
		Address: "000c.29ab.cdef", VRF: "CUST-A"}
	for ph, want := range map[string]string{
		"{if}": "Gi0/0", "{peer}": "10.0.0.2", "{prefix}": "10.0.0.0/8",
		"{addr}": "000c.29ab.cdef", "{vrf-scope}": "CUST-A", "{nope}": "",
	} {
		if got := placeholderValue(ph, tgt); got != want {
			t.Errorf("placeholderValue(%q) = %q, want %q", ph, got, want)
		}
	}
	if RedactOutput("") != "" {
		t.Error("RedactOutput on an empty capture must stay empty")
	}
	if !strings.Contains(RedactOutput("username admin password Sup3rS3cret"), redactionMark) {
		t.Error("RedactOutput did not redact a password")
	}
	if batteryVRFScope(showparse.DialectCiscoIOSXE, "  ") != "" {
		t.Error("an empty VRF must render no scope token")
	}
	if got := vendorTokenOf(showparse.DialectNokiaSROS); got != "nokia" {
		t.Errorf("vendorTokenOf = %q, want nokia", got)
	}
}
