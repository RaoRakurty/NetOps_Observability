// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// stream_test.go — the FIRST-ASK collection: the vendor's own support bundle,
// streamed to disk rather than buffered.
//
// These are the tests that make "tech-support first" safe to ship. The thing
// being proven is not that a big file arrives — it is that a 50 MB device
// output never becomes a 50 MB allocation, that every byte of it is redacted on
// the way past, that the bundle carries it without reading it back into memory,
// and that a truncation is stated rather than hidden.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/protocoldiag"
)

// streamingFake is a fake device that produces a LOT of output, one chunk at a
// time, without ever building the whole thing in memory itself — otherwise the
// test would prove nothing about the collector's allocation behaviour.
type streamingFake struct {
	*fakeRunner
	// bigCmd is the command that produces `bigBytes` of generated output.
	bigCmd   string
	bigBytes int64
	// secretEvery plants a credential line every N lines, so the redaction pass
	// has to hold across chunk boundaries for the whole stream.
	secretEvery int
	// truncateAt, when > 0, makes the fake behave like a device whose output
	// exceeded the cap: it writes that many bytes and reports ErrTooLarge.
	truncateAt int64
}

// streamLine is one line of the fake device's output. It is deliberately LONG:
// the assertion below is about memory, and a 50 MB stream of 70-character lines
// would spend the test's whole budget inside the redactor's per-line regexes
// while proving exactly the same thing about buffering.
var streamLine = strings.Repeat("Interface GigabitEthernet0/0/0 is up, line protocol is up ", 35) + "\n"

func (s *streamingFake) RunStream(ctx context.Context, dev protocoldiag.Device, cmd string, maxBytes int64, w io.Writer) (int64, error) {
	if cmd != s.bigCmd {
		out, err := s.fakeRunner.Run(ctx, dev, cmd)
		if err != nil {
			return 0, err
		}
		n, werr := io.WriteString(w, out)
		return int64(n), werr
	}
	limit := s.bigBytes
	if s.truncateAt > 0 {
		limit = s.truncateAt
	}
	var written int64
	for line := 0; written < limit; line++ {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		text := streamLine
		if s.secretEvery > 0 && line%s.secretEvery == 0 {
			text = "snmp-server community s3cr3t-" + fmt.Sprint(line) + " ro\n"
		}
		n, err := io.WriteString(w, text)
		written += int64(n)
		if err != nil {
			return written, err
		}
		if maxBytes > 0 && written >= maxBytes {
			break
		}
	}
	if s.truncateAt > 0 {
		return written, protocoldiag.ErrTooLarge
	}
	return written, nil
}

func newStreamingFake(bigCmd string, bigBytes int64) *streamingFake {
	return &streamingFake{fakeRunner: newFake(), bigCmd: bigCmd, bigBytes: bigBytes, secretEvery: 500}
}

// firstAskStep returns the plan's first-ask step, failing the test when the
// dialect has none — every assertion below is about that step.
func firstAskStep(t *testing.T, p *Plan) Step {
	t.Helper()
	for _, s := range p.Steps {
		if s.Section == SectionFirstAsk {
			return s
		}
	}
	t.Fatalf("plan for %s carries no first-ask step", p.Dialect)
	return Step{}
}

// TestFirstAskLeadsEveryCapture is the owner's requirement stated as a test: the
// vendor's own first-ask collection is the FIRST thing in the plan and the FIRST
// line of the default capture, on every dialect that has one.
func TestFirstAskLeadsEveryCapture(t *testing.T) {
	c := mustCatalog(t)
	// The dialects whose vendor publishes a first-ask collection Correlix will
	// run. The other five are asserted by TestDialectsWithoutAFirstAskSayWhy.
	want := map[string]string{
		"cisco-ios":        "show tech-support",
		"cisco-iosxe":      "show tech-support",
		"cisco-nxos":       "show tech-support details",
		"cisco-asa":        "show tech-support",
		"arista-eos":       "show tech-support",
		"juniper-junos":    "request support information",
		"fortinet-fortios": "execute tac report",
	}
	for dialect, command := range want {
		dp, ok := c.PlanFor(dialect)
		if !ok {
			t.Fatalf("the catalog has no %s plan", dialect)
		}
		if len(dp.FirstAsk) == 0 {
			t.Fatalf("%s: no first_ask list — the vendor's first ask must lead the capture", dialect)
		}
		b, bound := dp.Bound(dp.FirstAsk[0])
		if !bound {
			t.Fatalf("%s: first_ask names %q, which the dialect does not bind", dialect, dp.FirstAsk[0])
		}
		if b.Command != command {
			t.Fatalf("%s: first ask is %q, want %q", dialect, b.Command, command)
		}
		// The budgets are part of the fact: the loader refuses a first-ask
		// binding without them, and this asserts they are vendor-sized rather
		// than the package default.
		if b.MaxBytes <= defaultMaxOutputBytes {
			t.Fatalf("%s: first-ask max_bytes is %d, which is not larger than the buffered ceiling %d",
				dialect, b.MaxBytes, defaultMaxOutputBytes)
		}
		if b.Timeout < time.Minute {
			t.Fatalf("%s: first-ask timeout is %s — a support bundle takes minutes", dialect, b.Timeout)
		}
		if len(b.Sources) == 0 {
			t.Fatalf("%s: the first-ask binding cites nothing", dialect)
		}
		if b.Verified != VerifiedDocClaimed && b.Verified != VerifiedCapture {
			t.Fatalf("%s: first-ask verification is %q", dialect, b.Verified)
		}
	}
}

// TestFirstAskIsTheFirstLineOfTheDefaultCapture proves the ordering all the way
// through to what the operator's capture actually runs.
func TestFirstAskIsTheFirstLineOfTheDefaultCapture(t *testing.T) {
	c := mustCatalog(t)
	p, err := c.Plan("bgp-session", iosxeDevice(), PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if p.Steps[0].Section != SectionFirstAsk || p.Steps[0].Command != "show tech-support" {
		t.Fatalf("the plan does not lead with the vendor's first ask: %+v", p.Steps[0])
	}
	capt := VendorDefaultCapture(p)
	if capt == nil || len(capt.Commands) == 0 {
		t.Fatal("no default capture was derived")
	}
	if capt.Commands[0].Command != "show tech-support" {
		t.Fatalf("the default capture leads with %q", capt.Commands[0].Command)
	}
}

// TestDialectsWithoutAFirstAskSayWhy is the honesty half. A platform whose own
// bundle command writes to the device gets NO first-ask capture and an explicit
// note naming the refused command — never a silent gap.
func TestDialectsWithoutAFirstAskSayWhy(t *testing.T) {
	c := mustCatalog(t)
	// dialect → a phrase the note must contain, which is the vendor's own
	// spelling of the command Correlix refuses (or the out-of-band path).
	want := map[string]string{
		"cisco-iosxr":    "show tech-support",
		"nokia-sros":     "admin tech-support",
		"nokia-srlinux":  "tech-support",
		"paloalto-panos": "tech-support",
		"huawei-vrp":     "display diagnostic-information",
	}
	for dialect, phrase := range want {
		dp, ok := c.PlanFor(dialect)
		if !ok {
			t.Fatalf("the catalog has no %s plan", dialect)
		}
		if len(dp.FirstAsk) != 0 {
			t.Fatalf("%s must have no first-ask capture, got %v", dialect, dp.FirstAsk)
		}
		if !strings.Contains(dp.FirstAskNote, phrase) {
			t.Fatalf("%s: the note does not name %q:\n%s", dialect, phrase, dp.FirstAskNote)
		}
		if !strings.Contains(dp.FirstAskNote, "http") {
			t.Fatalf("%s: the note cites no vendor page:\n%s", dialect, dp.FirstAskNote)
		}
	}
}

// TestWriteClassSupportBundlesAreRefusedByName is the output-only policy applied
// to the one class of command this feature most wants to run.
func TestWriteClassSupportBundlesAreRefusedByName(t *testing.T) {
	_, p := policyForTest(t)
	cases := []struct{ dialect, cmd, want string }{
		{"nokia-sros", "admin tech-support", "admin tech-support"},
		{"nokia-sros", "admin tech-support cf3:/ts.dat", "admin tech-support"},
		{"nokia-srlinux", "tech-support", "tech-support"},
		{"nokia-srlinux", "tech-support exclude-binaries", "tech-support"},
		{"nokia-srlinux", "tools system tech-support", "tools system tech-support"},
	}
	for _, tc := range cases {
		rule, hit := p.Match(tc.dialect, tc.cmd)
		if !hit {
			t.Fatalf("%s: %q was NOT refused — it writes a file on the device", tc.dialect, tc.cmd)
		}
		if rule.Family != FamilyConfig {
			t.Fatalf("%s: %q landed in family %q, want %q", tc.dialect, tc.cmd, rule.Family, FamilyConfig)
		}
		// "Refused BY NAME" is the requirement: the operator is told which rule
		// hit, not merely that something was invalid.
		if !strings.Contains(rule.String(), tc.want) {
			t.Fatalf("%s: the rule that refused %q is %q, which does not name it", tc.dialect, tc.cmd, rule)
		}
		if !strings.Contains(strings.ToLower(rule.Why), "write") {
			t.Fatalf("%s: the refusal reason does not say it writes to the device: %q", tc.dialect, rule.Why)
		}
	}
}

// TestFirstAskCitedExceptionsReachTheWire is the regression that this whole
// seam exists for. Junos and FortiOS spell their documented READ as something
// the read-only grammar cannot recognise; without the cited-exception seam the
// plan loads, the gate admits it, and the runner refuses it at the last step —
// which is what happened to every FortiOS `diagnose debug … read` before
// 2026-09-07.
func TestFirstAskCitedExceptionsReachTheWire(t *testing.T) {
	c := mustCatalog(t)
	gate := NewGate(c)
	cases := []struct{ platform, cmd string }{
		{"juniper junos", "request support information"},
		{"fortinet fortios", "execute tac report"},
		{"fortinet fortios", "diagnose debug crashlog read"},
	}
	for _, tc := range cases {
		dev := protocoldiag.Device{ID: "d1", Hostname: "h1", Platform: tc.platform, Address: "192.0.2.10"}
		if protocoldiag.ValidateReadOnly(tc.cmd) == nil {
			t.Fatalf("%q now passes the grammar, so this test no longer proves anything", tc.cmd)
		}
		if !gate.ReadOnlyExempt(dev, tc.cmd) {
			t.Fatalf("%s: %q is an authored, cited documented-status read and was not exempted", tc.platform, tc.cmd)
		}
		if !gate.Allows(dev, tc.cmd) {
			t.Fatalf("%s: %q is not in the closed table", tc.platform, tc.cmd)
		}
	}
	// And the seam is not a hole: a command that is neither authored nor cited
	// is refused, and so is a forbidden one that happens to be authored-looking.
	dev := protocoldiag.Device{ID: "d1", Platform: "fortinet fortios", Address: "192.0.2.10"}
	for _, cmd := range []string{"execute reboot", "execute restore config tftp x y", "request system reboot"} {
		if gate.ReadOnlyExempt(dev, cmd) {
			t.Fatalf("%q must never be exempted", cmd)
		}
	}
}

// TestStreamedFirstAskNeverBuffersFiftyMegabytes is the allocation proof.
func TestStreamedFirstAskNeverBuffersFiftyMegabytes(t *testing.T) {
	const fifty = 50 << 20
	p := bgpPlan(t)
	first := firstAskStep(t, p)
	f := newStreamingFake(first.Command, fifty)
	for _, s := range p.Steps {
		if s.Command != first.Command {
			f.out[s.Command] = "ok\n"
		}
	}
	dir := t.TempDir()
	col := testCollector(t, f, WithClock(fixedClock()), WithSpillRoot(dir))
	if !col.CanStream() {
		t.Fatal("a runner that implements StreamingRunner must be detected as streamable")
	}

	// PEAK LIVE HEAP is the measure, not TotalAlloc: the redactor legitimately
	// churns through hundreds of megabytes of short-lived per-line strings while
	// it works, and counting those would say nothing about whether the stream
	// was buffered. What must stay small is how much is LIVE at once.
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	peak := make(chan uint64, 1)
	stop := make(chan struct{})
	go func() {
		var high uint64
		var ms runtime.MemStats
		// SAMPLED, not spun: ReadMemStats stops the world, and calling it in a
		// tight loop would make this test measure the sampler rather than the
		// collector. 2 ms is far finer than the seconds a 50 MB stream takes.
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				peak <- high
				return
			case <-tick.C:
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > high {
					high = ms.HeapAlloc
				}
			}
		}
	}()

	capt, err := col.Collect(context.Background(), p, nil, nil)
	close(stop)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defer func() {
		if cerr := capt.Close(); cerr != nil {
			t.Fatalf("close: %v", cerr)
		}
	}()

	high := <-peak
	if high > base.HeapAlloc && high-base.HeapAlloc > 16<<20 {
		t.Fatalf("collecting a %d-byte output held %d bytes live at once — something buffered the stream",
			fifty, high-base.HeapAlloc)
	}

	var streamed *CollectedCommand
	for i := range capt.Commands {
		if capt.Commands[i].Command == first.Command {
			streamed = &capt.Commands[i]
		}
	}
	if streamed == nil {
		t.Fatal("the first-ask command is not in the capture")
	}
	if !streamed.Streamed() {
		t.Fatal("the first-ask command was buffered, not streamed")
	}
	if streamed.Output != "" {
		t.Fatal("a streamed command must carry no in-memory output")
	}
	if streamed.Err != "" {
		t.Fatalf("the streamed command failed: %s", streamed.Err)
	}
	st, err := os.Stat(streamed.SpillPath)
	if err != nil {
		t.Fatalf("the spill file is not there: %v", err)
	}
	if st.Size() < fifty/2 {
		t.Fatalf("the spill file is %d bytes, far short of the %d the device produced", st.Size(), fifty)
	}
	if int64(streamed.Bytes) != st.Size() {
		t.Fatalf("the recorded size %d does not match the file's %d", streamed.Bytes, st.Size())
	}
	// Spill files live under the collector's own directory and nowhere else.
	if filepath.Dir(filepath.Dir(streamed.SpillPath)) != dir {
		t.Fatalf("the spill file %q is not under the pinned spill root %q", streamed.SpillPath, dir)
	}
}

// TestStreamedOutputIsRedactedAcrossChunkBoundaries proves the redaction runs
// over the WHOLE stream, not only over the first chunk.
func TestStreamedOutputIsRedactedAcrossChunkBoundaries(t *testing.T) {
	p := bgpPlan(t)
	first := firstAskStep(t, p)
	f := newStreamingFake(first.Command, 4<<20)
	f.secretEvery = 97 // a prime, so secrets land at unaligned offsets
	for _, s := range p.Steps {
		if s.Command != first.Command {
			f.out[s.Command] = "ok\n"
		}
	}
	col := testCollector(t, f, WithClock(fixedClock()), WithSpillRoot(t.TempDir()))
	capt, err := col.Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defer capt.Close() //nolint:errcheck // the assertion below is the point; cleanup failure is not
	var path string
	for _, cc := range capt.Commands {
		if cc.Command == first.Command {
			path = cc.SpillPath
		}
	}
	if path == "" {
		t.Fatal("nothing was streamed")
	}
	body, err := os.ReadFile(path) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatalf("read spill: %v", err)
	}
	if strings.Contains(string(body), "s3cr3t-") {
		t.Fatal("a planted community string survived into the spill file")
	}
	if !strings.Contains(string(body), "[REDACTED]") {
		t.Fatal("nothing was redacted, so the corpus was wrong rather than the redactor right")
	}
}

// TestStreamedOutputReachesTheBundleWithoutBeingReadBack proves the bundle
// carries the streamed body and states its size honestly.
func TestStreamedOutputReachesTheBundleWithoutBeingReadBack(t *testing.T) {
	p := bgpPlan(t)
	first := firstAskStep(t, p)
	f := newStreamingFake(first.Command, 2<<20)
	for _, s := range p.Steps {
		if s.Command != first.Command {
			f.out[s.Command] = "line\n"
		}
	}
	col := testCollector(t, f, WithClock(fixedClock()), WithSpillRoot(t.TempDir()))
	capt, err := col.Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defer capt.Close() //nolint:errcheck // best effort in a temp dir
	b, err := BuildBundle(context.Background(), BundleInput{
		TenantID: "t1", IncidentID: "inc-1", Plan: p, Capture: capt, Profile: ProfileFull,
	}, nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	files := unzip(t, b.Zip)
	var found bool
	for name, data := range files {
		if !strings.HasPrefix(name, "outputs/") || !strings.Contains(string(data), "# streamed : yes") {
			continue
		}
		found = true
		if !strings.Contains(string(data), first.Command) {
			t.Fatalf("%s does not name the command it holds", name)
		}
		if len(data) < 1<<20 {
			t.Fatalf("%s is %d bytes; the streamed body did not reach the bundle", name, len(data))
		}
		if strings.Contains(string(data), "s3cr3t-") {
			t.Fatalf("%s carries an unredacted secret", name)
		}
	}
	if !found {
		t.Fatal("no streamed output reached the bundle")
	}
}

// TestStreamedTruncationIsStatedNotHidden — a device that overran the cap
// produces a SHORT file with the truncation on the record, never a file that
// looks complete.
func TestStreamedTruncationIsStatedNotHidden(t *testing.T) {
	p := bgpPlan(t)
	first := firstAskStep(t, p)
	f := newStreamingFake(first.Command, 8<<20)
	f.truncateAt = 1 << 20
	for _, s := range p.Steps {
		if s.Command != first.Command {
			f.out[s.Command] = "ok\n"
		}
	}
	col := testCollector(t, f, WithClock(fixedClock()), WithSpillRoot(t.TempDir()))
	capt, err := col.Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	defer capt.Close() //nolint:errcheck // best effort in a temp dir
	for _, cc := range capt.Commands {
		if cc.Command != first.Command {
			continue
		}
		if !strings.Contains(cc.Err, "truncated") {
			t.Fatalf("a truncated capture must say so, got %q", cc.Err)
		}
		if cc.Bytes == 0 {
			t.Fatal("the bytes collected before the cap must be kept, not discarded")
		}
		return
	}
	t.Fatal("the first-ask command is not in the capture")
}

// TestCaptureCloseRemovesTheSpill proves the disk is released.
func TestCaptureCloseRemovesTheSpill(t *testing.T) {
	p := bgpPlan(t)
	first := firstAskStep(t, p)
	f := newStreamingFake(first.Command, 1<<20)
	for _, s := range p.Steps {
		if s.Command != first.Command {
			f.out[s.Command] = "ok\n"
		}
	}
	root := t.TempDir()
	col := testCollector(t, f, WithClock(fixedClock()), WithSpillRoot(root))
	capt, err := col.Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	dir := capt.SpillDir
	if dir == "" {
		t.Fatal("no spill directory was created")
	}
	if err := capt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the spill directory survived Close: %v", err)
	}
	if capt.SpillDir != "" {
		t.Fatal("Close must clear the recorded directory so a second call is a no-op")
	}
	if err := capt.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
}

// TestBufferedRunnerDoesNotPretendToStream — a transport with no streaming half
// runs the first-ask command through the buffered path, where the plan's own
// per-command cap still applies. Nothing silently claims to have streamed.
func TestBufferedRunnerDoesNotPretendToStream(t *testing.T) {
	p := bgpPlan(t)
	first := firstAskStep(t, p)
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "ok\n"
	}
	col := testCollector(t, f, WithClock(fixedClock()))
	if col.CanStream() {
		t.Fatal("a plain CommandRunner must not be reported as streamable")
	}
	capt, err := col.Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if capt.SpillDir != "" {
		t.Fatal("a non-streaming collection must not create a spill directory")
	}
	for _, cc := range capt.Commands {
		if cc.Streamed() {
			t.Fatalf("%q claims to have been streamed with no streaming transport", cc.Command)
		}
	}
	_ = first
}

// bgpPlan builds an IOS-XE plan whose first step is the first-ask collection.
func bgpPlan(t *testing.T) *Plan {
	t.Helper()
	cat := mustCatalog(t)
	p, err := cat.Plan("bgp-session", iosxeDevice(), PlanOptions{Target: Target{Peer: "192.0.2.1"}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	p.IncidentID = "inc-stream"
	return p
}
