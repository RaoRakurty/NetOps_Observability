package tac

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/protocoldiag"
)

// fakeRunner is the offline command source: it answers from a map, can be made
// slow, and records what it was asked to run. No test in this package opens a
// socket.
type fakeRunner struct {
	mu       sync.Mutex
	out      map[string]string
	fail     map[string]error
	delay    time.Duration
	ran      []string
	blockCh  chan struct{}
	blockCmd string
}

func (f *fakeRunner) Run(ctx context.Context, _ protocoldiag.Device, cmd string) (string, error) {
	f.mu.Lock()
	f.ran = append(f.ran, cmd)
	block := f.blockCh != nil && cmd == f.blockCmd
	f.mu.Unlock()
	if block {
		select {
		case <-f.blockCh:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err, ok := f.fail[cmd]; ok {
		return "", err
	}
	return f.out[cmd], nil
}

func (f *fakeRunner) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ran...)
}

func newFake() *fakeRunner {
	return &fakeRunner{out: map[string]string{}, fail: map[string]error{}}
}

func testCollector(t *testing.T, r protocoldiag.CommandRunner, opts ...CollectorOption) *Collector {
	t.Helper()
	base := []CollectorOption{WithPacing(0), WithSleeper(func(context.Context, time.Duration) error { return nil })}
	c, err := NewCollector(r, append(base, opts...)...)
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	return c
}

func testPlan(t *testing.T) *Plan {
	t.Helper()
	cat := mustCatalog(t)
	p, err := cat.Plan("ospf-adjacency", iosxeDevice(), PlanOptions{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	p.IncidentID = "inc-1"
	return p
}

// TestNewCollectorRefusesANilRunner is the fail-closed rule: no runner means an
// error, never a silent empty capture.
func TestNewCollectorRefusesANilRunner(t *testing.T) {
	if _, err := NewCollector(nil); !errors.Is(err, ErrNoRunner) {
		t.Fatalf("expected ErrNoRunner, got %v", err)
	}
}

// TestCollectRunsEveryBoundStepInOrder.
func TestCollectRunsEveryBoundStepInOrder(t *testing.T) {
	p := testPlan(t)
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "output of " + s.Command
	}
	capt, err := testCollector(t, f).Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(capt.Commands) != len(p.Steps) {
		t.Fatalf("collected %d commands, plan has %d steps", len(capt.Commands), len(p.Steps))
	}
	for i, s := range p.Steps {
		if capt.Commands[i].Command != s.Command {
			t.Fatalf("step %d ran %q, plan said %q", i, capt.Commands[i].Command, s.Command)
		}
	}
	if !capt.Redacted {
		t.Fatal("a capture must state that it is redacted")
	}
	if capt.TotalBytes <= 0 {
		t.Fatal("total bytes not accounted")
	}
}

// TestCollectRecordsAPerCommandFailureAndContinues — a partial capture is still
// worth escalating with; a fabricated one is not.
func TestCollectRecordsAPerCommandFailureAndContinues(t *testing.T) {
	p := testPlan(t)
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "ok"
	}
	f.fail[p.Steps[1].Command] = errors.New("device refused: % Invalid input detected")
	capt, err := testCollector(t, f).Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(capt.Commands) != len(p.Steps) {
		t.Fatal("a failed command aborted the collection")
	}
	if capt.Commands[1].Err == "" {
		t.Fatal("the failure was not recorded on its command")
	}
	if capt.Commands[1].Output != "" {
		t.Fatal("a failed command must never carry invented output")
	}
	if capt.Commands[2].Err != "" {
		t.Fatal("collection did not continue past the failure")
	}
}

// TestCollectAppliesThePerCommandSizeCap.
func TestCollectAppliesThePerCommandSizeCap(t *testing.T) {
	p := testPlan(t)
	p.Steps = p.Steps[:1]
	p.Steps[0].MaxBytes = 64
	f := newFake()
	f.out[p.Steps[0].Command] = strings.Repeat("x", 4096)
	capt, _ := testCollector(t, f).Collect(context.Background(), p, nil, nil)
	if capt.Commands[0].Bytes > 64 {
		t.Fatalf("output of %d bytes exceeded the 64-byte cap", capt.Commands[0].Bytes)
	}
	if !strings.Contains(capt.Commands[0].Err, "size cap") {
		t.Fatalf("truncation must be stated, got %q", capt.Commands[0].Err)
	}
}

// TestCollectAppliesTheWholeCollectionCap.
func TestCollectAppliesTheWholeCollectionCap(t *testing.T) {
	p := testPlan(t)
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = strings.Repeat("y", 2048)
	}
	capt, _ := testCollector(t, f, WithMaxTotalBytes(4096)).Collect(context.Background(), p, nil, nil)
	if capt.TotalBytes > 8192 {
		t.Fatalf("collection ran to %d bytes past a 4096-byte ceiling", capt.TotalBytes)
	}
	if capt.Stopped == "" {
		t.Fatal("an early stop must be stated on the capture")
	}
	if len(capt.Commands) == len(p.Steps) {
		t.Fatal("the ceiling did not stop the collection")
	}
}

// TestCollectHonoursThePerCommandTimeout.
func TestCollectHonoursThePerCommandTimeout(t *testing.T) {
	p := testPlan(t)
	p.Steps = p.Steps[:1]
	p.Steps[0].TimeoutSeconds = 0 // falls back to the package default; use a blocking runner
	f := newFake()
	f.blockCh = make(chan struct{})
	f.blockCmd = p.Steps[0].Command
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	capt, err := testCollector(t, f).Collect(ctx, p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	close(f.blockCh)
	if capt.Commands[0].Err == "" {
		t.Fatal("a command that outlived its deadline must be recorded as failed")
	}
}

// TestCollectIsCancellable.
func TestCollectIsCancellable(t *testing.T) {
	p := testPlan(t)
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "ok"
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	capt, err := testCollector(t, f).Collect(ctx, p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(capt.Commands) != 0 || capt.Stopped == "" {
		t.Fatalf("a cancelled collection ran %d commands (stopped=%q)", len(capt.Commands), capt.Stopped)
	}
}

// TestCollectRefusesASecondCollectionOnTheSameDevice is the one-in-flight rule.
func TestCollectRefusesASecondCollectionOnTheSameDevice(t *testing.T) {
	p := testPlan(t)
	f := newFake()
	f.blockCh = make(chan struct{})
	f.blockCmd = p.Steps[0].Command
	for _, s := range p.Steps {
		f.out[s.Command] = "ok"
	}
	col := testCollector(t, f)

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		_, _ = col.Collect(context.Background(), p, nil, nil)
		close(done)
	}()
	<-started
	// Wait until the first collection is actually inside a command.
	deadline := time.After(2 * time.Second)
	for len(f.commands()) == 0 {
		select {
		case <-deadline:
			t.Fatal("the first collection never started a command")
		case <-time.After(time.Millisecond):
		}
	}
	if _, err := col.Collect(context.Background(), p, nil, nil); !errors.Is(err, ErrCollectBusy) {
		t.Fatalf("a second concurrent collection was not refused: %v", err)
	}
	close(f.blockCh)
	<-done
	// The claim is released, so a later collection is allowed.
	if _, err := col.Collect(context.Background(), p, nil, nil); err != nil {
		t.Fatalf("the device stayed claimed after the collection finished: %v", err)
	}
}

// TestCollectPacesItsCommands proves the gap between commands is real and
// context-aware.
func TestCollectPacesItsCommands(t *testing.T) {
	p := testPlan(t)
	p.Steps = p.Steps[:3]
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "ok"
	}
	var waits []time.Duration
	col, err := NewCollector(f, WithPacing(250*time.Millisecond),
		WithSleeper(func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }))
	if err != nil {
		t.Fatalf("collector: %v", err)
	}
	if _, err := col.Collect(context.Background(), p, nil, nil); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(waits) != len(p.Steps)-1 {
		t.Fatalf("paced %d times for %d commands", len(waits), len(p.Steps))
	}
	for _, w := range waits {
		if w != 250*time.Millisecond {
			t.Fatalf("pacing gap = %v", w)
		}
	}
}

// TestCollectRedactsAtCapture is the §8 rule: nothing unredacted is ever held.
func TestCollectRedactsAtCapture(t *testing.T) {
	p := testPlan(t)
	p.Steps = p.Steps[:1]
	f := newFake()
	f.out[p.Steps[0].Command] = "interface Gi0/1\n ip ospf message-digest-key 1 md5 S3cr3tK3y!\n"
	capt, _ := testCollector(t, f).Collect(context.Background(), p, nil, nil)
	if strings.Contains(capt.Commands[0].Output, "S3cr3tK3y") {
		t.Fatal("a secret survived capture-time redaction")
	}
	if !strings.Contains(capt.Commands[0].Output, "[REDACTED]") {
		t.Fatal("the redaction mark is missing — the line was dropped rather than masked")
	}
	if !strings.Contains(capt.Commands[0].Output, "md5") {
		t.Fatal("redaction removed the surrounding structure; a TAC reader must still see WHICH knob it was")
	}
}

// TestCollectRedactsAnErrorString — a device's refusal can echo its own config.
func TestCollectRedactsAnErrorString(t *testing.T) {
	p := testPlan(t)
	p.Steps = p.Steps[:1]
	f := newFake()
	f.fail[p.Steps[0].Command] = errors.New("rejected near: snmp-server community S3cr3tCommunity ro")
	capt, _ := testCollector(t, f).Collect(context.Background(), p, nil, nil)
	if strings.Contains(capt.Commands[0].Err, "S3cr3tCommunity") {
		t.Fatal("a secret survived in an error string")
	}
}

// TestCollectFoldsSuppliedOutputs — the paste fallback, labelled honestly.
func TestCollectFoldsSuppliedOutputs(t *testing.T) {
	cat := mustCatalog(t)
	p, _ := cat.Plan("ospf-adjacency", Device{ID: "edge9", Hostname: "edge9", Platform: "MikroTik RouterOS 7.14", TenantID: "t1"}, PlanOptions{})
	f := newFake()
	capt, err := testCollector(t, f).Collect(context.Background(), p, []SuppliedOutput{
		{Intent: "ospf.neighbors", Command: "/routing ospf neighbor print",
			Output: "Neighbor 10.0.0.2 state FULL\n snmp-server community Sup3rS3cret ro\n"},
	}, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(f.commands()) != 0 {
		t.Fatal("a platform with no authored plan must run NOTHING on the device")
	}
	if len(capt.Commands) != 1 || capt.Commands[0].Section != "supplied" {
		t.Fatalf("a pasted output must be labelled `supplied`, got %+v", capt.Commands)
	}
	if strings.Contains(capt.Commands[0].Output, "Sup3rS3cret") {
		t.Fatal("a pasted output was not redacted on the way in")
	}
}

// TestCollectProgressEvents proves the UI gets a per-command start and end.
func TestCollectProgressEvents(t *testing.T) {
	p := testPlan(t)
	p.Steps = p.Steps[:2]
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "ok"
	}
	var got []Progress
	_, _ = testCollector(t, f).Collect(context.Background(), p, nil, func(pr Progress) { got = append(got, pr) })
	if len(got) != 4 {
		t.Fatalf("expected a start and an end per command, got %d events", len(got))
	}
	if got[0].Phase != "start" || got[1].Phase != "done" {
		t.Fatalf("progress phases = %q, %q", got[0].Phase, got[1].Phase)
	}
	if got[0].Total != 2 {
		t.Fatalf("progress must carry the total, got %d", got[0].Total)
	}
}
