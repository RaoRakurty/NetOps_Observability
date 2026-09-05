package tac

// collect.go — running an approved plan, read-only, against one device.
//
// This is the file that touches a production router, so every bound in CLAUDE.md
// §9 is here and none of them is optional:
//
//	· ONE COLLECTION PER DEVICE, refused rather than queued — an operator (or a
//	  retry storm) cannot multiply sessions on a router. The reused
//	  protocoldiag runner enforces the same rule per COMMAND; this enforces it
//	  for the whole multi-command collection, which is the unit an operator
//	  actually starts.
//	· PER-COMMAND DEADLINE, from the plan step (already clamped by the loader).
//	· PER-COMMAND OUTPUT CAP, from the plan step, plus a WHOLE-COLLECTION cap so
//	  a hundred merely-large outputs cannot add up to something unbounded.
//	· PACING between commands, so a collection is a trickle and not a burst
//	  against a device that is, by definition, already having a bad day.
//	· CANCELLATION: the operator's context stops the collection between commands
//	  and inside one.
//
// And the honesty rules:
//
//	· A per-command failure is RECORDED ON THAT COMMAND and the collection
//	  continues. A partial capture is still worth escalating with; a fabricated
//	  one is not.
//	· Output is REDACTED AT CAPTURE (protocoldiag's redactor, the same one the
//	  export uses), so nothing unredacted is ever held, shown, logged or written.
//	· Unbound intents travel WITH the capture, so the bundle can say what was not
//	  collected and why.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/protocoldiag"
)

const (
	// defaultCommandTimeout bounds ONE command end to end.
	defaultCommandTimeout = 30 * time.Second
	// defaultMaxOutputBytes is the per-command output ceiling.
	defaultMaxOutputBytes int64 = 512 << 10
	// defaultPacing is the gap between commands.
	defaultPacing = 1 * time.Second
	// defaultMaxTotalBytes is the WHOLE-collection ceiling. A collection that
	// reaches it stops, honestly, with everything captured so far.
	defaultMaxTotalBytes int64 = 32 << 20
	// maxCommandsPerCollection bounds the plan length a collector will run.
	maxCommandsPerCollection = 200
)

// CollectedCommand is one command's result.
type CollectedCommand struct {
	Intent   string   `json:"intent"`
	Title    string   `json:"title"`
	Section  Section  `json:"section"`
	Command  string   `json:"command"`
	Verified Verified `json:"verified"`
	// Output is REDACTED text. Bytes is its size after redaction.
	Output     string    `json:"output"`
	Bytes      int       `json:"bytes"`
	Err        string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// OK reports a command that ran and produced usable output.
func (c CollectedCommand) OK() bool { return c.Err == "" }

// Capture is one whole collection.
type Capture struct {
	TenantID   string `json:"-"`
	IncidentID string `json:"incident_id"`
	PlanID     string `json:"plan_id"`
	ClassID    string `json:"class_id"`
	ClassTitle string `json:"class_title"`

	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	Dialect  string `json:"dialect"`
	Display  string `json:"dialect_display"`
	HasPlan  bool   `json:"has_plan"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	Commands []CollectedCommand `json:"commands"`
	// Unbound travels with the capture so the bundle can state the gap.
	Unbound  []Step         `json:"unbound"`
	Topology []TopologyNote `json:"topology"`
	Target   Target         `json:"target"`

	TotalBytes int64 `json:"total_bytes"`
	// Redacted is always true — it is stated rather than assumed, so a reader
	// of the JSON never has to wonder.
	Redacted bool `json:"redacted"`
	// Stopped records an early stop honestly (total cap reached, cancelled).
	Stopped string `json:"stopped,omitempty"`

	CatalogVersion string `json:"catalog_version"`
	PlanVersion    string `json:"plan_version,omitempty"`
	EngineVersion  string `json:"engine_version"`
}

// SuppliedOutput is one manually-pasted output, the fallback path for a platform
// with no authored plan (and for an unbound intent on one that has). It is
// UNTRUSTED operator text: it is redacted on the way in exactly like a live
// capture, and it is labelled in the bundle as pasted, never as collected.
type SuppliedOutput struct {
	Intent  string
	Command string
	Output  string
}

// Progress is one collection-progress event, emitted before and after each
// command so the UI can show a live per-command state.
type Progress struct {
	Index   int    `json:"index"`
	Total   int    `json:"total"`
	Intent  string `json:"intent"`
	Command string `json:"command"`
	// Phase is "start" | "done" | "error".
	Phase string `json:"phase"`
	Bytes int    `json:"bytes,omitempty"`
	Err   string `json:"error,omitempty"`
}

// Collector runs plans. It holds the per-device in-flight claim set — the only
// mutable state in this package — as a mutex-guarded map on the struct (§5: no
// package globals, no hidden singletons).
type Collector struct {
	runner protocoldiag.CommandRunner
	now    func() time.Time
	sleep  func(ctx context.Context, d time.Duration) error
	pace   time.Duration
	maxTot int64

	mu   sync.Mutex
	busy map[string]bool
}

// CollectorOption configures a Collector.
type CollectorOption func(*Collector)

// WithClock injects the timestamp source (tests pin it).
func WithClock(now func() time.Time) CollectorOption {
	return func(c *Collector) {
		if now != nil {
			c.now = now
		}
	}
}

// WithPacing overrides the inter-command gap. A negative value is ignored; zero
// is allowed (tests run without waiting).
func WithPacing(d time.Duration) CollectorOption {
	return func(c *Collector) {
		if d >= 0 {
			c.pace = d
		}
	}
}

// WithSleeper injects the wait used for pacing so a test never actually sleeps.
func WithSleeper(f func(ctx context.Context, d time.Duration) error) CollectorOption {
	return func(c *Collector) {
		if f != nil {
			c.sleep = f
		}
	}
}

// WithMaxTotalBytes overrides the whole-collection ceiling. A value above the
// package ceiling is clamped — a caller cannot widen the bound.
func WithMaxTotalBytes(n int64) CollectorOption {
	return func(c *Collector) {
		if n > 0 && n <= defaultMaxTotalBytes {
			c.maxTot = n
		}
	}
}

// NewCollector builds a Collector over an injected read-only command runner. A
// nil runner is a fail-closed error, never a silent no-op that would fabricate
// an empty capture.
func NewCollector(runner protocoldiag.CommandRunner, opts ...CollectorOption) (*Collector, error) {
	if runner == nil {
		return nil, ErrNoRunner
	}
	c := &Collector{
		runner: runner, now: time.Now, sleep: sleepCtx,
		pace: defaultPacing, maxTot: defaultMaxTotalBytes, busy: map[string]bool{},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// sleepCtx waits d, or returns early when the context is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Collect runs the plan's bound steps in order. progress may be nil.
//
// It returns a Capture even when individual commands failed — that is the point.
// It returns an ERROR only when the collection could not be started at all
// (device busy, plan too long, nothing to run).
func (c *Collector) Collect(ctx context.Context, p *Plan, supplied []SuppliedOutput, progress func(Progress)) (*Capture, error) {
	if p == nil {
		return nil, errors.New("tac: nil plan")
	}
	if len(p.Steps) > maxCommandsPerCollection {
		return nil, errors.New("tac: plan exceeds the collection command cap")
	}
	key := p.DeviceID
	if key == "" {
		key = p.Hostname
	}
	if key == "" {
		return nil, errors.New("tac: plan has no device identity")
	}
	if !c.claim(key) {
		return nil, ErrCollectBusy
	}
	defer c.release(key)

	capt := &Capture{
		TenantID: p.TenantID, IncidentID: p.IncidentID, PlanID: p.ID,
		ClassID: p.ClassID, ClassTitle: p.ClassTitle,
		DeviceID: p.DeviceID, Hostname: p.Hostname, Platform: p.Platform,
		Dialect: p.Dialect, Display: p.DialectDisplay, HasPlan: p.HasPlan,
		StartedAt: c.now().UTC(), Unbound: p.Unbound, Topology: p.Topology, Target: p.Target,
		Redacted: true, CatalogVersion: p.CatalogVersion, PlanVersion: p.PlanVersion,
		EngineVersion: Version, Commands: []CollectedCommand{},
	}
	if capt.Unbound == nil {
		capt.Unbound = []Step{}
	}
	if capt.Topology == nil {
		capt.Topology = []TopologyNote{}
	}

	dev := protocoldiag.Device{
		ID: p.DeviceID, Hostname: p.Hostname, Platform: p.Platform, TenantID: p.TenantID,
		Address: p.Address, Port: p.Port,
	}
	total := len(p.Steps)
	for i, st := range p.Steps {
		if err := ctx.Err(); err != nil {
			capt.Stopped = "the operator cancelled the collection"
			break
		}
		if capt.TotalBytes >= c.maxTot {
			capt.Stopped = "the collection reached its total output ceiling; the commands below are what was captured"
			break
		}
		if i > 0 && c.pace > 0 {
			if err := c.sleep(ctx, c.pace); err != nil {
				capt.Stopped = "the operator cancelled the collection"
				break
			}
		}
		emit(progress, Progress{Index: i, Total: total, Intent: st.Intent, Command: st.Command, Phase: "start"})
		cc := c.runOne(ctx, dev, st)
		capt.Commands = append(capt.Commands, cc)
		capt.TotalBytes += int64(cc.Bytes)
		if st.Teardown != "" {
			// A session-scoped setter is allowed ONLY because Correlix undoes
			// it, so the teardown runs unconditionally — after a failure, and
			// after a cancellation too. It is recorded like any other command:
			// a teardown that did not work is not something to hide.
			td := c.runTeardown(ctx, dev, st)
			capt.Commands = append(capt.Commands, td)
			capt.TotalBytes += int64(td.Bytes)
		}
		ph := "done"
		if cc.Err != "" {
			ph = "error"
		}
		emit(progress, Progress{Index: i, Total: total, Intent: st.Intent, Command: st.Command,
			Phase: ph, Bytes: cc.Bytes, Err: cc.Err})
	}

	// Pasted outputs are folded in AFTER the live ones, labelled as supplied.
	for _, s := range supplied {
		cc := c.foldSupplied(p, s)
		capt.Commands = append(capt.Commands, cc)
		capt.TotalBytes += int64(cc.Bytes)
	}

	capt.FinishedAt = c.now().UTC()
	return capt, nil
}

// runOne runs a single step under its own deadline and redacts its output.
func (c *Collector) runOne(ctx context.Context, dev protocoldiag.Device, st Step) CollectedCommand {
	to := time.Duration(st.TimeoutSeconds) * time.Second
	if to <= 0 {
		to = defaultCommandTimeout
	}
	start := c.now().UTC()
	cc := CollectedCommand{
		Intent: st.Intent, Title: st.Title, Section: st.Section,
		Command: st.Command, Verified: st.Verified, StartedAt: start,
	}
	runCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	out, err := c.runner.Run(runCtx, dev, st.Command)
	cc.DurationMS = c.now().UTC().Sub(start).Milliseconds()
	if err != nil {
		// §8: an error string can echo device output — redact it too.
		cc.Err = protocoldiag.RedactOutput(err.Error())
		return cc
	}
	if int64(len(out)) > st.MaxBytes && st.MaxBytes > 0 {
		out = out[:st.MaxBytes]
		cc.Err = "output exceeded this command's size cap and was truncated"
	}
	cc.Output = protocoldiag.RedactOutput(out)
	cc.Bytes = len(cc.Output)
	return cc
}

// runTeardown runs a step's session-scope teardown. It deliberately does NOT
// inherit the operator's cancellation: the whole basis for allowing a
// session-scoped setter is that Correlix clears it again, and a cancelled
// collection is exactly when leaving scope behind would be worst.
func (c *Collector) runTeardown(ctx context.Context, dev protocoldiag.Device, st Step) CollectedCommand {
	start := c.now().UTC()
	cc := CollectedCommand{
		Intent: st.Intent, Title: st.Title + " — session scope cleared",
		Section: st.Section, Command: st.Teardown, Verified: st.Verified, StartedAt: start,
	}
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultCommandTimeout)
	defer cancel()
	out, err := c.runner.Run(runCtx, dev, st.Teardown)
	cc.DurationMS = c.now().UTC().Sub(start).Milliseconds()
	if err != nil {
		cc.Err = protocoldiag.RedactOutput(err.Error())
		return cc
	}
	if int64(len(out)) > defaultMaxOutputBytes {
		out = out[:defaultMaxOutputBytes]
	}
	cc.Output = protocoldiag.RedactOutput(out)
	cc.Bytes = len(cc.Output)
	return cc
}

// foldSupplied turns one pasted output into a capture row. It is redacted on the
// way in and labelled `supplied` so a bundle reader never mistakes an operator's
// paste for something Correlix ran itself.
func (c *Collector) foldSupplied(p *Plan, s SuppliedOutput) CollectedCommand {
	title := s.Intent
	if st, ok := findStep(p, s.Intent); ok {
		title = st.Title
	}
	out := s.Output
	if int64(len(out)) > defaultMaxOutputBytes {
		out = out[:defaultMaxOutputBytes]
	}
	red := protocoldiag.RedactOutput(out)
	return CollectedCommand{
		Intent: s.Intent, Title: title, Section: "supplied",
		Command: strings.TrimSpace(s.Command), Verified: "",
		Output: red, Bytes: len(red), StartedAt: c.now().UTC(),
	}
}

func findStep(p *Plan, intent string) (Step, bool) {
	for _, s := range p.Steps {
		if s.Intent == intent {
			return s, true
		}
	}
	for _, s := range p.Unbound {
		if s.Intent == intent {
			return s, true
		}
	}
	return Step{}, false
}

func emit(f func(Progress), pr Progress) {
	if f != nil {
		f(pr)
	}
}

func (c *Collector) claim(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy[key] {
		return false
	}
	c.busy[key] = true
	return true
}

func (c *Collector) release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.busy, key)
}
