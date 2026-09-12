// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	"fmt"
	"os"
	"path/filepath"
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
	//
	// It was 32 MiB while every command was buffered in memory, which was the
	// right number for a heap bound. Since 2026-09-07 the vendor's first-ask
	// support collection is STREAMED to disk and a single one of those may be
	// 64 MiB by its own authored ceiling, so a 32 MiB whole-collection cap would
	// stop the collection in the middle of the one command TAC asks for first.
	// What this number now bounds is the spill directory, not the heap.
	defaultMaxTotalBytes int64 = 256 << 20
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
	//
	// Output is EMPTY for a STREAMED command; its body is in SpillPath. The two
	// are never both set, and Bytes is the redacted size either way, so
	// everything that reports a size — the summary, the manifest, the total-cap
	// arithmetic — reads one field and cannot disagree with itself.
	Output string `json:"output"`
	Bytes  int    `json:"bytes"`
	// SpillPath is the on-disk file holding this command's REDACTED output when
	// it was streamed rather than buffered (the vendor's first-ask support
	// collection: tens of megabytes, minutes long).
	//
	// It is `json:"-"` deliberately. A spill path is process-local state, not a
	// fact about the capture: serialising it would put a filesystem location in
	// the state endpoint, in the learning backlog and in anything that persists
	// a capture, and none of those can do anything useful with it. The bundle
	// builder, which runs in this process, is the only reader.
	SpillPath  string    `json:"-"`
	Err        string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// Streamed reports a command whose output is on disk rather than in memory.
func (c CollectedCommand) Streamed() bool { return c.SpillPath != "" }

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
	// VendorID / Serial / Model are the device's identity as the VENDOR checks
	// it, carried from the plan so the case form and the bundle's device.json
	// both name the same chassis.
	VendorID string `json:"vendor,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Model    string `json:"model,omitempty"`
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

	// Reviewed / Template / Edits carry the operator's command review into the
	// bundle. They are on the CAPTURE, not only on the plan, because the plan is
	// in-memory state that dies with the api and the capture is what a bundle is
	// built from — a bundle that could not say which template ran, and what a
	// human changed, would be exactly the provenance TAC needs and lacks.
	Reviewed bool        `json:"reviewed"`
	Template TemplateRef `json:"template,omitzero"`
	Edits    []PlanEdit  `json:"edits,omitempty"`

	// SpillDir is the directory holding this capture's streamed outputs. It is
	// this process's own temporary directory, owned by the capture, and removed
	// by Close — which the service calls when the capture is replaced or the
	// escalation is evicted. Like SpillPath it never crosses the wire.
	SpillDir string `json:"-"`

	TotalBytes int64 `json:"total_bytes"`
	// Redacted is always true — it is stated rather than assumed, so a reader
	// of the JSON never has to wonder.
	Redacted bool `json:"redacted"`
	// Stopped records an early stop honestly (total cap reached, cancelled).
	Stopped string `json:"stopped,omitempty"`

	CatalogVersion string `json:"catalog_version"`
	PlanVersion    string `json:"plan_version,omitempty"`
	EngineVersion  string `json:"engine_version"`

	// mu guards this capture's RELEASE — SpillDir, every command's SpillPath,
	// and the reader count below. It is the capture's own lock and never the
	// service's: a bundle is streamed from the spill files WITHOUT the service
	// lock held, on purpose, so the service lock cannot be what protects them.
	//
	// A Capture is always passed by pointer (go vet's copylocks check keeps it
	// that way), so this costs nothing but the words.
	mu sync.Mutex
	// readers is how many bundle builds are streaming this capture right now.
	readers int
	// closeAsked records a Close that arrived while a reader held a lease. The
	// LAST reader out does the removal, so a capture is released exactly once
	// and never underneath a build that is already reading it.
	closeAsked bool
	// released records that the removal has run. A released capture can never
	// be leased again: the honest answer to "bundle this" is a refusal.
	released bool
}

// Close releases the capture's streamed outputs. It is idempotent, and it is
// safe to call on a capture that streamed nothing.
//
// A capture that is never closed leaks a temporary directory for the life of the
// process, which is why the service closes the OLD capture at the moment it
// records a new one and at eviction — the two points where a capture stops being
// reachable. It is not tied to the bundle: a bundle can be built many times from
// one capture (once per profile the operator tries), so the bundle cannot own
// the bytes it reads.
//
// It does not, however, get to delete them out from under a build that is
// already reading them. A Close that arrives while a bundle holds a read lease
// (Retain) is DEFERRED to the last reader out, so the capture stops being
// reachable immediately and its bytes survive exactly as long as the build that
// needs them.
func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.released {
		c.mu.Unlock()
		return nil
	}
	c.closeAsked = true
	if c.readers > 0 {
		// A bundle is mid-build from these files. The removal is DEFERRED to
		// the last reader out rather than skipped: the caller has still asked
		// for the capture to stop being reachable, and it is.
		c.mu.Unlock()
		return nil
	}
	return c.releaseLocked()
}

// Retain takes a read lease on the capture's streamed outputs, so they cannot
// be removed while a bundle is being built from them.
//
// It reports FALSE when the outputs are already gone, or are about to be: a
// caller that cannot lease must refuse honestly rather than build a bundle from
// what is left, because a streamed command's in-memory body is empty by
// construction and the bundle would carry a header-only stub with a real
// checksum over it.
//
// Every Retain is paired with exactly one Release.
func (c *Capture) Retain() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released || c.closeAsked {
		return false
	}
	c.readers++
	return true
}

// Release drops one read lease. When it is the last one out of a capture whose
// Close was deferred, it performs the removal and returns its error — which is
// the only place that error can still be reported (§10).
func (c *Capture) Release() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.readers > 0 {
		c.readers--
	}
	if c.readers > 0 || !c.closeAsked || c.released {
		c.mu.Unlock()
		return nil
	}
	return c.releaseLocked()
}

// releaseLocked blanks the paths and removes the directory. It is called with
// c.mu HELD and unlocks it.
func (c *Capture) releaseLocked() error {
	defer c.mu.Unlock()
	c.released = true
	dir := c.SpillDir
	c.SpillDir = ""
	for i := range c.Commands {
		c.Commands[i].SpillPath = ""
	}
	if dir == "" {
		return nil
	}
	return os.RemoveAll(dir)
}

// Vendor returns the device's vendor id, which is what a TAC route is keyed on.
// It is a method rather than a bare field read so a capture with no resolved
// vendor answers "" once, here, instead of at every call site.
func (c *Capture) Vendor() string {
	if c == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(c.VendorID))
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
	// stream is the runner's OPTIONAL streaming half. It is set only when the
	// injected runner implements protocoldiag.StreamingRunner; when it is nil
	// every command is buffered, and a first-ask support collection is refused
	// rather than silently truncated to the buffered ceiling.
	stream protocoldiag.StreamingRunner
	// spillRoot is where streamed outputs are written. Empty means the OS
	// temporary directory, which is what production uses; a test pins it.
	spillRoot string
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error
	pace      time.Duration
	maxTot    int64

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

// WithSpillRoot pins the directory streamed outputs are written under. Tests use
// it; production leaves it empty and gets the OS temporary directory.
func WithSpillRoot(dir string) CollectorOption {
	return func(c *Collector) {
		if strings.TrimSpace(dir) != "" {
			c.spillRoot = dir
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
	// The streaming half is DISCOVERED, not configured: a runner either can
	// stream or cannot, and asking a deployment to declare it would be one more
	// thing to get wrong. A runner that cannot is not degraded — every command
	// but the first-ask collection is kilobytes and buffers fine.
	if sr, ok := runner.(protocoldiag.StreamingRunner); ok {
		c.stream = sr
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// CanStream reports whether this collector can run a first-ask support
// collection. It is read by the escalation so the UI can say plainly that this
// deployment's transport will not carry one, rather than producing a truncated
// bundle and calling it done.
func (c *Collector) CanStream() bool { return c != nil && c.stream != nil }

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
		VendorID: p.Vendor, Serial: p.Serial, Model: p.Model,
		Dialect: p.Dialect, Display: p.DialectDisplay, HasPlan: p.HasPlan,
		StartedAt: c.now().UTC(), Unbound: p.Unbound, Topology: p.Topology, Target: p.Target,
		Reviewed: p.Reviewed, Template: p.Template, Edits: p.Edits,
		Redacted: true, CatalogVersion: p.CatalogVersion, PlanVersion: p.PlanVersion,
		EngineVersion: Version, Commands: []CollectedCommand{},
	}
	if capt.Unbound == nil {
		capt.Unbound = []Step{}
	}
	if capt.Topology == nil {
		capt.Topology = []TopologyNote{}
	}
	// The spill directory is created ONLY when the plan actually carries a
	// streamed step, so an ordinary collection touches no disk at all.
	if c.stream != nil && planNeedsStream(p) {
		dir, derr := os.MkdirTemp(c.spillRoot, "correlix-tac-capture-")
		if derr != nil {
			// A collection that cannot spill still runs: the streamed steps fall
			// back to the buffered path and record their own truncation, which
			// is far better than refusing to collect anything.
			capt.Stopped = ""
		} else {
			capt.SpillDir = dir
		}
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
		var cc CollectedCommand
		if c.streamable(st) && capt.SpillDir != "" {
			cc = c.runStreamed(ctx, dev, st, capt.SpillDir, i)
		} else {
			cc = c.runOne(ctx, dev, st)
		}
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

// streamable reports that this step is one the collector should STREAM.
//
// The rule is the step's own budget, not its section: a step whose authored
// MaxBytes exceeds what the buffered path can carry would be truncated by the
// buffered path, and truncating the vendor's support bundle is the one failure
// this whole seam exists to prevent. First-ask steps are exactly the steps that
// carry such a budget, which is why the loader REQUIRES them to declare one.
func (c *Collector) streamable(st Step) bool {
	return c.stream != nil && st.MaxBytes > defaultMaxOutputBytes
}

// planNeedsStream reports whether any of the plan's steps will be streamed.
func planNeedsStream(p *Plan) bool {
	for _, st := range p.Steps {
		if st.MaxBytes > defaultMaxOutputBytes {
			return true
		}
	}
	return false
}

// runStreamed runs one step with its output written STRAIGHT INTO a spill file,
// redacted on the way through.
//
// The redaction is the load-bearing part. Nothing unredacted is ever written to
// disk: protocoldiag.RedactingWriter applies the identical per-line rules the
// buffered path applies, in a stream, with the PEM-block state carried across
// write boundaries — so a private key split over a hundred packets is redacted
// exactly as it would be in a 4 KB `show run` output.
func (c *Collector) runStreamed(ctx context.Context, dev protocoldiag.Device, st Step, dir string, idx int) CollectedCommand {
	start := c.now().UTC()
	cc := CollectedCommand{
		Intent: st.Intent, Title: st.Title, Section: st.Section,
		Command: st.Command, Verified: st.Verified, StartedAt: start,
	}
	path := filepath.Join(dir, spillName(idx, st.Intent))
	// #nosec G304 -- path is built from this collector's own temp dir and a
	// slugged intent id from the loaded catalog; no caller supplies it.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cc.Err = "this output could not be streamed to disk: " + err.Error()
		cc.DurationMS = c.now().UTC().Sub(start).Milliseconds()
		return cc
	}
	red := protocoldiag.NewRedactingWriter(f)
	to := time.Duration(st.TimeoutSeconds) * time.Second
	if to <= 0 {
		to = defaultCommandTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, to)
	n, runErr := c.stream.RunStream(runCtx, dev, st.Command, st.MaxBytes, red)
	cancel()
	closeErr := red.Close()
	if ferr := f.Close(); ferr != nil && closeErr == nil {
		closeErr = ferr
	}
	cc.DurationMS = c.now().UTC().Sub(start).Milliseconds()
	cc.Bytes = int(red.Written())
	cc.SpillPath = path
	switch {
	case runErr != nil && errors.Is(runErr, protocoldiag.ErrTooLarge):
		// Honest truncation: the bytes collected are KEPT and the operator and
		// the TAC engineer are both told the file is short.
		cc.Err = "output exceeded this command's size cap and was truncated"
	case runErr != nil:
		// §8: an error string can echo device output — redact it too.
		cc.Err = protocoldiag.RedactOutput(runErr.Error())
	case closeErr != nil:
		cc.Err = "this output could not be flushed to disk: " + closeErr.Error()
	}
	if cc.Bytes == 0 && cc.Err == "" {
		// Nothing came back. The empty spill file is not evidence; drop it so
		// the bundle reports "returned no output" the way it always has.
		cc.SpillPath = ""
		if rerr := os.Remove(path); rerr != nil {
			cc.Err = "an empty streamed output could not be cleaned up: " + rerr.Error()
		}
	}
	_ = n // the redacted count (red.Written) is the size that matters, not the raw one
	return cc
}

// spillName is the on-disk name of one streamed output. It is built from a
// closed character set so a catalog id can never steer a path.
func spillName(idx int, intent string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%03d-", idx)
	for _, r := range intent {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		default:
			b.WriteByte('-')
		}
	}
	b.WriteString(".txt")
	return b.String()
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
