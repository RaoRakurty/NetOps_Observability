package protocoldiag

// fanout.go — PARALLEL, FAILURE-ISOLATED state collection across the devices a
// case names (design IRIS_TROUBLESHOOTING_MODEL_2026-09-02 §3.2, phase A3).
//
// NetClaw's rule for fleet collection is one sentence long — "one device timeout
// must not block others" — and it is the whole design here. RunBattery runs the
// state battery against N devices at once and returns a per-device verdict; a
// device that is unreachable, slow, busy, or on a platform we have no commands
// for produces its own honest status and changes NOTHING about the others.
//
// The bounds (§9), all constant and none caller-widenable past the ceiling:
//
//	MaxBatteryConcurrency   ≤ 8 devices in flight
//	DefaultDeviceTimeout      per-device wall clock
//	DefaultBatteryTimeout     whole-run wall clock
//	MaxBatteryDevices         devices per run (the rest are reported, not run)
//	MaxOutputBytes            per command, enforced by the runner/gateway
//
// One-in-flight-per-device is preserved two ways: the device list is DEDUPED by
// id before scheduling (so one run never schedules the same router twice), and
// the live SSHCommandRunner's own claim set still refuses a concurrent command
// from any other caller — a refusal that lands as that command's error, never as
// a stall.
//
// REDACTION IS NOT OPTIONAL HERE. Every captured output is passed through
// RedactOutput BEFORE it is stored on the result and BEFORE it is parsed, so no
// unredacted byte can reach a typed row, a Reason string, or a caller. The
// battery contains no `show running-config`-class command in the first place;
// redaction is the second of the two locks.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/showparse"
)

const (
	// MaxBatteryConcurrency is the ceiling on devices collected in parallel. It
	// is a CONSTANT, not a tunable: the cost of a wider fan-out is paid by the
	// production routers, not by us.
	MaxBatteryConcurrency = 8
	// DefaultDeviceTimeout bounds ONE device's whole battery.
	DefaultDeviceTimeout = 60 * time.Second
	// DefaultBatteryTimeout bounds the WHOLE run, however many devices it has.
	DefaultBatteryTimeout = 5 * time.Minute
	// MaxBatteryDevices bounds how many devices one run will touch. Devices past
	// the bound are REPORTED as not-run rather than silently dropped (§10).
	MaxBatteryDevices = 64
)

// DeviceStatus is one device's outcome in a battery run.
type DeviceStatus string

const (
	// DeviceStatusOK means every rendered command ran.
	DeviceStatusOK DeviceStatus = "ok"
	// DeviceStatusPartial means some commands ran and some failed.
	DeviceStatusPartial DeviceStatus = "partial"
	// DeviceStatusFailed means no command produced output.
	DeviceStatusFailed DeviceStatus = "failed"
	// DeviceStatusTimedOut means the device's own deadline (or the run's, or the
	// caller's cancellation) cut it short.
	DeviceStatusTimedOut DeviceStatus = "timed_out"
	// DeviceStatusUnsupported means the platform resolved to no dialect, or the
	// dialect has no authored command for this area. It is an honest
	// "not established", never a fallback to another platform's commands.
	DeviceStatusUnsupported DeviceStatus = "unsupported"
	// DeviceStatusNotRun means the device was past MaxBatteryDevices.
	DeviceStatusNotRun DeviceStatus = "not_run"
)

// DeviceState is one device's battery result: what ran, what it returned
// (REDACTED), and what the parsers made of it.
type DeviceState struct {
	// TenantID is stamped from the SUBJECT DEVICE (§3a), never a request body.
	TenantID string
	DeviceID string
	Hostname string
	Platform string
	// Dialect is the resolved dialect, or "" when the platform is unassessed.
	Dialect showparse.Dialect
	Area    Area
	Status  DeviceStatus
	// Note explains a non-OK status in operator-readable words.
	Note           string
	StartedAt      time.Time
	FinishedAt     time.Time
	Commands       []CollectedCommand
	Parsed         []showparse.Result
	RulesetVersion string
}

// BatteryRun is the whole fan-out result, in the caller's device order.
type BatteryRun struct {
	Area           Area
	RulesetVersion string
	StartedAt      time.Time
	FinishedAt     time.Time
	Devices        []DeviceState
	// Truncated is true when the device list was capped at MaxBatteryDevices.
	Truncated bool
}

// Counts summarizes the run by status — the aggregation a caller shows first.
func (r BatteryRun) Counts() map[DeviceStatus]int {
	out := map[DeviceStatus]int{}
	for _, d := range r.Devices {
		out[d.Status]++
	}
	return out
}

// BatteryCollector runs the state battery across devices. It holds no mutable
// state of its own (the per-run state lives on the stack), so one collector is
// safe to share.
type BatteryCollector struct {
	battery       *StateBattery
	runner        CommandRunner
	now           func() time.Time
	concurrency   int
	deviceTimeout time.Duration
	totalTimeout  time.Duration
}

// BatteryOption configures a BatteryCollector.
type BatteryOption func(*BatteryCollector)

// WithBatteryClock injects the timestamp source (default time.Now).
func WithBatteryClock(now func() time.Time) BatteryOption {
	return func(c *BatteryCollector) {
		if now != nil {
			c.now = now
		}
	}
}

// WithConcurrency narrows the parallelism. It can only NARROW: a value above
// MaxBatteryConcurrency is clamped, and a non-positive value is ignored.
func WithConcurrency(n int) BatteryOption {
	return func(c *BatteryCollector) {
		if n <= 0 {
			return
		}
		if n > MaxBatteryConcurrency {
			n = MaxBatteryConcurrency
		}
		c.concurrency = n
	}
}

// WithDeviceTimeout overrides the per-device deadline. A non-positive value is
// ignored — there is no "no timeout" setting (§9).
func WithDeviceTimeout(d time.Duration) BatteryOption {
	return func(c *BatteryCollector) {
		if d > 0 {
			c.deviceTimeout = d
		}
	}
}

// WithTotalTimeout overrides the whole-run deadline. A non-positive value is
// ignored.
func WithTotalTimeout(d time.Duration) BatteryOption {
	return func(c *BatteryCollector) {
		if d > 0 {
			c.totalTimeout = d
		}
	}
}

// NewBatteryCollector builds a collector. Both dependencies are REQUIRED: a nil
// battery or runner is a fail-closed error, never a silent no-op that would
// report every device healthy.
func NewBatteryCollector(b *StateBattery, runner CommandRunner, opts ...BatteryOption) (*BatteryCollector, error) {
	if b == nil {
		return nil, errors.New("protocoldiag: nil state battery")
	}
	if runner == nil {
		return nil, errors.New("protocoldiag: nil command runner")
	}
	c := &BatteryCollector{
		battery:       b,
		runner:        runner,
		now:           time.Now,
		concurrency:   MaxBatteryConcurrency,
		deviceTimeout: DefaultDeviceTimeout,
		totalTimeout:  DefaultBatteryTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// RunBattery collects one area of state from every device, in parallel, with
// bounded concurrency and per-device isolation.
//
// It returns an error ONLY for a caller contract violation (an unknown area).
// Everything a device can do wrong — unreachable, slow, busy, unassessed
// platform, a command refused by the closed table — is that device's own status
// and note. The run always finishes within the total timeout and always returns
// one DeviceState per (deduped) input device, in input order.
func (c *BatteryCollector) RunBattery(ctx context.Context, devices []Device, area Area, tgt Target) (BatteryRun, error) {
	if !ValidArea(area) {
		return BatteryRun{}, fmt.Errorf("%w: %q", ErrUnknownArea, area)
	}
	run := BatteryRun{Area: area, RulesetVersion: RulesetVersion, StartedAt: c.now().UTC()}

	unique, overflow := dedupeDevices(devices)
	run.Truncated = len(overflow) > 0

	results := make([]DeviceState, len(unique))
	if len(unique) > 0 {
		runCtx, cancel := context.WithTimeout(ctx, c.totalTimeout)
		defer cancel()

		workers := c.concurrency
		if workers > len(unique) {
			workers = len(unique)
		}
		idx := make(chan int)
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for i := range idx {
					// Each worker writes ONLY results[i] for the index it pulled,
					// so the slice needs no lock and the run is deterministic in
					// output order regardless of completion order.
					results[i] = c.collectOne(runCtx, unique[i], area, tgt)
				}
			}()
		}
		// The feeder stops early on cancellation so a cancelled run does not
		// keep dialing devices; the indices it never fed are filled in below.
		fed := 0
	feed:
		for i := range unique {
			select {
			case idx <- i:
				fed++
			case <-runCtx.Done():
				break feed
			}
		}
		close(idx)
		wg.Wait()
		// The feeder hands out indices IN ORDER, so everything from `fed` on was
		// never dispatched. Filling those explicitly (rather than sniffing for a
		// zero-valued result) is what guarantees one DeviceState per input
		// device even when the run is cancelled mid-fan-out.
		for i := fed; i < len(results); i++ {
			results[i] = c.notRun(unique[i], area, runCtx.Err())
		}
	}
	run.Devices = results
	for _, d := range overflow {
		run.Devices = append(run.Devices, DeviceState{
			TenantID: d.TenantID, DeviceID: d.ID, Hostname: d.Hostname, Platform: d.Platform,
			Area: area, Status: DeviceStatusNotRun, RulesetVersion: RulesetVersion,
			Note: fmt.Sprintf("not run: the request named more than %d devices", MaxBatteryDevices),
		})
	}
	run.FinishedAt = c.now().UTC()
	return run, nil
}

// notRun builds the state for a device the run never reached.
func (c *BatteryCollector) notRun(dev Device, area Area, cause error) DeviceState {
	note := "not run: the battery's wall-clock budget was spent before this device was reached"
	if cause != nil {
		note = "not run: " + cause.Error()
	}
	now := c.now().UTC()
	return DeviceState{
		TenantID: dev.TenantID, DeviceID: dev.ID, Hostname: dev.Hostname, Platform: dev.Platform,
		Area: area, Status: DeviceStatusTimedOut, Note: note, RulesetVersion: RulesetVersion,
		StartedAt: now, FinishedAt: now,
	}
}

// collectOne runs one device's battery under its own deadline. It never returns
// an error: every failure is recorded on the returned state, which is what makes
// one device's trouble invisible to the others.
func (c *BatteryCollector) collectOne(ctx context.Context, dev Device, area Area, tgt Target) DeviceState {
	st := DeviceState{
		TenantID: dev.TenantID, // §3a: owner from the resolved device, never a body
		DeviceID: dev.ID, Hostname: dev.Hostname, Platform: dev.Platform,
		Area: area, RulesetVersion: RulesetVersion, StartedAt: c.now().UTC(),
	}
	defer func() { st.FinishedAt = c.now().UTC() }()

	dialect, ok := showparse.DialectFromPlatform(dev.Platform)
	if !ok {
		st.Status = DeviceStatusUnsupported
		st.Note = fmt.Sprintf("platform %q does not resolve to a known CLI dialect — no command was run (a guessed dialect would be a guessed command at a production device)", dev.Platform)
		return st
	}
	st.Dialect = dialect

	cmds := c.battery.Battery(area, dialect, tgt)
	if len(cmds) == 0 {
		st.Status = DeviceStatusUnsupported
		st.Note = fmt.Sprintf("no %s command is established for dialect %s (or its required argument was not supplied)", area, dialect)
		return st
	}

	devCtx, cancel := context.WithTimeout(ctx, c.deviceTimeout)
	defer cancel()

	okCount := 0
	for _, rc := range cmds {
		if err := devCtx.Err(); err != nil {
			st.Commands = append(st.Commands, CollectedCommand{
				SpecID: rc.SpecID, Command: rc.Command, Purpose: rc.Purpose,
				Timestamp: c.now().UTC(), Err: err.Error(),
			})
			continue
		}
		cc := CollectedCommand{
			SpecID: rc.SpecID, Command: rc.Command, Purpose: rc.Purpose, Timestamp: c.now().UTC(),
		}
		out, err := c.runner.Run(devCtx, dev, rc.Command)
		if err != nil {
			cc.Err = err.Error()
			st.Commands = append(st.Commands, cc)
			continue
		}
		// REDACT FIRST, then parse: nothing unredacted reaches a typed row.
		cc.Output = RedactOutput(out)
		st.Commands = append(st.Commands, cc)
		okCount++

		res, perr := showparse.Parse(rc.SpecID, dialect, cc.Output)
		if perr != nil {
			// A parse contract violation (an over-cap blob that slipped the
			// runner's own cap) is recorded, never swallowed (§10).
			res = showparse.Result{
				CmdID: rc.SpecID, Dialect: dialect, Skipped: true,
				Reason: "parser refused the capture: " + perr.Error(),
			}
		}
		st.Parsed = append(st.Parsed, res)
	}

	switch {
	case okCount == len(cmds):
		st.Status = DeviceStatusOK
	case okCount > 0:
		st.Status = DeviceStatusPartial
		st.Note = fmt.Sprintf("%d of %d commands failed", len(cmds)-okCount, len(cmds))
	case deadlineHit(devCtx):
		st.Status = DeviceStatusTimedOut
		st.Note = "the device did not answer within its collection deadline"
	default:
		st.Status = DeviceStatusFailed
		st.Note = "no command produced output"
	}
	return st
}

// deadlineHit reports whether ctx ended because of a deadline or cancellation.
func deadlineHit(ctx context.Context) bool { return ctx.Err() != nil }

// dedupeDevices removes duplicate device ids (keeping the first occurrence and
// the caller's order) and splits off everything past MaxBatteryDevices. A device
// with no id is keyed on its address, and one with neither is kept as-is — it
// will fail at the runner with an honest ErrNoAddress rather than be dropped
// here.
func dedupeDevices(devices []Device) (kept, overflow []Device) {
	seen := map[string]bool{}
	for _, d := range devices {
		key := strings.TrimSpace(d.ID)
		if key == "" {
			key = strings.TrimSpace(d.Address)
		}
		if key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		if len(kept) >= MaxBatteryDevices {
			overflow = append(overflow, d)
			continue
		}
		kept = append(kept, d)
	}
	return kept, overflow
}

// TypedRows flattens a device's parsed results into the evidence lines a caller
// (today: the RCA narrative; tomorrow: the `get_device_state` skill tool) cites.
// A skipped parse contributes its REASON, never a fabricated row — so an
// inconclusive read is visible as inconclusive rather than as silence.
func (s DeviceState) TypedRows() (rows int, skipped []string) {
	for _, r := range s.Parsed {
		if r.Skipped {
			skipped = append(skipped, fmt.Sprintf("%s: %s", r.CmdID, r.Reason))
			continue
		}
		rows += r.Rows()
	}
	sort.Strings(skipped)
	return rows, skipped
}
