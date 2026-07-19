package main

// verify_engine.go — Active Verification engine (RCA postmortem-enhancements
// spec, item 8). When a correlation case sits at SUSPECTED ("needs a second
// independent source"), this engine interrogates the implicated devices with a
// bounded, READ-ONLY check battery and the results feed back to the bus as a
// NEW evidence modality (active_verification) that can independently confirm
// or refute — the IEEE Node-Test loop, but async, parallel and bounded (their
// serial SSH took 41 s; this engine's whole run is budget-capped).
//
// READ-ONLY guarantees (non-negotiable, CLAUDE.md §8):
//   - SSH commands come ONLY from the closed vendor table below. Check ids
//     select a row; command text is never composed from user input.
//   - The SSH runner re-validates every command against the table before
//     executing (defense in depth: a non-allowlisted command is impossible
//     even if a caller is buggy).
//   - Every executed command is recorded on the result (and therefore in the
//     audit trail and on the emitted evidence).
//
// Reliability (§9): hard per-check timeout, total run budget, bounded
// concurrency, bounded output reads. Checks that cannot start inside the
// budget are reported as skipped — never silently dropped.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/collectors"
	"netops/backend/models"
)

// ---- tunables (env-overridable; clamped to sane bounds) ---------------------

func verifyCheckTimeout() time.Duration {
	return secEnvDuration("VERIFY_CHECK_TIMEOUT_SEC", 10, 1, 60)
}
func verifyRunBudget() time.Duration {
	return secEnvDuration("VERIFY_RUN_BUDGET_SEC", 60, 10, 300)
}
func verifyMaxConcurrent() int { return clampInt(envInt("VERIFY_MAX_CONCURRENT", 4), 1, 16) }
func verifyMaxDevices() int    { return clampInt(envInt("VERIFY_MAX_DEVICES", 5), 1, 20) }

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- normalized results (the wire/UI contract) ------------------------------

const (
	verifyStatusPass        = "pass"
	verifyStatusFail        = "fail"
	verifyStatusUnreachable = "unreachable"
	verifyStatusSkipped     = "skipped"
)

// verifyCheckResult is one normalized check outcome:
// {check, target, status pass/fail/unreachable/skipped, observed value, ts}.
type verifyCheckResult struct {
	Check             string    `json:"check"`
	DeviceID          string    `json:"device_id"`
	DeviceName        string    `json:"device_name,omitempty"`
	Target            string    `json:"target"`
	Method            string    `json:"method"` // tcp | snmp | ssh
	Status            string    `json:"status"`
	Observed          string    `json:"observed,omitempty"`
	Command           string    `json:"command,omitempty"` // exact allowlisted command executed
	Ts                time.Time `json:"ts"`
	DurationMS        int64     `json:"duration_ms"`
	CorroboratesKinds []string  `json:"corroborates_kinds,omitempty"` // stamped on fail/unreachable
	RefutesKinds      []string  `json:"refutes_kinds,omitempty"`      // stamped on pass
}

// ---- check battery + CLOSED command allowlist -------------------------------

type verifyCheckSpec struct {
	ID     string
	Method string // tcp | snmp | ssh
	// Evidence semantics: what a FAILING check corroborates and what a HEALTHY
	// one refutes. Mirrored by the correlation producer's closed vocabulary
	// (verification_producer.py REFUTABLE_KINDS) — the scorer only ever matches
	// these declarations, never invents a mapping.
	Corroborates []string
	Refutes      []string
}

// verifyBattery is the FIXED, ordered check set. Small on purpose: each check
// earns its place by corroborating or refuting a specific fault vocabulary.
func verifyBattery() []verifyCheckSpec {
	return []verifyCheckSpec{
		// Platform-executed reachability (weak witness; support-only in the
		// verdict gate). Claims no vocabulary — unreachability is honest
		// evidence on its own, not proof of a specific fault kind.
		{ID: "reach_tcp", Method: "tcp"},
		{ID: "reach_snmp", Method: "snmp"},
		// Device answers (authoritative-leaning).
		{ID: "snmp_uptime", Method: "snmp",
			Corroborates: []string{"device_restart"}, Refutes: []string{"device_restart"}},
		{ID: "ssh_interfaces", Method: "ssh",
			Corroborates: []string{"link_state_change"}, Refutes: []string{"link_state_change"}},
		{ID: "ssh_routing", Method: "ssh",
			Corroborates: []string{"bgp_adjacency_change", "routing_adjacency_change"},
			Refutes:      []string{"bgp_adjacency_change", "routing_adjacency_change"}},
	}
}

// verifyCommandTable is the CLOSED read-only command allowlist, keyed by the
// discovery vendor family (collectors.vendorFromDescr vocabulary) → check id →
// the EXACT command line executed. Amending this table is the ONLY way a new
// command can ever be run; nothing is composed at runtime. Every entry must be
// a state-inspection (show/display) command — verifyCommandTableReadOnly in
// verify_engine_test.go guards the invariant.
var verifyCommandTable = map[string]map[string]string{
	"cisco": {
		"ssh_interfaces": "show ip interface brief",
		"ssh_routing":    "show ip bgp summary",
	},
	"arista": {
		"ssh_interfaces": "show interfaces status",
		"ssh_routing":    "show ip bgp summary",
	},
	"juniper": {
		"ssh_interfaces": "show interfaces terse",
		"ssh_routing":    "show bgp summary",
	},
	"huawei": {
		"ssh_interfaces": "display interface brief",
		"ssh_routing":    "display bgp peer",
	},
	"nokia": {
		"ssh_interfaces": "show port",
		"ssh_routing":    "show router bgp summary",
	},
}

// verifyCommandFor resolves (vendor, check) → the allowlisted command.
// Unknown vendor or check ⇒ no command (the check is skipped, never guessed).
func verifyCommandFor(vendor, checkID string) (string, bool) {
	fam, ok := verifyCommandTable[strings.ToLower(strings.TrimSpace(vendor))]
	if !ok {
		return "", false
	}
	cmd, ok := fam[checkID]
	return cmd, ok
}

// verifyCommandAllowed reports whether cmd appears VERBATIM in the closed
// table — the SSH runner's defense-in-depth gate.
func verifyCommandAllowed(cmd string) bool {
	for _, fam := range verifyCommandTable {
		for _, c := range fam {
			if c == cmd {
				return true
			}
		}
	}
	return false
}

// ---- targets & executor seams (interfaces for tests, §5 injectable deps) ----

// verifySSHCred is the tenant-configured, non-interactive read-only login the
// battery uses. Never logged; never echoed by any API.
type verifySSHCred struct {
	User       string
	Password   string
	PrivateKey string
	Passphrase string
	Port       int
}

// verifyTarget is one implicated device plus whatever management channels are
// actually configured for it. Nil channel ⇒ those checks are skipped honestly.
type verifyTarget struct {
	Device models.Device
	SNMP   *collectors.Target // nil ⇒ snmp checks skipped (no credential)
	SSH    *verifySSHCred     // nil ⇒ ssh checks skipped (not configured)
}

// verifySSHOut is one command's outcome from the SSH runner.
type verifySSHOut struct {
	Output string
	Err    error
}

// verifyDialers are the engine's injectable executors. Production wiring lives
// on the server (newVerifyDialers); tests inject fakes — the engine itself
// performs no network IO of its own.
type verifyDialers struct {
	TCPReach   func(ctx context.Context, addr string) error
	SNMPReach  func(ctx context.Context, t collectors.Target) error
	SNMPUptime func(ctx context.Context, t collectors.Target) (int64, error)
	// SSHRun executes the given allowlisted commands (check id → command) over
	// ONE connection to the device and returns per-check outcomes. It must
	// respect ctx and never execute a command that fails verifyCommandAllowed.
	SSHRun func(ctx context.Context, dev models.Device, cred verifySSHCred, cmds map[string]string) map[string]verifySSHOut
}

// ---- engine -----------------------------------------------------------------

type verifyEngine struct {
	dial         verifyDialers
	checkTimeout time.Duration
	runBudget    time.Duration
	maxConc      int
}

func newVerifyEngine(d verifyDialers) *verifyEngine {
	return &verifyEngine{
		dial:         d,
		checkTimeout: verifyCheckTimeout(),
		runBudget:    verifyRunBudget(),
		maxConc:      verifyMaxConcurrent(),
	}
}

// run executes the battery against every target: parallel across devices and
// method groups, bounded by maxConc, each check under checkTimeout, the whole
// run under runBudget. Deterministic result order (device, then battery order).
func (e *verifyEngine) run(ctx context.Context, targets []verifyTarget) []verifyCheckResult {
	if len(targets) > verifyMaxDevices() {
		targets = targets[:verifyMaxDevices()]
	}
	runCtx, cancel := context.WithTimeout(ctx, e.runBudget)
	defer cancel()

	sem := make(chan struct{}, e.maxConc)
	var mu sync.Mutex
	var out []verifyCheckResult
	var wg sync.WaitGroup

	add := func(rs ...verifyCheckResult) {
		mu.Lock()
		out = append(out, rs...)
		mu.Unlock()
	}

	// One task per (device, method group): tcp, snmp, ssh. The ssh group runs
	// its commands over a single connection; every group honors the semaphore
	// and the run budget.
	for i := range targets {
		t := targets[i]
		for _, group := range []string{"tcp", "snmp", "ssh"} {
			specs := groupSpecs(group)
			if len(specs) == 0 {
				continue
			}
			wg.Add(1)
			go func(t verifyTarget, group string, specs []verifyCheckSpec) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-runCtx.Done():
					add(skippedResults(t, specs, "run budget exhausted before check started")...)
					return
				}
				if runCtx.Err() != nil {
					add(skippedResults(t, specs, "run budget exhausted before check started")...)
					return
				}
				switch group {
				case "tcp":
					add(e.runTCP(runCtx, t, specs)...)
				case "snmp":
					add(e.runSNMP(runCtx, t, specs)...)
				case "ssh":
					add(e.runSSH(runCtx, t, specs)...)
				}
			}(t, group, specs)
		}
	}
	wg.Wait()

	// Deterministic ordering: device order as given, then battery order.
	order := map[string]int{}
	for i, s := range verifyBattery() {
		order[s.ID] = i
	}
	devOrder := map[string]int{}
	for i, t := range targets {
		devOrder[t.Device.ID] = i
	}
	sort.SliceStable(out, func(a, b int) bool {
		if devOrder[out[a].DeviceID] != devOrder[out[b].DeviceID] {
			return devOrder[out[a].DeviceID] < devOrder[out[b].DeviceID]
		}
		return order[out[a].Check] < order[out[b].Check]
	})
	return out
}

func groupSpecs(method string) []verifyCheckSpec {
	var out []verifyCheckSpec
	for _, s := range verifyBattery() {
		if s.Method == method {
			out = append(out, s)
		}
	}
	return out
}

func baseResult(t verifyTarget, spec verifyCheckSpec) verifyCheckResult {
	return verifyCheckResult{
		Check:      spec.ID,
		DeviceID:   t.Device.ID,
		DeviceName: t.Device.Name,
		Target:     t.Device.Address,
		Method:     spec.Method,
		Ts:         time.Now().UTC(),
	}
}

func skippedResults(t verifyTarget, specs []verifyCheckSpec, why string) []verifyCheckResult {
	out := make([]verifyCheckResult, 0, len(specs))
	for _, s := range specs {
		r := baseResult(t, s)
		r.Status = verifyStatusSkipped
		r.Observed = why
		out = append(out, r)
	}
	return out
}

// finalize stamps the evidence-semantics claim that matches the outcome: a
// healthy check refutes, a failing/unreachable one corroborates. A skipped
// check claims nothing.
func finalize(r verifyCheckResult, spec verifyCheckSpec, started time.Time) verifyCheckResult {
	r.DurationMS = time.Since(started).Milliseconds()
	r.Ts = time.Now().UTC()
	switch r.Status {
	case verifyStatusPass:
		r.RefutesKinds = append([]string(nil), spec.Refutes...)
	case verifyStatusFail, verifyStatusUnreachable:
		r.CorroboratesKinds = append([]string(nil), spec.Corroborates...)
	}
	return r
}

func (e *verifyEngine) runTCP(ctx context.Context, t verifyTarget, specs []verifyCheckSpec) []verifyCheckResult {
	var out []verifyCheckResult
	for _, spec := range specs {
		started := time.Now()
		r := baseResult(t, spec)
		if strings.TrimSpace(t.Device.Address) == "" {
			r.Status = verifyStatusSkipped
			r.Observed = "device has no address"
			out = append(out, finalize(r, spec, started))
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, e.checkTimeout)
		port := 22
		if t.SSH != nil && t.SSH.Port > 0 {
			port = t.SSH.Port
		}
		err := e.dial.TCPReach(cctx, net.JoinHostPort(hostOnly(t.Device.Address), fmt.Sprintf("%d", port)))
		cancel()
		if err != nil {
			r.Status = verifyStatusUnreachable
			r.Observed = "tcp connect failed: " + sanitizeObserved(err.Error())
		} else {
			r.Status = verifyStatusPass
			r.Observed = fmt.Sprintf("tcp port %d reachable", port)
		}
		out = append(out, finalize(r, spec, started))
	}
	return out
}

func (e *verifyEngine) runSNMP(ctx context.Context, t verifyTarget, specs []verifyCheckSpec) []verifyCheckResult {
	var out []verifyCheckResult
	for _, spec := range specs {
		started := time.Now()
		r := baseResult(t, spec)
		if t.SNMP == nil {
			r.Status = verifyStatusSkipped
			r.Observed = "no SNMP credential bound to device"
			out = append(out, finalize(r, spec, started))
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, e.checkTimeout)
		switch spec.ID {
		case "reach_snmp":
			if err := e.dial.SNMPReach(cctx, *t.SNMP); err != nil {
				r.Status = verifyStatusUnreachable
				r.Observed = "snmp get failed: " + sanitizeObserved(err.Error())
			} else {
				r.Status = verifyStatusPass
				r.Observed = "snmp sysUpTime answered"
			}
		case "snmp_uptime":
			up, err := e.dial.SNMPUptime(cctx, *t.SNMP)
			switch {
			case err != nil:
				r.Status = verifyStatusUnreachable
				r.Observed = "snmp get failed: " + sanitizeObserved(err.Error())
			case up < 900:
				// A device that rebooted inside the last 15 minutes CORROBORATES
				// a restart hypothesis; a long uptime refutes it.
				r.Status = verifyStatusFail
				r.Observed = fmt.Sprintf("sysUpTime %ds — device restarted recently", up)
			default:
				r.Status = verifyStatusPass
				r.Observed = fmt.Sprintf("sysUpTime %ds — no recent restart", up)
			}
		default:
			r.Status = verifyStatusSkipped
			r.Observed = "unknown snmp check"
		}
		cancel()
		out = append(out, finalize(r, spec, started))
	}
	return out
}

func (e *verifyEngine) runSSH(ctx context.Context, t verifyTarget, specs []verifyCheckSpec) []verifyCheckResult {
	started := time.Now()
	if t.SSH == nil {
		return skippedResults(t, specs, "no verification SSH credential configured for tenant")
	}
	// Resolve every check's command from the CLOSED table for this vendor.
	cmds := map[string]string{}
	var runnable []verifyCheckSpec
	var out []verifyCheckResult
	for _, spec := range specs {
		cmd, ok := verifyCommandFor(t.Device.Vendor, spec.ID)
		if !ok {
			r := baseResult(t, spec)
			r.Status = verifyStatusSkipped
			r.Observed = "no read-only command profile for vendor " + sanitizeObserved(t.Device.Vendor)
			out = append(out, finalize(r, spec, started))
			continue
		}
		cmds[spec.ID] = cmd
		runnable = append(runnable, spec)
	}
	if len(cmds) == 0 {
		return out
	}
	// One connection, per-command timeouts inside the runner; the whole group
	// is additionally bounded here (dial + N commands).
	gctx, cancel := context.WithTimeout(ctx, e.checkTimeout*time.Duration(len(cmds)+1))
	defer cancel()
	results := e.dial.SSHRun(gctx, t.Device, *t.SSH, cmds)
	for _, spec := range runnable {
		cstart := time.Now()
		r := baseResult(t, spec)
		r.Command = cmds[spec.ID]
		res, ok := results[spec.ID]
		switch {
		case !ok:
			r.Status = verifyStatusSkipped
			r.Observed = "command did not run (budget or connection loss)"
		case res.Err != nil:
			r.Status = verifyStatusUnreachable
			r.Observed = "ssh exec failed: " + sanitizeObserved(res.Err.Error())
		default:
			r.Status, r.Observed = parseVerifyOutput(spec.ID, res.Output)
		}
		out = append(out, finalize(r, spec, cstart))
	}
	return out
}

// ---- output parsing (conservative: unparseable output is SKIPPED, never a
// fabricated pass/fail) ------------------------------------------------------

var (
	// admin-up/oper-down ("up    down") and error-disabled states — the honest
	// "an interface that should be up is not" indicators across the table's
	// vendor families. Plain oper-down unused ports do NOT fail the check.
	reIfaceHalfUp = regexp.MustCompile(`(?im)\bup\s+down\b`)
	reIfaceErr    = regexp.MustCompile(`(?i)err[- ]?disabled`)
	// BGP neighbor non-established FSM states as they appear in summary tables.
	reBGPDown = regexp.MustCompile(`(?m)\s(Idle|Active|Connect|OpenSent|OpenConfirm)\s*(\(Admin\))?\s*$`)
	reBGPUp   = regexp.MustCompile(`(?i)Estab`)
	reBGPNum  = regexp.MustCompile(`(?m)\s\d+\s*$`) // cisco/arista: established shows prefix count
)

// parseVerifyOutput classifies one allowlisted command's output. Device output
// is untrusted input: bounded upstream, sanitized before storage.
func parseVerifyOutput(checkID, output string) (status, observed string) {
	txt := strings.TrimSpace(output)
	if txt == "" {
		return verifyStatusSkipped, "empty command output"
	}
	lines := strings.Count(txt, "\n") + 1
	switch checkID {
	case "ssh_interfaces":
		if lines < 2 {
			return verifyStatusSkipped, "unrecognized interface listing: " + sanitizeObserved(firstLine(txt))
		}
		var faults []string
		for _, l := range strings.Split(txt, "\n") {
			ll := strings.ToLower(l)
			if strings.Contains(ll, "administratively down") || strings.Contains(ll, "admin down") {
				continue // intended state — not a fault
			}
			if reIfaceHalfUp.MatchString(l) || reIfaceErr.MatchString(l) {
				faults = append(faults, strings.Fields(strings.TrimSpace(l))[0])
			}
		}
		if len(faults) > 0 {
			if len(faults) > 8 {
				faults = faults[:8]
			}
			return verifyStatusFail, "interfaces admin-up but not up: " + sanitizeObserved(strings.Join(faults, ", "))
		}
		return verifyStatusPass, "no interface in an error or half-up state"
	case "ssh_routing":
		if strings.Contains(strings.ToLower(txt), "not active") ||
			strings.Contains(strings.ToLower(txt), "not running") {
			return verifyStatusSkipped, "bgp not running on device — nothing to verify"
		}
		if m := reBGPDown.FindAllString(txt, -1); len(m) > 0 {
			return verifyStatusFail, fmt.Sprintf("%d bgp neighbor(s) not established", len(m))
		}
		if reBGPUp.MatchString(txt) || reBGPNum.MatchString(txt) {
			return verifyStatusPass, "all bgp neighbors established"
		}
		return verifyStatusSkipped, "unrecognized bgp summary output: " + sanitizeObserved(firstLine(txt))
	default:
		return verifyStatusSkipped, "no parser for check " + sanitizeObserved(checkID)
	}
}

// ---- small helpers ----------------------------------------------------------
// (hostOnly is shared from health_score.go)

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// sanitizeObserved makes device/error text safe for logs, storage and the wire
// (§8: no control characters, hard cap). Device output is untrusted input.
func sanitizeObserved(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\t' || r == ' ' || (r > 0x1f && r != 0x7f) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	out := b.String()
	if len(out) > 500 {
		out = out[:500]
	}
	return out
}

// errVerifyDisabled distinguishes "feature off" from transient errors for
// callers that surface run failures.
var errVerifyDisabled = errors.New("active verification is not enabled")
