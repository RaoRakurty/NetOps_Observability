package cli

// collect.go — the host-side evidence collectors: container logs and the Vector
// event tap.
//
// §8 (NO UNSAFE SHELL EXECUTION). Every external command is executed as an
// ARGV LIST through os/exec — never a shell string, never an interpolated
// command line. The only caller-derived values that reach an argv are:
//
//	* a compose SERVICE name, which comes from pipedebug.ComposeService's fixed
//	  table (an operator string is validated into a Module first, and the table
//	  maps that closed set to literals);
//	* a Vector COMPONENT id, checked against validComponent below;
//	* durations and counts, which are rendered from clamped integers.
//
// A container NAME is never taken from the operator at all: it is resolved by
// asking docker for the container carrying the compose service label.
//
// §9 (ALL IO BOUNDED). Every command runs under a context deadline and its
// output is read through a byte-capped, line-bounded scanner, so a container
// spraying megabytes a second cannot fill the operator's disk through us.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/pipedebug"
)

const (
	// maxCollectedLines bounds one collector's contribution to one module file.
	maxCollectedLines = 5000
	// maxCollectedLine bounds one line before it is written.
	maxCollectedLine = 16 << 10
	// dockerCmd is the only external binary this package runs.
	dockerCmd = "docker"
)

// Runner executes a bounded external command and returns its stdout stream.
// Injected so every collector is testable without docker.
type Runner interface {
	Run(ctx context.Context, name string, args []string) (stdout string, stderr string, err error)
	Stream(ctx context.Context, name string, args []string, onLine func(string)) error
}

// ExecRunner is the production Runner over os/exec.
type ExecRunner struct{}

// Run executes name with args and returns the captured output. The context
// carries the deadline; no shell is involved.
func (ExecRunner) Run(ctx context.Context, name string, args []string) (string, string, error) {
	var out, errBuf strings.Builder
	// #nosec G204 -- name is the fixed literal dockerCmd and every element of
	// args is either a literal or a value validated against a closed grammar
	// (see the package comment). No shell interpretation occurs: exec.Command
	// passes argv directly.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return out.String(), errBuf.String(), err
}

// Stream executes name with args and calls onLine for each stdout line, under
// the context's deadline.
func (ExecRunner) Stream(ctx context.Context, name string, args []string, onLine func(string)) error {
	// #nosec G204 -- see Run.
	cmd := exec.CommandContext(ctx, name, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64<<10), maxCollectedLine)
	n := 0
	for scanner.Scan() {
		onLine(scanner.Text())
		n++
		if n >= maxCollectedLines {
			break
		}
	}
	// The scanner's own error is reported, but a killed-by-deadline process is
	// the NORMAL end of a bounded tail, not a failure.
	scanErr := scanner.Err()
	_ = cmd.Wait() // best-effort: the process is killed by the context deadline on every bounded tail, so a non-zero status here is expected and carries no information
	if scanErr != nil && !errors.Is(scanErr, context.DeadlineExceeded) {
		return scanErr
	}
	return nil
}

// Collector reads container logs and Vector taps for one compose project.
//
// CONCURRENCY. `trace` attaches every host-side tap in PARALLEL — that is not
// an optimisation, it is required: a tap is a live subscription, so all of them
// must be attached before the record is injected. Two of those taps resolve the
// SAME compose service (ingress and parser both live on vector-aggregator), so
// the resolution cache is written from several goroutines at once. It was an
// unsynchronised map until 2026-09-04, which is a `fatal error: concurrent map
// writes` — a crash of the debugger, mid-incident, at the exact moment someone
// is using it. The mutex is the fix; the cache is deliberately kept (docker ps
// per tap would triple the attach latency the taps are racing against).
type Collector struct {
	run     Runner
	project string
	// mu guards resolved.
	mu sync.Mutex
	// resolved caches service → container name for the run.
	resolved map[string]string
}

// NewCollector builds a collector for a compose project (default "netops").
func NewCollector(run Runner, project string) *Collector {
	if strings.TrimSpace(project) == "" {
		project = "netops"
	}
	return &Collector{run: run, project: project, resolved: map[string]string{}}
}

// ContainerFor resolves the running container name for a compose service by
// LABEL, never by guessing a name pattern. A `--scale`d service resolves to its
// first replica, and the caller is told which.
func (c *Collector) ContainerFor(ctx context.Context, service string) (string, error) {
	c.mu.Lock()
	name, cached := c.resolved[service]
	c.mu.Unlock()
	if cached {
		return name, nil
	}
	if !validComposeService(service) {
		return "", fmt.Errorf("refusing to resolve service %q: not a legal compose service name", service)
	}
	args := []string{
		"ps", "--format", "{{.Names}}",
		"--filter", "label=com.docker.compose.project=" + c.project,
		"--filter", "label=com.docker.compose.service=" + service,
	}
	out, errOut, err := c.run.Run(ctx, dockerCmd, args)
	if err != nil {
		return "", fmt.Errorf("docker ps for service %s: %w (%s)", service, err, strings.TrimSpace(errOut))
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if found := strings.TrimSpace(line); found != "" {
			c.mu.Lock()
			c.resolved[service] = found
			c.mu.Unlock()
			return found, nil
		}
	}
	return "", fmt.Errorf("no running container for compose service %q in project %q", service, c.project)
}

// validComposeService is the closed grammar for a name that reaches a docker
// filter argument.
func validComposeService(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// validComponent is the closed grammar for a Vector component id.
func validComponent(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// DockerLogs streams a container's recent logs into onLine, bounded by the
// context deadline. `since` is rendered from a duration, never taken as text.
func (c *Collector) DockerLogs(ctx context.Context, service string, since time.Duration, follow bool, onLine func(string)) error {
	name, err := c.ContainerFor(ctx, service)
	if err != nil {
		return err
	}
	if since <= 0 {
		since = 5 * time.Minute
	}
	args := []string{"logs", "--timestamps", "--since", strconv.Itoa(int(since.Seconds())) + "s"}
	if follow {
		args = append(args, "--follow")
	}
	args = append(args, name)
	return c.run.Stream(ctx, dockerCmd, args, onLine)
}

// VectorTap streams the Vector event tap for one component into onLine.
//
// `vector tap` is the RIGHT instrument here, and is why Vector's log level is
// left alone: it streams the actual EVENTS crossing a transform, which is
// strictly more evidence than a debug log line would be, and it needs no
// restart and no config change to obtain.
func (c *Collector) VectorTap(ctx context.Context, service, component string, window time.Duration, onLine func(string)) error {
	if !validComponent(component) {
		return fmt.Errorf("refusing to tap component %q: not a legal Vector component id", component)
	}
	name, err := c.ContainerFor(ctx, service)
	if err != nil {
		return err
	}
	ms := int(window.Milliseconds())
	if ms <= 0 || ms > int(pipedebug.MaxWindow.Milliseconds()) {
		ms = int(pipedebug.DefaultTraceTTL.Milliseconds())
	}
	args := []string{
		"exec", name, "vector", "tap",
		"--outputs-of", component,
		"--duration-ms", strconv.Itoa(ms),
		"--format", "json", "--quiet", "--limit", "200",
	}
	return c.run.Stream(ctx, dockerCmd, args, onLine)
}

// TapComponents names the Vector components that carry a kind at each host-side
// stage. The table is here, in one place, so the CLI never interpolates a
// component id from anything an operator typed.
//
// THE FLOW LANE HAS A DIFFERENT SHAPE, and the table reflects the shape rather
// than forcing the lane into the syslog one. goflow2 — not Vector — is the flow
// ingress AND the flow parser: it decodes the binary NetFlow/IPFIX/sFlow into
// JSON in its own process and produces straight to Kafka. So stages 1 and 2
// have no tap at all (TapMissingReason says so, and the timeline carries
// not_observable with that reason rather than an absent row), the bus is the
// first observable hop, and the Vector-side work — the tenant re-key and the
// VRL normalisation — is one router stage tapped at `flows_decoded`. Mapping
// flows_decoded onto the PARSER slot instead would have put stage 2 later in
// wall-clock time than stage 3, which BuildTimeline would render as a negative
// latency: a cosmetic-looking bug that would make every flow trace read wrong.
func TapComponents(kind pipedebug.Kind, stage pipedebug.Stage) (service, component string, ok bool) {
	switch stage {
	case pipedebug.StageIngress:
		switch kind {
		case pipedebug.KindSyslog:
			return "vector-aggregator", "syslog_in", true
		case pipedebug.KindTrap:
			return "vector-aggregator", "trap_in", true
		}
	case pipedebug.StageParser:
		switch kind {
		case pipedebug.KindSyslog:
			return "vector-aggregator", "syslog_normalized", true
		case pipedebug.KindTrap:
			return "vector-aggregator", "snmptrap_normalized", true
		}
	case pipedebug.StageRouter:
		if kind == pipedebug.KindFlow {
			// The remap that consumes netops.flows and does the lane's decode +
			// tenant work. A record only reaches it if flows_rekey already
			// republished it, so this one tap covers the whole router path.
			return "vector-router", "flows_decoded", true
		}
		// The `*_tagged` remap, not the `*_store_route` route transform: a
		// Vector `route` exposes only its NAMED outputs to the tap (here just
		// `quarantine`), so tapping it would show an empty router stage for
		// every healthy record. The remap is where the router does its own work
		// — the per-tenant index segment and timestamp normalisation — so it is
		// also the more informative place to look.
		switch kind {
		case pipedebug.KindSyslog:
			return "vector-router", "syslog_tagged", true
		case pipedebug.KindTrap:
			return "vector-router", "snmptrap_tagged", true
		}
	}
	return "", "", false
}

// TapMissingReason explains why a host-side stage has no Vector tap for a kind.
//
// It exists so that "no tap" produces an honest not_observable row instead of a
// silently absent stage. A stage that simply vanishes from the timeline is the
// same defect as an empty log file: the reader concludes nothing happened
// there, when in fact nothing was looked at.
func TapMissingReason(kind pipedebug.Kind, stage pipedebug.Stage) string {
	switch kind {
	case pipedebug.KindFlow:
		switch stage {
		case pipedebug.StageIngress:
			return "goflow2 is the flow ingress and is not a Vector component, so there is no tap to attach; with the kafka:// transport it writes no per-record log line either. The flow lane's first OBSERVABLE hop is the bus (kafka.log)"
		case pipedebug.StageParser:
			return "the flow PARSER is goflow2 itself — it decodes the binary NetFlow/IPFIX/sFlow into JSON in its own process and exposes no per-record parse trace. The Vector-side normalisation that follows runs in vector-router and is reported, with its `cx_parse_trace` decision line, at the ROUTER stage (router.log)"
		}
	case pipedebug.KindGNMI:
		switch stage {
		case pipedebug.StageParser:
			return "gnmic decodes gNMI protobuf in its own process and emits no per-update parse line; the gNMI lane crosses no Vector transform, so there is nothing to tap"
		case pipedebug.StageRouter:
			return "the gNMI lane does not cross vector-router: gnmic writes straight to VictoriaMetrics over prometheus_write (victoria.log is this kind's evidence)"
		}
	}
	return fmt.Sprintf("no Vector component carries a %s record at the %s stage in this deployment", kind, stage)
}

// GNMIIngressService is the container whose logs stand in for the gNMI ingress
// stage. gnmic logs TARGET LIFECYCLE (dial, subscribe, retry), not per-update
// lines, so a match proves the collector is talking about this device inside
// the window — which is the honest limit of what this stage can claim, and the
// reason victoria.log rather than ingress.log is a passive gNMI trace's
// load-bearing evidence.
const GNMIIngressService = "gnmic"
