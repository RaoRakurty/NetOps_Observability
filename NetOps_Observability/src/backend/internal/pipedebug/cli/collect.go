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
type Collector struct {
	run     Runner
	project string
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
	if name, ok := c.resolved[service]; ok {
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
		if name := strings.TrimSpace(line); name != "" {
			c.resolved[service] = name
			return name, nil
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
