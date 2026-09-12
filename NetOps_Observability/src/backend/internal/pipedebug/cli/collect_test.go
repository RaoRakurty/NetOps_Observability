// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/pipedebug"
)

// fakeRunner records the ARGV it was handed. The argv, not a command string, is
// the whole point: §8 forbids unsafe shell execution, so these tests assert
// there is no shell and no interpolated command line anywhere.
type fakeRunner struct {
	calls  [][]string
	stdout string
	err    error
	lines  []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string) (string, string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.stdout, "", f.err
}

func (f *fakeRunner) Stream(_ context.Context, name string, args []string, onLine func(string)) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	for _, l := range f.lines {
		onLine(l)
	}
	return f.err
}

func TestContainerIsResolvedByComposeLabelNeverByGuessingAName(t *testing.T) {
	r := &fakeRunner{stdout: "netops-api-1\n"}
	c := NewCollector(r, "netops")
	got, err := c.ContainerFor(context.Background(), "api")
	if err != nil || got != "netops-api-1" {
		t.Fatalf("ContainerFor = %q, %v", got, err)
	}
	argv := r.calls[0]
	if argv[0] != "docker" || argv[1] != "ps" {
		t.Fatalf("unexpected command: %v", argv)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "label=com.docker.compose.project=netops") ||
		!strings.Contains(joined, "label=com.docker.compose.service=api") {
		t.Errorf("the container was not resolved by compose label: %v", argv)
	}
	// Second call is cached — a debug session must not fork docker per line.
	if _, err := c.ContainerFor(context.Background(), "api"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Errorf("ContainerFor did not cache: %d calls", len(r.calls))
	}
}

func TestNoRunningContainerIsAnErrorNotAnEmptyResult(t *testing.T) {
	c := NewCollector(&fakeRunner{stdout: "\n"}, "netops")
	if _, err := c.ContainerFor(context.Background(), "api"); err == nil {
		t.Error("a service with no running container returned an empty name instead of an error")
	}
}

func TestDockerFailureIsReportedNotSwallowed(t *testing.T) {
	c := NewCollector(&fakeRunner{err: errors.New("permission denied")}, "netops")
	_, err := c.ContainerFor(context.Background(), "api")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("a docker failure was swallowed: %v", err)
	}
}

// The closed grammars are what make the argv construction safe.
func TestServiceAndComponentNamesAreClosedGrammars(t *testing.T) {
	c := NewCollector(&fakeRunner{stdout: "x\n"}, "netops")
	for _, bad := range []string{"api; rm -rf /", "../api", "API", "a b", "", strings.Repeat("a", 100)} {
		if _, err := c.ContainerFor(context.Background(), bad); err == nil {
			t.Errorf("ContainerFor accepted %q", bad)
		}
	}
	for _, bad := range []string{"syslog_in; x", "../x", "a b", ""} {
		if err := c.VectorTap(context.Background(), "vector-aggregator", bad, time.Second, func(string) {}); err == nil {
			t.Errorf("VectorTap accepted component %q", bad)
		}
	}
}

func TestVectorTapArgvIsBoundedAndNamesTheComponent(t *testing.T) {
	r := &fakeRunner{stdout: "netops-vector-aggregator-1\n"}
	c := NewCollector(r, "netops")
	if err := c.VectorTap(context.Background(), "vector-aggregator", "syslog_normalized", 20*time.Second, func(string) {}); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(r.calls[1], " ")
	for _, want := range []string{
		"docker exec netops-vector-aggregator-1 vector tap",
		"--outputs-of syslog_normalized",
		"--duration-ms 20000",
		"--format json",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("tap argv missing %q: %s", want, argv)
		}
	}
}

func TestVectorTapWindowIsClamped(t *testing.T) {
	r := &fakeRunner{stdout: "c\n"}
	c := NewCollector(r, "netops")
	if err := c.VectorTap(context.Background(), "vector-aggregator", "syslog_in", 99*time.Hour, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(r.calls[1], " "), "356400000") {
		t.Error("an unbounded tap duration reached the argv")
	}
}

func TestDockerLogsArgvIsTimestampedAndTimeBounded(t *testing.T) {
	r := &fakeRunner{stdout: "netops-api-1\n", lines: []string{"a", "b"}}
	c := NewCollector(r, "netops")
	var got []string
	if err := c.DockerLogs(context.Background(), "api", 90*time.Second, true, func(l string) { got = append(got, l) }); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(r.calls[1], " ")
	for _, want := range []string{"docker logs", "--timestamps", "--since 90s", "--follow", "netops-api-1"} {
		if !strings.Contains(argv, want) {
			t.Errorf("logs argv missing %q: %s", want, argv)
		}
	}
	if len(got) != 2 {
		t.Errorf("lines not delivered: %v", got)
	}
}

// The router stage must tap the REMAP, not the `route` transform: a Vector
// route exposes only its named outputs to the tap, so tapping it would show an
// empty router stage for every healthy record.
func TestRouterStageTapsTheRemapNotTheRouteTransform(t *testing.T) {
	svc, comp, ok := TapComponents(pipedebug.KindSyslog, pipedebug.StageRouter)
	if !ok || svc != "vector-router" || comp != "syslog_tagged" {
		t.Errorf("router tap = %s/%s (ok=%v)", svc, comp, ok)
	}
	if strings.HasSuffix(comp, "_store_route") {
		t.Error("the router stage taps a `route` transform, whose unmatched output is invisible to the tap")
	}
}

// Every (kind, host-stage) pair must resolve to EITHER a legal tap OR a stated
// reason there is none. The middle case — no tap and no reason — is the one
// that produces a silently missing stage row, which reads to an operator as a
// hop that was fine.
func TestEveryHostStageResolvesToATapOrAStatedReason(t *testing.T) {
	for _, kind := range pipedebug.Kinds {
		for _, stage := range []pipedebug.Stage{pipedebug.StageIngress, pipedebug.StageParser, pipedebug.StageRouter} {
			svc, comp, ok := TapComponents(kind, stage)
			if ok {
				if svc == "" || comp == "" {
					t.Errorf("%s/%s claimed a tap with an empty service or component", kind, stage)
				}
				if !validComponent(comp) || !validComposeService(svc) {
					t.Errorf("%s/%s produced a value its own grammar rejects: %s/%s", kind, stage, svc, comp)
				}
				continue
			}
			reason := TapMissingReason(kind, stage)
			if len(reason) < 40 {
				t.Errorf("%s/%s has no tap and no usable reason (got %q)", kind, stage, reason)
			}
		}
	}
	// The flow lane's Vector work is one ROUTER stage, deliberately: mapping it
	// onto the parser slot would put stage 2 later in wall-clock time than
	// stage 3 and render a negative latency on every healthy flow trace.
	svc, comp, ok := TapComponents(pipedebug.KindFlow, pipedebug.StageRouter)
	if !ok || svc != "vector-router" || comp != "flows_decoded" {
		t.Errorf("flow router tap = %s/%s (ok=%v), want vector-router/flows_decoded", svc, comp, ok)
	}
	if _, _, ok := TapComponents(pipedebug.KindFlow, pipedebug.StageParser); ok {
		t.Error("the flow lane claims a Vector parser tap — goflow2 is the flow parser and is not a Vector component")
	}
	if _, _, ok := TapComponents(pipedebug.KindGNMI, pipedebug.StageRouter); ok {
		t.Error("the gNMI lane claims a vector-router tap — it never crosses vector-router")
	}
	// Server-side stages must NOT claim a tap.
	if _, _, ok := TapComponents(pipedebug.KindSyslog, pipedebug.StageOpenSearch); ok {
		t.Error("a server-side stage claims a host-side tap")
	}
}
