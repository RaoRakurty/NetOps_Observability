package collectors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// selfhealth_test.go — the collectors must be able to report their own
// blindness (CLAUDE.md §10). Before this: `collector_up` was the literal
// constant 1 at every emitter, so the shipped CollectorDown alert
// (`collector_up == 0`) could never fire; Status.Healthy was re-set true on
// every tick; and LastError was cleared unless EVERY target failed, so a 9-of-10
// blackout read as "healthy, no error".

// captureMetrics points the collectors' metric push at a local server and
// returns the bodies they pushed.
func captureMetrics(t *testing.T) *pushRecorder {
	t.Helper()
	rec := &pushRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, string(b))
		rec.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL)
	t.Setenv("METRICS_URL", "")
	return rec
}

type pushRecorder struct {
	mu     sync.Mutex
	bodies []string
}

func (p *pushRecorder) all() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.bodies, "\n")
}

func testTargets(n int) TargetFunc {
	return func() []Target {
		out := make([]Target, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, Target{ID: fmt.Sprintf("dev%d", i), Address: fmt.Sprintf("192.0.2.%d", i+1)})
		}
		return out
	}
}

// TestCollectorUpReflectsBlackout: every target refusing the probe must emit
// collector_up 0 (so CollectorDown can fire), report Healthy=false, and name
// the failure — the exact three things the literal `1` made impossible.
func TestCollectorUpReflectsBlackout(t *testing.T) {
	rec := captureMetrics(t)
	p := newPoller("t-blackout", time.Minute, 161,
		func(context.Context, string, Target) error { return errors.New("i/o timeout") },
		testTargets(3))
	p.pollOnce(context.Background())

	body := rec.all()
	if !strings.Contains(body, `collector_up{collector="t-blackout"} 0`) {
		t.Errorf("collector_up did not go to 0 during a total blackout; pushed:\n%s", body)
	}
	st := p.Status()
	if st.Healthy {
		t.Error("Status().Healthy is true while no target answered")
	}
	if !strings.Contains(st.LastError, "i/o timeout") || !strings.Contains(st.LastError, "3/3") {
		t.Errorf("LastError = %q, want it to name the scale of the failure and its cause", st.LastError)
	}
}

// TestCollectorUpHealthyWhenTargetsAnswer is the no-false-alarm leg: a working
// collector still reports 1 and a blank error.
func TestCollectorUpHealthyWhenTargetsAnswer(t *testing.T) {
	rec := captureMetrics(t)
	p := newPoller("t-ok", time.Minute, 161,
		func(context.Context, string, Target) error { return nil },
		testTargets(3))
	p.pollOnce(context.Background())

	if body := rec.all(); !strings.Contains(body, `collector_up{collector="t-ok"} 1`) {
		t.Errorf("collector_up not 1 for a fully healthy cycle; pushed:\n%s", body)
	}
	if st := p.Status(); !st.Healthy || st.LastError != "" {
		t.Errorf("healthy cycle reported Healthy=%v LastError=%q", st.Healthy, st.LastError)
	}
}

// TestPartialBlackoutIsNotSilent is the nuance the audit found: LastError was
// only kept when reachable==0, so 9 of 10 devices dead reported healthy AND
// blank. Below degradedReachFraction the cycle is unhealthy and says why.
func TestPartialBlackoutIsNotSilent(t *testing.T) {
	rec := captureMetrics(t)
	var mu sync.Mutex
	answered := 0
	p := newPoller("t-partial", time.Minute, 161,
		func(_ context.Context, _ string, tg Target) error {
			mu.Lock()
			defer mu.Unlock()
			if answered == 0 && tg.ID == "dev0" { // exactly 1 of 10 answers
				answered++
				return nil
			}
			return errors.New("connection refused")
		}, testTargets(10))
	p.pollOnce(context.Background())

	st := p.Status()
	if st.Healthy {
		t.Error("9-of-10 blackout reported Healthy=true")
	}
	if !strings.Contains(st.LastError, "9/10") {
		t.Errorf("LastError = %q, want the partial blackout named", st.LastError)
	}
	if body := rec.all(); !strings.Contains(body, `collector_up{collector="t-partial"} 0`) {
		t.Errorf("collector_up stayed 1 through a 9-of-10 blackout; pushed:\n%s", body)
	}

	// And an equal split stays healthy — the threshold is a threshold, not a
	// hair trigger on any single failure.
	if !cycleHealthy(10, 5) {
		t.Error("cycleHealthy(10,5) = false; half the fleet answering is the documented boundary")
	}
	if cycleHealthy(10, 4) {
		t.Error("cycleHealthy(10,4) = true; below half must be degraded")
	}
	if !cycleHealthy(0, 0) {
		t.Error("a collector with no targets must stay healthy-and-idle")
	}
}

// TestCycleErrorNamesPartialLoss pins the LastError contract directly.
func TestCycleErrorNamesPartialLoss(t *testing.T) {
	if got := cycleError(10, 10, "boom"); got != "" {
		t.Errorf("cycleError with everything answering = %q, want empty", got)
	}
	if got := cycleError(0, 0, ""); got != "" {
		t.Errorf("cycleError with no targets = %q, want empty", got)
	}
	got := cycleError(10, 9, "")
	if !strings.Contains(got, "1/10") {
		t.Errorf("a single failed target must still be reported: %q", got)
	}
	if got := cycleError(4, 1, "timeout"); !strings.Contains(got, "3/4") || !strings.Contains(got, "timeout") {
		t.Errorf("cycleError = %q, want the count and the cause", got)
	}
}

// TestEmitMetricsObservesFailures: emitMetrics swallowed every failure mode and
// never looked at the status code, so VictoriaMetrics could reject 100% of the
// platform's own telemetry indefinitely with no signal at all.
func TestEmitMetricsObservesFailures(t *testing.T) {
	before := func() (uint64, uint64, uint64) {
		ok, failed, dropped, _ := MetricsPushStats()
		return ok, failed, dropped
	}

	// (a) a rejected import is a FAILURE, not a success.
	ok0, failed0, _ := before()
	reject := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unsupported line format", http.StatusBadRequest)
	}))
	defer reject.Close()
	t.Setenv("VICTORIA_URL", reject.URL)
	t.Setenv("METRICS_URL", "")
	emitMetrics(context.Background(), `collector_up{collector="x"} 1 1`)
	ok1, failed1, _ := before()
	if failed1 != failed0+1 {
		t.Errorf("HTTP 400 from the metric store was not counted as a failure (failed %d → %d)", failed0, failed1)
	}
	if ok1 != ok0 {
		t.Errorf("a rejected push was counted as a success (ok %d → %d)", ok0, ok1)
	}
	if _, _, _, lastErr := MetricsPushStats(); !strings.Contains(lastErr, "400") {
		t.Errorf("last push error = %q, want the status code", lastErr)
	}

	// (b) a dead endpoint is a failure too.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	t.Setenv("VICTORIA_URL", deadURL)
	_, failed2, _ := before()
	emitMetrics(context.Background(), "x 1 1")
	if _, failed3, _ := before(); failed3 != failed2+1 {
		t.Errorf("a dead metric store was not counted (failed %d → %d)", failed2, failed3)
	}

	// (c) an unconfigured endpoint drops the samples — counted separately, since
	// it is a configuration fault rather than a transient one.
	t.Setenv("VICTORIA_URL", "")
	t.Setenv("METRICS_URL", "")
	_, _, dropped0 := before()
	emitMetrics(context.Background(), "x 1 1")
	if _, _, dropped1 := before(); dropped1 != dropped0+1 {
		t.Errorf("push with no configured endpoint was not counted as dropped (%d → %d)", dropped0, dropped1)
	}

	// (d) the happy path still counts as success.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()
	t.Setenv("VICTORIA_URL", good.URL)
	okA, _, _ := before()
	emitMetrics(context.Background(), "x 1 1")
	if okB, _, _ := before(); okB != okA+1 {
		t.Errorf("a successful push was not counted (ok %d → %d)", okA, okB)
	}
}

// TestCollectorUpLineRendersBothStates guards the helper every emitter now uses.
func TestCollectorUpLineRendersBothStates(t *testing.T) {
	if got := collectorUpLine("lldp", false, 7); got != `collector_up{collector="lldp"} 0 7` {
		t.Errorf("down line = %q", got)
	}
	if got := collectorUpLine("lldp", true, 7); got != `collector_up{collector="lldp"} 1 7` {
		t.Errorf("up line = %q", got)
	}
}

// TestEnvIntRejectsTrailingGarbage: fmt.Sscanf("%d") accepted "20x" as 20 and
// "1e3" as 1 — silently probing at a rate the operator never configured.
func TestEnvIntRejectsTrailingGarbage(t *testing.T) {
	cases := map[string]int{
		"20":   20,
		"20x":  7, // trailing garbage → default, not 20
		"1e3":  7, // not an integer → default, not 1
		"":     7,
		"  8 ": 8,
		"-4":   7, // non-positive → default
		"0":    7,
	}
	for in, want := range cases {
		t.Setenv("TEST_ENV_INT", in)
		if got := envInt("TEST_ENV_INT", 7); got != want {
			t.Errorf("envInt(%q) = %d, want %d", in, got, want)
		}
	}
}
