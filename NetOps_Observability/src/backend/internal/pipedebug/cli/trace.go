package cli

// trace.go — the `trace` verb.
//
// SHAPE OF A TRACE, and why it is this shape:
//
//	1. open the session directory (one log file per module, §3);
//	2. START THE VECTOR TAPS FIRST. A tap is a LIVE subscription — it sees only
//	   events that cross the transform after it attaches — so attaching after
//	   injection would guarantee an empty ingress and parser stage and report a
//	   healthy pipeline as broken;
//	3. inject ONE marked synthetic record through the API (the API is inside the
//	   compose network and owns the ingress sockets; the CLI is on the host);
//	4. poll the server-side follow while the taps run;
//	5. join both halves into one ordered timeline and write summary.txt.
//
// PRIVACY (§3a). The taps see EVERY tenant's traffic crossing those transforms.
// Only lines carrying THIS trace's marker are written to disk; everything else
// is counted and dropped. A debug session must not become an unfiltered copy of
// the fleet's telemetry sitting in a directory.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/pipedebug"
)

// TraceOptions is the parsed `trace` invocation.
type TraceOptions struct {
	Kind    pipedebug.Kind
	Device  string
	Tenant  string
	TTL     time.Duration
	Passive bool
	Since   time.Duration
	Root    string // data/debug
	Project string // compose project
}

// tapResult is one host-side stage's collected evidence.
type tapResult struct {
	stage     pipedebug.Stage
	service   string
	component string
	matched   []string
	scanned   int
	err       error
}

// RunTrace executes the verb and returns the process exit code.
func RunTrace(ctx context.Context, opts TraceOptions, cl *Client, coll *Collector, out io.Writer) (int, error) {
	now := time.Now().UTC()
	sess, err := pipedebug.NewSession(opts.Root, "trace", "", now, pipedebug.Manifest{
		Kind: opts.Kind, Device: opts.Device, Tenant: opts.Tenant,
		Actor: cl.User(), APIBase: cl.Base(),
		Flags: map[string]string{
			"kind": string(opts.Kind), "device": opts.Device, "tenant": opts.Tenant,
			"ttl": opts.TTL.String(), "passive": fmt.Sprint(opts.Passive),
		},
	})
	if err != nil {
		return 2, err
	}
	fmt.Fprintf(out, "session: %s\n", sess.Dir())

	if opts.Passive {
		// W1 ships ACTIVE tracing only. Saying so and stopping is the honest
		// answer; a "passive" mode that silently degraded into an active
		// injection would put a synthetic record into a customer's pipeline
		// that the operator did not ask for.
		note(sess, sess.EnsureAllModules(func(pipedebug.Stage) string {
			return "passive tracing (--passive) is W2; this build injects a marked synthetic record instead, which --passive explicitly declines"
		}))
		note(sess, sess.Close(time.Now().UTC()))
		return 2, fmt.Errorf("--passive is not implemented in this build (W2); run without it to inject a marked synthetic record")
	}

	// 2. Taps first (see the file comment).
	tapWindow := opts.TTL + 5*time.Second
	tapCtx, cancelTaps := context.WithTimeout(ctx, tapWindow+10*time.Second)
	defer cancelTaps()

	var wg sync.WaitGroup
	results := make([]*tapResult, 0, 3)
	for _, stage := range []pipedebug.Stage{pipedebug.StageIngress, pipedebug.StageParser, pipedebug.StageRouter} {
		service, component, ok := TapComponents(opts.Kind, stage)
		if !ok {
			continue
		}
		res := &tapResult{stage: stage, service: service, component: component}
		results = append(results, res)
		wg.Add(1)
		go func(res *tapResult) {
			defer wg.Done()
			var lines []string
			scanned := 0
			err := coll.VectorTap(tapCtx, res.service, res.component, tapWindow, func(line string) {
				scanned++
				// PRIVACY (§3a): the tap sees EVERY tenant's traffic crossing
				// this transform. Only marked lines are buffered here — and
				// writeTapStage then narrows to THIS trace's marker, which is
				// not yet known when this goroutine starts (the tap must attach
				// BEFORE the record is injected). Everything else is counted
				// and dropped without ever leaving memory.
				if m := markerLine(line); m != "" {
					lines = append(lines, m+"\t"+line)
				}
			})
			res.matched, res.scanned, res.err = lines, scanned, err
		}(res)
	}
	// Give the taps a moment to attach before the record is injected.
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
	}

	// 3. Inject.
	receipt, err := cl.StartTrace(ctx, opts.Kind, opts.Device, opts.Tenant, opts.TTL)
	if err != nil {
		cancelTaps()
		wg.Wait()
		note(sess, sess.EnsureAllModules(func(pipedebug.Stage) string {
			return "the trace never started: " + err.Error()
		}))
		note(sess, sess.Close(time.Now().UTC()))
		return 2, err
	}
	if err := sess.SetMarker(receipt.Marker); err != nil {
		sess.Warn("the API returned a marker this build does not recognise: %v", err)
	}
	fmt.Fprintf(out, "marker : %s (synthetic, tagged %s)\n", receipt.Marker, pipedebug.SyntheticTag)
	if !receipt.Injected {
		fmt.Fprintf(out, "WARNING: injection failed: %s\n", receipt.InjectErr)
	}

	// 4. Poll the server-side follow.
	status := pollTrace(ctx, cl, receipt.Marker, opts.TTL, out)

	// 5. Join.
	cancelTaps()
	wg.Wait()

	entries := make([]pipedebug.Entry, 0, len(pipedebug.Stages))
	for _, res := range results {
		entries = append(entries, writeTapStage(sess, res, receipt.Marker, tapWindow))
	}
	for _, e := range status.Stages {
		writeServerStage(sess, e)
		entries = append(entries, e)
	}
	entries = append(entries, uiStage(sess))

	timeline := pipedebug.BuildTimeline(receipt.Marker, opts.Kind, opts.Device, receipt.Tenant, now, entries)
	if err := sess.WriteTimeline(timeline); err != nil {
		sess.Warn("writing timeline.json failed: %v", err)
	}
	summary := pipedebug.RenderSummary(timeline, sess.Dir())
	if err := sess.WriteSummary(summary); err != nil {
		sess.Warn("writing summary.txt failed: %v", err)
	}
	if err := sess.EnsureAllModules(nil); err != nil {
		sess.Warn("writing the not-observable placeholders failed: %v", err)
	}
	if err := sess.Close(time.Now().UTC()); err != nil {
		return 2, err
	}
	fmt.Fprint(out, "\n"+summary)
	return timeline.ExitCode(), nil
}

// pollTrace polls the server-side follow until it reports done or the TTL runs
// out, printing progress so a human sees the trace advancing.
func pollTrace(ctx context.Context, cl *Client, marker string, ttl time.Duration, out io.Writer) pipedebug.TraceStatus {
	deadline := time.Now().Add(ttl + 10*time.Second)
	var last pipedebug.TraceStatus
	for time.Now().Before(deadline) {
		st, err := cl.TraceStatus(ctx, marker)
		if err == nil {
			last = st
			if st.Done {
				return st
			}
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(2 * time.Second):
		}
		fmt.Fprint(out, ".")
	}
	fmt.Fprintln(out)
	return last
}

// writeTapStage writes one host-side stage's module file and returns its entry.
func writeTapStage(sess *pipedebug.Session, res *tapResult, marker string, window time.Duration) pipedebug.Entry {
	how := fmt.Sprintf("docker exec %s vector tap --outputs-of %s (events filtered to this trace's marker; everything else counted and dropped)", res.service, res.component)
	e := pipedebug.Entry{Stage: res.stage, Module: string(res.stage), Query: how}
	if err := sess.Header(res.stage, string(res.stage), how, window); err != nil {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = "could not open the module log file: " + err.Error()
		return e
	}
	if res.err != nil {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = fmt.Sprintf("the Vector tap on %s/%s failed: %v", res.service, res.component, res.err)
		note(sess, sess.Line(res.stage, "warn", "tap failed", map[string]any{"reason": e.Reason}))
		return e
	}
	// Narrow to THIS trace's marker. The tap goroutine buffered every MARKED
	// line it saw, because the marker is minted by the api and is not yet known
	// when the tap has to attach; a concurrent trace's probe crossing the same
	// transform must not be filed as this one's evidence.
	mine := make([]string, 0, len(res.matched))
	for _, tagged := range res.matched {
		if m, line, ok := strings.Cut(tagged, "\t"); ok && m == marker {
			mine = append(mine, line)
		}
	}
	note(sess, sess.Line(res.stage, "info", "tap finished", map[string]any{
		"scanned": res.scanned, "marked_seen": len(res.matched), "matched": len(mine),
		"note": "only events carrying THIS trace's marker are retained; the rest are counted and dropped without leaving memory",
	}))
	if len(mine) == 0 {
		e.Verdict = pipedebug.VerdictNotSeen
		e.Reason = fmt.Sprintf("the tap saw %d events on %s without this trace's marker", res.scanned, res.component)
		return e
	}
	for _, line := range mine {
		note(sess, sess.Raw(res.stage, "vector-tap:"+res.component, line))
	}
	e.Verdict = pipedebug.VerdictSeen
	e.EvidenceRef = res.stage.LogFile()
	e.FirstSeen = tapTimestamp(mine[0])
	return e
}

// writeServerStage renders one API-supplied stage into its module file.
func writeServerStage(sess *pipedebug.Session, e pipedebug.Entry) {
	how := "GET /api/debug/stage/" + string(e.Stage) + " (the API's own store/bus query)"
	note(sess, sess.Header(e.Stage, string(e.Stage), how, 0))
	note(sess, sess.Line(e.Stage, verdictLevel(e.Verdict), "stage evidence", map[string]any{
		"verdict": string(e.Verdict), "reason": e.Reason,
		"query": e.Query, "evidence_ref": e.EvidenceRef,
	}))
	if e.Detail != nil {
		note(sess, sess.Line(e.Stage, "info", "evidence detail", e.Detail))
	}
}

// uiStage is stage 8. W1 does not implement the UI-query contract, and it says
// so — a stage that quietly reported "seen" because the API answered would be
// claiming a UI check that never ran.
func uiStage(sess *pipedebug.Session) pipedebug.Entry {
	const reason = "the UI-query contract (which route and query the SPA would issue for this record) is W2; the api stage above is the closest proven point"
	note(sess, sess.NotObservable(pipedebug.StageUI, reason))
	return pipedebug.Entry{
		Stage: pipedebug.StageUI, Module: string(pipedebug.StageUI),
		Verdict: pipedebug.VerdictNotObservable, Reason: reason,
		Query: "(none — the UI-query contract is W2)",
	}
}

// note records a session-write failure on the manifest instead of dropping it.
//
// §5 forbids ignored errors, and a blanket `// best-effort:` is the wrong answer
// here: a debug session that could not write its own evidence has to SAY so, or
// the reader is looking at a file that is silently short. The write is still not
// fatal — losing one line must not abort a trace that is mid-flight — so the
// failure lands in manifest.json's warnings, where §10 can see it.
func note(sess *pipedebug.Session, err error) {
	if err != nil {
		sess.Warn("writing a session line failed: %v", err)
	}
}

func verdictLevel(v pipedebug.Verdict) string {
	if v == pipedebug.VerdictSeen {
		return "info"
	}
	return "warn"
}

// markerLine returns the marker a tapped line carries, or "".
func markerLine(line string) string {
	return pipedebug.MarkerIn(line, nil)
}

// tapTimestamp pulls the event timestamp out of a tapped JSON line. An
// undecodable line yields the zero time, which BuildTimeline renders as "no
// latency" rather than a fabricated one.
func tapTimestamp(line string) time.Time {
	var ev map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &ev); err != nil {
		return time.Time{}
	}
	for _, key := range []string{"timestamp", "ts", "@timestamp"} {
		if raw, ok := ev[key].(string); ok {
			for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
				if t, err := time.Parse(layout, raw); err == nil {
					return t.UTC()
				}
			}
		}
	}
	return time.Time{}
}
