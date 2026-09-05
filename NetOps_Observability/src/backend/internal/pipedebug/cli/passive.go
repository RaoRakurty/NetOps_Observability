package cli

// passive.go — the `--passive` half of the `trace` verb.
//
// SEPARATE FILE, SEPARATE CODE PATH, ON PURPOSE. The one outcome a passive run
// must never produce is an injection: an operator who typed `--passive` has
// asked, explicitly, for nothing to be added to a live pipeline. Sharing the
// injection function with a boolean guard would put that promise one inverted
// condition away from being broken, so the two paths share nothing but the
// session writer and the summary renderer.
//
// WHAT IT COLLECTS, and the honest limits of each:
//
//	ingress    `docker logs gnmic` for the window, filtered to the device.
//	           gnmic logs TARGET LIFECYCLE, not per-update lines, so a quiet log
//	           is the normal state of a HEALTHY subscription — the stage reports
//	           what it found and never converts silence into a fault.
//	parser     no tap: gnmic decodes protobuf in-process (TapMissingReason).
//	router     no tap: the gNMI lane never crosses vector-router.
//	victoria   THE evidence — the device's raw `gnmi_*` series in the window.
//	ui         the metrics query the SPA itself issues for those series.
//
// The claim a passive run makes is deliberately weaker than a marked trace's:
// "traffic from this device reached this hop inside the window", not "this
// record did". Every reason it writes says so.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"netops/backend/internal/pipedebug"
)

// runPassive executes a passive follow and returns the process exit code.
func runPassive(ctx context.Context, opts TraceOptions, sess *pipedebug.Session,
	cl *Client, coll *Collector, started time.Time, out io.Writer) (int, error) {

	since := opts.Since
	if since <= 0 {
		since = 10 * time.Minute
	}
	if since > pipedebug.MaxPassiveSince {
		since = pipedebug.MaxPassiveSince
	}

	receipt, err := cl.StartTrace(ctx, TraceRequest{
		Kind: opts.Kind, Device: opts.Device, Tenant: opts.Tenant, TTL: opts.TTL,
		Passive: true, Since: since, Path: opts.Path,
	})
	if err != nil {
		note(sess, sess.EnsureAllModules(func(pipedebug.Stage) string {
			return "the passive follow never started: " + err.Error()
		}))
		note(sess, sess.Close(time.Now().UTC()))
		return 2, err
	}
	if receipt.Injected {
		// Defence in depth against the ONE unacceptable outcome. If a future
		// api ever answered a passive request with an injection, the operator
		// must hear about it here, loudly, rather than read a summary that
		// quietly says `synthetic`.
		sess.Warn("the api reported an INJECTION for a --passive request; this build asked for none. Treat the marker %s as a synthetic record and report this", receipt.Marker)
		fmt.Fprintf(out, "WARNING: the api injected a record for a --passive request (marker %s)\n", receipt.Marker)
	}
	if err := sess.SetMarker(receipt.Marker); err != nil {
		sess.Warn("the API returned a session id this build does not recognise: %v", err)
	}
	fmt.Fprintf(out, "session id: %s (passive — NOTHING was injected)\n", receipt.Marker)
	fmt.Fprintf(out, "following  : device=%s path=%s window=%s\n",
		opts.Device, orNone(opts.Path), since)

	status := pollTrace(ctx, cl, receipt.Marker, opts.TTL, out)

	entries := make([]pipedebug.Entry, 0, len(pipedebug.Stages))
	entries = append(entries, passiveIngress(ctx, sess, coll, opts, since))
	for _, st := range []pipedebug.Stage{pipedebug.StageParser, pipedebug.StageRouter} {
		reason := TapMissingReason(opts.Kind, st)
		note(sess, sess.NotObservable(st, reason))
		entries = append(entries, pipedebug.Entry{
			Stage: st, Module: string(st),
			Verdict: pipedebug.VerdictNotObservable, Reason: reason,
			Query: "(no Vector tap exists for this lane)",
		})
	}
	for _, e := range status.Stages {
		writeServerStage(sess, e)
		entries = append(entries, e)
	}
	entries = append(entries, uiStage(ctx, sess, cl, opts, receipt.Marker, receipt.Tenant))

	timeline := pipedebug.BuildTimeline(receipt.Marker, opts.Kind, opts.Device, receipt.Tenant, started, entries)
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

// passiveIngress reads the collector container's own log for the window.
func passiveIngress(ctx context.Context, sess *pipedebug.Session, coll *Collector,
	opts TraceOptions, since time.Duration) pipedebug.Entry {

	service := GNMIIngressService
	how := fmt.Sprintf("docker logs %s --since %s (lines naming the device; gnmic logs target lifecycle, not per-update lines)", service, since)
	e := pipedebug.Entry{Stage: pipedebug.StageIngress, Module: string(pipedebug.StageIngress), Query: how}
	if err := sess.Header(pipedebug.StageIngress, string(pipedebug.StageIngress), how, since); err != nil {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = "could not open the module log file: " + err.Error()
		return e
	}

	logCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	matched, scanned := 0, 0
	needle := strings.ToLower(opts.Device)
	collectErr := coll.DockerLogs(logCtx, service, since, false, func(line string) {
		scanned++
		if needle != "" && !strings.Contains(strings.ToLower(line), needle) {
			return
		}
		matched++
		note(sess, sess.Raw(pipedebug.StageIngress, "docker-logs:"+service, line))
	})
	if collectErr != nil {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = fmt.Sprintf("could not read %s's container log: %v", service, collectErr)
		note(sess, sess.Line(pipedebug.StageIngress, "warn", "collector log unavailable", map[string]any{"reason": e.Reason}))
		return e
	}
	note(sess, sess.Line(pipedebug.StageIngress, "info", "collector log read", map[string]any{
		"service": service, "scanned": scanned, "matched": matched,
		"note": "gnmic logs target lifecycle (dial, subscribe, retry), NOT per-update lines. A quiet log is the normal state of a healthy subscription, so an unmatched window is reported as not-observable rather than as a fault; victoria.log is this kind's load-bearing evidence",
	}))
	if matched == 0 {
		e.Verdict = pipedebug.VerdictNotObservable
		e.Reason = fmt.Sprintf("%s logged nothing naming %q in the last %s. That is the NORMAL state of a healthy subscription — gnmic logs lifecycle, not updates — so it is not evidence either way; read victoria.log for whether the device's telemetry actually arrived",
			service, opts.Device, since)
		return e
	}
	e.Verdict = pipedebug.VerdictSeen
	e.EvidenceRef = pipedebug.StageIngress.LogFile()
	e.Detail = map[string]any{"matched_lines": matched, "scanned_lines": scanned}
	return e
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(all subscribed paths)"
	}
	return s
}
