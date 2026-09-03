package cli

// logs.go — the `logs` verb: raise chosen modules to debug for a BOUNDED
// window and tail each one's output into its own file.
//
// THE ONE INVARIANT: no module is ever left at debug. Three independent
// mechanisms hold it, because any one of them can fail:
//
//	1. the MODULE's own process arms an auto-revert timer when it is raised
//	   (internal/pipedebug.LevelSwitch in the api, a threading.Timer in
//	   correlation), so the level comes back down even if this CLI is SIGKILLed;
//	2. this function reverts explicitly when the window ends;
//	3. it also reverts on SIGINT/SIGTERM, through the deferred revert below,
//	   which runs on the context cancellation the signal handler triggers.
//
// A module that CANNOT be switched at runtime is reported as such, with the
// reason, and is still TAILED — the container log is available either way, and
// pretending the level changed would be worse than saying it did not.

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"netops/backend/internal/pipedebug"
)

// LogsOptions is the parsed `logs` invocation.
type LogsOptions struct {
	Modules []pipedebug.Module
	For     time.Duration
	Root    string
	Project string
}

// RunLogs executes the verb and returns the process exit code.
func RunLogs(ctx context.Context, opts LogsOptions, cl *Client, coll *Collector, out io.Writer) (int, error) {
	window := pipedebug.ClampWindow(opts.For)
	now := time.Now().UTC()

	names := make([]string, 0, len(opts.Modules))
	for _, m := range opts.Modules {
		names = append(names, string(m))
	}
	sess, err := pipedebug.NewSession(opts.Root, "logs", "", now, pipedebug.Manifest{
		Actor: cl.User(), APIBase: cl.Base(), Modules: names,
		Flags: map[string]string{"for": window.String()},
	})
	if err != nil {
		return 2, err
	}
	fmt.Fprintf(out, "session: %s\nwindow : %s (hard cap %s)\n", sess.Dir(), window, pipedebug.MaxWindow)

	// 1+2. Raise, and register the explicit revert BEFORE any tailing starts, so
	// an early return cannot skip it.
	raised := make([]pipedebug.Module, 0, len(opts.Modules))
	for _, m := range opts.Modules {
		change, err := cl.SetLogLevel(ctx, m, pipedebug.LevelDebug, window)
		stage := pipedebug.ModuleStage(m)
		switch {
		case err != nil:
			fmt.Fprintf(out, "  %-12s level: FAILED (%v)\n", m, err)
			sess.Warn("raising %s to debug failed: %v", m, err)
		case change.Applied:
			raised = append(raised, m)
			fmt.Fprintf(out, "  %-12s level: debug until %s\n", m, change.RevertAt.Format(time.RFC3339))
			note(sess, sess.Header(stage, string(m), "docker logs (level raised to debug for this window)", window))
		default:
			fmt.Fprintf(out, "  %-12s level: unchanged — %s\n", m, change.Reason)
			note(sess, sess.Header(stage, string(m), "docker logs (level NOT raised: "+change.Reason+")", window))
		}
	}
	defer func() {
		// Runs on the normal path, on an error return AND on the context
		// cancellation a SIGINT triggers.
		revertCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		for _, m := range raised {
			if _, err := cl.SetLogLevel(revertCtx, m, pipedebug.LevelInfo, 0); err != nil {
				// Loud, never swallowed: the module's own timer is the backstop,
				// and the operator must know they are relying on it.
				fmt.Fprintf(out, "WARNING: reverting %s to info failed (%v) — the module's own auto-revert timer is now the only thing bringing it down\n", m, err)
			}
		}
	}()

	// 3. Tail each module for the window.
	tailCtx, cancelTail := context.WithTimeout(ctx, window)
	defer cancelTail()
	var wg sync.WaitGroup
	for _, m := range opts.Modules {
		service, ok := pipedebug.ComposeService(m)
		if !ok {
			continue
		}
		stage := pipedebug.ModuleStage(m)
		wg.Add(1)
		go func(m pipedebug.Module, service string, stage pipedebug.Stage) {
			defer wg.Done()
			n := 0
			err := coll.DockerLogs(tailCtx, service, 30*time.Second, true, func(line string) {
				n++
				note(sess, sess.Raw(stage, "docker-logs:"+service, line))
			})
			if err != nil {
				sess.Warn("tailing %s failed: %v", m, err)
				note(sess, sess.Line(stage, "warn", "tail ended early", map[string]any{"error": err.Error(), "lines": n}))
				return
			}
			note(sess, sess.Line(stage, "info", "tail finished", map[string]any{"lines": n}))
		}(m, service, stage)
	}
	wg.Wait()

	if err := sess.EnsureAllModules(func(st pipedebug.Stage) string {
		return "this module was not selected for this `logs` session (--modules)"
	}); err != nil {
		sess.Warn("writing the not-selected placeholders failed: %v", err)
	}
	if err := sess.WriteSummary(fmt.Sprintf(
		"CORRELIX PIPELINE DEBUG — LOGS SESSION\n"+
			"======================================\n"+
			"modules : %v\nwindow  : %s\nsession : %s\n\n"+
			"Every module raised to debug has been reverted; each module that could not be\n"+
			"raised says so in the first line of its own log file.\n",
		names, window, sess.Dir())); err != nil {
		sess.Warn("writing summary.txt failed: %v", err)
	}
	if err := sess.Close(time.Now().UTC()); err != nil {
		return 2, err
	}
	fmt.Fprintf(out, "\nwrote %s\n", sess.Dir())
	return 0, nil
}
