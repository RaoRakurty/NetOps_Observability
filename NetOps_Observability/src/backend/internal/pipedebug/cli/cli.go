package cli

// cli.go — argument parsing, signal handling and verb dispatch.
//
// Run() returns an exit code rather than calling os.Exit, so every path is
// testable and cmd/correlix-debug stays a two-line `func main` (§2).

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"netops/backend/internal/pipedebug"
)

// Usage is printed for -h and for an unknown verb.
const Usage = `correlix-debug — trace one record through the Correlix pipeline

USAGE
  correlix-debug trace  --kind syslog|trap|flow --device <id> [--tenant <id>] [--ttl 60s]
  correlix-debug trace  --kind gnmi --passive --device <id> [--since 10m] [--path <gnmi path>]
  correlix-debug logs   --modules api,correlation,vector [--for 5m]
  correlix-debug bundle [--session <dir> | --last N]

COMMON FLAGS
  --root <dir>     repository/deployment root (default: the working directory)
  --api  <url>     API base URL (default: http://localhost:<BASE_PORT from .env>)
  --token <jwt>    platform-admin token (default: log in with the admin account
                   from deployment/docker/.env)
  --project <name> docker compose project (default: netops)

WHAT IT DOES
  trace   injects ONE marked synthetic record into the STACK's own ingress —
          never into a device — and follows the marker hop by hop, writing one
          log file per module into data/debug/<UTC>-trace-<id>/ (the marker is
          recorded in summary.txt, timeline.json and manifest.json).
          Exit 0 only if the record reached the UI-facing API.
          --kind gnmi is PASSIVE-ONLY: a gNMI update originates on the device
          and this tool never writes to a device, so it follows REAL traffic by
          device and window and injects nothing.
  logs    raises the chosen modules to debug for a BOUNDED window (hard cap
          30m) and tails each into its own file. Every raise auto-reverts, in
          the module's own process, even if this command is killed.
  bundle  packages a session with SHA256SUMS for support (already redacted).

SAFETY
  Injected records are tagged cx_synthetic=true and are excluded from the
  customer-facing log search. No device is ever written to.
`

// Run parses args and executes a verb. It returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, Usage)
		return 2
	}
	verb := args[0]
	rest := args[1:]

	// SIGINT/SIGTERM cancel the context, which is what makes `logs` revert every
	// raised module on Ctrl-C (see logs.go).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch verb {
	case "trace":
		return RunTraceCLI(ctx, rest, stdout, stderr)
	case "logs":
		return RunLogsCLI(ctx, rest, stdout, stderr)
	case "bundle":
		return RunBundleCLI(ctx, rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, Usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown verb %q\n\n%s", verb, Usage)
		return 2
	}
}

// commonFlags are the flags every authenticated verb shares.
type commonFlags struct {
	root    *string
	api     *string
	token   *string
	project *string
}

func bindCommon(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		root:    fs.String("root", ".", "repository/deployment root"),
		api:     fs.String("api", "", "API base URL (default: from BASE_PORT in deployment/docker/.env)"),
		token:   fs.String("token", "", "platform-admin bearer token (default: log in with the admin account from .env)"),
		project: fs.String("project", "netops", "docker compose project name"),
	}
}

// DebugRoot is data/debug under a deployment root.
func DebugRoot(root string) string { return filepath.Join(root, "data", "debug") }

// connect builds the authenticated client for a verb.
func connect(ctx context.Context, common commonFlags) (*Client, *Collector, error) {
	creds := LoadEnvCredentials(DefaultEnvPath(*common.root))
	if *common.api != "" {
		creds.Base = *common.api
	}
	if creds.Base == "" {
		creds.Base = "http://localhost:8000"
	}
	if *common.token != "" {
		creds.Token = *common.token
	}
	if env := os.Getenv("CORRELIX_TOKEN"); creds.Token == "" && env != "" {
		creds.Token = env
	}
	cl, err := NewClient(ctx, creds, 60*time.Second)
	if err != nil {
		return nil, nil, err
	}
	return cl, NewCollector(ExecRunner{}, *common.project), nil
}

// RunBundleCLI parses and runs the bundle verb.
func RunBundleCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", ".", "repository/deployment root")
	session := fs.String("session", "", "one session directory to bundle")
	last := fs.Int("last", 1, "bundle the last N sessions")
	outDir := fs.String("out", "", "output directory (default: the debug root)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	code, err := RunBundle(ctx, BundleOptions{
		Session: *session, Last: *last, Root: DebugRoot(*root), Out: *outDir,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", err)
	}
	return code
}

// RunTraceCLI parses and runs the trace verb.
func RunTraceCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommon(fs)
	kind := fs.String("kind", "syslog", "record kind: syslog|trap|flow|gnmi")
	device := fs.String("device", "", "device the record claims to come from, or (with --passive) the device to follow (required)")
	tenant := fs.String("tenant", "", "tenant to trace within (narrows a platform admin's scope)")
	ttl := fs.Duration("ttl", pipedebug.DefaultTraceTTL, "how long to follow the marker")
	passive := fs.Bool("passive", false, "follow REAL traffic and inject nothing (required for --kind gnmi)")
	since := fs.Duration("since", 10*time.Minute, "how far back --passive looks (cap 24h)")
	path := fs.String("path", "", "gNMI path family to narrow a --passive follow to")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	k, err := pipedebug.ParseKind(*kind)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", err)
		return 2
	}
	// The mode is settled BEFORE anything is dialled, so an impossible
	// combination costs an operator a message and not a live injection they did
	// not want. The api enforces the same two rules independently.
	if pipedebug.PassiveOnly(k) && !*passive {
		fmt.Fprintf(stderr, "correlix-debug: --kind %s is passive-only (a %s update originates on the device, and this tool never writes to a device). Re-run with --passive --device <id> [--since 10m]\n", k, k)
		return 2
	}
	if *passive && !pipedebug.PassiveOnly(k) {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", pipedebug.PassiveRefusal(k))
		return 2
	}
	if err := pipedebug.ValidDeviceKey(*device); err != nil {
		fmt.Fprintf(stderr, "correlix-debug: --device: %v\n", err)
		return 2
	}
	if _, err := pipedebug.NormalizePathFilter(*path); err != nil {
		fmt.Fprintf(stderr, "correlix-debug: --path: %v\n", err)
		return 2
	}
	cl, coll, err := connect(ctx, common)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", err)
		return 2
	}
	code, err := RunTrace(ctx, TraceOptions{
		Kind: k, Device: *device, Tenant: *tenant,
		TTL: pipedebug.ClampTraceTTL(*ttl), Passive: *passive, Since: *since, Path: *path,
		Root: DebugRoot(*common.root), Project: *common.project,
	}, cl, coll, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", err)
	}
	return code
}

// RunLogsCLI parses and runs the logs verb.
func RunLogsCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := bindCommon(fs)
	modules := fs.String("modules", "api,correlation,vector", "modules to raise and tail")
	window := fs.Duration("for", pipedebug.DefaultWindow, "window (hard cap 30m)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	mods, err := pipedebug.ParseModules(*modules)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: --modules: %v\n", err)
		return 2
	}
	cl, coll, err := connect(ctx, common)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", err)
		return 2
	}
	code, err := RunLogs(ctx, LogsOptions{
		Modules: mods, For: *window,
		Root: DebugRoot(*common.root), Project: *common.project,
	}, cl, coll, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "correlix-debug: %v\n", err)
	}
	return code
}
