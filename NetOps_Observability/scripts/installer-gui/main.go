// correlix-setup — the graphical installer for the Correlix appliance bundle.
//
// A single static binary (Go stdlib only, per the repo dependency rules) that
// ships inside the customer bundle and serves an embedded one-page setup
// wizard: system check → prepare host → install → live progress → credentials.
// It is a thin, safe orchestrator over the same battle-tested shell entry
// points the CLI path uses (prepare-host.sh / install-correlix.sh) — the GUI
// never re-implements install logic, so CLI and GUI can't drift apart.
//
// Zero-trust posture (§3/§8/§15 + design gui-installer-2026-08.md §5):
//   - TLS always: a self-signed ECDSA P-256 certificate is minted in memory at
//     launch; its SHA-256 fingerprint is printed under the URLs so the operator
//     can pin it in the browser (H1).
//   - Binds 127.0.0.1 by default; --remote opts into 0.0.0.0 for headless
//     appliances set up from a laptop on the LAN (H1).
//   - Every request must carry a one-time session token (printed at launch);
//     the token is exchanged exactly once for an HttpOnly Secure session
//     cookie. A second token exchange while a session lives is refused (H2),
//     and sessions die after 15 idle minutes (sliding).
//   - The API executes a FIXED set of commands (I1: no request data ever
//     reaches a shell line — argv is constant; the only user input, the sudo
//     password, is written to sudo's stdin and the buffer zeroed after use).
//   - Log streams are rendered client-side with textContent (no innerHTML).
//   - The server stops itself 60 s after the browser acknowledges the success
//     screen (POST /api/done), or 15 min after an install result if never
//     acknowledged (H2 auto-stop).
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed ui.html
var uiFS embed.FS

// Phase is the wizard's server-side state machine position.
type Phase string

const (
	PhaseIdle       Phase = "idle"       // nothing run yet
	PhaseChecking   Phase = "checking"   // prepare-host.sh --check running
	PhaseNeedsPrep  Phase = "needs-prep" // check found FIX items
	PhaseReady      Phase = "ready"      // check passed — host is ready
	PhasePreparing  Phase = "preparing"  // sudo prepare-host.sh running
	PhaseInstalling Phase = "installing" // install-correlix.sh running
	PhaseInstalled  Phase = "installed"  // install finished OK
	PhaseError      Phase = "error"      // last run failed (see log)
)

const (
	idleTimeout      = 15 * time.Minute // H2: sliding session idle timeout
	ackShutdownDelay = 60 * time.Second // H2: auto-stop after POST /api/done
	resultShutdown   = 15 * time.Minute // H2: auto-stop after an unacked result
	logRingSize      = 5000             // bounded buffers (§9)
	watchdogTimeout  = 2 * time.Minute  // §9: bound the synchronous watchdog op
)

// CheckItem is one PASS/FIX line from prepare-host.sh --check.
type CheckItem struct {
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

// Stage is one engine progress stage from a `@CX@ {"kind":"stage",…}` marker.
type Stage struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Status  string `json:"status"` // start|ok|fail
	Message string `json:"message,omitempty"`
}

// Result is the terminal `@CX@ {"kind":"result",…}` event (password excluded
// by contract — the Go side reads it from .env after a successful install).
type Result struct {
	Status    string // ok|fail — internal, not serialized into /api/state
	URL       string
	AdminUser string
}

// state is the single wizard session. One installer, one host, one state.
type state struct {
	mu         sync.Mutex
	phase      Phase
	checks     []CheckItem
	checkOut   []string // raw --check output for the support bundle
	err        string
	uiURL      string
	adminUser  string
	adminPW    string
	stages     []Stage
	result     *Result
	installKey string // Idempotency-Key of the accepted install job (H5)
	factsJSON  []byte
	factsHash  string

	watchdogBusy      bool // single-flight guard for the synchronous watchdog op
	watchdogInstalled bool // POST /api/watchdog succeeded (surfaced in /api/state)

	logMu   sync.Mutex
	logBuf  []string // raw sanitized log lines (support bundle)
	events  []string // JSON event history replayed to new SSE clients
	waiters []chan string
}

// runner abstracts command execution so tests can fake the shell scripts.
// The child's exit status is delivered as the stream's terminal read error.
type runner interface {
	start(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error)
}

type execRunner struct{}

// killReader closes over the child process so an abandoned read (capture
// timeout) terminates it instead of leaking it (§9: bounded IO).
type killReader struct {
	*io.PipeReader
	cmd *exec.Cmd
}

func (k *killReader) Close() error {
	if p := k.cmd.Process; p != nil {
		_ = p.Kill() // no-op error once the child has exited; justified
	}
	return k.PipeReader.Close()
}

func (execRunner) start(dir string, stdin []byte, extraEnv []string, argv ...string) (io.ReadCloser, error) {
	// #nosec G204 — I1: argv is always one of this file's fixed command
	// vocabularies; no user input is ever concatenated into a shell string.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var sp io.WriteCloser
	if len(stdin) > 0 {
		var err error
		sp, err = cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if sp != nil {
		secret := stdin
		go func() {
			// A failed stdin write makes the child (sudo) fail loudly on its
			// own; the buffer is zeroed by writeSecret either way (H3).
			_ = writeSecret(sp, secret)
		}()
	}
	go func() {
		err := cmd.Wait()
		_ = pw.CloseWithError(err) // conveys the exit status to the reader
	}()
	return &killReader{pr, cmd}, nil
}

// writeSecret writes secret to w, closes w, and ALWAYS zeroes secret before
// returning so the plaintext does not linger in this process's heap (H3).
func writeSecret(w io.WriteCloser, secret []byte) error {
	defer zeroBytes(secret)
	_, werr := w.Write(secret)
	cerr := w.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type server struct {
	bundle string // bundle dir holding prepare-host.sh / install-correlix.sh
	token  string
	st     *state
	run    runner

	// Injection points (tests swap these; production uses the defaults).
	fsRoot     string                                  // "/" in production
	now        func() time.Time                        // clock (idle timeout)
	afterFunc  func(time.Duration, func()) *time.Timer // shutdown scheduling
	probePort  func(port int) bool                     // true when the port is free
	statfs     func(path string) (uint64, error)       // free bytes at path
	shutdownFn func(reason string)                     // auto-stop action
	setupPort  int

	sessMu   sync.Mutex
	sessID   string
	sessLast time.Time

	shutMu    sync.Mutex
	shutTimer *time.Timer
}

func newServer(bundle, token string, run runner) *server {
	s := &server{
		bundle:    bundle,
		token:     token,
		st:        &state{phase: PhaseIdle},
		run:       run,
		fsRoot:    "/",
		now:       time.Now,
		afterFunc: time.AfterFunc,
		setupPort: 8800,
	}
	s.probePort = func(port int) bool {
		ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
		if err != nil {
			return false
		}
		_ = ln.Close() // probe socket; nothing was written
		return true
	}
	s.statfs = diskFree
	s.shutdownFn = func(reason string) {
		log.Printf("correlix-setup: shutting down (%s)", reason)
		os.Exit(0)
	}
	return s
}

func diskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Bsize < 0 { // defensive: a negative block size would wrap the product
		return 0, fmt.Errorf("statfs %s: negative block size %d", path, st.Bsize)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// ---------------------------------------------------------------------------
// Event bus: SSE events are JSON objects per the v1 contract —
// {"kind":"log"|"phase"|"stage"|"result",…}. Engine marker payloads are
// forwarded as-is; everything else is wrapped as a log event.

// mustJSON marshals values built by this file (maps/structs of plain strings);
// a failure is a programming error and is reported in-band, never dropped.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"kind":"log","line":"internal: event marshal failed"}`
	}
	return string(b)
}

func (s *server) emit(eventJSON string) {
	s.st.logMu.Lock()
	defer s.st.logMu.Unlock()
	s.st.events = append(s.st.events, eventJSON)
	if len(s.st.events) > logRingSize {
		s.st.events = s.st.events[len(s.st.events)-logRingSize:]
	}
	for _, w := range s.st.waiters {
		select {
		case w <- eventJSON:
		default: // slow consumer: drop rather than block the installer
		}
	}
}

func (s *server) appendLog(line string) {
	s.st.logMu.Lock()
	s.st.logBuf = append(s.st.logBuf, line)
	if len(s.st.logBuf) > logRingSize {
		s.st.logBuf = s.st.logBuf[len(s.st.logBuf)-logRingSize:]
	}
	s.st.logMu.Unlock()
	s.emit(mustJSON(map[string]string{"kind": "log", "line": line}))
}

func (s *server) setPhase(p Phase, errMsg string) {
	s.st.mu.Lock()
	s.st.phase = p
	s.st.err = errMsg
	s.st.mu.Unlock()
	s.emit(mustJSON(map[string]string{"kind": "phase", "phase": string(p)}))
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// stream pumps a command's output through perLine, returning the child's exit
// error (delivered by the runner as the terminal read error).
func (s *server) stream(rc io.ReadCloser, perLine func(string)) error {
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		perLine(ansiRE.ReplaceAllString(sc.Text(), ""))
	}
	err := sc.Err()
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	return err
}

// handleMarker consumes one `@CX@ {json}` progress line from the engine:
// stage/result markers update wizard state and are forwarded on SSE as-is.
// Returns false when the line is not a well-formed marker (it stays a log line).
func (s *server) handleMarker(line string) bool {
	payload, found := strings.CutPrefix(line, "@CX@ ")
	if !found {
		return false
	}
	var ev struct {
		Kind      string `json:"kind"`
		ID        string `json:"id"`
		Title     string `json:"title"`
		Status    string `json:"status"`
		Message   string `json:"message"`
		URL       string `json:"url"`
		AdminUser string `json:"admin_user"`
	}
	if err := json.Unmarshal([]byte(payload), &ev); err != nil || ev.Kind == "" {
		return false // malformed marker: keep it visible as a log line
	}
	switch ev.Kind {
	case "stage":
		s.st.mu.Lock()
		s.st.stages = upsertStage(s.st.stages, Stage{ID: ev.ID, Title: ev.Title, Status: ev.Status, Message: ev.Message})
		s.st.mu.Unlock()
	case "result":
		s.st.mu.Lock()
		if ev.URL != "" {
			s.st.uiURL = ev.URL
		}
		s.st.result = &Result{Status: ev.Status, URL: s.st.uiURL, AdminUser: ev.AdminUser}
		s.st.mu.Unlock()
	}
	s.emit(payload)
	return true
}

func upsertStage(stages []Stage, ev Stage) []Stage {
	for i := range stages {
		if stages[i].ID == ev.ID {
			stages[i].Status = ev.Status
			if ev.Title != "" {
				stages[i].Title = ev.Title
			}
			stages[i].Message = ev.Message
			return stages
		}
	}
	return append(stages, ev)
}

// runPhase executes one fixed command as a wizard phase, in the background.
// Returns false if another phase is already running (single-flight).
func (s *server) runPhase(running Phase, done Phase, stdin []byte, extraEnv []string, onLine func(string), after func(err error, out []string), argv ...string) bool {
	s.st.mu.Lock()
	if s.st.watchdogBusy { // the synchronous watchdog op holds the run guard too
		s.st.mu.Unlock()
		return false
	}
	switch s.st.phase {
	case PhaseChecking, PhasePreparing, PhaseInstalling:
		s.st.mu.Unlock()
		return false
	}
	s.st.phase = running
	s.st.err = ""
	s.st.mu.Unlock()
	s.emit(mustJSON(map[string]string{"kind": "phase", "phase": string(running)}))

	go func() {
		var out []string
		perLine := func(l string) {
			if s.handleMarker(l) {
				return
			}
			s.appendLog(l)
			out = append(out, l)
			if onLine != nil {
				onLine(l)
			}
		}
		rc, err := s.run.start(s.bundle, stdin, extraEnv, argv...)
		if err == nil {
			err = s.stream(rc, perLine)
		}
		if after != nil {
			after(err, out)
		} else if err != nil {
			s.setPhase(PhaseError, err.Error())
		} else {
			s.setPhase(done, "")
		}
	}()
	return true
}

// ---------------------------------------------------------------------------
// Bundle / source-tree path resolution (mirrors install-correlix.sh).

// rootDir resolves the product source root the same way install-correlix.sh
// does: bundle layout first (<bundle>/NetOps_Observability), then source tree
// (<bundle>/.. when the GUI runs from scripts/).
func (s *server) rootDir() string {
	if _, err := os.Stat(filepath.Join(s.bundle, "NetOps_Observability", "deployment", "docker", "docker-compose.yml")); err == nil {
		return filepath.Join(s.bundle, "NetOps_Observability")
	}
	if _, err := os.Stat(filepath.Join(s.bundle, "..", "deployment", "docker", "docker-compose.yml")); err == nil {
		return filepath.Clean(filepath.Join(s.bundle, ".."))
	}
	return s.bundle
}

func (s *server) composeDir() string { return filepath.Join(s.rootDir(), "deployment", "docker") }
func (s *server) envPath() string    { return filepath.Join(s.composeDir(), ".env") }
func (s *server) dataPath() string   { return filepath.Join(s.rootDir(), "data") }

// readFileOr returns the file's content, or "" when it cannot be read —
// callers treat absence as a normal, reportable condition (facts, bundle).
func readFileOr(path string) string {
	// #nosec G304 — every path is server-derived (fsRoot/bundle constants
	// joined with fixed names); no request data ever reaches a file path.
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func envValue(env, key string) string {
	for _, l := range strings.Split(env, "\n") {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// API: check / prepare

var checkLineRE = regexp.MustCompile(`^\s*(PASS|FIX)\s+(.*)$`)

func (s *server) apiCheck(w http.ResponseWriter, _ *http.Request) {
	ok := s.runPhase(PhaseChecking, PhaseReady, nil, nil, nil, func(err error, out []string) {
		var items []CheckItem
		needs := false
		for _, l := range out {
			if m := checkLineRE.FindStringSubmatch(l); m != nil {
				it := CheckItem{OK: m[1] == "PASS", Text: strings.TrimSpace(m[2])}
				if !it.OK {
					needs = true
				}
				items = append(items, it)
			}
		}
		s.st.mu.Lock()
		s.st.checks = items
		s.st.checkOut = out
		s.st.mu.Unlock()
		switch {
		case len(items) == 0 && err != nil:
			s.setPhase(PhaseError, "system check could not run — see log")
		case needs:
			s.setPhase(PhaseNeedsPrep, "")
		default:
			s.setPhase(PhaseReady, "")
		}
	}, "bash", "./prepare-host.sh", "--check")
	writeJSON(w, map[string]bool{"started": ok})
}

func (s *server) apiPrepare(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		// H3: the sudo password is accepted over TLS only — this server always
		// serves TLS, so a cleartext arrival means a broken deployment.
		writeErr(w, http.StatusForbidden, "the sudo password is accepted over TLS only")
		return
	}
	var body struct {
		Password string `json:"password"`
		Firewall bool   `json:"firewall"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.Password == "" {
		writeErr(w, http.StatusBadRequest, "password required")
		return
	}
	// -S: password on stdin; -p '': no prompt garbage in the log; -k: don't
	// reuse a cached credential so a wrong password fails loudly here.
	argv := []string{"sudo", "-k", "-S", "-p", "", "bash", "./prepare-host.sh"}
	if body.Firewall {
		argv = append(argv, "--firewall")
	}
	pw := append([]byte(body.Password), '\n')
	body.Password = ""
	ok := s.runPhase(PhasePreparing, PhaseIdle, pw, nil, nil, func(err error, _ []string) {
		if err != nil {
			s.setPhase(PhaseError, "host preparation failed — check the sudo password and the log")
			return
		}
		s.appendLog("host prepared — re-running system check")
		s.st.mu.Lock()
		s.st.phase = PhaseIdle
		s.st.mu.Unlock()
		s.apiCheck(nil, nil) // writeJSON tolerates nil — internal re-check
	}, argv...)
	writeJSON(w, map[string]bool{"started": ok})
}

// ---------------------------------------------------------------------------
// API: install (Profile JSON v1 → temp config → fixed argv)

// Profile is the v1 unattended install profile the GUI exports and the
// engine consumes via `install-correlix.sh install --config FILE`.
// Secret-free by construction (H7): secrets are generated on-host.
type Profile struct {
	Version          int            `json:"version"`
	Port             int            `json:"port"`
	TLS              string         `json:"tls"`
	RetentionProfile string         `json:"retention_profile,omitempty"`
	Addons           []string       `json:"addons,omitempty"`
	ExternalKafka    *ExternalKafka `json:"external_kafka,omitempty"`
	Discovery        *Discovery     `json:"discovery,omitempty"`
	Sizing           *Sizing        `json:"sizing,omitempty"`
}

type ExternalKafka struct {
	BrokerURLs string `json:"broker_urls"`
}

type Discovery struct {
	Enabled bool     `json:"enabled"`
	CIDRs   []string `json:"cidrs,omitempty"`
}

type Sizing struct {
	Profile string `json:"profile"`
}

var (
	retentionProfiles = map[string]bool{"lab": true, "demo": true, "production": true, "extended": true}
	sizingProfiles    = map[string]bool{"auto": true, "demo": true, "small": true, "medium": true, "large": true}
	knownAddons       = map[string]bool{"log-search-ui": true, "self-monitoring": true, "netbox": true, "sso": true}
)

// decodeProfile parses and validates a Profile fail-closed: unknown fields are
// a hard error and every value is checked against its allowed shape.
func decodeProfile(r io.Reader, p *Profile) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return fmt.Errorf("invalid profile JSON: %v", err)
	}
	if dec.More() {
		return fmt.Errorf("invalid profile JSON: trailing data after the profile object")
	}
	return validateProfile(p)
}

func validateProfile(p *Profile) error {
	if p.Version != 1 {
		return fmt.Errorf("version: must be 1")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("port: must be between 1 and 65535")
	}
	if p.TLS != "yes" && p.TLS != "no" {
		return fmt.Errorf(`tls: must be "yes" or "no"`)
	}
	if p.RetentionProfile != "" && !retentionProfiles[p.RetentionProfile] {
		return fmt.Errorf("retention_profile: must be one of lab, demo, production, extended")
	}
	for _, a := range p.Addons {
		if !knownAddons[a] {
			return fmt.Errorf("addons: unknown add-on %q", a)
		}
	}
	if p.ExternalKafka != nil {
		if strings.TrimSpace(p.ExternalKafka.BrokerURLs) == "" {
			return fmt.Errorf("external_kafka.broker_urls: must not be empty")
		}
		for _, b := range strings.Split(p.ExternalKafka.BrokerURLs, ",") {
			b = strings.TrimSpace(b)
			host, port, err := net.SplitHostPort(b)
			if err != nil || host == "" {
				return fmt.Errorf("external_kafka.broker_urls: %q is not HOST:PORT", b)
			}
			if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("external_kafka.broker_urls: %q has an invalid port", b)
			}
		}
	}
	if p.Discovery != nil {
		if p.Discovery.Enabled && len(p.Discovery.CIDRs) == 0 {
			return fmt.Errorf("discovery.cidrs: at least one CIDR is required when discovery is enabled")
		}
		for i, c := range p.Discovery.CIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				return fmt.Errorf("discovery.cidrs[%d]: %q is not a valid CIDR", i, c)
			}
		}
	}
	if p.Sizing != nil && !sizingProfiles[p.Sizing.Profile] {
		return fmt.Errorf("sizing.profile: must be one of auto, demo, small, medium, large")
	}
	return nil
}

// writeProfile re-marshals the VALIDATED profile (never the raw request body,
// so unknown input can never reach the engine) into a 0600 temp file inside
// the bundle dir.
func (s *server) writeProfile(p Profile) (string, error) {
	f, err := os.CreateTemp(s.bundle, "correlix-profile-*.json") // 0600 by contract of CreateTemp
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err == nil {
		_, err = f.Write(b)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		s.removeQuiet(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func (s *server) removeQuiet(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		s.appendLog("warning: could not remove temp file " + filepath.Base(path) + ": " + err.Error())
	}
}

// needSGDocker is the docker-group chicken-and-egg decision: the server
// process was started before prepare-host.sh added the user to the docker
// group, so /etc/group lists the membership but the process doesn't have it —
// spawning via `sg docker -c …` picks the group up without a re-login.
func needSGDocker(procMember, etcListed bool) bool {
	return !procMember && etcListed
}

var safeCfgPathRE = regexp.MustCompile(`^[A-Za-z0-9/._-]+$`)

// installArgv builds the fixed install command (I1). The sg form must embed
// the config path inside the -c command string, so the path — which is always
// produced by os.CreateTemp in the bundle dir, never by a request — is
// re-validated to contain no shell metacharacters before it is accepted.
func installArgv(useSG bool, cfgPath string) ([]string, error) {
	if !useSG {
		return []string{"bash", "./install-correlix.sh", "install", "--config", cfgPath}, nil
	}
	if !safeCfgPathRE.MatchString(cfgPath) || strings.Contains(cfgPath, "..") {
		return nil, fmt.Errorf("refusing sg exec: config path %q is not a plain server-generated temp path", cfgPath)
	}
	return []string{"sg", "docker", "-c", "bash ./install-correlix.sh install --config " + cfgPath}, nil
}

// dockerGroupFacts parses /etc/group content and reports whether username is
// listed as a docker-group member, and whether procGids includes docker's gid.
func dockerGroupFacts(groupFile, username string, procGids []int) (etcListed, procMember bool) {
	for _, l := range strings.Split(groupFile, "\n") {
		parts := strings.Split(l, ":")
		if len(parts) < 4 || parts[0] != "docker" {
			continue
		}
		if gid, err := strconv.Atoi(parts[2]); err == nil {
			for _, g := range procGids {
				if g == gid {
					procMember = true
				}
			}
		}
		if username != "" {
			for _, m := range strings.Split(parts[3], ",") {
				if strings.TrimSpace(m) == username {
					etcListed = true
				}
			}
		}
		return etcListed, procMember
	}
	return false, false
}

func (s *server) dockerGroupMembership() (etcListed, procMember bool) {
	u, err := user.Current()
	if err != nil {
		return false, false
	}
	gids, err := os.Getgroups()
	if err != nil {
		gids = nil // fall back to the primary gid below; membership stays detectable via /etc/group
	}
	gids = append(gids, os.Getgid())
	group := readFileOr(filepath.Join(s.fsRoot, "etc", "group"))
	if group == "" {
		return false, false
	}
	return dockerGroupFacts(group, u.Username, gids)
}

var (
	uiURLRE = regexp.MustCompile(`https?://[0-9a-zA-Z.:\-]+:8000\b`)
	adminRE = regexp.MustCompile(`^\s*Password:\s+(\S+)`)
)

func (s *server) apiInstall(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		writeErr(w, http.StatusBadRequest, "Idempotency-Key header required")
		return
	}
	s.st.mu.Lock()
	if s.st.installKey != "" && key == s.st.installKey {
		s.st.mu.Unlock()
		writeJSON(w, map[string]string{"job": "existing"})
		return
	}
	busy := s.st.phase == PhaseChecking || s.st.phase == PhasePreparing ||
		s.st.phase == PhaseInstalling || s.st.watchdogBusy
	s.st.mu.Unlock()
	if busy {
		writeErr(w, http.StatusConflict, "another job is already running")
		return
	}

	var p Profile
	if err := decodeProfile(io.LimitReader(r.Body, 64*1024), &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cfgPath, err := s.writeProfile(p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not stage the install profile: "+err.Error())
		return
	}
	etcListed, procMember := s.dockerGroupMembership()
	argv, err := installArgv(needSGDocker(procMember, etcListed), cfgPath)
	if err != nil {
		s.removeQuiet(cfgPath)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	onLine := func(l string) {
		if m := uiURLRE.FindString(l); m != "" {
			s.st.mu.Lock()
			s.st.uiURL = m
			s.st.mu.Unlock()
		}
		if m := adminRE.FindStringSubmatch(l); m != nil {
			s.st.mu.Lock()
			s.st.adminPW = m[1]
			s.st.mu.Unlock()
		}
	}
	started := s.runPhase(PhaseInstalling, PhaseInstalled, nil, []string{"CORRELIX_PROGRESS_JSON=1"}, onLine, func(err error, _ []string) {
		s.removeQuiet(cfgPath)
		s.finishInstall(err)
	}, argv...)
	if !started {
		s.removeQuiet(cfgPath)
		writeErr(w, http.StatusConflict, "another job is already running")
		return
	}
	s.st.mu.Lock()
	s.st.installKey = key
	s.st.mu.Unlock()
	s.disarmShutdown() // a fresh install cancels any pending auto-stop
	writeJSON(w, map[string]any{"started": true, "job": "new"})
}

// finishInstall settles the terminal install state: the engine's result marker
// and the process exit status must both be good, credentials come from the
// generated .env (banner scrape stays as the fallback), and the auto-stop
// clock starts (H2).
func (s *server) finishInstall(runErr error) {
	s.st.mu.Lock()
	res := s.st.result
	s.st.mu.Unlock()
	failed := runErr != nil || (res != nil && res.Status == "fail")
	if failed {
		msg := "installation failed — see the log and the support bundle"
		if runErr != nil {
			msg = "installation failed: " + runErr.Error()
		}
		s.st.mu.Lock()
		if s.st.result == nil {
			s.st.result = &Result{Status: "fail", URL: s.st.uiURL}
		}
		s.st.mu.Unlock()
		s.setPhase(PhaseError, msg)
		s.armShutdown(resultShutdown, "install result never acknowledged")
		return
	}
	env := readFileOr(s.envPath())
	adminUser := envValue(env, "ADMIN_USERNAME")
	adminPW := envValue(env, "ADMIN_INITIAL_PASSWORD")
	s.st.mu.Lock()
	if adminUser != "" {
		s.st.adminUser = adminUser
	}
	if adminPW != "" {
		s.st.adminPW = adminPW // .env is authoritative; scrape was the fallback
	}
	if s.st.result == nil {
		// Engine predates result markers — synthesize from the banner scrape.
		s.st.result = &Result{Status: "ok", URL: s.st.uiURL, AdminUser: firstNonEmpty(adminUser, "admin")}
	} else if adminUser != "" {
		s.st.result.AdminUser = adminUser
	}
	s.st.mu.Unlock()
	s.setPhase(PhaseInstalled, "")
	s.armShutdown(resultShutdown, "install result never acknowledged")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// API: state / stream / done

func (s *server) apiState(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	uiURL := s.st.uiURL
	if uiURL == "" && r != nil {
		// Best guess for the success card before/without install output: the
		// appliance UI rides port 8000 on the same host the wizard is on.
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		uiURL = "http://" + host + ":8000"
	}
	resp := map[string]any{
		"phase":              s.st.phase,
		"check_items":        s.st.checks,
		"error":              s.st.err,
		"stages":             s.st.stages,
		"ui_url":             uiURL,
		"admin_pw":           s.st.adminPW,
		"bundle":             filepath.Base(s.bundle),
		"facts_hash":         s.st.factsHash,
		"watchdog_installed": s.st.watchdogInstalled,
	}
	if s.st.result != nil {
		res := map[string]any{
			"url":        firstNonEmpty(s.st.result.URL, uiURL),
			"admin_user": firstNonEmpty(s.st.adminUser, s.st.result.AdminUser, "admin"),
		}
		if s.st.result.Status == "ok" && s.st.adminPW != "" {
			// H2/I5: the one-time credential handover, TLS + session gated.
			res["admin_password"] = s.st.adminPW
		}
		resp["result"] = res
	}
	writeJSON(w, resp)
}

// apiStream is the SSE live feed: JSON event history first, then follow.
func (s *server) apiStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "stream unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")

	ch := make(chan string, 256)
	s.st.logMu.Lock()
	history := append([]string(nil), s.st.events...)
	s.st.waiters = append(s.st.waiters, ch)
	s.st.logMu.Unlock()
	defer func() {
		s.st.logMu.Lock()
		for i, c := range s.st.waiters {
			if c == ch {
				s.st.waiters = append(s.st.waiters[:i], s.st.waiters[i+1:]...)
				break
			}
		}
		s.st.logMu.Unlock()
	}()

	send := func(line string) bool {
		if _, err := fmt.Fprintf(w, "data: %s\n\n", line); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	for _, l := range history {
		if !send(l) {
			return
		}
	}
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case l := <-ch:
			if !send(l) {
				return
			}
		case <-keep.C:
			// SSE comment line: keeps the connection alive, invisible to
			// EventSource consumers.
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *server) apiDone(w http.ResponseWriter, _ *http.Request) {
	s.armShutdown(ackShutdownDelay, "success screen acknowledged")
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------
// API: watchdog handover (design §8 — privileged op #3)

var (
	ntfyTopicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	emailRE     = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	httpsURLRE  = regexp.MustCompile(`^https://[A-Za-z0-9.-]+/[A-Za-z0-9/_-]+$`)
	tokenRE     = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{8,256}$`)
	appURLRE    = regexp.MustCompile(`^https?://[A-Za-z0-9.:\[\]-]+$`)
)

// watchdogReq is the POST /api/watchdog body. The sudo password rides the same
// TLS-only stdin path as prepare; everything else mirrors an
// install-watchdog.sh flag and is validated here BEFORE sudo runs (defense in
// depth — the script re-validates on its side).
type watchdogReq struct {
	Password     string `json:"password"`
	NtfyTopic    string `json:"ntfy_topic"`
	NtfyServer   string `json:"ntfy_server"`
	NtfyToken    string `json:"ntfy_token"`
	Email        string `json:"email"`
	HCURL        string `json:"hc_url"`
	WebhookURL   string `json:"webhook_url"`
	WebhookToken string `json:"webhook_token"`
}

func checkHTTPSURL(field, v string) error {
	if v == "" {
		return nil
	}
	if len(v) > 200 || !httpsURLRE.MatchString(v) {
		return fmt.Errorf("%s: must be an https://host/path URL of at most 200 characters", field)
	}
	return nil
}

func checkToken(field, v string) error {
	if v == "" {
		return nil
	}
	if !tokenRE.MatchString(v) {
		return fmt.Errorf("%s: must be 8-256 characters of A-Za-z0-9._~+/=-", field)
	}
	return nil
}

// validateWatchdogReq enforces the per-field shapes and the "at least one
// notification channel" rule (ntfy_topic, email, hc_url, or webhook_url).
// Every error names the offending field; secret values never appear in errors.
func validateWatchdogReq(q *watchdogReq) error {
	if q.NtfyTopic != "" && !ntfyTopicRE.MatchString(q.NtfyTopic) {
		return fmt.Errorf("ntfy_topic: must be 1-64 characters of A-Za-z0-9_-")
	}
	if err := checkHTTPSURL("ntfy_server", q.NtfyServer); err != nil {
		return err
	}
	if err := checkToken("ntfy_token", q.NtfyToken); err != nil {
		return err
	}
	if q.Email != "" && (len(q.Email) > 254 || !emailRE.MatchString(q.Email)) {
		return fmt.Errorf("email: not a valid address")
	}
	if err := checkHTTPSURL("hc_url", q.HCURL); err != nil {
		return err
	}
	if err := checkHTTPSURL("webhook_url", q.WebhookURL); err != nil {
		return err
	}
	if err := checkToken("webhook_token", q.WebhookToken); err != nil {
		return err
	}
	if q.NtfyTopic == "" && q.Email == "" && q.HCURL == "" && q.WebhookURL == "" {
		return fmt.Errorf("at least one of ntfy_topic, email, hc_url, or webhook_url is required")
	}
	return nil
}

// watchdogArgv builds the fixed watchdog install command (I1): every element is
// a discrete argv entry — validated request values never touch a shell string.
// The option order is fixed so tests can assert exact assembly. scriptPath is
// server-derived (rootDir-resolved — the script lives under scripts/ in both
// the extracted-bundle and source-tree layouts), never from the request.
func watchdogArgv(scriptPath, appURL string, q *watchdogReq) []string {
	argv := []string{"sudo", "-k", "-S", "-p", "", "bash", scriptPath, "--app-url", appURL}
	if q.NtfyTopic != "" {
		argv = append(argv, "--topic", q.NtfyTopic)
	}
	if q.NtfyServer != "" {
		argv = append(argv, "--ntfy-server", q.NtfyServer)
	}
	if q.NtfyToken != "" {
		argv = append(argv, "--ntfy-token", q.NtfyToken)
	}
	if q.Email != "" {
		argv = append(argv, "--email", q.Email)
	}
	if q.HCURL != "" {
		argv = append(argv, "--hc-url", q.HCURL)
	}
	if q.WebhookURL != "" {
		argv = append(argv, "--webhook-url", q.WebhookURL)
	}
	if q.WebhookToken != "" {
		argv = append(argv, "--webhook-token", q.WebhookToken)
	}
	return argv
}

// scrubArgv returns a copy of argv safe to log: the value following a
// secret-bearing flag is replaced so tokens never reach the log ring or the
// SSE stream (§8 — no secrets in logs).
func scrubArgv(argv []string) []string {
	out := append([]string(nil), argv...)
	for i := 0; i < len(out)-1; i++ {
		switch out[i] {
		case "--ntfy-token", "--webhook-token":
			out[i+1] = "<secret>"
		}
	}
	return out
}

// apiWatchdog installs the stack-watchdog cron — the wizard's final privileged
// op (design §8). The app URL comes from the install result held server-side,
// never from the request. The handler is synchronous: the script finishes in
// seconds and the caller needs the pass/fail verdict in the response; the SSE
// stream still carries every output line live.
func (s *server) apiWatchdog(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		// H3: the sudo password is accepted over TLS only — this server always
		// serves TLS, so a cleartext arrival means a broken deployment.
		writeErr(w, http.StatusForbidden, "the sudo password is accepted over TLS only")
		return
	}
	var body watchdogReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil || body.Password == "" {
		writeErr(w, http.StatusBadRequest, "password required")
		return
	}
	if err := validateWatchdogReq(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Single-flight against the run guard: acquire the watchdog slot only when
	// no phase job is running AND a successful install result exists.
	s.st.mu.Lock()
	busy := s.st.phase == PhaseChecking || s.st.phase == PhasePreparing ||
		s.st.phase == PhaseInstalling || s.st.watchdogBusy
	appURL := ""
	if !busy && s.st.result != nil && s.st.result.Status == "ok" {
		appURL = firstNonEmpty(s.st.result.URL, s.st.uiURL)
	}
	acquired := !busy && appURL != ""
	if acquired {
		s.st.watchdogBusy = true
	}
	s.st.mu.Unlock()
	if busy {
		writeErr(w, http.StatusConflict, "another job is already running")
		return
	}
	if !acquired {
		writeErr(w, http.StatusConflict, "install first — the watchdog needs a successful install's stack URL")
		return
	}
	defer func() {
		s.st.mu.Lock()
		s.st.watchdogBusy = false
		s.st.mu.Unlock()
	}()
	if !appURLRE.MatchString(appURL) {
		// Server-held state, but it crossed the engine boundary (§3: validate
		// at every boundary before it becomes an argv element).
		writeErr(w, http.StatusInternalServerError, "install result URL is malformed")
		return
	}

	argv := watchdogArgv(filepath.Join(s.rootDir(), "scripts", "install-watchdog.sh"), appURL, &body)
	pw := append([]byte(body.Password), '\n')
	body.Password = ""
	s.appendLog("installing the stack watchdog cron: " + strings.Join(scrubArgv(argv), " "))
	rc, err := s.run.start(s.bundle, pw, nil, argv...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not start the watchdog installer: "+err.Error())
		return
	}
	var last string
	done := make(chan error, 1)
	go func() {
		done <- s.stream(rc, func(l string) {
			s.appendLog(l)
			if strings.TrimSpace(l) != "" {
				last = l // read only after <-done (channel happens-before)
			}
		})
	}()
	select {
	case err = <-done:
	case <-time.After(watchdogTimeout):
		_ = rc.Close() // kills the child (killReader); the stream goroutine drains and exits
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("watchdog install timed out after %s", watchdogTimeout))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError,
			"watchdog install failed: "+firstNonEmpty(strings.TrimSpace(last), err.Error()))
		return
	}
	s.st.mu.Lock()
	s.st.watchdogInstalled = true
	s.st.mu.Unlock()
	s.appendLog("stack watchdog installed")
	writeJSON(w, map[string]bool{"watchdog_installed": true})
}

func (s *server) armShutdown(d time.Duration, reason string) {
	s.shutMu.Lock()
	defer s.shutMu.Unlock()
	if s.shutTimer != nil {
		s.shutTimer.Stop()
	}
	s.shutTimer = s.afterFunc(d, func() { s.shutdownFn(reason) })
}

func (s *server) disarmShutdown() {
	s.shutMu.Lock()
	defer s.shutMu.Unlock()
	if s.shutTimer != nil {
		s.shutTimer.Stop()
		s.shutTimer = nil
	}
}

// ---------------------------------------------------------------------------
// API: facts

type dockerFactsT struct {
	Present   bool   `json:"present"`
	Version   string `json:"version"`
	ComposeV2 bool   `json:"compose_v2"`
	DaemonOK  bool   `json:"daemon_ok"`
}

type portFact struct {
	Port int   `json:"port"`
	Free *bool `json:"free,omitempty"`
}

type bundleFactsT struct {
	Dir        string `json:"dir"`
	Version    string `json:"version"`
	SourceTree bool   `json:"source_tree"`
}

// Facts is the read-only host snapshot the wizard's readiness screen renders
// (contract §GET /api/facts — field names are load-bearing).
type Facts struct {
	OSPretty          string       `json:"os_pretty"`
	OSID              string       `json:"os_id"`
	OSSupported       bool         `json:"os_supported"`
	Arch              string       `json:"arch"`
	ArchSupported     bool         `json:"arch_supported"`
	CPUs              int          `json:"cpus"`
	MemBytes          uint64       `json:"mem_bytes"`
	DiskFreeBytes     uint64       `json:"disk_free_bytes"`
	DataPath          string       `json:"data_path"`
	Docker            dockerFactsT `json:"docker"`
	UserInDockerGroup bool         `json:"user_in_docker_group"`
	TimeSync          bool         `json:"time_sync"`
	Ports             struct {
		Stack portFact `json:"stack"`
		Setup portFact `json:"setup"`
	} `json:"ports"`
	Bundle bundleFactsT    `json:"bundle"`
	Sizing json.RawMessage `json:"sizing,omitempty"`
}

func parseOSRelease(content string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}

func parseVer(v string) (major, minor int) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) > 0 {
		major, _ = strconv.Atoi(parts[0]) // non-numeric → 0 → unsupported; justified
	}
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1]) // same
	}
	return major, minor
}

// osSupported mirrors install-correlix.sh preflight: Ubuntu ≥ 22.04, Debian ≥ 12.
func osSupported(id, versionID string) bool {
	major, minor := parseVer(versionID)
	switch id {
	case "ubuntu":
		return major > 22 || (major == 22 && minor >= 4)
	case "debian":
		return major >= 12
	}
	return false
}

func unameArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return goarch
}

var memTotalRE = regexp.MustCompile(`(?m)^MemTotal:\s+(\d+)\s+kB`)

func memTotalBytes(meminfo string) uint64 {
	m := memTotalRE.FindStringSubmatch(meminfo)
	if m == nil {
		return 0
	}
	kb, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return kb * 1024
}

// nearestExisting walks up from path to the closest existing directory so
// statfs works before data/ has been created.
func nearestExisting(path string) string {
	for p := path; ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		if p == filepath.Dir(p) {
			return p
		}
	}
}

var dockerVerRE = regexp.MustCompile(`[0-9]+\.[0-9]+\.[0-9]+`)

func dockerVersionOf(out string) string {
	if m := dockerVerRE.FindString(out); m != "" {
		return m
	}
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
}

// capture runs argv and returns its combined output; the child is killed and
// an error returned when it exceeds timeout (§9: every external call bounded).
func (s *server) capture(timeout time.Duration, dir string, argv ...string) (string, error) {
	rc, err := s.run.start(dir, nil, nil, argv...)
	if err != nil {
		return "", err
	}
	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		b, rerr := io.ReadAll(io.LimitReader(rc, 1<<20)) // bounded output
		if cerr := rc.Close(); rerr == nil {
			rerr = cerr
		}
		ch <- res{b, rerr}
	}()
	select {
	case r := <-ch:
		return string(r.out), r.err
	case <-time.After(timeout):
		_ = rc.Close() // kills the child (killReader); the reader goroutine drains and exits
		return "", fmt.Errorf("%s timed out after %s", argv[0], timeout)
	}
}

func (s *server) dockerFactsNow() dockerFactsT {
	var d dockerFactsT
	out, err := s.capture(5*time.Second, "", "docker", "--version")
	if err != nil {
		return d // docker absent: report present=false, nothing else to probe
	}
	d.Present = true
	d.Version = dockerVersionOf(out)
	if _, err := s.capture(5*time.Second, "", "docker", "compose", "version"); err == nil {
		d.ComposeV2 = true
	}
	if _, err := s.capture(10*time.Second, "", "docker", "info"); err == nil {
		d.DaemonOK = true
	}
	return d
}

func (s *server) timeSyncNow() bool {
	// systemd-timesyncd drops this flag file once the clock synchronizes.
	if _, err := os.Stat(filepath.Join(s.fsRoot, "run", "systemd", "timesync", "synchronized")); err == nil {
		return true
	}
	out, err := s.capture(3*time.Second, "", "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil {
		return false // graceful absence: no timedatectl → report unsynchronized
	}
	return strings.TrimSpace(out) == "yes"
}

func (s *server) bundleFactsNow() bundleFactsT {
	b := bundleFactsT{Dir: s.bundle}
	mf := readFileOr(filepath.Join(s.bundle, "MANIFEST"))
	if mf == "" {
		b.SourceTree = true
		b.Version = "source"
		return b
	}
	for _, l := range strings.Split(mf, "\n") {
		if v, ok := strings.CutPrefix(l, "version:"); ok {
			b.Version = strings.TrimSpace(v)
			break
		}
	}
	return b
}

// sizingNow shells to the resource planner's detect CLI; ANY failure omits the
// sizing block (contract: degrade gracefully, never block facts on sizing).
func (s *server) sizingNow() json.RawMessage {
	planner := ""
	for _, cand := range []string{
		filepath.Join(s.rootDir(), "scripts", "resource_planner.py"),
		filepath.Join(s.bundle, "resource_planner.py"),
	} {
		if _, err := os.Stat(cand); err == nil {
			planner = cand
			break
		}
	}
	if planner == "" {
		return nil
	}
	out, err := s.capture(15*time.Second, s.bundle, "python3", planner, "--detect-json")
	if err != nil {
		return nil
	}
	i := strings.IndexByte(out, '{')
	if i < 0 {
		return nil
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(out[i:]), &probe); err != nil || len(probe) == 0 {
		return nil
	}
	compact, err := json.Marshal(probe)
	if err != nil {
		return nil
	}
	return compact
}

func (s *server) collectFacts() Facts {
	var f Facts
	osr := parseOSRelease(readFileOr(filepath.Join(s.fsRoot, "etc", "os-release")))
	f.OSPretty = osr["PRETTY_NAME"]
	f.OSID = osr["ID"]
	f.OSSupported = osSupported(osr["ID"], osr["VERSION_ID"])
	f.Arch = unameArch(runtime.GOARCH)
	f.ArchSupported = runtime.GOARCH == "amd64"
	f.CPUs = runtime.NumCPU()
	f.MemBytes = memTotalBytes(readFileOr(filepath.Join(s.fsRoot, "proc", "meminfo")))
	f.DataPath = s.dataPath()
	if free, err := s.statfs(nearestExisting(f.DataPath)); err == nil {
		f.DiskFreeBytes = free
	} // else: 0 = unknown, rendered as such — never a fatal facts failure
	f.Docker = s.dockerFactsNow()
	etcListed, procMember := s.dockerGroupMembership()
	f.UserInDockerGroup = etcListed || procMember
	f.TimeSync = s.timeSyncNow()
	stackPort := 8000
	if v := envValue(readFileOr(s.envPath()), "BASE_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			stackPort = n
		}
	}
	free := s.probePort(stackPort)
	f.Ports.Stack = portFact{Port: stackPort, Free: &free}
	f.Ports.Setup = portFact{Port: s.setupPort}
	f.Bundle = s.bundleFactsNow()
	f.Sizing = s.sizingNow()
	return f
}

func (s *server) apiFacts(w http.ResponseWriter, _ *http.Request) {
	f := s.collectFacts()
	b, err := json.Marshal(f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "facts marshal failed: "+err.Error())
		return
	}
	sum := sha256.Sum256(b)
	s.st.mu.Lock()
	s.st.factsJSON = b
	s.st.factsHash = hex.EncodeToString(sum[:])
	s.st.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(b); err != nil {
		return // client went away — nothing actionable server-side
	}
}

// ---------------------------------------------------------------------------
// API: support bundle

var secretKeyRE = regexp.MustCompile(`(?i)(password|secret|token|key)`)

// redactEnv keeps every KEY of a dotenv file but replaces the value of any
// key matching (?i)(password|secret|token|key) with "<set>" (H7 — tested).
func redactEnv(in string) string {
	lines := strings.Split(in, "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		eq := strings.IndexByte(l, '=')
		if eq <= 0 {
			continue
		}
		k, v := l[:eq], l[eq+1:]
		if secretKeyRE.MatchString(k) && v != "" {
			lines[i] = k + "=<set>"
		}
	}
	return strings.Join(lines, "\n")
}

var svcNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// failedServices parses `docker compose ps -a --format json` output (one JSON
// object per line on compose ≥ 2.21, a single array on older releases) and
// returns the service names worth pulling log tails for.
func failedServices(out string) []string {
	type psRow struct {
		Service  string `json:"Service"`
		State    string `json:"State"`
		Health   string `json:"Health"`
		ExitCode int    `json:"ExitCode"`
	}
	var rows []psRow
	trimmed := strings.TrimSpace(out)
	if strings.HasPrefix(trimmed, "[") {
		// Unparseable ps output simply yields no log tails — the raw ps text
		// is in the bundle either way.
		_ = json.Unmarshal([]byte(trimmed), &rows)
	} else {
		for _, l := range strings.Split(trimmed, "\n") {
			var r psRow
			if err := json.Unmarshal([]byte(l), &r); err == nil {
				rows = append(rows, r)
			}
		}
	}
	var failed []string
	seen := map[string]bool{}
	for _, r := range rows {
		bad := r.Health == "unhealthy" || r.State == "dead" || r.State == "restarting" ||
			(r.State == "exited" && r.ExitCode != 0)
		if bad && r.Service != "" && svcNameRE.MatchString(r.Service) && !seen[r.Service] {
			seen[r.Service] = true
			failed = append(failed, r.Service)
		}
	}
	return failed
}

func (s *server) apiSupportBundle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="correlix-support-bundle.tar.gz"`)
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	now := s.now()
	add := func(name string, content []byte) {
		const maxFile = 1 << 20 // bound every member (§9)
		if len(content) > maxFile {
			content = content[len(content)-maxFile:] // keep the tail — that's where failures live
		}
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), ModTime: now}
		if err := tw.WriteHeader(hdr); err != nil {
			return // client went away mid-download — abandon quietly
		}
		if _, err := tw.Write(content); err != nil {
			return // same
		}
	}

	if env := readFileOr(s.envPath()); env != "" {
		add("env.redacted", []byte(redactEnv(env)))
	}

	s.st.mu.Lock()
	checkOut := strings.Join(s.st.checkOut, "\n")
	stages := append([]Stage(nil), s.st.stages...)
	facts := append([]byte(nil), s.st.factsJSON...)
	s.st.mu.Unlock()
	if checkOut == "" {
		checkOut = "(prepare-host.sh --check has not been run in this session)"
	}
	add("prepare-check.txt", []byte(checkOut+"\n"))

	if len(facts) == 0 {
		if b, err := json.Marshal(s.collectFacts()); err == nil {
			facts = b
		}
	}
	add("facts.json", facts)

	if b, err := json.MarshalIndent(stages, "", "  "); err == nil {
		add("stages.json", b)
	}

	if mf := readFileOr(filepath.Join(s.bundle, "MANIFEST")); mf != "" {
		add("MANIFEST", []byte(mf))
	}

	// Docker parts: skipped gracefully when docker (or the compose project)
	// is absent — the capture error is the skip signal, not a bundle failure.
	if psOut, err := s.capture(10*time.Second, s.composeDir(), "docker", "compose", "ps", "-a"); err == nil {
		add("compose-ps.txt", []byte(psOut))
		if psJSON, err := s.capture(10*time.Second, s.composeDir(), "docker", "compose", "ps", "-a", "--format", "json"); err == nil {
			for _, svc := range failedServices(psJSON) {
				logOut, err := s.capture(15*time.Second, s.composeDir(), "docker", "compose", "logs", "--no-color", "--tail", "200", svc)
				if err != nil {
					logOut = "log collection failed: " + err.Error()
				}
				add("logs/"+svc+".txt", []byte(logOut))
			}
		}
	}

	if err := tw.Close(); err != nil {
		return // stream already broken; nothing to salvage
	}
	_ = gz.Close() // flush; a broken client connection is not actionable here
}

// ---------------------------------------------------------------------------
// JSON helpers, auth, routes

func writeJSON(w http.ResponseWriter, v any) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // best-effort: a gone client is not actionable
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg}) // same
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// authenticate resolves a request against the single-session model (H2):
// a live session cookie wins (and slides the idle window); otherwise the
// one-time token may be exchanged for a NEW session — but only when no other
// session is alive (conflict=true → 409).
func (s *server) authenticate(r *http.Request) (ok bool, conflict bool, newCookie string) {
	now := s.now()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.sessID != "" && now.Sub(s.sessLast) > idleTimeout {
		s.sessID = "" // idle session died; the token becomes exchangeable again
	}
	if c, err := r.Cookie("cx_setup"); err == nil && s.sessID != "" &&
		subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.sessID)) == 1 {
		s.sessLast = now // sliding idle window
		return true, false, ""
	}
	if t := r.URL.Query().Get("t"); subtle.ConstantTimeCompare([]byte(t), []byte(s.token)) == 1 {
		if s.sessID != "" {
			return false, true, ""
		}
		id, err := randomHex(16)
		if err != nil {
			return false, false, "" // no entropy → fail closed
		}
		s.sessID = id
		s.sessLast = now
		return true, false, id
	}
	return false, false, ""
}

// auth gates every route behind the token/session model.
func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, conflict, cookie := s.authenticate(r)
		if conflict {
			writeErr(w, http.StatusConflict,
				"another setup session is already active — close that browser tab or wait 15 minutes for it to time out")
			return
		}
		if !ok {
			writeErr(w, http.StatusForbidden, "forbidden — open the tokened URL printed by correlix-setup")
			return
		}
		if cookie != "" {
			http.SetCookie(w, &http.Cookie{
				Name: "cx_setup", Value: cookie, Path: "/",
				HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
			})
		}
		next(w, r)
	}
}

// secureHeaders stamps the H4 header set on every response; the HTML page
// handler overrides the CSP with its own (inline style/script) needs.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	ui, err := uiFS.ReadFile("ui.html")
	if err != nil {
		// go:embed guarantees presence at build time; defensive fallback only.
		ui = []byte("correlix-setup: embedded UI missing")
	}
	mux.HandleFunc("GET /", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-ancestors 'none'")
		if _, err := w.Write(ui); err != nil {
			return // client went away
		}
	}))
	mux.HandleFunc("GET /api/state", s.auth(s.apiState))
	mux.HandleFunc("GET /api/facts", s.auth(s.apiFacts))
	mux.HandleFunc("GET /api/stream", s.auth(s.apiStream))
	mux.HandleFunc("GET /api/support-bundle", s.auth(s.apiSupportBundle))
	mux.HandleFunc("POST /api/run/check", s.auth(s.apiCheck))
	mux.HandleFunc("POST /api/run/prepare", s.auth(s.apiPrepare))
	mux.HandleFunc("POST /api/run/install", s.auth(s.apiInstall))
	mux.HandleFunc("POST /api/watchdog", s.auth(s.apiWatchdog))
	mux.HandleFunc("POST /api/done", s.auth(s.apiDone))
	return secureHeaders(mux)
}

// ---------------------------------------------------------------------------
// TLS + launch

// mintCert creates an in-memory self-signed ECDSA P-256 serving certificate
// valid for one year (H1). Nothing is written to disk.
func mintCert(hosts []string, now time.Time) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "correlix-setup", Organization: []string{"Correlix"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return cert, certFingerprint(der), nil
}

// certFingerprint renders the SHA-256 of the DER certificate the way browsers
// display it: colon-separated uppercase hex pairs.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// listenAddr resolves the effective bind address: loopback by default, all
// interfaces only when the operator explicitly asked for --remote (H1).
func listenAddr(addrFlag string, remote bool) string {
	host, port, err := net.SplitHostPort(addrFlag)
	if err != nil {
		host, port = "", "8800"
	}
	if host == "" {
		if remote {
			host = "0.0.0.0"
		} else {
			host = "127.0.0.1"
		}
	}
	return net.JoinHostPort(host, port)
}

// lanIP returns the host's first non-loopback IPv4 address ("" if none).
func lanIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() {
			if v4 := ipn.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

func main() {
	addr := flag.String("addr", ":8800", "listen address (host defaults to 127.0.0.1 unless --remote)")
	remote := flag.Bool("remote", false, "bind all interfaces (0.0.0.0) so setup can be driven from another machine")
	bundle := flag.String("bundle", ".", "bundle directory (holds prepare-host.sh / install-correlix.sh)")
	flag.Parse()

	if abs, err := filepath.Abs(*bundle); err == nil {
		*bundle = abs // so the UI shows the real bundle name, not "."
	}
	for _, need := range []string{"prepare-host.sh", "install-correlix.sh"} {
		if _, err := os.Stat(filepath.Join(*bundle, need)); err != nil {
			log.Fatalf("not a Correlix bundle directory (missing %s): %s", need, *bundle)
		}
	}
	token, err := randomHex(16)
	if err != nil {
		log.Fatal(err)
	}
	s := newServer(*bundle, token, execRunner{})

	la := listenAddr(*addr, *remote)
	_, portStr, err := net.SplitHostPort(la)
	if err != nil {
		log.Fatalf("invalid listen address %q: %v", la, err)
	}
	if n, err := strconv.Atoi(portStr); err == nil {
		s.setupPort = n
	}

	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	lan := lanIP()
	sans := []string{"localhost", "127.0.0.1"}
	if host != "" {
		sans = append(sans, host)
	}
	if *remote && lan != "" {
		sans = append(sans, lan)
	}
	cert, fp, err := mintCert(sans, time.Now())
	if err != nil {
		log.Fatalf("could not mint the setup TLS certificate: %v", err)
	}

	done := make(chan struct{})
	var once sync.Once
	s.shutdownFn = func(reason string) {
		once.Do(func() {
			log.Printf("correlix-setup: shutting down (%s)", reason)
			close(done)
		})
	}

	srv := &http.Server{
		Addr:              la,
		Handler:           s.handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second, // §9: bound header IO (slowloris)
	}
	ln, err := net.Listen("tcp", la)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v", la, err)
	}

	fmt.Printf("\n  Correlix Setup is running (TLS).\n\n")
	if *remote {
		where := firstNonEmpty(lan, host, "0.0.0.0")
		fmt.Printf("  Open from your laptop:    https://%s/?t=%s\n", net.JoinHostPort(where, portStr), token)
	} else {
		fmt.Printf("  Open from this machine:   https://localhost:%s/?t=%s\n", portStr, token)
	}
	fmt.Printf("\n  Certificate SHA-256 fingerprint (compare in the browser's warning screen):\n    %s\n\n", fp)
	fmt.Printf("  (The link contains a one-time access token — treat it like a password.)\n\n")

	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx) // best-effort drain — the process is exiting either way
	}()
	if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
