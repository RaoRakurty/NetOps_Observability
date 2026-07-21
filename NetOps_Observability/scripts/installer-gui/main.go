// correlix-setup — the graphical installer for the Correlix appliance bundle.
//
// A single static binary (Go stdlib only, per the repo dependency rules) that
// ships inside the customer bundle and serves an embedded one-page setup
// wizard: system check → prepare host → install → live logs → credentials.
// It is a thin, safe orchestrator over the same battle-tested shell entry
// points the CLI path uses (prepare-host.sh / install-correlix.sh) — the GUI
// never re-implements install logic, so CLI and GUI can't drift apart.
//
// Zero-trust posture (§3/§8/§15):
//   - Every request must carry a one-time session token (printed at launch);
//     without it the server returns 403. The token cookie is HttpOnly.
//   - The API executes a FIXED set of commands (no request data ever reaches
//     a shell line — argv is constant; the only user input, the sudo
//     password, is written to sudo's stdin and never logged or echoed).
//   - Log streams are rendered client-side with textContent (no innerHTML).
//   - Binds 0.0.0.0 so a headless appliance can be set up from a laptop on
//     the LAN; the token gates it. Install-time plaintext HTTP is the same
//     trust model as the SSH session that copied the bundle in.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

// CheckItem is one PASS/FIX line from prepare-host.sh --check.
type CheckItem struct {
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

// state is the single wizard session. One installer, one host, one state.
type state struct {
	mu      sync.Mutex
	phase   Phase
	checks  []CheckItem
	err     string
	uiURL   string
	adminPW string

	logMu   sync.Mutex
	logBuf  []string
	waiters []chan string
}

// runner abstracts command execution so tests can fake the shell scripts.
type runner interface {
	// start launches argv (with optional stdin) and returns a line stream.
	start(dir string, stdin string, argv ...string) (io.ReadCloser, func() error, error)
}

type execRunner struct{}

func (execRunner) start(dir string, stdin string, argv ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	go func() {
		err := cmd.Wait()
		_ = pw.CloseWithError(err)
	}()
	return pr, func() error { return cmd.Wait() }, nil
}

type server struct {
	bundle string // bundle dir holding prepare-host.sh / install-correlix.sh
	token  string
	st     *state
	run    runner
}

func (s *server) appendLog(line string) {
	s.st.logMu.Lock()
	defer s.st.logMu.Unlock()
	s.st.logBuf = append(s.st.logBuf, line)
	if len(s.st.logBuf) > 5000 { // bounded buffer (§9)
		s.st.logBuf = s.st.logBuf[len(s.st.logBuf)-5000:]
	}
	for _, w := range s.st.waiters {
		select {
		case w <- line:
		default: // slow consumer: drop rather than block the installer
		}
	}
}

func (s *server) setPhase(p Phase, errMsg string) {
	s.st.mu.Lock()
	s.st.phase = p
	s.st.err = errMsg
	s.st.mu.Unlock()
	s.appendLog("::phase::" + string(p))
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// stream pumps a command's output into the log, returning its final error.
func (s *server) stream(rc io.ReadCloser, onLine func(string)) error {
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := ansiRE.ReplaceAllString(sc.Text(), "")
		s.appendLog(line)
		if onLine != nil {
			onLine(line)
		}
	}
	err := rc.Close()
	return err
}

// runPhase executes one fixed command as a wizard phase, in the background.
// Returns false if another phase is already running (single-flight).
func (s *server) runPhase(running Phase, done Phase, stdin string, onLine func(string), after func(failed bool, out []string), argv ...string) bool {
	s.st.mu.Lock()
	switch s.st.phase {
	case PhaseChecking, PhasePreparing, PhaseInstalling:
		s.st.mu.Unlock()
		return false
	}
	s.st.phase = running
	s.st.err = ""
	s.st.mu.Unlock()
	s.appendLog("::phase::" + string(running))

	go func() {
		var out []string
		collect := func(l string) {
			out = append(out, l)
			if onLine != nil {
				onLine(l)
			}
		}
		rc, _, err := s.run.start(s.bundle, stdin, argv...)
		if err == nil {
			err = s.stream(rc, collect)
		}
		failed := err != nil
		if after != nil {
			after(failed, out)
		} else if failed {
			s.setPhase(PhaseError, err.Error())
		} else {
			s.setPhase(done, "")
		}
	}()
	return true
}

var checkLineRE = regexp.MustCompile(`^\s*(PASS|FIX)\s+(.*)$`)

func (s *server) apiCheck(w http.ResponseWriter, _ *http.Request) {
	ok := s.runPhase(PhaseChecking, PhaseReady, "", nil, func(failed bool, out []string) {
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
		s.st.mu.Unlock()
		switch {
		case len(items) == 0 && failed:
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
	var body struct {
		SudoPassword string `json:"sudo_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.SudoPassword == "" {
		http.Error(w, `{"error":"sudo password required"}`, http.StatusBadRequest)
		return
	}
	// -S: password on stdin; -p '': no prompt garbage in the log; -k: don't
	// reuse a cached credential so a wrong password fails loudly here.
	ok := s.runPhase(PhasePreparing, PhaseIdle, body.SudoPassword+"\n", nil, func(failed bool, _ []string) {
		if failed {
			s.setPhase(PhaseError, "host preparation failed — check the sudo password and the log")
			return
		}
		s.appendLog("host prepared — re-running system check")
		s.st.mu.Lock()
		s.st.phase = PhaseIdle
		s.st.mu.Unlock()
		s.apiCheck(nil, nil) // writeJSON tolerates nil — internal re-check
	}, "sudo", "-k", "-S", "-p", "", "bash", "./prepare-host.sh")
	writeJSON(w, map[string]bool{"started": ok})
}

var (
	uiURLRE = regexp.MustCompile(`https?://[0-9a-zA-Z.:\-]+:8000\b`)
	adminRE = regexp.MustCompile(`^\s*Password:\s+(\S+)`)
)

func (s *server) apiInstall(w http.ResponseWriter, _ *http.Request) {
	ok := s.runPhase(PhaseInstalling, PhaseInstalled, "", func(l string) {
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
	}, nil, "bash", "./install-correlix.sh", "install")
	writeJSON(w, map[string]bool{"started": ok})
}

func (s *server) apiState(w http.ResponseWriter, r *http.Request) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	uiURL := s.st.uiURL
	if uiURL == "" {
		// Best guess for the success card before/without install output: the
		// appliance UI rides port 8000 on the same host the wizard is on.
		host := r.Host
		if i := strings.LastIndex(host, ":"); i > 0 {
			host = host[:i]
		}
		uiURL = "http://" + host + ":8000"
	}
	writeJSON(w, map[string]any{
		"phase":    s.st.phase,
		"checks":   s.st.checks,
		"error":    s.st.err,
		"ui_url":   uiURL,
		"admin_pw": s.st.adminPW,
		"bundle":   filepath.Base(s.bundle),
	})
}

// apiStream is the SSE live-log feed: history first, then follow.
func (s *server) apiStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")

	ch := make(chan string, 256)
	s.st.logMu.Lock()
	history := append([]string(nil), s.st.logBuf...)
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
			if !send("::ping::") {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// auth gates every route behind the one-time token: accepted once as ?t=
// (which sets an HttpOnly cookie), thereafter via the cookie.
func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		if tok == "" {
			if c, err := r.Cookie("cx_setup"); err == nil {
				tok = c.Value
			}
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
			http.Error(w, "Forbidden — open the tokened URL printed by correlix-setup", http.StatusForbidden)
			return
		}
		if r.URL.Query().Get("t") != "" {
			http.SetCookie(w, &http.Cookie{Name: "cx_setup", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		next(w, r)
	}
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	ui, _ := uiFS.ReadFile("ui.html")
	mux.HandleFunc("GET /", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'")
		_, _ = w.Write(ui)
	}))
	mux.HandleFunc("GET /api/state", s.auth(s.apiState))
	mux.HandleFunc("GET /api/stream", s.auth(s.apiStream))
	mux.HandleFunc("POST /api/run/check", s.auth(s.apiCheck))
	mux.HandleFunc("POST /api/run/prepare", s.auth(s.apiPrepare))
	mux.HandleFunc("POST /api/run/install", s.auth(s.apiInstall))
	return mux
}

func main() {
	addr := flag.String("addr", ":8800", "listen address")
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
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	s := &server{bundle: *bundle, token: hex.EncodeToString(b), st: &state{phase: PhaseIdle}, run: execRunner{}}

	host, _ := os.Hostname()
	fmt.Printf("\n  Correlix Setup is running.\n\n")
	fmt.Printf("  Open from this machine:   http://localhost%s/?t=%s\n", *addr, s.token)
	fmt.Printf("  Or from your laptop:      http://%s%s/?t=%s\n\n", host, *addr, s.token)
	fmt.Printf("  (The link contains a one-time access token — treat it like a password.)\n\n")
	log.Fatal(http.ListenAndServe(*addr, s.routes()))
}
