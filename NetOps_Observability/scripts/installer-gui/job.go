// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Detached install job: launch, job-state file, log follower, re-attach and
// settlement (FMEA 2026-09-15 §2 row 2, §3.1 G1-G7, §3.9).
//
// Why: on 2026-09-14 restarting correlix-setup killed an in-flight install
// (the child's stdout was a pipe owned by the wizard) and on 2026-09-15 the
// wizard stopped itself 15 minutes after a failed install, leaving the owner
// nothing to reconnect to. The install is now a job the wizard FOLLOWS, not a
// child it owns:
//
//   - The engine runs in its own session (setsid) with stdout/stderr going
//     straight to a 0600 log file, so a wizard crash, restart, Ctrl-C or
//     terminal hang-up cannot reach it. systemd-run (cgroup-level stop, a
//     journal) is future work — FMEA §7 Q2; setsid is the decided default.
//   - A small 0600 job-state file next to the log records pid + kernel start
//     time, argv[0..1], the log path, the validated (secret-free) profile, and
//     on completion the outcome. It never holds a secret.
//   - Every wizard — the one that launched the job or one started later —
//     follows the LOG FILE, so re-attaching streams progress exactly like the
//     original launch. Liveness is judged from /proc: pid + start time +
//     cmdline, or any surviving member of the job's session.
//   - A dead job with no recorded exit is settled from the log: its result
//     marker if the engine got that far, otherwise "interrupted", with a safe
//     re-run using the recorded answers (the installer is idempotent).
//   - The initial administrator password is redacted from every line before it
//     is buffered, scrubbed from the log once the job settles, and handed to
//     the authenticated page exactly once (POST /api/credential).
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	jobFileName       = "correlix-setup-install.job.json" // next to the job logs, in the bundle dir
	jobLockName       = "correlix-setup-install.lock"     // serialises "is one alive? → launch"
	jobLogPrefix      = "correlix-setup-install-"
	jobLogSuffix      = ".log"
	jobFileMaxBytes   = 256 << 10 // bound the job-state read (§9)
	jobLogMaxReplay   = 64 << 20  // a re-attach replays at most the last 64 MiB
	jobLogMaxLine     = 1 << 20   // one line is flushed at 1 MiB even without a newline
	jobSessionDrain   = 15 * time.Second
	defaultJobPoll    = time.Second
	defaultTailPoll   = 250 * time.Millisecond
	defaultHeartbeat  = 15 * time.Second
	interruptedStage  = "stopped here — the installer was interrupted"
	outcomeOK         = "ok"
	outcomeFail       = "fail"
	outcomeInterrupt  = "interrupted"
	settledByWait     = "wait"             // this wizard reaped the child: exit code known
	settledByMarker   = "log-marker"       // dead job, verdict taken from its result marker
	settledByNoMarker = "no-result-marker" // dead job that never reported: interrupted
)

// jobState is the on-disk job record. Secret-free by construction: the profile
// is the validated, secret-free Profile (H7), argv stops at [0..1], and the
// credential is represented only by whether it has been shown.
type jobState struct {
	Version         int      `json:"version"`
	Pid             int      `json:"pid"`
	ProcStart       string   `json:"proc_start,omitempty"` // /proc/<pid>/stat field 22 — defeats pid reuse
	StartedUTC      string   `json:"started_utc"`
	Argv0           string   `json:"argv0"`
	Argv1           string   `json:"argv1"`
	Log             string   `json:"log"`
	Detached        bool     `json:"detached"`
	ProfileFile     string   `json:"profile_file,omitempty"`
	Profile         *Profile `json:"profile,omitempty"`
	EndedUTC        string   `json:"ended_utc,omitempty"`
	ExitCode        *int     `json:"exit_code,omitempty"`
	Outcome         string   `json:"outcome,omitempty"`
	SettledBy       string   `json:"settled_by,omitempty"`
	CredentialShown bool     `json:"credential_shown,omitempty"`
}

// detachedProc is a started install job.
type detachedProc struct {
	pid       int    // 0 when the runner could not detach (test runners)
	procStart string // kernel start time of pid, "" when unknown
	wait      func() (exitCode int, err error)
}

// detachedStarter is implemented by runners that can launch a job which
// survives this process. execRunner does; test fakes do not, and are followed
// through the same log-file path by startAttachedToLog.
type detachedStarter interface {
	startDetached(dir string, logFile *os.File, extraEnv []string, argv ...string) (detachedProc, error)
}

// jobExit is how a follower learns the job ended.
type jobExit struct {
	known bool // exit status observed by this process (Wait)
	code  int
	err   error
}

// startDetached runs argv in a new session with stdout/stderr on logFile. The
// file is closed in this process once the child holds its own descriptor.
func (execRunner) startDetached(dir string, logFile *os.File, extraEnv []string, argv ...string) (detachedProc, error) {
	// #nosec G204 — I1: argv is the fixed install vocabulary built by
	// installArgv; no request data reaches a shell string.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdin = nil // /dev/null: the engine is unattended (--config)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Own session and process group: a terminal hang-up, Ctrl-C to the
	// wizard's group, or the wizard exiting never signals the install.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Start()
	if cerr := logFile.Close(); err == nil && cerr != nil {
		// The child already holds its own descriptor; a close error here is
		// reported but does not stop a running install.
		log.Printf("correlix-setup: closing the install log in the wizard: %v", cerr)
	}
	if err != nil {
		return detachedProc{}, err
	}
	pid := cmd.Process.Pid
	start, serr := procStartTime("/proc", pid)
	if serr != nil {
		log.Printf("correlix-setup: install pid %d start time unreadable (%v) — a later wizard cannot re-attach to it", pid, serr)
	}
	return detachedProc{pid: pid, procStart: start, wait: func() (int, error) {
		werr := cmd.Wait()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		return code, werr
	}}, nil
}

// startAttachedToLog adapts a runner that cannot detach (test fakes) to the
// same log-file pipeline: its output is copied into the job log.
func (s *server) startAttachedToLog(logFile *os.File, extraEnv []string, argv ...string) (detachedProc, error) {
	rc, err := s.run.start(s.bundle, nil, extraEnv, argv...)
	if err != nil {
		if cerr := logFile.Close(); cerr != nil {
			log.Printf("correlix-setup: closing the install log: %v", cerr)
		}
		return detachedProc{}, err
	}
	return detachedProc{wait: func() (int, error) {
		_, cerr := io.Copy(logFile, rc)
		rerr := rc.Close()
		ferr := logFile.Close()
		err := errors.Join(cerr, rerr, ferr)
		if err != nil {
			return -1, err
		}
		return 0, nil
	}}, nil
}

// createJobLog creates a fresh 0600 install log in dir.
func createJobLog(dir string, now time.Time) (*os.File, string, error) {
	f, err := os.CreateTemp(dir, jobLogPrefix+now.UTC().Format("20060102-150405")+"-*"+jobLogSuffix)
	if err != nil {
		return nil, "", err
	}
	return f, f.Name(), nil
}

// writeJobState writes j atomically (temp file + rename), mode 0600.
func writeJobState(path string, j *jobState) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".job-*.tmp") // 0600 by contract of CreateTemp
	if err != nil {
		return err
	}
	// No fsync, deliberately: the record is advisory (a missing or corrupt file
	// only means "nothing to re-attach to"), and on the slow disks this wizard
	// must survive a single fsync can take seconds (FMEA §1.1, H1).
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		if rerr := os.Remove(f.Name()); rerr != nil && !os.IsNotExist(rerr) {
			err = errors.Join(err, rerr)
		}
		return err
	}
	return nil
}

var validOutcomes = map[string]bool{"": true, outcomeOK: true, outcomeFail: true, outcomeInterrupt: true}

// readJobState reads and validates a job-state file. Its content is treated as
// untrusted (§3): a log path outside dir or an unknown outcome is rejected.
func readJobState(path string) (*jobState, error) {
	// #nosec G304 — path is the fixed job file name joined to the bundle dir.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // read-only handle
	var j jobState
	if err := json.NewDecoder(io.LimitReader(f, jobFileMaxBytes)).Decode(&j); err != nil {
		return nil, fmt.Errorf("job-state file %s: %v", filepath.Base(path), err)
	}
	dir := filepath.Dir(path)
	if !insideDir(dir, j.Log) || !strings.HasPrefix(filepath.Base(j.Log), jobLogPrefix) || !strings.HasSuffix(j.Log, jobLogSuffix) {
		return nil, fmt.Errorf("job-state file %s: log path is not a wizard install log in %s", filepath.Base(path), dir)
	}
	if j.ProfileFile != "" && (!insideDir(dir, j.ProfileFile) || !strings.HasPrefix(filepath.Base(j.ProfileFile), "correlix-profile-")) {
		return nil, fmt.Errorf("job-state file %s: profile path is not a wizard profile in %s", filepath.Base(path), dir)
	}
	if !validOutcomes[j.Outcome] || j.Pid < 0 {
		return nil, fmt.Errorf("job-state file %s: invalid outcome or pid", filepath.Base(path))
	}
	return &j, nil
}

// insideDir reports whether p is a plain file path directly inside dir.
func insideDir(dir, p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	return filepath.Clean(filepath.Dir(p)) == filepath.Clean(dir)
}

// ---------------------------------------------------------------------------
// /proc inspection

// procStat is the part of /proc/<pid>/stat the job liveness check needs.
type procStat struct {
	state   byte
	session int
	start   string
}

func readProcStat(procRoot string, pid int) (procStat, error) {
	b, err := readBounded(filepath.Join(procRoot, strconv.Itoa(pid), "stat"), 4096)
	if err != nil {
		return procStat{}, err
	}
	// The comm field is parenthesised and may itself contain spaces or ')'.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return procStat{}, fmt.Errorf("pid %d: malformed stat", pid)
	}
	f := strings.Fields(string(b)[i+1:])
	// f[0] is field 3 (state), f[3] field 6 (session), f[19] field 22 (starttime).
	if len(f) < 20 || len(f[0]) != 1 {
		return procStat{}, fmt.Errorf("pid %d: short stat", pid)
	}
	sid, err := strconv.Atoi(f[3])
	if err != nil {
		return procStat{}, fmt.Errorf("pid %d: session: %v", pid, err)
	}
	return procStat{state: f[0][0], session: sid, start: f[19]}, nil
}

func procStartTime(procRoot string, pid int) (string, error) {
	st, err := readProcStat(procRoot, pid)
	if err != nil {
		return "", err
	}
	return st.start, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	// #nosec G304 — procfs paths built from an integer pid.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // read-only handle
	return io.ReadAll(io.LimitReader(f, max))
}

// installCmdline reports whether a process's cmdline belongs to the install
// engine: the entry script, install.py, or the engine's own log tee.
func installCmdline(procRoot string, pid int) bool {
	b, err := readBounded(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"), 64<<10)
	if err != nil {
		return false
	}
	for _, arg := range strings.Split(string(b), "\x00") {
		if strings.Contains(arg, "install-correlix.sh") || strings.Contains(arg, "install.py") ||
			strings.Contains(arg, "correlix-install-") {
			return true
		}
	}
	return false
}

func startNotBefore(start, floor string) bool {
	a, err1 := strconv.ParseUint(start, 10, 64)
	b, err2 := strconv.ParseUint(floor, 10, 64)
	return err1 == nil && err2 == nil && a >= b
}

// jobAlive reports whether the job is still running: its session leader is
// alive with the recorded start time and an install cmdline, or some member of
// its session (sid == pid, started no earlier than the leader) is an install
// process. A session id cannot be handed to a new process while any member
// still uses it, which is what makes the member scan safe after the leader
// died (e.g. `exec > >(tee …)` outliving bash).
func (s *server) jobAlive(j *jobState) bool {
	if j == nil || j.Pid <= 1 || j.ProcStart == "" {
		return false
	}
	if st, err := readProcStat(s.procRoot, j.Pid); err == nil && st.state != 'Z' &&
		st.start == j.ProcStart && installCmdline(s.procRoot, j.Pid) {
		return true
	}
	return len(s.sessionMembers(j, true)) > 0
}

// sessionMembers lists live processes in the job's session. With needInstall
// only processes whose cmdline belongs to the engine count.
func (s *server) sessionMembers(j *jobState, needInstall bool) []int {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == j.Pid {
			continue
		}
		st, err := readProcStat(s.procRoot, pid)
		if err != nil || st.session != j.Pid || st.state == 'Z' || !startNotBefore(st.start, j.ProcStart) {
			continue
		}
		if needInstall && !installCmdline(s.procRoot, pid) {
			continue
		}
		out = append(out, pid)
	}
	return out
}

// ---------------------------------------------------------------------------
// Redaction (FMEA row 6, GUI side)

// secretValueRE finds "<secret-ish key><sep><value>" in engine output: the
// success banner's "Password: …", dotenv "ADMIN_INITIAL_PASSWORD=…", and JSON
// "password":"…". Over-redacting a harmless word is the accepted cost.
var secretValueRE = regexp.MustCompile(`(?i)((?:password|passwd|passphrase|secret|token|api[_-]?key)[A-Za-z0-9_]*"?\s*[:=]\s*"?)([^\s",]+)`)

const redacted = "<redacted>"

// redactSecrets removes credential-looking values and every known secret value
// (at least 8 characters, so a short common word is never blanked) from line.
func redactSecrets(line string, known ...string) string {
	for _, k := range known {
		if len(k) >= 8 {
			line = strings.ReplaceAll(line, k, redacted)
		}
	}
	return secretValueRE.ReplaceAllString(line, "${1}"+redacted)
}

// scrubLogFile rewrites path with every line redacted (temp + rename, 0600).
// Lines are compared ANSI-stripped so a bold-wrapped value is still caught.
func scrubLogFile(path string, known ...string) error {
	// #nosec G304 — path comes from a validated job-state file (insideDir).
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close() // read-only handle
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > jobLogMaxReplay {
		return fmt.Errorf("%s is %d bytes — too large to scrub in place", filepath.Base(path), fi.Size())
	}
	out, err := os.CreateTemp(filepath.Dir(path), ".scrub-*.tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	r := bufio.NewReaderSize(in, 64<<10)
	changed := false
	for {
		chunk, rerr := r.ReadString('\n')
		if len(chunk) > 0 {
			body := strings.TrimRight(chunk, "\n")
			plain := ansiRE.ReplaceAllString(body, "")
			if red := redactSecrets(plain, known...); red != plain {
				body, changed = red, true
			}
			if _, werr := w.WriteString(body); werr != nil {
				err = werr
				break
			}
			if strings.HasSuffix(chunk, "\n") {
				if werr := w.WriteByte('\n'); werr != nil {
					err = werr
					break
				}
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				err = rerr
			}
			break
		}
	}
	if err == nil {
		err = w.Flush()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && changed {
		err = os.Rename(out.Name(), path)
	}
	if err != nil || !changed {
		if rerr := os.Remove(out.Name()); rerr != nil && !os.IsNotExist(rerr) {
			err = errors.Join(err, rerr)
		}
	}
	return err
}

// ---------------------------------------------------------------------------
// Launch

// jobLock takes the non-blocking single-launcher lock in the bundle dir. Two
// wizard processes (two ports, two tabs) cannot race "is one alive? → launch".
func (s *server) jobLock() (release func(), err error) {
	// #nosec G304 — fixed lock name in the bundle dir.
	f, err := os.OpenFile(filepath.Join(s.bundle, jobLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	// #nosec G115 — a file descriptor always fits in an int.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		return nil, err
	}
	return func() {
		// Closing the descriptor releases the flock.
		if cerr := f.Close(); cerr != nil {
			log.Printf("correlix-setup: releasing the install lock: %v", cerr)
		}
	}, nil
}

// installBusy reports whether an install (or any other job) holds the guard.
// Caller holds s.st.mu.
func (s *server) installBusyLocked() bool {
	return s.st.phase == PhaseChecking || s.st.phase == PhasePreparing ||
		s.st.phase == PhaseInstalling || s.st.watchdogBusy || s.st.following
}

// beginInstall launches profile p as a detached job and starts following it.
// It writes the HTTP response itself.
func (s *server) beginInstall(w http.ResponseWriter, key string, p Profile) {
	release, err := s.jobLock()
	if err != nil {
		writeErr(w, http.StatusConflict, "another correlix-setup is starting an install on this bundle right now")
		return
	}
	defer release()

	if prev, rerr := readJobState(filepath.Join(s.bundle, jobFileName)); rerr == nil && prev.Outcome == "" && s.jobAlive(prev) {
		writeErr(w, http.StatusConflict, fmt.Sprintf(
			"an install started at %s is still running (pid %d) — this page now follows it", prev.StartedUTC, prev.Pid))
		go s.recoverJob() // adopt it so the page shows its progress
		return
	} else if rerr != nil && !os.IsNotExist(rerr) {
		log.Printf("correlix-setup: ignoring the previous job-state file: %v", rerr)
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
	logFile, logPath, err := createJobLog(s.bundle, s.now())
	if err != nil {
		s.removeQuiet(cfgPath)
		writeErr(w, http.StatusInternalServerError, "could not create the install log: "+err.Error())
		return
	}

	s.st.mu.Lock()
	if s.installBusyLocked() {
		s.st.mu.Unlock()
		if cerr := logFile.Close(); cerr != nil {
			log.Printf("correlix-setup: closing an unused install log: %v", cerr)
		}
		s.removeQuiet(logPath)
		s.removeQuiet(cfgPath)
		writeErr(w, http.StatusConflict, "another job is already running")
		return
	}
	s.st.phase = PhaseInstalling
	s.st.err = ""
	s.st.stages = nil // G6: a retry never inherits the previous run's verdict
	s.st.result = nil
	s.st.adminPW = ""
	s.st.credShown = false
	s.st.lastOutput = s.now()
	s.st.installKey = key
	s.st.following = true
	s.st.jobReattached = false
	s.st.job = nil
	s.st.mu.Unlock()
	s.resetEvents()
	s.emit(mustJSON(map[string]string{"kind": "phase", "phase": string(PhaseInstalling)}))

	// PYTHONUNBUFFERED keeps install.py's lines (and markers) in order in the
	// log the wizard follows (FMEA row 14).
	env := []string{"CORRELIX_PROGRESS_JSON=1", "PYTHONUNBUFFERED=1"}
	var proc detachedProc
	if ds, ok := s.run.(detachedStarter); ok {
		proc, err = ds.startDetached(s.bundle, logFile, env, argv...)
	} else {
		proc, err = s.startAttachedToLog(logFile, env, argv...)
	}
	if err != nil {
		s.removeQuiet(cfgPath)
		s.st.mu.Lock()
		s.st.following = false
		s.st.result = &Result{Status: outcomeFail}
		s.st.mu.Unlock()
		s.setPhase(PhaseError, "the installer could not start: "+err.Error())
		s.emit(mustJSON(map[string]string{"kind": "result", "status": outcomeFail, "message": "the installer could not start"}))
		writeErr(w, http.StatusInternalServerError, "could not start the installer: "+err.Error())
		return
	}
	job := &jobState{
		Version: 1, Pid: proc.pid, ProcStart: proc.procStart, StartedUTC: s.now().UTC().Format(time.RFC3339),
		Argv0: argv[0], Argv1: argv[1], Log: logPath, Detached: proc.pid > 0, ProfileFile: cfgPath, Profile: &p,
	}
	if err := writeJobState(filepath.Join(s.bundle, jobFileName), job); err != nil {
		// The install is already running; only re-attach is lost. Loud, not fatal.
		s.appendLog("warning: could not record the install job (a restarted wizard cannot re-attach): " + err.Error())
		log.Printf("correlix-setup: writing the job-state file: %v", err)
	}
	s.st.mu.Lock()
	s.st.job = job
	s.st.mu.Unlock()

	done := make(chan jobExit, 1)
	go func() {
		code, werr := proc.wait()
		if proc.pid > 0 {
			s.waitSessionEmpty(job, jobSessionDrain)
		}
		done <- jobExit{known: true, code: code, err: werr}
	}()
	go s.follow(job, done)
	s.disarmShutdown() // a fresh install cancels any pending auto-stop
	writeJSON(w, map[string]any{"started": true, "job": "new"})
}

// waitSessionEmpty gives processes left in the job's session (the engine's log
// tee) a bounded moment to write their last lines before the final drain.
func (s *server) waitSessionEmpty(j *jobState, max time.Duration) {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if len(s.sessionMembers(j, false)) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Printf("correlix-setup: install pid %d exited but its session still has processes after %s — settling anyway", j.Pid, max)
}

// ---------------------------------------------------------------------------
// Follow + settle

// follow tails the job log from the start through perInstallLine until the
// job has ended and the log is drained, then settles the job.
func (s *server) follow(j *jobState, done <-chan jobExit) {
	var ex jobExit
	// #nosec G304 — j.Log is validated (readJobState) or server-created.
	f, err := os.Open(j.Log)
	if err != nil {
		s.appendLog("the install log cannot be read: " + err.Error())
		ex = <-done
		s.settle(j, ex)
		return
	}
	defer f.Close() // read-only handle
	if fi, serr := f.Stat(); serr == nil && fi.Size() > jobLogMaxReplay {
		if _, err := f.Seek(fi.Size()-jobLogMaxReplay, io.SeekStart); err != nil {
			s.appendLog("the install log cannot be replayed: " + err.Error())
		} else {
			s.appendLog("(showing only the last 64 MiB of the install log)")
		}
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var partial strings.Builder
	drain := func() error {
		for {
			chunk, rerr := r.ReadString('\n')
			if len(chunk) > 0 {
				partial.WriteString(chunk)
				if strings.HasSuffix(chunk, "\n") || partial.Len() >= jobLogMaxLine {
					s.perInstallLine(strings.TrimRight(partial.String(), "\r\n"))
					partial.Reset()
				}
			}
			if rerr == io.EOF {
				return nil
			}
			if rerr != nil {
				return rerr
			}
		}
	}
	exited := false
	for {
		if !exited {
			select {
			case ex = <-done:
				exited = true
			default:
			}
		}
		// Read what is there; exit only after a full drain that began AFTER the
		// job was known to have ended, so no final line is lost.
		if err := drain(); err != nil {
			s.appendLog("reading the install log failed: " + err.Error())
			if !exited {
				ex = <-done
			}
			break
		}
		if exited {
			break
		}
		time.Sleep(s.tailPoll)
	}
	if partial.Len() > 0 {
		s.perInstallLine(strings.TrimRight(partial.String(), "\r\n"))
	}
	s.settle(j, ex)
}

// perInstallLine handles one engine output line: scrape (in memory only),
// redact, then marker or log.
func (s *server) perInstallLine(raw string) {
	line := ansiRE.ReplaceAllString(raw, "")
	s.st.mu.Lock()
	s.st.lastOutput = s.now()
	if m := uiURLRE.FindString(line); m != "" {
		s.st.uiURL = m
	}
	if m := adminRE.FindStringSubmatch(line); m != nil && !s.st.credShown {
		s.st.adminPW = m[1] // held in memory for the one-time handover only
	}
	known := s.st.adminPW
	s.st.mu.Unlock()
	line = redactSecrets(line, known)
	if s.handleMarker(line) {
		return
	}
	s.appendLog(line)
}

// settle decides the job's outcome, updates wizard state, persists the
// job-state file and scrubs the log.
func (s *server) settle(j *jobState, ex jobExit) {
	s.st.mu.Lock()
	res := s.st.result
	outcome, via := j.Outcome, j.SettledBy
	credShownBefore := j.CredentialShown
	recordedCode := j.ExitCode
	s.st.mu.Unlock()

	var code *int
	// finalize publishes the terminal phase. It runs only AFTER the job-state
	// file and the log scrub are on disk, so anything that observes
	// installed/error also observes a consistent record.
	var finalize func()
	switch {
	case outcome != "": // settled by an earlier wizard: restore, do not re-judge
		code = recordedCode
	case ex.known:
		via = settledByWait
		c := ex.code
		code = &c
		outcome = outcomeOK
		if ex.err != nil || (res != nil && res.Status != outcomeOK) {
			outcome = outcomeFail
		}
	case res != nil && (res.Status == outcomeOK || res.Status == outcomeFail):
		outcome, via = res.Status, settledByMarker
	default:
		outcome, via = outcomeInterrupt, settledByNoMarker
	}

	switch outcome {
	case outcomeOK:
		env := readFileOr(s.envPath())
		adminUser := envValue(env, "ADMIN_USERNAME")
		adminPW := envValue(env, "ADMIN_INITIAL_PASSWORD")
		s.st.mu.Lock()
		if adminUser != "" {
			s.st.adminUser = adminUser
		}
		if credShownBefore || s.st.credShown {
			s.st.credShown = true
			s.st.adminPW = ""
		} else if adminPW != "" {
			s.st.adminPW = adminPW // .env is authoritative; the banner scrape was the fallback
		}
		if s.st.result == nil {
			// Engine predates result markers — synthesize from the banner scrape.
			s.st.result = &Result{Status: outcomeOK, URL: s.st.uiURL, AdminUser: firstNonEmpty(adminUser, "admin")}
		} else if adminUser != "" {
			s.st.result.AdminUser = adminUser
		}
		synth := res == nil
		url := s.st.result.URL
		s.st.mu.Unlock()
		finalize = func() {
			s.st.mu.Lock()
			s.st.following = false
			s.st.mu.Unlock()
			s.setPhase(PhaseInstalled, "")
			if synth {
				s.emit(mustJSON(map[string]string{"kind": "result", "status": outcomeOK, "url": url}))
			}
			s.armShutdown(resultShutdown, "install finished and the success screen was never acknowledged")
		}
	case outcomeFail, outcomeInterrupt:
		msg := "installation failed — see the log and the support bundle"
		if ex.known && ex.err != nil {
			msg = "installation failed: " + ex.err.Error()
		}
		if outcome == outcomeInterrupt {
			msg = "the installer stopped without reporting a result (it was interrupted) — it is safe to run it again"
		}
		var marked []Stage
		s.st.mu.Lock()
		synth := s.st.result == nil || s.st.result.Status != outcome
		if synth {
			s.st.result = &Result{Status: outcome, URL: s.st.uiURL}
		}
		if outcome == outcomeInterrupt {
			for i := range s.st.stages {
				if s.st.stages[i].Status == "start" {
					s.st.stages[i].Status = "fail"
					s.st.stages[i].Message = interruptedStage
					marked = append(marked, s.st.stages[i])
				}
			}
		}
		s.st.mu.Unlock()
		finalOutcome, finalVia := outcome, via
		finalize = func() {
			s.st.mu.Lock()
			s.st.following = false
			s.st.mu.Unlock()
			for _, st := range marked {
				s.emit(mustJSON(st.event()))
			}
			s.setPhase(PhaseError, msg)
			if synth {
				// G4: the page ends its progress view on a result event; a child
				// that died without a marker must still produce one.
				s.emit(mustJSON(map[string]string{"kind": "result", "status": finalOutcome, "message": msg}))
			}
			// G3: never auto-stop after a failure. The operator closes the wizard.
			s.disarmShutdown()
			log.Printf("correlix-setup: install %s (%s) — staying up until the operator closes this wizard", finalOutcome, finalVia)
		}
	}

	s.st.mu.Lock()
	if j.Outcome == "" {
		j.Outcome, j.SettledBy, j.ExitCode = outcome, via, code
		j.EndedUTC = s.now().UTC().Format(time.RFC3339)
	}
	j.CredentialShown = j.CredentialShown || s.st.credShown
	snapshot := *j
	known := s.st.adminPW
	s.st.mu.Unlock()
	if err := writeJobState(filepath.Join(s.bundle, jobFileName), &snapshot); err != nil {
		s.appendLog("warning: could not record the install result: " + err.Error())
	}
	if known == "" {
		known = envValue(readFileOr(s.envPath()), "ADMIN_INITIAL_PASSWORD")
	}
	if err := scrubLogFile(j.Log, known); err != nil && !os.IsNotExist(err) {
		s.appendLog("warning: could not scrub credentials from " + filepath.Base(j.Log) + ": " + err.Error())
	}
	if snapshot.ProfileFile != "" {
		// The answers live on in the job-state file (for a safe re-run).
		s.removeQuiet(snapshot.ProfileFile)
	}
	if finalize != nil {
		finalize()
	}
}

func (st Stage) event() map[string]string {
	ev := map[string]string{"kind": "stage", "id": st.ID, "title": st.Title, "status": st.Status}
	if st.Message != "" {
		ev["message"] = st.Message
	}
	return ev
}

// recoverJob re-attaches to the install recorded in the job-state file: a live
// job is followed, a dead or settled one is replayed and settled. Safe to call
// at any time; it does nothing while this wizard already follows a job.
func (s *server) recoverJob() {
	j, err := readJobState(filepath.Join(s.bundle, jobFileName))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("correlix-setup: not re-attaching: %v", err)
		}
		return
	}
	s.st.mu.Lock()
	if s.installBusyLocked() {
		s.st.mu.Unlock()
		return
	}
	s.st.following = true
	s.st.job = j
	s.st.jobReattached = true
	s.st.stages = nil
	s.st.result = nil
	s.st.adminPW = ""
	s.st.credShown = j.CredentialShown
	s.st.err = ""
	s.st.lastOutput = s.now()
	alive := j.Outcome == "" && s.jobAlive(j)
	if alive {
		s.st.phase = PhaseInstalling
	}
	s.st.mu.Unlock()
	s.resetEvents()

	if !alive {
		ended := make(chan jobExit, 1)
		ended <- jobExit{}
		log.Printf("correlix-setup: replaying the install recorded in %s (not running)", jobFileName)
		s.follow(j, ended) // synchronous: state is ready before the page asks
		return
	}
	s.emit(mustJSON(map[string]string{"kind": "phase", "phase": string(PhaseInstalling)}))
	log.Printf("correlix-setup: re-attached to the running install (pid %d, log %s)", j.Pid, filepath.Base(j.Log))
	done := make(chan jobExit, 1)
	go func() {
		for s.jobAlive(j) {
			time.Sleep(s.jobPoll)
		}
		done <- jobExit{}
	}()
	go s.follow(j, done)
}

// ---------------------------------------------------------------------------
// API: resume + one-time credential

// apiResume runs the last install again with its RECORDED answers — a page
// reloaded after a wizard restart has lost the form, and re-running with its
// defaults could silently change TLS or the administrator name.
func (s *server) apiResume(w http.ResponseWriter, r *http.Request) {
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
	busy := s.installBusyLocked()
	s.st.mu.Unlock()
	if busy {
		writeErr(w, http.StatusConflict, "another job is already running")
		return
	}
	j, err := readJobState(filepath.Join(s.bundle, jobFileName))
	switch {
	case err != nil:
		writeErr(w, http.StatusConflict, "there is no earlier install to run again — start from the Review step")
		return
	case j.Outcome == "" && s.jobAlive(j):
		writeErr(w, http.StatusConflict, "the earlier install is still running — this page now follows it")
		go s.recoverJob()
		return
	case j.Outcome == outcomeOK:
		writeErr(w, http.StatusConflict, "the last install succeeded — there is nothing to run again")
		return
	case j.Profile == nil:
		writeErr(w, http.StatusConflict, "the earlier install's answers were not recorded — start from the Review step")
		return
	}
	p := *j.Profile
	if err := validateProfile(&p); err != nil { // the file is untrusted input (§3)
		writeErr(w, http.StatusBadRequest, "the recorded answers are invalid: "+err.Error())
		return
	}
	s.beginInstall(w, key, p)
}

// apiCredential hands the initial administrator password to the authenticated
// page exactly once (H2/I5). It is never part of /api/state, never logged,
// and never written to disk by the wizard; afterwards the operator is pointed
// at .env on the server.
func (s *server) apiCredential(w http.ResponseWriter, _ *http.Request) {
	s.st.mu.Lock()
	if s.st.phase != PhaseInstalled || s.st.result == nil || s.st.result.Status != outcomeOK {
		s.st.mu.Unlock()
		writeErr(w, http.StatusConflict, "there is no finished install to hand a credential over for")
		return
	}
	if s.st.credShown {
		s.st.mu.Unlock()
		writeErr(w, http.StatusGone, "the initial password was already shown once — read ADMIN_INITIAL_PASSWORD in deployment/docker/.env on this server")
		return
	}
	pw := s.st.adminPW
	if pw == "" {
		s.st.mu.Unlock()
		writeErr(w, http.StatusNotFound, "the initial password is not available here — read ADMIN_INITIAL_PASSWORD in deployment/docker/.env on this server")
		return
	}
	s.st.credShown = true
	s.st.adminPW = ""
	user := firstNonEmpty(s.st.adminUser, s.st.result.AdminUser, "admin")
	url := firstNonEmpty(s.st.result.URL, s.st.uiURL)
	j := s.st.job
	var snapshot jobState
	if j != nil {
		j.CredentialShown = true
		snapshot = *j
	}
	s.st.mu.Unlock()
	if j != nil {
		if err := writeJobState(filepath.Join(s.bundle, jobFileName), &snapshot); err != nil {
			log.Printf("correlix-setup: recording that the credential was shown: %v", err)
		}
	}
	writeJSON(w, map[string]string{"admin_user": user, "admin_password": pw, "url": url})
}
