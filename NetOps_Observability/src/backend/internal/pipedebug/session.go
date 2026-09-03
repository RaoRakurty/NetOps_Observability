package pipedebug

// session.go — the on-disk session directory (design §3).
//
// Every run of every verb creates ONE directory,
// `data/debug/<UTC>-<verb>-<marker>/`, mode 0700, holding:
//
//	manifest.json      versions, flags, redaction, who ran it
//	summary.txt        the stage table a human reads first
//	timeline.json      machine-readable stage timeline
//	ingress.log parser.log kafka.log router.log
//	opensearch.log victoria.log clickhouse.log
//	correlation.log api.log ui.log
//
// Two rules the writer enforces rather than documents:
//
//  1. 0700 on the directory AND 0600 on every file. A session can contain
//     tenant telemetry and the operator's own device output (§3a: debug output
//     is platform-admin material, not world-readable).
//  2. A module file is NEVER left empty. An unobservable module gets exactly
//     one line saying so and why — an empty file reads as "nothing happened",
//     which is the silent-failure shape §10 exists to forbid.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// dirMode / fileMode: the session is operator-private (design §5).
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// Manifest is the session's provenance record.
type Manifest struct {
	Verb      string            `json:"verb"`
	Marker    string            `json:"marker,omitempty"`
	Kind      Kind              `json:"kind,omitempty"`
	Device    string            `json:"device,omitempty"`
	Tenant    string            `json:"tenant,omitempty"`
	Started   time.Time         `json:"started"`
	Finished  time.Time         `json:"finished,omitempty"`
	Actor     string            `json:"actor,omitempty"`
	APIBase   string            `json:"api_base,omitempty"`
	Flags     map[string]string `json:"flags,omitempty"`
	Redaction string            `json:"redaction"`
	Tool      string            `json:"tool"`
	Modules   []string          `json:"modules,omitempty"`
	// Warnings collects anything that degraded the run without failing it, so a
	// partial session says so on its face.
	Warnings []string `json:"warnings,omitempty"`
}

// Session is an open session directory. It is safe for concurrent use: the
// stage collectors run in parallel and each writes its own module file.
type Session struct {
	dir  string
	verb string

	mu     sync.Mutex
	files  map[Stage]*os.File
	opened map[Stage]bool
	man    Manifest
}

// sessionStamp renders the UTC directory prefix.
func sessionStamp(t time.Time) string { return t.UTC().Format("20060102T1504Z") }

// SessionDirName builds the session directory's base name. Every component is
// already validated (verb from a closed set, marker by ValidMarker), so the
// result can never escape the parent directory.
func SessionDirName(now time.Time, verb, marker string) string {
	return fmt.Sprintf("%s-%s-%s", sessionStamp(now), verb, marker)
}

// NewSession creates the session directory under root and opens one log file
// per module. `verb` and `marker` must already be validated by the caller.
func NewSession(root, verb, marker string, now time.Time, man Manifest) (*Session, error) {
	if verb == "" || strings.ContainsAny(verb, "/\\.") {
		return nil, fmt.Errorf("invalid verb %q", verb)
	}
	if marker != "" && !ValidMarker(marker) {
		return nil, errors.New("invalid marker for a session directory")
	}
	id := marker
	if id == "" {
		id = NewMarker(now)
	}
	dir := filepath.Join(root, SessionDirName(now, verb, id))
	if err := os.MkdirAll(root, dirMode); err != nil {
		return nil, fmt.Errorf("create debug root: %w", err)
	}
	if err := os.Mkdir(dir, dirMode); err != nil {
		return nil, fmt.Errorf("create session dir: %w", err)
	}
	// MkdirAll/Mkdir honour the umask, so an operator with a permissive umask
	// would otherwise get a group/world-readable session. Set it explicitly.
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("secure session dir: %w", err)
	}
	man.Started = now.UTC()
	man.Verb = verb
	if man.Marker == "" {
		man.Marker = marker
	}
	if man.Tool == "" {
		man.Tool = "correlix-debug"
	}
	if man.Redaction == "" {
		man.Redaction = RedactionNote
	}
	return &Session{
		dir: dir, verb: verb,
		files:  map[Stage]*os.File{},
		opened: map[Stage]bool{},
		man:    man,
	}, nil
}

// Dir returns the session directory path.
func (s *Session) Dir() string { return s.dir }

// SetMarker stamps the trace marker onto the manifest and onto every subsequent
// log line. It is separate from NewSession because the marker is minted by the
// API at injection time, AFTER the session directory has to exist (the Vector
// taps must already be attached — see cli/trace.go).
func (s *Session) SetMarker(marker string) error {
	if !ValidMarker(marker) {
		return errors.New("invalid marker")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.man.Marker = marker
	return nil
}

// Warn records a non-fatal degradation on the manifest.
func (s *Session) Warn(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.man.Warnings = append(s.man.Warnings, fmt.Sprintf(format, args...))
}

// file lazily opens a module's log file (0600) and writes its header line.
func (s *Session) file(st Stage) (*os.File, error) {
	if f, ok := s.files[st]; ok {
		return f, nil
	}
	// #nosec G304 -- st comes from the closed Stages table; LogFile() is a fixed
	// literal per stage, and s.dir was created by NewSession.
	f, err := os.OpenFile(filepath.Join(s.dir, st.LogFile()), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return nil, err
	}
	s.files[st] = f
	return f, nil
}

// Header writes the module file's FIRST line: which module, over what window,
// and HOW the lines below were obtained (design §3). Called once per module,
// before any content; a second call is a no-op.
func (s *Session) Header(st Stage, module, how string, window time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.opened[st] {
		return nil
	}
	f, err := s.file(st)
	if err != nil {
		return err
	}
	s.opened[st] = true
	line := map[string]any{
		"ts":     time.Now().UTC().Format(time.RFC3339Nano),
		"module": module,
		"level":  "info",
		"kind":   "header",
		"marker": s.man.Marker,
		"how":    how,
		"msg":    "module log opened",
	}
	if window > 0 {
		line["window"] = window.String()
	}
	return writeJSONLine(f, line)
}

// Line appends one structured record to a module's file. Every value passes
// through the redactor first (§5) — the session on disk is already safe to
// bundle, so `bundle` can never be the step that forgot.
func (s *Session) Line(st Stage, level, msg string, fields map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.file(st)
	if err != nil {
		return err
	}
	rec := map[string]any{
		"ts":     time.Now().UTC().Format(time.RFC3339Nano),
		"module": string(st),
		"level":  level,
		"marker": s.man.Marker,
		"msg":    RedactString(msg),
	}
	for k, v := range RedactFields(fields) {
		rec[k] = v
	}
	return writeJSONLine(f, rec)
}

// Raw appends one already-captured line (a docker-logs line, a tap event) to a
// module's file, redacted, wrapped so the file stays line-oriented JSON.
func (s *Session) Raw(st Stage, source, line string) error {
	return s.Line(st, "info", RedactString(line), map[string]any{"source": source, "raw": true})
}

// NotObservable writes the ONE line an unobservable module gets, and nothing
// else (design §3). The reason is mandatory: "not observable" with no cause is
// the same silent failure as an empty file.
func (s *Session) NotObservable(st Stage, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("NotObservable requires a reason")
	}
	if err := s.Header(st, string(st), "not observed", 0); err != nil {
		return err
	}
	return s.Line(st, "warn", "stage not observable", map[string]any{
		"verdict": string(VerdictNotObservable),
		"reason":  reason,
	})
}

// EnsureAllModules guarantees every module file in the design's §3 layout
// exists and is non-empty, writing the honest one-liner for any stage no
// collector reached. Called once at Close time.
func (s *Session) EnsureAllModules(reason func(Stage) string) error {
	var firstErr error
	for _, st := range Stages {
		s.mu.Lock()
		opened := s.opened[st]
		s.mu.Unlock()
		if opened {
			continue
		}
		r := "no collector ran for this stage in this session"
		if reason != nil {
			if got := strings.TrimSpace(reason(st)); got != "" {
				r = got
			}
		}
		if err := s.NotObservable(st, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WriteTimeline writes timeline.json.
func (s *Session) WriteTimeline(t Timeline) error {
	return s.writeFile("timeline.json", mustIndent(t))
}

// WriteSummary writes summary.txt — the stage table a human reads first.
func (s *Session) WriteSummary(text string) error {
	return s.writeFile("summary.txt", []byte(text))
}

// Close writes manifest.json (stamped with the finish time) and closes every
// module file. It is safe to call twice.
func (s *Session) Close(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.man.Finished = now.UTC()
	var firstErr error
	if err := s.writeFileLocked("manifest.json", mustIndent(s.man)); err != nil {
		firstErr = err
	}
	names := make([]Stage, 0, len(s.files))
	for st := range s.files {
		names = append(names, st)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, st := range names {
		if err := s.files[st].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(s.files, st)
	}
	return firstErr
}

func (s *Session) writeFile(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeFileLocked(name, data)
}

func (s *Session) writeFileLocked(name string, data []byte) error {
	return os.WriteFile(filepath.Join(s.dir, name), data, fileMode)
}

func writeJSONLine(f *os.File, rec map[string]any) error {
	// Marshal BEFORE writing (the F-21 ordering): an unencodable field must
	// fail here, not leave a half-written line in an evidence file.
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(buf, '\n')); err != nil {
		return err
	}
	return nil
}

func mustIndent(v any) []byte {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// Every value written here is a plain struct of strings/times/ints; an
		// error means a caller smuggled in a NaN. Fail loud in the file rather
		// than write nothing.
		return []byte(fmt.Sprintf("{\"error\":%q}\n", err.Error()))
	}
	return append(buf, '\n')
}

// ListSessions returns session directories under root, newest first (the
// directory name's UTC stamp sorts lexicographically, which is why it is
// formatted that way).
func ListSessions(root string) ([]string, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, filepath.Join(root, e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}
