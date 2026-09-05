package pipedebug

// sessions.go — the SESSION routes: what the GUI reads when it opens a past
// trace instead of running a new one (design §3, W3).
//
//	GET /api/debug/sessions                      the index, newest first
//	GET /api/debug/sessions/{id}                 manifest + timeline + summary
//	GET /api/debug/sessions/{id}/module/{module} one module's log file, bounded
//	GET /api/debug/sessions/{id}/bundle          the redacted, checksummed tar.gz
//
// WHY THE API SERVES THEM AT ALL. The session directory is the debugger's whole
// output (one file per module, §3). The CLI writes it on the host; a trace
// started from the GUI has no host-side process, so the api writes it too
// (sessionwrite.go) into its OWN debug root under DATA_DIR. These four routes
// are how a browser reads that directory — there is no other path into it, and
// there must not be: the directory is 0700 and holds tenant telemetry.
//
// ISOLATION (§3a). Same gate as every other debug route — requirePlatformAdmin,
// injected as Deps.Authz — plus a second, narrower rule: a session records the
// TENANT it traced, and a principal scoped into one tenant sees only its own
// sessions. A cross-tenant id is a 404, never a 403, so an id's existence is
// not confirmed to a caller who may not read it (rule 1). Every route is
// audited, because every one of them can return a customer's log line.
//
// ZERO TRUST (§3). The session id and the module name come off the URL. Both go
// through a CLOSED grammar before they touch the filesystem: the id must match
// the exact `<stamp>-<verb>-<marker>` shape SessionDirName produces, and the
// module must be a member of the Stages table (whose LogFile() is a fixed
// literal). Nothing else is ever joined onto the debug root — no cleaning, no
// "..", no user-chosen file name.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// maxSessionsListed bounds the index. A debug root is not an archive: an
	// operator reading a page of sessions wants the recent ones, and an
	// unbounded listing over a directory somebody let grow is a way to make the
	// api do arbitrary work.
	maxSessionsListed = 200
	// defaultSessionsListed is the page the GUI asks for when it says nothing.
	defaultSessionsListed = 50
	// maxModuleBytes / maxModuleLines bound ONE module file read. The files are
	// already bounded at write time; this bounds what a single HTTP response
	// can carry regardless of what is on disk.
	maxModuleBytes = 512 << 10
	maxModuleLines = 2000
	// maxSummaryBytes bounds summary.txt (a stage table; kilobytes).
	maxSummaryBytes = 256 << 10
	// maxManifestBytes bounds manifest.json / timeline.json.
	maxManifestBytes = 2 << 20
)

// EnvSessionRoot overrides where this api writes and serves session
// directories. The default is <DATA_DIR>/debug — inside the api's own data
// volume, which is the only directory it is guaranteed to be able to write.
// An operator who also wants the HOST-side CLI's data/debug visible here mounts
// it and points this variable at the mount.
const EnvSessionRoot = "DEBUG_SESSION_ROOT"

// ── the closed grammar for a session id ─────────────────────────────────────

// SessionVerbs is the closed set of verbs that create a session directory. It
// is part of the id grammar, so a caller cannot name a directory this tool did
// not write.
var SessionVerbs = []string{"trace", "logs"}

// ValidSessionID reports whether s is the exact shape SessionDirName produces:
// `20260904T1105Z-trace-<26-character marker>`. It is the ONLY gate an id
// passes before being joined onto the debug root.
func ValidSessionID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	stamp, verb, marker := parts[0], parts[1], parts[2]
	if !ValidMarker(marker) {
		return false
	}
	verbOK := false
	for _, v := range SessionVerbs {
		if verb == v {
			verbOK = true
			break
		}
	}
	if !verbOK {
		return false
	}
	// `20060102T1504Z` — 14 characters, digits with a fixed T and Z.
	if len(stamp) != 14 || stamp[8] != 'T' || stamp[13] != 'Z' {
		return false
	}
	for i, c := range stamp {
		if i == 8 || i == 13 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	if _, err := time.Parse("20060102T1504Z", stamp); err != nil {
		return false
	}
	return true
}

// NormalizeSessionID validates an untrusted id from a URL path.
func NormalizeSessionID(s string) (string, error) {
	id := strings.TrimSpace(s)
	if !ValidSessionID(id) {
		return "", errors.New("a session id is <UTC stamp>-<verb>-<marker>, exactly as the session directory is named")
	}
	return id, nil
}

// sessionPath joins a validated session id onto the debug root and then PROVES
// the result is inside that root before returning it.
//
// The grammar above is already what makes the join safe — a `..` cannot pass
// ValidSessionID. This is the second lock, and it exists because the first one
// is a rule a future edit could loosen without noticing: gosec's taint analysis
// (G703) is excluded tree-wide on the finding that no handler builds a path from
// request input, and this file is the first place that DOES. The containment
// check is what keeps that exclusion honest here, and it is tested.
func sessionPath(root, id string) (string, error) {
	if !ValidSessionID(id) {
		return "", errors.New("invalid session id")
	}
	base := filepath.Clean(root)
	dir := filepath.Clean(filepath.Join(base, id))
	if dir == base || !strings.HasPrefix(dir, base+string(os.PathSeparator)) {
		return "", errors.New("session path resolved outside the debug root")
	}
	return dir, nil
}

// ── the wire shapes ─────────────────────────────────────────────────────────

// SessionSummary is one row of the index.
type SessionSummary struct {
	ID       string    `json:"id"`
	Verb     string    `json:"verb"`
	Marker   string    `json:"marker,omitempty"`
	Kind     Kind      `json:"kind,omitempty"`
	Device   string    `json:"device,omitempty"`
	Tenant   string    `json:"tenant,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	// The verdict tally — the thing an operator scans a list for.
	Seen          int  `json:"seen"`
	NotSeen       int  `json:"not_seen"`
	NotObservable int  `json:"not_observable"`
	ReachedAPI    bool `json:"reached_api"`
	// Modules are the module log files this session actually holds.
	Modules  []string `json:"modules,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Bytes    int64    `json:"bytes"`
	// Incomplete names what could not be read, when a directory is half-written
	// or was interrupted. A row that says so is honest; omitting the row would
	// hide a session an operator may need (§10).
	Incomplete string `json:"incomplete,omitempty"`
}

// SessionIndex is GET /api/debug/sessions.
type SessionIndex struct {
	Root     string           `json:"root"`
	Sessions []SessionSummary `json:"sessions"`
	// Reason explains an EMPTY index: no root configured, root absent, nothing
	// written yet. An empty list with no reason is the silent-failure shape.
	Reason    string `json:"reason,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ModuleFile describes one module log file in a session.
type ModuleFile struct {
	Module Stage  `json:"module"`
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
}

// SessionDetail is GET /api/debug/sessions/{id}.
type SessionDetail struct {
	Session  SessionSummary `json:"session"`
	Manifest *Manifest      `json:"manifest,omitempty"`
	Timeline *Timeline      `json:"timeline,omitempty"`
	Summary  string         `json:"summary_text,omitempty"`
	Modules  []ModuleFile   `json:"modules"`
	Reason   string         `json:"reason,omitempty"`
}

// ModuleLog is GET /api/debug/sessions/{id}/module/{module}.
type ModuleLog struct {
	Session   string   `json:"session"`
	Module    Stage    `json:"module"`
	File      string   `json:"file"`
	Lines     []string `json:"lines"`
	Bytes     int64    `json:"bytes"`
	Truncated bool     `json:"truncated,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

// ── GET /api/debug/sessions ─────────────────────────────────────────────────

// HandleSessions serves the session index.
func (a *API) HandleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	limit := defaultSessionsListed
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("limit: %w", err))
			return
		}
		limit = n
	}
	if limit <= 0 {
		limit = defaultSessionsListed
	}
	if limit > maxSessionsListed {
		limit = maxSessionsListed
	}

	idx := a.sessionIndex(p, limit)
	a.audit(r, p.Tenant, "debug.sessions.list", map[string]any{
		"returned": len(idx.Sessions), "limit": limit,
	})
	a.deps.WriteJSON(w, http.StatusOK, idx)
}

// sessionIndex reads the debug root. An unreadable or absent root is an EMPTY
// index with a reason, not a 5xx: "this api has never written a session" is a
// legitimate state on a fresh install and must not read as a broken endpoint.
func (a *API) sessionIndex(p Principal, limit int) SessionIndex {
	root := strings.TrimSpace(a.deps.SessionRoot)
	idx := SessionIndex{Root: root, Sessions: []SessionSummary{}}
	if root == "" {
		idx.Reason = "no debug session root is configured in this API build, so sessions started from the GUI are not persisted — the CLI writes its own sessions on the host under data/debug/"
		return idx
	}
	dirs, err := ListSessions(root)
	if err != nil {
		if os.IsNotExist(err) {
			idx.Reason = "no debug session has been written yet — run a trace, or package a host-side CLI session with `correlix-debug bundle`"
			return idx
		}
		idx.Reason = "the debug session root could not be read: " + err.Error()
		return idx
	}
	for _, dir := range dirs {
		id := filepath.Base(dir)
		if !ValidSessionID(id) {
			// A directory this tool did not write is skipped rather than
			// parsed: the id grammar is what makes every later path join safe.
			continue
		}
		sum := a.readSessionSummary(root, id)
		// §3a rule 1: a scoped principal sees ONLY its own tenant's sessions.
		if !p.Cross && !strings.EqualFold(sum.Tenant, p.Tenant) {
			continue
		}
		idx.Sessions = append(idx.Sessions, sum)
		if len(idx.Sessions) >= limit {
			idx.Truncated = len(dirs) > len(idx.Sessions)
			break
		}
	}
	if len(idx.Sessions) == 0 && idx.Reason == "" {
		idx.Reason = "no debug session is readable for this caller yet"
	}
	return idx
}

// readSessionSummary builds one index row from manifest.json + timeline.json.
func (a *API) readSessionSummary(root, id string) SessionSummary {
	parts := strings.SplitN(id, "-", 3)
	sum := SessionSummary{ID: id, Verb: parts[1]}
	dir, err := sessionPath(root, id)
	if err != nil {
		sum.Incomplete = err.Error()
		return sum
	}

	man, manErr := readManifest(dir)
	if manErr != nil {
		sum.Incomplete = "manifest.json could not be read: " + manErr.Error()
	} else {
		sum.Marker, sum.Kind, sum.Device = man.Marker, man.Kind, man.Device
		sum.Tenant, sum.Actor = man.Tenant, man.Actor
		sum.Started, sum.Finished, sum.Warnings = man.Started, man.Finished, man.Warnings
	}
	tl, tlErr := readTimeline(dir)
	if tlErr != nil {
		if sum.Incomplete == "" {
			sum.Incomplete = "timeline.json could not be read: " + tlErr.Error()
		}
	} else {
		for _, e := range tl.Entries {
			switch e.Verdict {
			case VerdictSeen:
				sum.Seen++
			case VerdictNotSeen:
				sum.NotSeen++
			case VerdictNotObservable:
				sum.NotObservable++
			}
		}
		sum.ReachedAPI = tl.Reached(StageAPI)
		if sum.Marker == "" {
			sum.Marker = tl.Marker
		}
	}
	for _, mf := range moduleFiles(dir) {
		sum.Modules = append(sum.Modules, string(mf.Module))
		sum.Bytes += mf.Bytes
	}
	return sum
}

// ── GET /api/debug/sessions/{id}[/module/{module}|/bundle] ──────────────────

// HandleSession serves one session: its detail, one module file, or its bundle.
func (a *API) HandleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/debug/sessions/")
	seg := strings.Split(strings.Trim(rest, "/"), "/")
	id, err := NormalizeSessionID(seg[0])
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	root := strings.TrimSpace(a.deps.SessionRoot)
	if root == "" {
		a.deps.WriteError(w, http.StatusNotFound, errors.New("no debug session root is configured in this API build"))
		return
	}
	dir, pathErr := sessionPath(root, id)
	if pathErr != nil {
		a.deps.WriteError(w, http.StatusBadRequest, pathErr)
		return
	}
	info, statErr := os.Stat(dir)
	if statErr != nil || !info.IsDir() {
		a.deps.WriteError(w, http.StatusNotFound, errors.New("no such debug session"))
		return
	}
	// §3a rule 1 — a session outside the caller's scope is the SAME 404 an
	// absent one gets.
	sum := a.readSessionSummary(root, id)
	if !p.Cross && !strings.EqualFold(sum.Tenant, p.Tenant) {
		a.deps.WriteError(w, http.StatusNotFound, errors.New("no such debug session"))
		return
	}

	switch {
	case len(seg) == 1:
		a.audit(r, sum.Tenant, "debug.sessions.get", map[string]any{"session": id})
		a.deps.WriteJSON(w, http.StatusOK, a.sessionDetail(dir, sum))
	case len(seg) == 3 && seg[1] == "module":
		a.serveModule(w, r, dir, sum, seg[2])
	case len(seg) == 2 && seg[1] == "bundle":
		a.serveBundle(w, r, dir, sum)
	default:
		a.deps.WriteError(w, http.StatusNotFound, errors.New("unknown session sub-resource"))
	}
}

func (a *API) sessionDetail(dir string, sum SessionSummary) SessionDetail {
	out := SessionDetail{Session: sum, Modules: moduleFiles(dir)}
	if man, err := readManifest(dir); err == nil {
		out.Manifest = &man
	} else {
		out.Reason = "manifest.json could not be read: " + err.Error()
	}
	if tl, err := readTimeline(dir); err == nil {
		out.Timeline = &tl
	} else if out.Reason == "" {
		out.Reason = "timeline.json could not be read: " + err.Error()
	}
	if txt, err := readBounded(filepath.Join(dir, "summary.txt"), maxSummaryBytes); err == nil {
		out.Summary = string(txt)
	}
	return out
}

// serveModule streams one module's log file, bounded in bytes AND lines.
func (a *API) serveModule(w http.ResponseWriter, r *http.Request, dir string, sum SessionSummary, module string) {
	// CLOSED GRAMMAR: the module name is a member of the Stages table, whose
	// LogFile() is a fixed literal per stage. No caller string is ever joined
	// onto the session directory.
	stage, err := ParseStage(module)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	out := ModuleLog{Session: sum.ID, Module: stage, File: stage.LogFile(), Lines: []string{}}
	path := filepath.Join(dir, stage.LogFile())
	data, err := readBounded(path, maxModuleBytes)
	switch {
	case os.IsNotExist(err):
		// A missing module file is a 200 with the reason, not a 404: the
		// session EXISTS and this module simply produced no file in it, which
		// is a fact about the run rather than a bad request.
		out.Reason = "this session holds no log file for that module — the collector never ran for it in this session"
	case err != nil:
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	default:
		out.Bytes = int64(len(data))
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
		if len(lines) > maxModuleLines {
			lines = lines[:maxModuleLines]
			out.Truncated = true
			out.Reason = fmt.Sprintf("showing the first %d lines — download the session bundle for the whole file", maxModuleLines)
		}
		if fi, statErr := os.Stat(path); statErr == nil && fi.Size() > int64(len(data)) {
			out.Truncated = true
			out.Bytes = fi.Size()
			out.Reason = fmt.Sprintf("showing the first %d bytes of %d — download the session bundle for the whole file", maxModuleBytes, fi.Size())
		}
		out.Lines = lines
	}
	// A module file can hold a tenant's own log line: reading one is audited,
	// not merely gated.
	a.audit(r, sum.Tenant, "debug.sessions.module", map[string]any{
		"session": sum.ID, "module": string(stage), "lines": len(out.Lines),
	})
	a.deps.WriteJSON(w, http.StatusOK, out)
}

// serveBundle streams the session as a checksummed, gzip-compressed tar.
//
// The archive is assembled in memory (bounded by MaxBundleBytes) rather than
// streamed, for one reason: the SHA256 has to be in a HEADER, and a header
// cannot be written after the body. A support bundle whose checksum arrived
// separately from the file is a checksum nobody verifies.
func (a *API) serveBundle(w http.ResponseWriter, r *http.Request, dir string, sum SessionSummary) {
	var tarBuf bytes.Buffer
	if _, err := WriteBundleTar(&tarBuf, []string{dir}, MaxBundleBytes); err != nil {
		var tooBig ErrBundleTooLarge
		if errors.As(err, &tooBig) {
			a.deps.WriteError(w, http.StatusRequestEntityTooLarge, err)
			return
		}
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if err := zw.Close(); err != nil {
		a.deps.WriteError(w, http.StatusInternalServerError, err)
		return
	}
	body := gzBuf.Bytes()
	digest := sha256Hex(body)
	name := "correlix-debug-" + sum.ID + ".tar.gz"

	a.audit(r, sum.Tenant, "debug.sessions.bundle", map[string]any{
		"session": sum.ID, "bytes": len(body), "sha256": digest, "codec": "gzip",
	})

	h := w.Header()
	h.Set("Content-Type", "application/gzip")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	// The digest of THIS body, so a downloader can verify without a sidecar
	// file. SHA256SUMS for the members is inside the archive as well.
	h.Set("X-Correlix-Bundle-SHA256", digest)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body) // the response is committed; a short write is the client's disconnect, not an actionable error
}

// ── file helpers (every read is bounded) ────────────────────────────────────

func moduleFiles(dir string) []ModuleFile {
	out := make([]ModuleFile, 0, len(Stages))
	for _, st := range Stages {
		fi, err := os.Stat(filepath.Join(dir, st.LogFile()))
		if err != nil {
			continue
		}
		out = append(out, ModuleFile{Module: st, File: st.LogFile(), Bytes: fi.Size()})
	}
	return out
}

func readManifest(dir string) (Manifest, error) {
	buf, err := readBounded(filepath.Join(dir, "manifest.json"), maxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	var man Manifest
	if err := json.Unmarshal(buf, &man); err != nil {
		return Manifest{}, err
	}
	return man, nil
}

func readTimeline(dir string) (Timeline, error) {
	buf, err := readBounded(filepath.Join(dir, "timeline.json"), maxManifestBytes)
	if err != nil {
		return Timeline{}, err
	}
	var tl Timeline
	if err := json.Unmarshal(buf, &tl); err != nil {
		return Timeline{}, err
	}
	return tl, nil
}

// readBounded reads at most n bytes. Every file this package serves is read
// through here, so no single response can be sized by whatever ended up on
// disk (§9 — every dimension bounded).
func readBounded(path string, n int64) ([]byte, error) {
	// #nosec G304 -- path is <debug root>/<id validated by ValidSessionID>/<a
	// fixed literal or Stage.LogFile()>. No caller string reaches this join.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only handle; a close error is not actionable
	return io.ReadAll(io.LimitReader(f, n))
}
