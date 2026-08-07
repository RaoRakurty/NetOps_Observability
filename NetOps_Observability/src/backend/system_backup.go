package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// system_backup.go — Correlix DATA PROTECTION settings + status: the platform's
// backup destination and a live DR health view. Platform-global system config
// (like System → Backup on a network appliance), gated by requirePlatformAdmin —
// a tenant admin manages their tenant, never the platform's backup posture.
//
// ARCHITECTURE NOTE (why the UI stores intent and a host script enforces it):
// the backend runs in a container and cannot write the host crontab or the host
// .env where BACKUP_REMOTE lives. So this surface STORES the operator's intent
// (remote destination, schedule) and REPORTS live DR status; the host applier
// (install.py / scripts/backup.sh reading this config) enforces it. The status
// half is fully live here — an operator sees the truth (repo registered? last
// snapshot age? remote configured?) without leaving the UI.

// BackupConfig is the platform's data-protection intent (single global row).
type BackupConfig struct {
	// RemoteURL is the off-host destination (rsync://…, s3://…, /mnt/nas/…). Empty
	// means on-host-only — which is NOT disaster recovery (BACKUP-FAILURE-DOMAIN.md).
	RemoteURL string `json:"remote_url"`
	// PushCommand is the transport ("rsync -a", "rclone copy", …); empty → default.
	PushCommand string `json:"push_command,omitempty"`
	// ScheduleEnabled turns on the nightly backup. Deliberately defaults OFF and
	// SHOULD only be enabled once RemoteURL is set — a local-only nightly backup
	// fills the very disk it needs (F-55).
	ScheduleEnabled bool `json:"schedule_enabled"`
	// ScheduleCron is the backup schedule (default "30 2 * * *" — 02:30 daily).
	ScheduleCron string    `json:"schedule_cron,omitempty"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

type backupConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  BackupConfig
}

func newBackupConfigStore(path string) (*backupConfigStore, error) {
	if path == "" {
		path = "/data/system_backup.json"
	}
	s := &backupConfigStore{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *backupConfigStore) Get() BackupConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *backupConfigStore) Put(c BackupConfig) error {
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// sanitizeBackupConfig validates + normalizes. The remote is shape-checked (a
// known scheme or an absolute path) but not dialed — the push happens host-side.
func sanitizeBackupConfig(in BackupConfig) (BackupConfig, error) {
	out := BackupConfig{
		RemoteURL:       strings.TrimSpace(in.RemoteURL),
		PushCommand:     strings.TrimSpace(in.PushCommand),
		ScheduleEnabled: in.ScheduleEnabled,
		ScheduleCron:    strings.TrimSpace(in.ScheduleCron),
	}
	if out.RemoteURL != "" && !validBackupRemote(out.RemoteURL) {
		return out, errBadBackupRemote
	}
	// Guard the F-55 footgun at the API, not just in prose: a schedule with no
	// off-host destination is refused, because it would fill the local disk.
	if out.ScheduleEnabled && out.RemoteURL == "" {
		return out, errScheduleNeedsRemote
	}
	if out.ScheduleCron == "" {
		out.ScheduleCron = "30 2 * * *"
	}
	return out, nil
}

var (
	errBadBackupRemote     = jsonError("remote must be an absolute path or a rsync:// / s3:// / gs:// / file:// URL")
	errScheduleNeedsRemote = jsonError("cannot enable the scheduled backup without an off-host remote — a local-only nightly backup fills the disk it needs (F-55)")
)

func jsonError(s string) error { return &simpleErr{s} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }

func validBackupRemote(u string) bool {
	if strings.HasPrefix(u, "/") { // absolute path (a separately-mounted device)
		return true
	}
	for _, scheme := range []string{"rsync://", "s3://", "gs://", "file://", "b2://", "azure://"} {
		if strings.HasPrefix(u, scheme) {
			return true
		}
	}
	return false
}

// BackupStatus is the LIVE data-protection health an operator needs to trust the
// posture — computed, not stored. Honest by construction: an unregistered repo
// or an absent remote reads as a problem, never blank.
type BackupStatus struct {
	RemoteConfigured   bool   `json:"remote_configured"`
	ScheduleEnabled    bool   `json:"schedule_enabled"`
	OSSnapshotRepoOK   bool   `json:"os_snapshot_repo_ok"`
	OSLastSnapshotAgeH *int   `json:"os_last_snapshot_age_hours,omitempty"`
	OSSnapshotDetail   string `json:"os_snapshot_detail"`
	OnHostOnlyWarning  bool   `json:"on_host_only_warning"`
	LastDrillResult    string `json:"last_drill_result,omitempty"`
	LastDrillAtISO     string `json:"last_drill_at,omitempty"`
	// FullBackup is the host-cron tarball component's last run, read from the
	// report backup.sh writes (#150). nil = no report yet — the UI must render
	// that as "never ran / not reporting", never as blank (the F-59 lesson).
	FullBackup *FullBackupRun `json:"full_backup,omitempty"`
}

// FullBackupRun mirrors scripts/backup.sh's report JSON verbatim.
type FullBackupRun struct {
	Status          string `json:"status"`
	Ended           string `json:"ended"`
	SizeBytes       int64  `json:"size_bytes"`
	DurationSeconds int    `json:"duration_seconds"`
	Failures        int    `json:"failures"`
	Artifact        string `json:"artifact,omitempty"`
}

// osSnapshotStatus queries OpenSearch for the netops-fs repo + newest snapshot.
func (s *server) osSnapshotStatus(ctx context.Context) (ok bool, ageHours *int, detail string) {
	base := strings.TrimRight(envOr("OPENSEARCH_URL", "http://opensearch:9200"), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/_snapshot/netops-fs/_all", nil)
	if err != nil {
		return false, nil, "could not build request"
	}
	resp, err := backendHTTPClient(8 * time.Second).Do(req)
	if err != nil {
		return false, nil, "opensearch unreachable"
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil, "snapshot repository netops-fs is NOT registered — search tier has no backup"
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil, "opensearch returned " + resp.Status
	}
	var body struct {
		Snapshots []struct {
			Snapshot  string `json:"snapshot"`
			State     string `json:"state"`
			EndTimeMs int64  `json:"end_time_in_millis"`
		} `json:"snapshots"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, nil, "could not parse snapshot list"
	}
	if len(body.Snapshots) == 0 {
		return true, nil, "repository registered, but NO snapshots exist yet"
	}
	var newest int64
	for _, sn := range body.Snapshots {
		if sn.State == "SUCCESS" && sn.EndTimeMs > newest {
			newest = sn.EndTimeMs
		}
	}
	if newest == 0 {
		return true, nil, "repository registered; no SUCCESSful snapshot found"
	}
	age := int(time.Since(time.UnixMilli(newest)).Hours())
	return true, &age, "newest successful snapshot " + intToString(age) + "h ago"
}

func (s *server) buildBackupStatus(ctx context.Context, cfg BackupConfig) BackupStatus {
	ok, age, detail := s.osSnapshotStatus(ctx)
	st := BackupStatus{
		RemoteConfigured:   cfg.RemoteURL != "",
		ScheduleEnabled:    cfg.ScheduleEnabled,
		OSSnapshotRepoOK:   ok,
		OSLastSnapshotAgeH: age,
		OSSnapshotDetail:   detail,
		OnHostOnlyWarning:  cfg.RemoteURL == "",
	}
	// Surface the last restore-drill result if the report is mounted/readable.
	if b, err := os.ReadFile(envOr("RESTORE_DRILL_REPORT", "/data/restore-drill.report.json")); err == nil {
		var rep struct {
			Result string `json:"result"`
			Ended  string `json:"ended"`
		}
		if json.Unmarshal(b, &rep) == nil {
			st.LastDrillResult = rep.Result
			st.LastDrillAtISO = rep.Ended
		}
	}
	// Full-backup component (#150): the host cron's report, same pattern.
	if b, err := os.ReadFile(envOr("BACKUP_REPORT", "/data/backup-report.json")); err == nil {
		var rep FullBackupRun
		if json.Unmarshal(b, &rep) == nil && rep.Status != "" {
			st.FullBackup = &rep
		}
	}
	return st
}

// handleSystemBackup serves + updates the data-protection config (platform admin).
func (s *server) handleSystemBackup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		cfg := s.backupCfg.Get()
		writeJSON(w, http.StatusOK, map[string]any{
			"config": cfg,
			"status": s.buildBackupStatus(r.Context(), cfg),
		})
	case http.MethodPut:
		claims, ok := s.requirePlatformAdmin(w, r)
		if !ok {
			return
		}
		var req BackupConfig
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad body: " + err.Error()})
			return
		}
		clean, err := sanitizeBackupConfig(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		clean.UpdatedBy = claims.Sub
		clean.UpdatedAt = time.Now().UTC()
		if err := s.backupCfg.Put(clean); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"config": clean,
			"status": s.buildBackupStatus(r.Context(), clean),
		})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

// ── #150: OpenSearch snapshot policy control plane ──────────────────────────
//
// The GUI's snapshot controls are a THIN TRUTHFUL VIEW over the netops-daily
// Snapshot Management policy (owner decision: mirror the OS SM vocabulary —
// enabled / schedule cron / retention.max_count — never invent a parallel
// one). Reads combine the policy document with the SM explain API (last run,
// next trigger); writes go straight to the policy with the seq_no/primary_term
// concurrency dance apply-ism.sh proved necessary, and enable/disable rides
// the plugin's own _start/_stop. Policy CRUD only: snapshot create/restore/
// delete are deliberately NOT reachable from this surface (restore is
// runbook-only, owner decision (e)).

// SnapshotRun is one SM execution outcome (creation or deletion leg).
type SnapshotRun struct {
	Status          string `json:"status"`
	Time            string `json:"time,omitempty"` // end time, RFC3339
	DurationSeconds int    `json:"duration_seconds,omitempty"`
}

// SnapshotPolicyView is what the GUI renders. Detail carries the honest
// explanation whenever any part could not be read — never a blank panel.
type SnapshotPolicyView struct {
	Enabled           bool         `json:"enabled"`
	ScheduleCron      string       `json:"schedule_cron"`
	RetentionMaxCount int          `json:"retention_max_count"`
	LastRun           *SnapshotRun `json:"last_run,omitempty"`
	NextRun           string       `json:"next_run,omitempty"` // RFC3339
	Detail            string       `json:"detail,omitempty"`
}

// snapshotPolicyUpdate is the PUT body — all fields optional (partial update,
// the same convention the OS SM policy API itself uses).
type snapshotPolicyUpdate struct {
	Enabled           *bool   `json:"enabled,omitempty"`
	ScheduleCron      *string `json:"schedule_cron,omitempty"`
	RetentionMaxCount *int    `json:"retention_max_count,omitempty"`
}

const smPolicyPath = "/_plugins/_sm/policies/netops-daily"

func (s *server) osBase() string {
	return strings.TrimRight(envOr("OPENSEARCH_URL", "http://opensearch:9200"), "/")
}

// osJSON performs one OpenSearch request and decodes the JSON reply into out.
// A non-2xx status returns an error carrying the status text — callers turn
// that into an honest Detail string, never a silent zero value.
func (s *server) osJSON(ctx context.Context, method, path string, body []byte, out any) error {
	var rd *strings.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, s.osBase()+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := backendHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &simpleErr{"opensearch " + resp.Status + " on " + path}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// smPolicyDoc is the subset of the SM policy document we read AND write back.
// Raw preserves the full policy body so an update round-trips fields this
// struct does not model (notification config, deletion schedule, time limits).
type smPolicyDoc struct {
	SeqNo       int64
	PrimaryTerm int64
	Raw         map[string]any
}

func (s *server) smGetPolicy(ctx context.Context) (*smPolicyDoc, error) {
	var body struct {
		SeqNo       int64          `json:"_seq_no"`
		PrimaryTerm int64          `json:"_primary_term"`
		Policy      map[string]any `json:"sm_policy"`
	}
	if err := s.osJSON(ctx, http.MethodGet, smPolicyPath, nil, &body); err != nil {
		return nil, err
	}
	return &smPolicyDoc{SeqNo: body.SeqNo, PrimaryTerm: body.PrimaryTerm, Raw: body.Policy}, nil
}

// digMap walks nested map[string]any keys, returning nil when any hop is absent.
func digMap(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func (s *server) snapshotPolicyView(ctx context.Context) SnapshotPolicyView {
	v := SnapshotPolicyView{}
	doc, err := s.smGetPolicy(ctx)
	if err != nil {
		v.Detail = "snapshot policy unreadable: " + err.Error()
		return v
	}
	if b, ok := doc.Raw["enabled"].(bool); ok {
		v.Enabled = b
	}
	if cron, ok := digMap(doc.Raw, "creation", "schedule", "cron", "expression").(string); ok {
		v.ScheduleCron = cron
	}
	if mc, ok := digMap(doc.Raw, "deletion", "condition", "max_count").(float64); ok {
		v.RetentionMaxCount = int(mc)
	}

	// Explain: last execution + next trigger for the creation leg.
	var expl struct {
		Policies []struct {
			Name     string `json:"name"`
			Creation struct {
				Trigger struct {
					Time int64 `json:"time"`
				} `json:"trigger"`
				LatestExecution *struct {
					Status    string `json:"status"`
					StartTime int64  `json:"start_time"`
					EndTime   int64  `json:"end_time"`
				} `json:"latest_execution"`
			} `json:"creation"`
		} `json:"policies"`
	}
	if err := s.osJSON(ctx, http.MethodGet, smPolicyPath+"/_explain", nil, &expl); err == nil && len(expl.Policies) > 0 {
		c := expl.Policies[0].Creation
		if c.Trigger.Time > 0 {
			v.NextRun = time.UnixMilli(c.Trigger.Time).UTC().Format(time.RFC3339)
		}
		if le := c.LatestExecution; le != nil {
			run := &SnapshotRun{Status: le.Status}
			if le.EndTime > 0 {
				run.Time = time.UnixMilli(le.EndTime).UTC().Format(time.RFC3339)
				if le.StartTime > 0 {
					run.DurationSeconds = int((le.EndTime - le.StartTime) / 1000)
				}
			}
			v.LastRun = run
		}
	} else if err != nil && v.Detail == "" {
		v.Detail = "policy readable; explain unavailable: " + err.Error()
	}
	return v
}

var errBadSnapshotUpdate = jsonError("schedule_cron must be a 5-field cron expression and retention_max_count must be 1..365")

// validCron5 is a shape check (5 whitespace-separated fields), not a parser —
// OpenSearch validates semantics on write and its error is surfaced verbatim.
func validCron5(expr string) bool {
	return len(strings.Fields(expr)) == 5
}

func (s *server) smApplyUpdate(ctx context.Context, upd snapshotPolicyUpdate) error {
	// Cron / retention changes mutate the policy document in place and PUT it
	// back with the concurrency token (SM rejects a token-less PUT).
	if upd.ScheduleCron != nil || upd.RetentionMaxCount != nil {
		doc, err := s.smGetPolicy(ctx)
		if err != nil {
			return err
		}
		if upd.ScheduleCron != nil {
			if cron, ok := digMap(doc.Raw, "creation", "schedule", "cron").(map[string]any); ok {
				cron["expression"] = *upd.ScheduleCron
			} else {
				return jsonError("policy document has no creation.schedule.cron to update")
			}
		}
		if upd.RetentionMaxCount != nil {
			if cond, ok := digMap(doc.Raw, "deletion", "condition").(map[string]any); ok {
				cond["max_count"] = *upd.RetentionMaxCount
			} else {
				return jsonError("policy document has no deletion.condition to update")
			}
		}
		// The GET echoes server-side bookkeeping fields the PUT rejects.
		for _, k := range []string{"schema_version", "last_updated_time", "enabled_time", "policy_id"} {
			delete(doc.Raw, k)
		}
		body, err := json.Marshal(doc.Raw)
		if err != nil {
			return err
		}
		path := smPolicyPath + "?if_seq_no=" + strconv.FormatInt(doc.SeqNo, 10) + "&if_primary_term=" + strconv.FormatInt(doc.PrimaryTerm, 10)
		if err := s.osJSON(ctx, http.MethodPut, path, body, nil); err != nil {
			return err
		}
	}
	// Enable/disable rides the plugin's own endpoints — simpler and immune to
	// the document round-trip dropping a field.
	if upd.Enabled != nil {
		verb := "/_stop"
		if *upd.Enabled {
			verb = "/_start"
		}
		if err := s.osJSON(ctx, http.MethodPost, smPolicyPath+verb, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// handleSystemBackupSnapshots — GET/PUT /api/system/backup/snapshots.
// Platform-global config (§3a gate rule): requirePlatformAdmin, audited writes.
func (s *server) handleSystemBackupSnapshots(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.requirePlatformAdmin(w, r); !ok {
			return
		}
		writeJSON(w, http.StatusOK, s.snapshotPolicyView(r.Context()))
	case http.MethodPut:
		claims, ok := s.requirePlatformAdmin(w, r)
		if !ok {
			return
		}
		var upd snapshotPolicyUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&upd); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad body: " + err.Error()})
			return
		}
		if upd.Enabled == nil && upd.ScheduleCron == nil && upd.RetentionMaxCount == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "nothing to update — send enabled, schedule_cron and/or retention_max_count"})
			return
		}
		if (upd.ScheduleCron != nil && !validCron5(*upd.ScheduleCron)) ||
			(upd.RetentionMaxCount != nil && (*upd.RetentionMaxCount < 1 || *upd.RetentionMaxCount > 365)) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": errBadSnapshotUpdate.Error()})
			return
		}
		err := s.smApplyUpdate(r.Context(), upd)
		decision, status := "allow", http.StatusOK
		if err != nil {
			decision, status = "deny", http.StatusBadGateway
		}
		// Audit BOTH outcomes — a failed platform-config write that was never
		// recorded is indistinguishable from one that never happened.
		s.audit.Record(AuditEvent{
			Actor: claims.Sub, Method: r.Method, Path: r.URL.Path,
			Status: status, Decision: decision, Remote: auditClientIP(r),
			Detail: map[string]any{
				"action":  "snapshot_policy_update",
				"enabled": upd.Enabled, "schedule_cron": upd.ScheduleCron,
				"retention_max_count": upd.RetentionMaxCount,
			},
		})
		if err != nil {
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, s.snapshotPolicyView(r.Context()))
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}
