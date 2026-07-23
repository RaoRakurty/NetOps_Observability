package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
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
