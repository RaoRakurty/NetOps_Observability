// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/platformdb"
)

// config.go — Correlix DATA PROTECTION settings + status: the platform's backup
// destination and a live DR health view. Platform-global system config (like
// System → Backup on a network appliance), gated by the injected platform-admin
// Gate — a tenant admin manages their tenant, never the platform's backup
// posture.
//
// ARCHITECTURE NOTE (why the UI stores intent and a host script enforces it):
// the backend runs in a container and cannot write the host crontab or the host
// .env where BACKUP_REMOTE lives. So this surface STORES the operator's intent
// (remote destination, schedule) and REPORTS live DR status; the host applier
// (install.py / scripts/backup.sh reading this config) enforces it. The status
// half is fully live here — an operator sees the truth (repo registered? last
// snapshot age? remote configured?) without leaving the UI.

// Config is the platform's data-protection intent (single global row).
type Config struct {
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
	ScheduleCron string `json:"schedule_cron,omitempty"`

	// RetainCount is how many bundle ARTIFACTS the host keeps: the applier
	// writes it to BACKUP_KEEP, and backup.sh keeps the N newest and prunes the
	// rest (0 = pruning DISABLED, which backup.sh warns about rather than
	// treating as a silent default).
	//
	// It is a POINTER because three states are genuinely different and must
	// stay distinguishable: a count the operator chose, a deliberate 0, and
	// "never set" — which the applier resolves to its own fallback of 7. A
	// plain int would render "nobody chose" and "keep nothing" as the same
	// zero, which is the fabricated-value failure this whole surface exists to
	// refuse.
	//
	// THE DEFECT THIS CLOSES (2026-09-06). scripts/apply-backup-config.sh has
	// read `retain_count` out of THIS file since 2026-07-27 and written it to
	// BACKUP_KEEP — but the field did not exist on this struct. So the GUI
	// could not set the bundle's retention at all (tracker 150(g) asks for
	// exactly that, "tarball retention.max_count, default 7"), and worse, every
	// GUI save marshalled this struct over the whole file and SILENTLY DELETED
	// a retain_count an operator had set by hand. The applier then fell back to
	// 7 with nothing anywhere saying the operator's decision had been dropped.
	RetainCount *int `json:"retain_count,omitempty"`

	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// ── the OpenSearch snapshot-schedule INTENT (2026-09-03) ────────────────
	//
	// THE DEFECT THESE CLOSE, reproduced live on 2026-09-03T11:47Z:
	// deployment/docker/opensearch/apply-ism.sh PUT the netops-daily SM policy
	// on every bootstrap with NO `enabled` field, and OpenSearch defaults that
	// to true — so a policy an operator deliberately STOPPED through the GUI
	// was silently re-enabled on the next `docker compose up`. The GUI said
	// "off", the cluster said "on", and nothing reconciled them.
	//
	// The fix has two halves. This is the api's half: the operator's decision
	// is STORED here, with who made it and why, and exposed through
	// SnapshotScheduleIntent() so the bootstrap (and the tests) have exactly
	// one source of truth to read instead of guessing a default.
	//
	// A ZERO SnapshotScheduleDisabledAt means "no deliberate stop is on
	// record", which is the enabled state. These three fields are NEVER taken
	// from a request body (§3a rule 2): the PUT handler carries them forward
	// from the stored config and only the snapshot-policy PUT writes them.
	SnapshotScheduleDisabledAt     time.Time `json:"snapshot_schedule_disabled_at,omitempty"`
	SnapshotScheduleDisabledBy     string    `json:"snapshot_schedule_disabled_by,omitempty"`
	SnapshotScheduleDisabledReason string    `json:"snapshot_schedule_disabled_reason,omitempty"`
	// SnapshotPolicyWrittenAt is when THIS api last successfully wrote the SM
	// policy. It exists so managed_by can be answered from evidence instead of
	// assumption: compared against the policy document's own last_updated_time
	// it distinguishes "the GUI last wrote this" from "something else did"
	// (a redeploy's bootstrap, or a hand edit). Never client-settable.
	SnapshotPolicyWrittenAt time.Time `json:"snapshot_policy_written_at,omitempty"`
}

// FileConfigStore is the on-disk intent register (atomic tmp+rename, 0600).
type FileConfigStore struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

// NewFileConfigStore opens (or starts) the intent file.
func NewFileConfigStore(path string) (*FileConfigStore, error) {
	if path == "" {
		path = "/data/system_backup.json"
	}
	s := &FileConfigStore{path: path}
	// #nosec G304 -- `path` is deployment-owned (SYSTEM_BACKUP_FILE) with a fixed
	// default under the api's own /data mount. It is never reachable from a
	// request body, a query string or a snapshot name.
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.cfg) // best-effort: corrupt state file starts from defaults
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// Get returns the stored intent. Nil-safe: a server assembled without this
// store (a narrow unit-test harness) must read as "no intent recorded" rather
// than panic inside a data-protection surface.
func (s *FileConfigStore) Get() Config {
	if s == nil {
		return Config{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Put replaces the stored intent.
func (s *FileConfigStore) Put(c Config) error {
	if s == nil {
		return jsonError("no backup config store is configured on this server")
	}
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.WriteFileAtomic(s.path, b, 0o600)
}

// config reads the stored intent through the injected store, nil-safe.
func (s *Service) config() Config {
	if s.deps.Config == nil {
		return Config{}
	}
	return s.deps.Config.Get()
}

// putConfig writes the stored intent through the injected store, nil-safe.
func (s *Service) putConfig(c Config) error {
	if s.deps.Config == nil {
		return jsonError("no backup config store is configured on this server")
	}
	return s.deps.Config.Put(c)
}

// sanitizeConfig validates + normalizes. The remote is shape-checked (a known
// scheme or an absolute path) but not dialed — the push happens host-side.
func sanitizeConfig(in Config) (Config, error) {
	out := Config{
		RemoteURL:       strings.TrimSpace(in.RemoteURL),
		PushCommand:     strings.TrimSpace(in.PushCommand),
		ScheduleEnabled: in.ScheduleEnabled,
		ScheduleCron:    strings.TrimSpace(in.ScheduleCron),
	}
	// Every field flows host-side into the root crontab and .env (see the
	// applier). A control character — a newline above all — lets a value break
	// out of its line: a newline in remote_url injects extra .env lines, a
	// newline in schedule_cron injects extra crontab lines. Reject them on
	// every field BEFORE any shape check (host RCE class, review 2026-08-15).
	if hasControlChar(out.RemoteURL) || hasControlChar(out.PushCommand) || hasControlChar(out.ScheduleCron) {
		return out, errBackupControlChar
	}
	if out.RemoteURL != "" && !validBackupRemote(out.RemoteURL) {
		return out, errBadBackupRemote
	}
	// The push command is executed host-side as `$PUSH_CMD <src> <dest>` (word
	// split, run by the root backup cron). It is a TRANSPORT choice, never an
	// arbitrary command line: the first token must be an allowlisted binary and
	// every token a bare flag/value — no shell metacharacters, no second command.
	if out.PushCommand != "" && !validPushCommand(out.PushCommand) {
		return out, errBadPushCommand
	}
	// The schedule is written verbatim into the root crontab; require a real
	// 5-field cron expression (each field only digits and the cron operators),
	// not merely "5 whitespace-separated tokens".
	if out.ScheduleCron != "" && !validCronExpr(out.ScheduleCron) {
		return out, errBadBackupCron
	}
	// Guard the F-55 footgun at the API, not just in prose: a schedule with no
	// off-host destination is refused, because it would fill the local disk.
	if out.ScheduleEnabled && out.RemoteURL == "" {
		return out, errScheduleNeedsRemote
	}
	// Bundle retention. Bounded like the snapshot policy's own max_count, with
	// 0 admitted because it is a real (and loud, host-side) choice: keep every
	// artifact. The pointer is COPIED rather than aliased so nothing downstream
	// can be mutated through the request's own memory.
	if in.RetainCount != nil {
		n := *in.RetainCount
		if n < 0 || n > backupRetainMax {
			return out, errBadRetainCount
		}
		out.RetainCount = &n
	}
	if out.ScheduleCron == "" {
		out.ScheduleCron = "30 2 * * *"
	}
	return out, nil
}

// backupRetainMax bounds the stored bundle retention. It mirrors the snapshot
// policy's own retention_max_count ceiling (365) so the two halves of the same
// GUI cannot disagree about what a plausible number of copies is. The applier
// re-validates independently — it accepts any non-negative integer and is the
// security boundary — so this bound is a product decision, not the guard.
const backupRetainMax = 365

// BackupRetainApplierDefault is the count scripts/apply-backup-config.sh falls
// back to when no retain_count is stored. It is named here so the GUI can SAY
// which number is in force instead of leaving a blank field that reads as "no
// retention at all", and so the parity test can pin the two against each other.
const BackupRetainApplierDefault = 7

// hasControlChar reports whether s contains any ASCII control character
// (newline, CR, NUL, tab, …) — the primitive a value uses to break out of its
// .env or crontab line host-side.
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// backupPushBinaries is the allowlist of transports the push command may invoke.
// The applier runs `<binary> <flags…> <src> <dest>` as the root backup cron, so
// this set is a privilege boundary, not a convenience list — add only real
// file-copy transports, never a shell or interpreter.
var backupPushBinaries = map[string]bool{
	"rsync": true, "rclone": true, "scp": true, "sftp": true,
	"aws": true, "gsutil": true, "gcloud": true, "b2": true,
	"azcopy": true, "cp": true, "mc": true,
}

// pushTokenRe bounds each token of the push command to a bare flag or value:
// letters, digits and the characters that appear in flags/paths/URLs. It admits
// no space (tokens are already split), quote, $, `, ;, |, &, <, >, (, ), \, *,
// ?, ~ or newline — i.e. no shell metacharacter and no second command.
var pushTokenRe = regexp.MustCompile(`^[A-Za-z0-9._/@=:+-]+$`)

// validPushCommand reports whether cmd is an allowlisted transport invocation.
func validPushCommand(cmd string) bool {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	// The first token names the binary (bare name only — no path, so a planted
	// ./rsync cannot be selected). aws/gsutil/gcloud/mc take a subcommand; that
	// is just another allowlisted token, so no special-casing is needed.
	if !backupPushBinaries[fields[0]] {
		return false
	}
	for _, f := range fields {
		if !pushTokenRe.MatchString(f) {
			return false
		}
	}
	return true
}

// cronFieldRe bounds a single cron field to digits and the cron operators
// (`*`, `,`, `-`, `/`). No names, no spaces, no other characters.
var cronFieldRe = regexp.MustCompile(`^[0-9*,/-]+$`)

// validCronExpr reports whether expr is a real 5-field cron expression whose
// every field is digits/operators only — a stricter check than validCron5
// (which counts fields), used for the host-installed backup schedule.
func validCronExpr(expr string) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return false
		}
	}
	return true
}

var (
	errBadBackupRemote     = jsonError("remote must be an absolute path or a rsync:// / s3:// / gs:// / file:// URL")
	errScheduleNeedsRemote = jsonError("cannot enable the scheduled backup without an off-host remote — a local-only nightly backup fills the disk it needs (F-55)")
	errBackupControlChar   = jsonError("backup config fields must not contain control characters (newline/tab/etc.)")
	errBadPushCommand      = jsonError("push_command must be an allowlisted transport (rsync, rclone, scp, aws, gsutil, b2, azcopy, cp, …) with bare flags only — no shell metacharacters")
	errBadBackupCron       = jsonError("schedule_cron must be a 5-field cron expression using only digits and the operators * , - /")
	errBadRetainCount      = jsonError("retain_count must be a whole number between 0 and 365 (0 keeps every bundle artifact — pruning off)")
)

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

// Status is the LIVE data-protection health an operator needs to trust the
// posture — computed, not stored. Honest by construction: an unregistered repo
// or an absent remote reads as a problem, never blank.
type Status struct {
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

	// Components is the per-component verdict map the bundle writes
	// ("postgres" -> pass|fail|skip, and the same for clickhouse, opensearch,
	// victoriametrics, sealed_material, data_dir, signature, offhost).
	//
	// Before this existed every store's coverage row inherited the WHOLE run's
	// status, so a night on which only the VictoriaMetrics snapshot failed
	// reported a failed Postgres dump — and, worse, a night on which the sealed
	// custody material was skipped reported a covered custody root. An ABSENT
	// map means "this report predates per-component reporting", which is a
	// different answer from "every component passed", and the coverage rows say
	// so rather than assuming the generous reading.
	Components map[string]string `json:"components,omitempty"`

	// Remote is the off-host transfer's own record. VerifiedAt is set ONLY when
	// the run actually re-checksummed the bytes at the destination — "the push
	// command exited 0" is not that, and the page must be able to tell an
	// operator which of the two it has.
	Remote *FullBackupRemote `json:"remote,omitempty"`

	// DataExcludes echoes the operator-supplied rsync exclude patterns
	// (BACKUP_EXCLUDE) the run applied to the data/ copy. A NARROWED bundle must
	// never be presented as a full one.
	DataExcludes string `json:"data_excludes,omitempty"`
}

// FullBackupRemote is the off-host half of the bundle report. It deliberately
// carries NO destination string: BACKUP_PUSH can hold a credentialed transport,
// and the api already has (and redacts) the destination from the stored intent.
type FullBackupRemote struct {
	Configured bool   `json:"configured"`
	Pushed     bool   `json:"pushed"`
	VerifiedAt string `json:"verified_at,omitempty"` // RFC3339 UTC; empty = never proven at the destination
}

// Pushed reports whether the last run's artifact actually reached the off-host
// destination. Nil-safe at every level: a report that predates off-host
// reporting has not pushed anything as far as this page is concerned, which is
// the default-closed reading.
func (r *FullBackupRun) Pushed() bool {
	return r != nil && r.Remote != nil && r.Remote.Pushed
}

// componentVerdict returns the bundle's verdict for one component, and whether
// the report carried a component map at all. The two-value shape is the point:
// "not reported" must never collapse into "passed".
func (r *FullBackupRun) componentVerdict(name string) (verdict string, reported bool) {
	if r == nil || len(r.Components) == 0 {
		return "", false
	}
	v, ok := r.Components[name]
	if !ok {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(v)), true
}

// osSnapshotStatus queries OpenSearch for the repository + its newest snapshot.
func (s *Service) osSnapshotStatus(ctx context.Context) (ok bool, ageHours *int, detail string) {
	var body struct {
		Snapshots []struct {
			Snapshot  string `json:"snapshot"`
			State     string `json:"state"`
			EndTimeMs int64  `json:"end_time_in_millis"`
		} `json:"snapshots"`
	}
	if err := s.osDo(ctx, http.MethodGet, "/_snapshot/"+s.repo()+"/_all", nil, &body, 8*time.Second); err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			if se.Status == http.StatusNotFound {
				return false, nil, "snapshot repository " + s.repo() + " is NOT registered — search tier has no backup"
			}
			return false, nil, "opensearch returned " + se.StatusText
		}
		return false, nil, "opensearch unreachable"
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
	age := int(s.now().Sub(time.UnixMilli(newest)).Hours())
	return true, &age, "newest successful snapshot " + strconv.Itoa(age) + "h ago"
}

// BuildStatus assembles the live DR health view for one stored intent.
func (s *Service) BuildStatus(ctx context.Context, cfg Config) Status {
	ok, age, detail := s.osSnapshotStatus(ctx)
	st := Status{
		RemoteConfigured:   cfg.RemoteURL != "",
		ScheduleEnabled:    cfg.ScheduleEnabled,
		OSSnapshotRepoOK:   ok,
		OSLastSnapshotAgeH: age,
		OSSnapshotDetail:   detail,
		OnHostOnlyWarning:  cfg.RemoteURL == "",
	}
	// Surface the last restore-drill result if the report is mounted/readable.
	if b, err := readReportFile(s.deps.RestoreDrillReportPath); err == nil {
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
	if b, err := readReportFile(s.deps.BackupReportPath); err == nil {
		var rep FullBackupRun
		if json.Unmarshal(b, &rep) == nil && rep.Status != "" {
			st.FullBackup = &rep
		}
	}
	return st
}

// readReportFile reads one deployment-owned report path. An empty path is "no
// report configured", which reads exactly like an absent one.
func readReportFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, os.ErrNotExist
	}
	// #nosec G304 -- deployment-owned env paths (BACKUP_REPORT /
	// RESTORE_DRILL_REPORT) resolved once by the integrator; no request-supplied
	// string reaches this function.
	return os.ReadFile(path)
}

// auditRetain renders the stored bundle retention for the audit trail. A nil
// count is "unset" in words, never a 0: in this vocabulary 0 means "pruning
// off, keep everything", and an audit line that could not tell the two apart
// would be evidence of the wrong decision.
func auditRetain(n *int) any {
	if n == nil {
		return "unset"
	}
	return *n
}
