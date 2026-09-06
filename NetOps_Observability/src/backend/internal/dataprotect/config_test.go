package dataprotect

// config_test.go — the backup INTENT: what an operator may store, and the two
// footguns the API refuses on their behalf.
//
// Every field here flows host-side into the root crontab and the .env, so the
// validation is a privilege boundary, not input hygiene: a newline breaks a
// value out of its line, and the push command's first token becomes a binary
// the root backup cron executes.

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSanitizeConfigRejectsScheduleWithoutRemote guards the F-55 footgun at the
// API: enabling the scheduled full backup with no off-host remote is refused,
// because a local-only nightly backup fills the disk it needs.
func TestSanitizeConfigRejectsScheduleWithoutRemote(t *testing.T) {
	_, err := sanitizeConfig(Config{ScheduleEnabled: true, RemoteURL: ""})
	if err == nil {
		t.Fatal("a schedule with no remote must be refused (F-55)")
	}
	// With a remote it is accepted.
	if _, err := sanitizeConfig(Config{ScheduleEnabled: true, RemoteURL: "rsync://h/x/"}); err != nil {
		t.Fatalf("schedule + remote should be accepted: %v", err)
	}
}

func TestSanitizeConfigValidatesRemote(t *testing.T) {
	good := []string{"/mnt/nas/x", "rsync://h/x", "s3://b/", "gs://b/", "file:///x"}
	for _, r := range good {
		if _, err := sanitizeConfig(Config{RemoteURL: r}); err != nil {
			t.Errorf("remote %q should be valid: %v", r, err)
		}
	}
	for _, r := range []string{"not-a-url", "ftp://h/x", "relative/path"} {
		if _, err := sanitizeConfig(Config{RemoteURL: r}); err == nil {
			t.Errorf("remote %q should be rejected", r)
		}
	}
}

// TestSanitizeConfigDefaultsCron ensures a saved config always has a cron.
func TestSanitizeConfigDefaultsCron(t *testing.T) {
	c, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", ScheduleEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.ScheduleCron == "" {
		t.Error("cron must default when omitted")
	}
}

// TestSanitizeConfigRefusesLineBreakout — a control character in ANY field lets
// a value break out of its .env or crontab line host-side (host RCE class).
func TestSanitizeConfigRefusesLineBreakout(t *testing.T) {
	for _, c := range []Config{
		{RemoteURL: "/mnt/x\nBACKUP_REMOTE=/evil"},
		{RemoteURL: "/mnt/x", PushCommand: "rsync\n30 * * * * root sh"},
		{RemoteURL: "/mnt/x", ScheduleCron: "30 2 * * *\n* * * * * root sh"},
	} {
		if _, err := sanitizeConfig(c); err == nil {
			t.Errorf("a control character must be refused on every field: %+v", c)
		}
	}
}

// TestSanitizeConfigBoundsThePushCommand — the applier runs
// `<binary> <flags…> <src> <dest>` as the ROOT backup cron, so the first token
// is a privilege boundary and every token must be a bare flag or value.
func TestSanitizeConfigBoundsThePushCommand(t *testing.T) {
	for _, cmd := range []string{"rsync -a", "rclone copy", "aws s3 cp", "cp -r"} {
		if _, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", PushCommand: cmd}); err != nil {
			t.Errorf("allowlisted transport %q should be accepted: %v", cmd, err)
		}
	}
	for _, cmd := range []string{
		"sh -c evil", "bash", "/usr/bin/rsync", "./rsync",
		"rsync -a; rm -rf /", "rsync -a && curl x", "rsync $(id)", "rsync `id`",
		"rsync 'a b'", "rsync a|b", "rsync a>b",
	} {
		if _, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", PushCommand: cmd}); err == nil {
			t.Errorf("push_command %q must be refused — it is a root command line, not a transport choice", cmd)
		}
	}
}

// TestSanitizeConfigRequiresARealCron — the schedule is written verbatim into
// the root crontab, so "5 whitespace-separated tokens" is not enough.
func TestSanitizeConfigRequiresARealCron(t *testing.T) {
	for _, expr := range []string{"30 2 * * *", "*/15 * * * *", "0 1,13 * * 1-5"} {
		if _, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", ScheduleCron: expr}); err != nil {
			t.Errorf("cron %q should be accepted: %v", expr, err)
		}
	}
	for _, expr := range []string{"a b c d e", "30 2 * *", "30 2 * * * *", "@daily"} {
		if _, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", ScheduleCron: expr}); err == nil {
			t.Errorf("cron %q must be refused", expr)
		}
	}
}

// TestConfigRouteRoundTrip — the GET/PUT surface, including the live DR status
// half, which must be honest rather than blank on a fresh install.
func TestConfigRouteRoundTrip(t *testing.T) {
	h := newHarness(t, newOSStub())

	st, b := h.do(t, "GET", "/api/system/backup", nil)
	if st != 200 {
		t.Fatalf("GET: %d %s", st, b)
	}
	var got struct {
		Config Config `json:"config"`
		Status Status `json:"status"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
	if !got.Status.OnHostOnlyWarning {
		t.Error("no remote configured must raise the on-host-only warning — that is NOT disaster recovery")
	}
	if !got.Status.OSSnapshotRepoOK || got.Status.OSSnapshotDetail == "" {
		t.Errorf("the live snapshot status must be reported with a detail: %+v", got.Status)
	}

	// A bad remote is a 400 and nothing is stored.
	if st, _ = h.do(t, "PUT", "/api/system/backup", map[string]any{"remote_url": "ftp://h/x"}); st != 400 {
		t.Errorf("a bad remote must 400, got %d", st)
	}
	// A good one round-trips, stamped with the authenticated subject.
	st, b = h.do(t, "PUT", "/api/system/backup", map[string]any{"remote_url": "rsync://nas/backups"})
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Config.RemoteURL != "rsync://nas/backups" || got.Config.UpdatedBy != "admin" {
		t.Errorf("stored config: %+v", got.Config)
	}
	if got.Status.OnHostOnlyWarning {
		t.Error("with a remote configured the on-host-only warning must clear")
	}
	// Both outcomes audited.
	var sawDeny, sawAllow bool
	for _, e := range h.audit.all() {
		if e.Detail["action"] != "backup_config_update" {
			continue
		}
		switch e.Decision {
		case "allow":
			sawAllow = true
		case "deny":
			sawDeny = true
		}
	}
	if !sawAllow {
		t.Error("an accepted backup-config write was not audited")
	}
	_ = sawDeny // a refused BODY never reaches the audited write; the store-failure path does
	// A method the surface does not serve.
	if st, _ = h.do(t, "DELETE", "/api/system/backup", nil); st != 405 {
		t.Errorf("DELETE must 405, got %d", st)
	}
}

// TestStatusReportsAnUnregisteredRepositoryHonestly — a 404 from the cluster is
// "there is no backup", not "unreachable", and the two must never be conflated.
func TestStatusReportsAnUnregisteredRepositoryHonestly(t *testing.T) {
	stub := newOSStub()
	h := newHarness(t, stub, func(d *Deps) { d.Repository = "no-such-repo" })
	st := h.svc.BuildStatus(t.Context(), Config{})
	if st.OSSnapshotRepoOK {
		t.Error("an unregistered repository is not OK")
	}
	if !strings.Contains(st.OSSnapshotDetail, "NOT registered") {
		t.Errorf("the detail must say the repository is not registered: %q", st.OSSnapshotDetail)
	}
}

// ── bundle retention (retain_count), 2026-09-06 ─────────────────────────────
//
// The bundle's keep-N is the ONE data-loss control on this surface: it is what
// deletes copies. It is also a Go↔bash seam — scripts/apply-backup-config.sh
// reads the key out of the stored file and writes BACKUP_KEEP — so the tests
// below pin the value space, the three states, and the two ways an operator's
// decision could be lost.

func intp(n int) *int { return &n }

// TestSanitizeConfigBoundsRetainCount — the value space, including the two ends
// and the deliberate 0.
func TestSanitizeConfigBoundsRetainCount(t *testing.T) {
	for _, n := range []int{0, 1, 7, 365} {
		c, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", RetainCount: intp(n)})
		if err != nil {
			t.Errorf("retain_count %d should be accepted: %v", n, err)
			continue
		}
		if c.RetainCount == nil || *c.RetainCount != n {
			t.Errorf("retain_count %d did not survive sanitize: %v", n, c.RetainCount)
		}
	}
	for _, n := range []int{-1, 366, 100000} {
		if _, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", RetainCount: intp(n)}); err == nil {
			t.Errorf("retain_count %d must be refused", n)
		}
	}
}

// TestSanitizeConfigKeepsRetainCountUnsetDistinctFromZero — "nobody chose" and
// "keep everything" are different operational states and must never collapse.
// A plain int would have made them the same value, and the applier's fallback
// of 7 would then have been reported as an operator's decision.
func TestSanitizeConfigKeepsRetainCountUnsetDistinctFromZero(t *testing.T) {
	unset, err := sanitizeConfig(Config{RemoteURL: "/mnt/x"})
	if err != nil {
		t.Fatal(err)
	}
	if unset.RetainCount != nil {
		t.Fatalf("an omitted retain_count must stay nil, got %d", *unset.RetainCount)
	}
	b, err := json.Marshal(unset)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "retain_count") {
		t.Errorf("an unset retention must not be serialized at all (the applier reads its own fallback): %s", b)
	}
	zero, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", RetainCount: intp(0)})
	if err != nil {
		t.Fatal(err)
	}
	b, err = json.Marshal(zero)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"retain_count":0`) {
		t.Errorf("a deliberate 0 must be written out verbatim: %s", b)
	}
}

// TestSanitizeConfigCopiesRetainPointer — the stored config must never alias
// the caller's memory (§3 zero-trust: a request body is not our storage).
func TestSanitizeConfigCopiesRetainPointer(t *testing.T) {
	in := intp(5)
	c, err := sanitizeConfig(Config{RemoteURL: "/mnt/x", RetainCount: in})
	if err != nil {
		t.Fatal(err)
	}
	*in = 999
	if c.RetainCount == nil || *c.RetainCount != 5 {
		t.Errorf("sanitized retain_count aliased the request: %v", c.RetainCount)
	}
}

// TestConfigPUTPreservesRetainCountWhenOmitted is the regression this field was
// added for: before it existed, every GUI save marshalled the struct over the
// whole intent file and DELETED a hand-set retain_count, after which the host
// applier silently fell back to 7. A partial write must never drop it.
func TestConfigPUTPreservesRetainCountWhenOmitted(t *testing.T) {
	h := newHarness(t, newOSStub())

	st, body := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "/mnt/nas/x", "retain_count": 21,
	})
	if st != 200 {
		t.Fatalf("first write: %d %s", st, body)
	}
	// A later write that says nothing about retention (an older client, or a
	// destination-only edit) must leave the stored count alone.
	st, body = h.do(t, "PUT", "/api/system/backup", map[string]any{"remote_url": "/mnt/nas/y"})
	if st != 200 {
		t.Fatalf("second write: %d %s", st, body)
	}
	var got struct {
		Config Config `json:"config"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Config.RetainCount == nil || *got.Config.RetainCount != 21 {
		t.Fatalf("a partial write dropped the stored retention: %v", got.Config.RetainCount)
	}
	// And an explicit 0 is a change, not an omission.
	st, body = h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "/mnt/nas/y", "retain_count": 0,
	})
	if st != 200 {
		t.Fatalf("third write: %d %s", st, body)
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Config.RetainCount == nil || *got.Config.RetainCount != 0 {
		t.Fatalf("an explicit 0 must be stored as 0: %v", got.Config.RetainCount)
	}
}

// TestConfigPUTAuditsRetentionDistinctly — retention is what deletes copies, so
// the trail must carry it, and must not spell "unset" as 0.
func TestConfigPUTAuditsRetentionDistinctly(t *testing.T) {
	h := newHarness(t, newOSStub())
	if st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{"remote_url": "/mnt/x"}); st != 200 {
		t.Fatalf("write: %d %s", st, b)
	}
	if st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "/mnt/x", "retain_count": 3,
	}); st != 200 {
		t.Fatalf("write: %d %s", st, b)
	}
	var sawUnset, sawThree bool
	for _, e := range h.audit.all() {
		if e.Detail["action"] != "backup_config_update" {
			continue
		}
		switch v := e.Detail["retain_count"].(type) {
		case string:
			sawUnset = sawUnset || v == "unset"
		case int:
			sawThree = sawThree || v == 3
		}
	}
	if !sawUnset {
		t.Error("an unset retention must be audited as \"unset\", never as 0")
	}
	if !sawThree {
		t.Error("the chosen retention was not in the audit trail")
	}
}

// TestSanitizeConfigRefusesRetainCountControlPath — the bound is enforced
// BEFORE the value can reach the file the host applier parses.
func TestSanitizeConfigRefusesRetainCountControlPath(t *testing.T) {
	h := newHarness(t, newOSStub())
	st, b := h.do(t, "PUT", "/api/system/backup", map[string]any{
		"remote_url": "/mnt/x", "retain_count": -4,
	})
	if st != 400 {
		t.Fatalf("a negative retention must be refused with 400, got %d %s", st, b)
	}
	if !strings.Contains(string(b), "retain_count") {
		t.Errorf("the refusal must name the field: %s", b)
	}
}
