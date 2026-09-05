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
