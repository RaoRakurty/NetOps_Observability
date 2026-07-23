package main

import "testing"

// TestSanitizeBackupConfigRejectsScheduleWithoutRemote guards the F-55 footgun
// at the API: enabling the scheduled full backup with no off-host remote is
// refused, because a local-only nightly backup fills the disk it needs.
func TestSanitizeBackupConfigRejectsScheduleWithoutRemote(t *testing.T) {
	_, err := sanitizeBackupConfig(BackupConfig{ScheduleEnabled: true, RemoteURL: ""})
	if err == nil {
		t.Fatal("a schedule with no remote must be refused (F-55)")
	}
	// With a remote it is accepted.
	if _, err := sanitizeBackupConfig(BackupConfig{ScheduleEnabled: true, RemoteURL: "rsync://h/x/"}); err != nil {
		t.Fatalf("schedule + remote should be accepted: %v", err)
	}
}

func TestSanitizeBackupConfigValidatesRemote(t *testing.T) {
	good := []string{"/mnt/nas/x", "rsync://h/x", "s3://b/", "gs://b/", "file:///x"}
	for _, r := range good {
		if _, err := sanitizeBackupConfig(BackupConfig{RemoteURL: r}); err != nil {
			t.Errorf("remote %q should be valid: %v", r, err)
		}
	}
	for _, r := range []string{"not-a-url", "ftp://h/x", "relative/path"} {
		if _, err := sanitizeBackupConfig(BackupConfig{RemoteURL: r}); err == nil {
			t.Errorf("remote %q should be rejected", r)
		}
	}
}

// TestSanitizeBackupConfigDefaultsCron ensures a saved config always has a cron.
func TestSanitizeBackupConfigDefaultsCron(t *testing.T) {
	c, err := sanitizeBackupConfig(BackupConfig{RemoteURL: "/mnt/x", ScheduleEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.ScheduleCron == "" {
		t.Error("cron must default when omitted")
	}
}
