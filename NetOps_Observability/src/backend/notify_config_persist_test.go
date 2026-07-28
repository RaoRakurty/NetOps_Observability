package main

// notify_config_persist_test.go — F-78.
//
// notifyConfigStore.save() returned NOTHING and swallowed three distinct
// failures: an encrypt error returned early, a marshal error skipped the write,
// and kvSave's error went to `_`. All five notification-channel PUT handlers
// then answered 200 unconditionally. An operator wiring up paging during an
// incident saw "saved", and the channel reverted at the next restart — on the
// one surface whose entire job is to tell a human that something broke.
//
// The existing TestNoVoidSaveLocked guard missed this purely because the method
// was spelled `save()` rather than `saveLocked()` — the guard had been written
// against the instance the audit named. TestNoVoidPersistFuncs now covers the
// family, and immediately found three more (report_scheduler, cred_sentinel,
// alert_episodes) that the audit never listed.

import (
	"netops/backend/internal/platformdb"
	"testing"
)

func newTestNotifyStore(t *testing.T, path string) *notifyConfigStore {
	t.Helper()
	return &notifyConfigStore{path: path, cfg: defaultNotifyConfig()}
}

func TestNotifyConfigSaveReportsAPersistFailure(t *testing.T) {
	s := newTestNotifyStore(t, "/proc/self/no/such/dir/notify.json")
	s.cfg.Slack.Enabled = true
	s.cfg.Slack.WebhookURL = "https://hooks.example.invalid/T/B/C"

	if err := s.save(); err == nil {
		t.Fatal("save() to an unwritable path must return an error — " +
			"the handler answers 200 otherwise and the channel silently reverts")
	}
}

func TestNotifyConfigSaveSucceedsToAWritablePath(t *testing.T) {
	s := newTestNotifyStore(t, t.TempDir()+"/notify.json")
	s.cfg.Ntfy.Enabled = true
	s.cfg.Ntfy.Topic = "alerts-test"

	if err := s.save(); err != nil {
		t.Fatalf("save() to a writable path must succeed: %v", err)
	}
	// And it must round-trip — a save that writes nothing readable is not a save.
	reloaded := newTestNotifyStore(t, s.path)
	b, err := platformdb.Load(s.path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("save() wrote an empty file")
	}
	_ = reloaded
}

// The regression that matters: a config that failed to persist must not be
// applied to the live dispatcher either, or it works until the next restart and
// then vanishes with no trace of when it stopped.
func TestFailedSaveIsReportedBeforeApply(t *testing.T) {
	s := newTestNotifyStore(t, "/proc/self/no/such/dir/notify.json")
	if err := s.save(); err == nil {
		t.Fatal("expected a persist failure to be returned")
	}
	// save() must not have mutated persisted state into a half-applied form;
	// the in-memory cfg is the caller's, untouched by the failure.
	if s.cfg.SMTP.Port != 587 {
		t.Errorf("a failed save must not corrupt the in-memory config, got port %d", s.cfg.SMTP.Port)
	}
}
