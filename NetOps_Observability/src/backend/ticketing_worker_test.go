package main

import (
	"context"
	"testing"
	"time"
)

// testWorker builds a worker over an in-mem store + the mock ServiceNow adapter.
func testWorker(t *testing.T, m *mockServiceNow) (*ticketWorker, ticketingStore) {
	t.Helper()
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	store := newMemTicketingStore()
	resolve := func(_ context.Context, tenant, _ string) (ticketSystemConfig, bool, error) {
		c := m.cfg()
		c.TenantID = tenant // mirror production: the resolver stamps tenant identity
		return c, true, nil
	}
	w := newTicketWorker(store, resolve)
	w.adapters["servicenow"] = m.adapter() // inject the mock-backed adapter
	return w, store
}

func TestOutboxWorker_CreateHappyPath(t *testing.T) {
	m := newMockServiceNow()
	defer m.Close()
	w, store := testWorker(t, m)
	ctx := context.Background()

	if err := enqueueTicketCreate(ctx, store, "t_a", "servicenow", samplePayload("obj-1")); err != nil {
		t.Fatal(err)
	}

	n, err := w.tick(ctx, time.Now().UTC())
	if err != nil || n != 1 {
		t.Fatalf("tick processed=%d err=%v", n, err)
	}

	// One incident created and bound by correlation id.
	if _, ok := m.incidentByCorr("obj-1"); !ok {
		t.Fatal("no incident created on the mock")
	}
	// Link advanced to open with the ticket number + sys id.
	link, found, _ := store.GetLink(ctx, "t_a", false, "obj-1", "servicenow")
	if !found || !link.Open() || link.TicketNumber == "" || link.SysID == "" {
		t.Fatalf("link not advanced: found=%v %+v", found, link)
	}
	// Audit trail recorded the create.
	au, _, _ := store.ListAudit(ctx, "t_a", false, "obj-1", ticketMaxPage, 0)
	if len(au) != 1 || au[0].Action != "create" || au[0].Result != "ok" {
		t.Fatalf("audit not recorded: %+v", au)
	}
	// Outbox item is sent (terminal).
	out, _, _ := store.ListOutbox(ctx, "t_a", false, ticketMaxPage, 0)
	if len(out) != 1 || out[0].Status != "sent" {
		t.Fatalf("outbox not marked sent: %+v", out)
	}
}

func TestOutboxWorker_NeverDoubleCreates(t *testing.T) {
	m := newMockServiceNow()
	defer m.Close()
	w, store := testWorker(t, m)
	ctx := context.Background()

	// Simulate a create that reached ServiceNow but whose link store never
	// persisted (no link). A fresh create item must ADOPT the existing incident
	// via correlation-id lookup, not open a second.
	a := m.adapter()
	if _, err := a.CreateIncident(ctx, m.cfg(), samplePayload("obj-2")); err != nil {
		t.Fatal(err)
	}
	if m.creates != 1 {
		t.Fatalf("setup expected 1 create, got %d", m.creates)
	}

	_ = enqueueTicketCreate(ctx, store, "t_a", "servicenow", samplePayload("obj-2"))
	if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	if m.creates != 1 {
		t.Fatalf("worker double-created: total creates=%d (want 1)", m.creates)
	}
	link, found, _ := store.GetLink(ctx, "t_a", false, "obj-2", "servicenow")
	if !found || link.SysID == "" {
		t.Fatalf("link not bound to the adopted incident: %+v", link)
	}
}

func TestOutboxWorker_RetryThenDeadLetter(t *testing.T) {
	m := newMockServiceNow()
	defer m.Close()
	w, store := testWorker(t, m)
	w.maxRetries = 2 // dead-letter fast
	ctx := context.Background()

	m.failNext = 10 // every create fails
	_ = enqueueTicketCreate(ctx, store, "t_a", "servicenow", samplePayload("obj-3"))

	// First attempt fails → retrying, retry_count=1, future next_retry_at.
	if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	out, _, _ := store.ListOutbox(ctx, "t_a", false, ticketMaxPage, 0)
	if len(out) != 1 || out[0].Status != "retrying" || out[0].RetryCount != 1 {
		t.Fatalf("after fail1: %+v", out)
	}
	if !out[0].NextRetryAt.After(time.Now().UTC()) {
		t.Fatalf("backoff did not push next_retry_at into the future: %+v", out[0])
	}

	// Force it due again and tick: second failure hits maxRetries → dead_letter.
	due := out[0]
	due.NextRetryAt = time.Now().UTC().Add(-time.Second)
	due.Status = "pending"
	_ = store.FinishOutbox(ctx, due)

	if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	out, _, _ = store.ListOutbox(ctx, "t_a", false, ticketMaxPage, 0)
	if out[0].Status != "dead_letter" {
		t.Fatalf("expected dead_letter, got %q (retries=%d)", out[0].Status, out[0].RetryCount)
	}
	// No incident was ever created.
	if _, ok := m.incidentByCorr("obj-3"); ok {
		t.Fatal("an incident was created despite all-failures")
	}
}

func TestOutboxWorker_HoldsWhenNoConnection(t *testing.T) {
	m := newMockServiceNow()
	defer m.Close()
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	store := newMemTicketingStore()
	// resolver reports "not configured yet".
	w := newTicketWorker(store, func(_ context.Context, _, _ string) (ticketSystemConfig, bool, error) {
		return ticketSystemConfig{}, false, nil
	})
	w.adapters["servicenow"] = m.adapter()
	ctx := context.Background()

	_ = enqueueTicketCreate(ctx, store, "t_a", "servicenow", samplePayload("obj-4"))
	if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	out, _, _ := store.ListOutbox(ctx, "t_a", false, ticketMaxPage, 0)
	if out[0].Status != "retrying" {
		t.Fatalf("missing connection should hold (retry), got %q", out[0].Status)
	}
	if m.creates != 0 {
		t.Fatal("nothing should have been created without a connection")
	}
}
