package ticketing

import (
	"context"
	"fmt"
	"testing"
)

// TestMemTicketingAuditIsRingBuffered: the in-memory ticketing audit slice was
// append-only forever, while its sibling audit store ring-buffers at 5000.
func TestMemTicketingAuditIsRingBuffered(t *testing.T) {
	m := NewMemStore()
	total := memTicketAuditMax + 500
	for i := 0; i < total; i++ {
		if err := m.AppendAudit(context.Background(), AuditEntry{
			TenantID: "t1", ID: fmt.Sprintf("c%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.RLock()
	n := len(m.audit)
	oldest := m.audit[0].ID
	m.mu.RUnlock()
	if n > memTicketAuditMax {
		t.Fatalf("audit trail holds %d entries, cap is %d — append-only growth in the API heap", n, memTicketAuditMax)
	}
	if oldest == "c0" {
		t.Error("the oldest entry survived — nothing was evicted")
	}
}
