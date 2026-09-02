package seclane

// spool.go — the LAST rung of the dead-letter ladder: a bounded local JSONL
// file, written only when the dead-letter TOPIC is itself unreachable. It is
// what keeps `lost_total` honest (the 189 persist contract): evidence with a
// durable copy on disk is dead-lettered, not lost.

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// NewFileSpool returns a Deps.Spool implementation appending to path. A blank
// path disables the spool (the ladder then ends at the dead-letter topic and a
// failure there is honestly counted as LOST). maxBytes <= 0 uses
// DeadLetterMaxBytes.
//
// The file is opened 0600 and append-only: this is evidence about a tenant's
// devices, so it never becomes group- or world-readable, and an existing spool
// is never truncated.
func NewFileSpool(path string, maxBytes int64, now func() time.Time,
	tenantSeg func(string) string, scrub func(string) string) func(string, []Record, error) error {

	if maxBytes <= 0 {
		maxBytes = DeadLetterMaxBytes
	}
	return func(tenant string, recs []Record, cause error) error {
		if path == "" {
			return fmt.Errorf("seclane: local dead-letter spool is disabled (%s empty)", EnvDeadLetterFile)
		}
		if fi, err := os.Stat(path); err == nil && fi.Size() > maxBytes {
			return fmt.Errorf("seclane: local dead-letter spool is full (%d bytes > %d)", fi.Size(), maxBytes)
		}
		fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured spool path, never request input
		if err != nil {
			return err
		}
		defer func() { _ = fh.Close() }()
		enc := json.NewEncoder(fh)
		for _, r := range recs {
			if err := enc.Encode(map[string]any{
				"dropped_at": now().UTC().Format(time.RFC3339Nano),
				"lane":       "security_lane",
				"tenant_seg": tenantSeg(tenant),
				"reason":     "producer_retries_exhausted",
				"detail":     scrub(cause.Error()),
				"key":        r.Key,
				"raw":        r.Value,
			}); err != nil {
				return err
			}
		}
		return nil
	}
}
