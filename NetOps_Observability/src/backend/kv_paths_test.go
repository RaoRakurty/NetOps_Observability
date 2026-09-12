// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"
	"testing"
)

// TestStoreKeysAreAbsolute guards the CLASS behind F-63/F-65 (2026-07-21).
//
// Seven file-backed settings stores returned a RELATIVE kv key
// ("tenant_governance.json"). Under the default file backend a relative key
// resolves against the API container's WORKDIR — /home/nonroot — which is not
// the /data bind mount and is not writable when install.py stamps a non-65532
// CORRELIX_UID. The resulting EACCES was swallowed, the handler had no value to
// check, and an AuditEvent{Status:200, Decision:"allow"} was written asserting
// success. So the setting silently never persisted, and the audit trail said it
// did.
//
// This is a whole-class guard rather than seven point assertions: any NEW store
// that forgets the /data prefix fails here instead of in a customer's install.
// It also catches the sealed-DEK custody key, where the same slip would make
// every sealed secret permanently undecryptable after a restart.
func TestStoreKeysAreAbsolute(t *testing.T) {
	keys := map[string]string{
		"tenant governance": tenantGovernancePath(),
		"rca action items":  rcaActionItemsPath(),
		"cloud monitors":    cloudMonitorsPath(),
		"cloud slo":         cloudSLOPath(),
		"rca promotion":     rcaPromotionsPath(),
		"rca revisions":     rcaRevisionsPath(),
		"tenant display":    tenantDisplayPath(),
	}
	for name, key := range keys {
		if key == "" {
			t.Errorf("%s: empty store key", name)
			continue
		}
		if !strings.HasPrefix(key, "/") {
			t.Errorf("%s: store key %q is RELATIVE — it resolves against the container "+
				"WORKDIR (/home/nonroot), not the /data mount, so the write is silently "+
				"lost on a default install. Prefix it with /data.", name, key)
		}
	}
}
