// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cred_sentinel.go — main-side wiring for the self-healing SNMP credential
// sentinel (internal/snmpcred/sentinel.go, extracted P2 RA.14): env intervals
// and the devices-API annotation join.

import (
	"netops/backend/internal/snmpcred"
	"time"

	"netops/backend/models"
)

type (
	credOverride      = snmpcred.Override
	credOverrideStore = snmpcred.OverrideStore
	credSentinel      = snmpcred.Sentinel
)

func newCredOverrideStore(path string) (*credOverrideStore, error) {
	return snmpcred.NewOverrideStore(path)
}

func newCredSentinel(overrides *credOverrideStore, creds *snmpcred.Store, devices func() []models.Device) *credSentinel {
	return snmpcred.NewSentinel(overrides, creds, devices,
		envDuration("CRED_SENTINEL_INTERVAL", 2*time.Minute),
		envDuration("CRED_SENTINEL_COOLDOWN", 10*time.Minute))
}

// withCredActive annotates devices with the sentinel's learned binding, so the
// Devices UI/API can show when polling runs on a different profile than bound.
func (s *server) withCredActive(devs []models.Device) []models.Device {
	if s.credOverrides == nil {
		return devs
	}
	for i := range devs {
		if ov, ok := s.credOverrides.Get(devs[i].ID); ok {
			devs[i].CredentialActive = ov.ProfileID
		}
	}
	return devs
}
