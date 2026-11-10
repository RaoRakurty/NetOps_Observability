// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// platformSettings is the pre-scope operator config as settings: one platform
// scope.
func platformSettings(enabled bool, ranges []string, creds []ScanCredential) ScanSettings {
	return ScanSettings{Enabled: enabled, Scopes: []ScanScope{{ID: PlatformScopeID, Ranges: ranges, Credentials: creds}}}
}

func ptrSettings(s ScanSettings) *ScanSettings { return &s }

// withPlatform returns a copy of c whose platform scope (Scopes[0]) is mutated;
// the scope slice is copied so c itself is untouched.
func withPlatform(c ScanSettings, mutate func(*ScanScope)) ScanSettings {
	scopes := append([]ScanScope(nil), c.Scopes...)
	mutate(&scopes[0])
	c.Scopes = scopes
	return c
}
