// Package models holds the shared data types exchanged between subsystems
// and over the public HTTP API. Keep this package free of behaviour so it
// can be imported anywhere without creating dependency cycles.
package models

import "time"

// Device is the canonical representation of a managed network element.
type Device struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Address           string            `json:"address"`
	Vendor            string            `json:"vendor,omitempty"`
	Model             string            `json:"model,omitempty"`
	OS                string            `json:"os,omitempty"`
	PreferredProtocol string            `json:"preferred_protocol,omitempty"`
	CredentialRef     string            `json:"credential_ref,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Source            string            `json:"source"`
	LastSeen          time.Time         `json:"last_seen"`
}

// Metric is a single time-series sample emitted by a collector.
type Metric struct {
	DeviceID  string            `json:"device_id"`
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// Alert represents a fired alert ready for notification dispatch.
type Alert struct {
	ID          string            `json:"id"`
	Rule        string            `json:"rule"`
	Severity    string            `json:"severity"`
	DeviceID    string            `json:"device_id,omitempty"`
	Summary     string            `json:"summary"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	FiredAt     time.Time         `json:"fired_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
}
