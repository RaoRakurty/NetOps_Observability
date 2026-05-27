// Package store wraps the database and time-series-DB clients. The
// scaffold ships with in-memory stubs so the binary runs without
// PostgreSQL or VictoriaMetrics; production code should swap in
// pgx / VictoriaMetrics-go bindings here.
package store

import (
	"sync"

	"netops/backend/models"
)

// DeviceStore is an in-memory device registry. Replace with a PostgreSQL-
// backed implementation when persistence is required.
type DeviceStore struct {
	mu      sync.RWMutex
	devices map[string]models.Device
}

func NewDeviceStore() *DeviceStore {
	return &DeviceStore{devices: make(map[string]models.Device)}
}

func (s *DeviceStore) Put(d models.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.ID] = d
}

func (s *DeviceStore) Get(id string) (models.Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	return d, ok
}

func (s *DeviceStore) List() []models.Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d)
	}
	return out
}
