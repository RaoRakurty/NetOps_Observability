// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

// mock_test.go — the offline upstream. CI has no network (§11), so EVERY test
// in this package drives this fake; a test that reached stat.ripe.net would be
// a broken test, not a thorough one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type fakeFetcher struct {
	mu sync.Mutex
	// data maps "<call>:<resource>" → raw data JSON.
	data map[string]string
	// fail maps "<call>:<resource>" → an error to return instead.
	fail map[string]error
	// gets maps a URL → its body.
	gets     map[string]string
	getFail  map[string]error
	calls    atomic.Int64
	getCalls atomic.Int64
	// seen records every (call, resource, extra) triple for assertions.
	seen []string
}

func newFake() *fakeFetcher {
	return &fakeFetcher{
		data: map[string]string{}, fail: map[string]error{},
		gets: map[string]string{}, getFail: map[string]error{},
	}
}

func (f *fakeFetcher) RIPEstat(_ context.Context, call, resource, extra string, _ time.Duration) (json.RawMessage, error) {
	f.calls.Add(1)
	key := call + ":" + resource
	f.mu.Lock()
	f.seen = append(f.seen, fmt.Sprintf("%s|%s|%s", call, resource, extra))
	err, bad := f.fail[key]
	body, ok := f.data[key]
	f.mu.Unlock()
	if bad {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("fake: no scripted answer for %s", key)
	}
	return json.RawMessage(body), nil
}

func (f *fakeFetcher) Get(_ context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	f.getCalls.Add(1)
	if _, err := SafeOutboundURL(rawURL); err != nil {
		return nil, err // the fake enforces the same gate the real client does
	}
	f.mu.Lock()
	err, bad := f.getFail[rawURL]
	body, ok := f.gets[rawURL]
	f.mu.Unlock()
	if bad {
		return nil, err
	}
	if !ok {
		return nil, errors.New("fake: no scripted body for " + rawURL)
	}
	if int64(len(body)) > maxBytes {
		body = body[:maxBytes]
	}
	return []byte(body), nil
}

func (f *fakeFetcher) put(call, resource, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[call+":"+resource] = data
}

func (f *fakeFetcher) putErr(call, resource string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[call+":"+resource] = err
}

func (f *fakeFetcher) putGet(url, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets[url] = body
}

func (f *fakeFetcher) sawExtra(sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.seen {
		if len(sub) > 0 && contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// fixedNow makes every timestamp assertion deterministic.
func fixedNow() func() time.Time {
	t := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}
