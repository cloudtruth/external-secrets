/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sigmaconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	// cacheTTL is fixed by the PRD: every store costs at most one bulk fetch per 30 s.
	cacheTTL = 30 * time.Second
	// cacheMaxEntries bounds memory; the oldest entry is evicted first.
	cacheMaxEntries = 256
)

// snapshot is the result of one fetch: either the parameters or the error it ended with.
// Errors are cached too, so a broken template or a missing tag costs one call per 30 s, not one per reconcile.
type snapshot struct {
	// values maps parameter name to its value in the environment; nil means "no value".
	values map[string]*paramValue
	err    error
}

type paramValue struct {
	value *string
	// externalError is the external_status.error_code of a value pulled from another store.
	externalError string
}

type cacheEntry struct {
	snap    *snapshot
	expires time.Time
	added   time.Time
}

type inflight struct {
	done chan struct{}
	snap *snapshot
}

// snapshotCache is shared by every client in the process: ESO builds a new client per
// reconcile, so a per-client cache would never be hit. Concurrent misses for one key share
// a single fetch.
type snapshotCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*cacheEntry
	pending map[string]*inflight
}

func newSnapshotCache(now func() time.Time) *snapshotCache {
	return &snapshotCache{
		now:     now,
		entries: map[string]*cacheEntry{},
		pending: map[string]*inflight{},
	}
}

// get returns the cached snapshot for key, or calls fill once (across concurrent callers)
// and caches its result for cacheTTL.
func (c *snapshotCache) get(key string, fill func() *snapshot) *snapshot {
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.snap
	}
	if p, ok := c.pending[key]; ok {
		c.mu.Unlock()
		<-p.done
		return p.snap
	}
	p := &inflight{done: make(chan struct{})}
	c.pending[key] = p
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		// A canceled caller's error says nothing about the API; don't hand it to the next reconcile.
		if !isContextError(p.snap.err) {
			now := c.now()
			c.evictLocked(now)
			c.entries[key] = &cacheEntry{snap: p.snap, expires: now.Add(cacheTTL), added: now}
		}
		delete(c.pending, key)
		c.mu.Unlock()
		close(p.done)
	}()
	p.snap = fill()
	return p.snap
}

// evictLocked drops expired entries and, if still full, the oldest one.
func (c *snapshotCache) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= cacheMaxEntries {
		var oldestKey string
		var oldest time.Time
		for k, e := range c.entries {
			if oldestKey == "" || e.added.Before(oldest) {
				oldestKey, oldest = k, e.added
			}
		}
		delete(c.entries, oldestKey)
	}
}

// projectIDCache maps server + key hash + project name to the project's ID. It has no TTL;
// an ID is dropped only when the API says it no longer exists.
type projectIDCache struct {
	mu  sync.Mutex
	ids map[string]string
}

func (p *projectIDCache) get(key string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.ids[key]
	return id, ok
}

func (p *projectIDCache) set(key, id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ids == nil {
		p.ids = map[string]string{}
	}
	p.ids[key] = id
}

func (p *projectIDCache) drop(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.ids, key)
}

// Process-wide caches.
var (
	sharedSnapshots  = newSnapshotCache(time.Now)
	sharedProjectIDs = &projectIDCache{}
)

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// hashKey is the SHA-256 of the API key, so the raw key never sits in a map key.
func hashKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// cacheKey hashes its parts with a separator that cannot appear in a SHA-256 hex string.
func cacheKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
