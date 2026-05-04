package tlsrouter

import (
	"sync/atomic"
	"time"
)

const (
	minTTL     = 30 * time.Second
	maxTTL     = 10 * time.Minute
	staleTTL   = 5 * time.Minute
	defaultTTL = 5 * time.Minute
)

type CacheState int

const (
	CacheFresh CacheState = iota
	CacheStale
	CacheExpired
)

type dnsCacheEntry struct {
	service   *ConfigService
	staleAt   atomic.Int64 // Unix seconds; zero means forever-fresh
	expiresAt atomic.Int64 // Unix seconds; zero means never-expires
}

func newCacheEntry(service *ConfigService, staleAt, expiresAt time.Time) *dnsCacheEntry {
	e := &dnsCacheEntry{service: service}
	if !staleAt.IsZero() {
		e.staleAt.Store(staleAt.Unix())
		e.expiresAt.Store(expiresAt.Unix())
	}
	return e
}

func (e *dnsCacheEntry) state() CacheState {
	stale := e.staleAt.Load()
	if stale == 0 {
		return CacheFresh
	}
	now := time.Now().Unix()
	if now < stale {
		return CacheFresh
	}
	if now < e.expiresAt.Load() {
		return CacheStale
	}
	return CacheExpired
}

func (e *dnsCacheEntry) extend(staleAt, expiresAt time.Time) {
	e.staleAt.Store(staleAt.Unix())
	e.expiresAt.Store(expiresAt.Unix())
}

func clampTTL(ttl uint32) time.Duration {
	d := time.Duration(ttl) * time.Second
	if d < minTTL {
		d = minTTL
	}
	if d > maxTTL {
		d = maxTTL
	}
	return d
}
