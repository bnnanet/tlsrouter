package tlsrouter

import "time"

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
	staleAt   time.Time
	expiredAt time.Time
}

func (e *dnsCacheEntry) state() CacheState {
	now := time.Now()
	if now.Before(e.staleAt) {
		return CacheFresh
	}
	if now.Before(e.expiredAt) {
		return CacheStale
	}
	return CacheExpired
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
