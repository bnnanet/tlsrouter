// Package wildcardlimit tracks ACME issuance attempts against wildcard parent
// zones detected by DNS probing. It enforces a sliding-window cap on new
// issuances per zone and persists counters to a TSV file alongside other
// tlsrouter metrics so the limit survives process restarts.
package wildcardlimit

import (
	"encoding/csv"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func log() *slog.Logger { return slog.Default().WithGroup("wildcardlimit") }

type zoneBucket struct {
	WindowTimes  []time.Time
	LastIssuedAt time.Time
	LastDeniedAt time.Time
	TotalIssued  uint64
	TotalDenied  uint64
	ProbeHits    uint64 // probe detected this zone as wildcard
}

// Limiter enforces a per-zone sliding-window cap on ACME issuance attempts.
type Limiter struct {
	mu     sync.Mutex
	fileMu sync.Mutex
	zones  map[string]*zoneBucket
	limit  int
	window time.Duration
	dirty  bool
	stop   chan struct{}
	path   string
}

// New constructs a Limiter, loads any persisted state, and starts the flush
// loop. limit == 0 disables the cap (probes are still recorded). window == 0
// is treated as 24h.
func New(dataDir string, limit int, window time.Duration) *Limiter {
	if window <= 0 {
		window = 24 * time.Hour
	}
	wl := &Limiter{
		zones:  make(map[string]*zoneBucket),
		limit:  limit,
		window: window,
		stop:   make(chan struct{}),
		path:   filepath.Join(dataDir, "wildcard_probes.tsv"),
	}
	wl.load()
	go wl.flushLoop()
	return wl
}

// Allow reports whether a new issuance for zone is permitted. Each call —
// allowed or not — is recorded so denied attempts are visible in the TSV.
func (wl *Limiter) Allow(zone string) bool {
	now := time.Now()
	wl.mu.Lock()
	defer wl.mu.Unlock()

	bucket, ok := wl.zones[zone]
	if !ok {
		bucket = &zoneBucket{}
		wl.zones[zone] = bucket
	}
	cutoff := now.Add(-wl.window)
	bucket.WindowTimes = trimBefore(bucket.WindowTimes, cutoff)

	if wl.limit > 0 && len(bucket.WindowTimes) >= wl.limit {
		bucket.LastDeniedAt = now
		bucket.TotalDenied++
		wl.dirty = true
		return false
	}
	bucket.WindowTimes = append(bucket.WindowTimes, now)
	bucket.LastIssuedAt = now
	bucket.TotalIssued++
	wl.dirty = true
	return true
}

// RecordProbe notes that a probe determined whether zone is served by a
// wildcard. It does not affect the rate limit.
func (wl *Limiter) RecordProbe(zone string, isWildcard bool) {
	if !isWildcard {
		return
	}
	wl.mu.Lock()
	defer wl.mu.Unlock()
	bucket, ok := wl.zones[zone]
	if !ok {
		bucket = &zoneBucket{}
		wl.zones[zone] = bucket
	}
	bucket.ProbeHits++
	wl.dirty = true
}

// Shutdown flushes pending state to disk and stops the background flush loop.
func (wl *Limiter) Shutdown() {
	close(wl.stop)
	wl.flush()
}

func (wl *Limiter) flushLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			wl.flush()
		case <-wl.stop:
			return
		}
	}
}

func (wl *Limiter) flush() {
	wl.fileMu.Lock()
	defer wl.fileMu.Unlock()

	wl.mu.Lock()
	if !wl.dirty {
		wl.mu.Unlock()
		return
	}

	var buf strings.Builder
	w := csv.NewWriter(&buf)
	w.Comma = '\t'
	_ = w.Write([]string{"zone", "last_issued_at", "last_denied_at", "window_count", "total_issued", "total_denied", "probe_hits"})
	for zone, bucket := range wl.zones {
		_ = w.Write([]string{
			zone,
			formatTime(bucket.LastIssuedAt),
			formatTime(bucket.LastDeniedAt),
			strconv.Itoa(len(bucket.WindowTimes)),
			strconv.FormatUint(bucket.TotalIssued, 10),
			strconv.FormatUint(bucket.TotalDenied, 10),
			strconv.FormatUint(bucket.ProbeHits, 10),
		})
	}
	w.Flush()
	wl.mu.Unlock()

	tmp := wl.path + ".tmp"
	_ = os.MkdirAll(filepath.Dir(wl.path), 0o700)
	if err := os.WriteFile(tmp, []byte(buf.String()), 0o644); err != nil {
		log().Warn("failed to write", "path", tmp, "err", err)
		return
	}
	_ = os.Remove(wl.path + ".bak")
	if _, err := os.Stat(wl.path); err == nil {
		if err := os.Rename(wl.path, wl.path+".bak"); err != nil {
			log().Warn("failed to backup", "path", wl.path, "err", err)
			return
		}
	}
	if err := os.Rename(tmp, wl.path); err != nil {
		log().Warn("failed to rename", "path", wl.path, "err", err)
		return
	}

	wl.mu.Lock()
	wl.dirty = false
	wl.mu.Unlock()
}

func (wl *Limiter) load() {
	f, err := os.Open(wl.path)
	if err != nil {
		return
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comma = '\t'
	r.Comment = '#'
	r.FieldsPerRecord = -1

	rows, err := r.ReadAll()
	if err != nil {
		log().Warn("failed to read", "path", wl.path, "err", err)
		return
	}

	cutoff := time.Now().Add(-wl.window)
	for _, fields := range rows {
		if len(fields) < 7 {
			continue
		}
		if fields[0] == "zone" {
			continue
		}
		bucket := &zoneBucket{}
		bucket.LastIssuedAt = parseTime(fields[1])
		bucket.LastDeniedAt = parseTime(fields[2])
		bucket.TotalIssued, _ = strconv.ParseUint(fields[4], 10, 64)
		bucket.TotalDenied, _ = strconv.ParseUint(fields[5], 10, 64)
		bucket.ProbeHits, _ = strconv.ParseUint(fields[6], 10, 64)

		// Reconstruct an approximate window from the last issuance: if the
		// most recent issuance still falls inside the window, assume the
		// recorded window_count remains current. Persisted timestamps for
		// every issuance would be more accurate but balloon the TSV size.
		windowCount, _ := strconv.Atoi(fields[3])
		if !bucket.LastIssuedAt.IsZero() && bucket.LastIssuedAt.After(cutoff) && windowCount > 0 {
			for range windowCount {
				bucket.WindowTimes = append(bucket.WindowTimes, bucket.LastIssuedAt)
			}
		}
		wl.zones[fields[0]] = bucket
	}
}

func trimBefore(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for ; i < len(times); i++ {
		if times[i].After(cutoff) {
			break
		}
	}
	return times[i:]
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
