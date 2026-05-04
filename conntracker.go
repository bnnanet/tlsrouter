package tlsrouter

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type connRecord struct {
	IP       string
	LastSeen time.Time
	Count    uint64
	BytesIn  uint64
	BytesOut uint64
}

type connTracker struct {
	mu      sync.Mutex
	records map[string]*connRecord // keyed by "domain\tip"
	dirty   bool
	stop    chan struct{}
}

func newConnTracker() *connTracker {
	ct := &connTracker{
		records: make(map[string]*connRecord),
		stop:    make(chan struct{}),
	}
	ct.load()
	go ct.flushLoop()
	return ct
}

func (ct *connTracker) Track(domain, ip string, bytesIn, bytesOut uint64) {
	key := domain + "\t" + ip
	ct.mu.Lock()
	rec, ok := ct.records[key]
	if !ok {
		rec = &connRecord{IP: ip}
		ct.records[key] = rec
	}
	rec.LastSeen = time.Now()
	rec.Count++
	rec.BytesIn += bytesIn
	rec.BytesOut += bytesOut
	ct.dirty = true
	ct.mu.Unlock()
}

func (ct *connTracker) Shutdown() {
	close(ct.stop)
	ct.flush()
}

func (ct *connTracker) flushLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ct.flush()
		case <-ct.stop:
			return
		}
	}
}

func (ct *connTracker) flush() {
	ct.mu.Lock()
	if !ct.dirty {
		ct.mu.Unlock()
		return
	}

	var buf strings.Builder
	w := csv.NewWriter(&buf)
	w.Comma = '\t'
	_ = w.Write([]string{"domain", "ip", "last_seen", "count", "bytes_in", "bytes_out"})
	for key, rec := range ct.records {
		domain, ip, _ := strings.Cut(key, "\t")
		_ = w.Write([]string{
			domain,
			ip,
			rec.LastSeen.UTC().Format(time.RFC3339),
			strconv.FormatUint(rec.Count, 10),
			strconv.FormatUint(rec.BytesIn, 10),
			strconv.FormatUint(rec.BytesOut, 10),
		})
	}
	w.Flush()
	ct.dirty = false
	ct.mu.Unlock()

	path := connTrackerPath()
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(buf.String()), 0o644); err != nil {
		return
	}
	_ = os.Remove(path + ".bak")
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, path+".bak"); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: conntracker: failed to backup %s: %v\n", path, err)
			return
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: conntracker: failed to rename %s: %v\n", tmp, err)
	}
}

func (ct *connTracker) load() {
	f, err := os.Open(connTrackerPath())
	if err != nil {
		return
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.Comma = '\t'
	r.Comment = '#'

	records, err := r.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: conntracker: failed to read %s: %v\n", connTrackerPath(), err)
		return
	}

	for _, fields := range records {
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "domain" {
			continue
		}
		domain := fields[0]
		ip := fields[1]
		t, err := time.Parse(time.RFC3339, fields[2])
		if err != nil {
			continue
		}
		count, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			continue
		}
		var bytesIn, bytesOut uint64
		if len(fields) >= 6 {
			bytesIn, _ = strconv.ParseUint(fields[4], 10, 64)
			bytesOut, _ = strconv.ParseUint(fields[5], 10, 64)
		}
		key := domain + "\t" + ip
		ct.records[key] = &connRecord{
			IP:       ip,
			LastSeen: t,
			Count:    count,
			BytesIn:  bytesIn,
			BytesOut: bytesOut,
		}
	}
}

func connTrackerPath() string {
	return filepath.Join(certmagicDataDir(), "connections.tsv")
}
