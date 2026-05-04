package tlsrouter

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/ipcohort"
)

const whitelistRefreshInterval = 5 * time.Minute

type whitelistEntry struct {
	Raw   string
	Label string
}

type IPFilter struct {
	staticPrefixes []string
	domains        []whitelistEntry
	resolved       atomic.Pointer[map[string][]string] // domain → resolved IPs from last success
	cohort         atomic.Pointer[ipcohort.Cohort]
}

func NewIPFilter(ctx context.Context, whitelistPath string) (*IPFilter, error) {
	if whitelistPath == "" {
		return nil, nil
	}

	staticPrefixes, domains, err := parseWhitelist(whitelistPath)
	if err != nil {
		return nil, fmt.Errorf("whitelist %q: %w", whitelistPath, err)
	}

	f := &IPFilter{
		staticPrefixes: staticPrefixes,
		domains:        domains,
	}

	// Initialize resolved map
	emptyResolved := make(map[string][]string)
	f.resolved.Store(&emptyResolved)

	// Initial resolve (blocking)
	f.resolveDomains(ctx)

	// Rebuild cohort from static + resolved
	f.rebuildCohort()

	cohort := f.cohort.Load()
	fmt.Fprintf(os.Stderr, "INFO: ip-whitelist: %d static + %d domains (%d total entries) from %s\n",
		len(staticPrefixes), len(domains), cohort.Size(), whitelistPath)

	go f.refreshLoop(ctx)

	return f, nil
}

func (f *IPFilter) IsAllowed(addr netip.Addr) bool {
	cohort := f.cohort.Load()
	if cohort == nil {
		return false
	}
	return cohort.ContainsAddr(addr)
}

func (f *IPFilter) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(whitelistRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.resolveDomains(ctx)
			f.rebuildCohort()
		}
	}
}

func (f *IPFilter) resolveDomains(ctx context.Context) {
	if len(f.domains) == 0 {
		return
	}

	prev := *f.resolved.Load()
	next := make(map[string][]string, len(f.domains))

	resolver := &net.Resolver{}
	for _, entry := range f.domains {
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := resolver.LookupHost(resolveCtx, entry.Raw)
		cancel()

		if err != nil || len(addrs) == 0 {
			// Keep previous resolution on failure
			if old, ok := prev[entry.Raw]; ok {
				next[entry.Raw] = old
				fmt.Fprintf(os.Stderr, "WARN: ip-whitelist: %s: resolve failed, keeping %d prior IPs: %v\n",
					entry.Raw, len(old), err)
			} else {
				fmt.Fprintf(os.Stderr, "WARN: ip-whitelist: %s: resolve failed (no prior data): %v\n",
					entry.Raw, err)
			}
			continue
		}

		next[entry.Raw] = addrs
	}

	f.resolved.Store(&next)
}

func (f *IPFilter) rebuildCohort() {
	var all []string
	all = append(all, f.staticPrefixes...)

	resolved := *f.resolved.Load()
	for _, addrs := range resolved {
		for _, addr := range addrs {
			all = append(all, addr+"/32")
		}
	}

	cohort, err := ipcohort.Parse(all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: ip-whitelist: rebuild: %v\n", err)
	}
	if cohort != nil {
		f.cohort.Store(cohort)
	}
}

func parseWhitelist(path string) (staticPrefixes []string, domains []whitelistEntry, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()

	r := csv.NewReader(file)
	r.FieldsPerRecord = -1
	r.Comment = '#'
	if strings.HasSuffix(path, ".tsv") {
		r.Comma = '\t'
	}

	for {
		record, readErr := r.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, nil, fmt.Errorf("csv read: %w", readErr)
		}
		if len(record) == 0 {
			continue
		}

		raw := strings.TrimSpace(record[0])
		if raw == "" {
			continue
		}

		var label string
		if len(record) > 1 {
			label = strings.TrimSpace(record[1])
		}

		// Try parsing as IP or CIDR
		if _, err := netip.ParseAddr(raw); err == nil {
			staticPrefixes = append(staticPrefixes, raw+"/32")
			continue
		}
		if _, err := netip.ParsePrefix(raw); err == nil {
			staticPrefixes = append(staticPrefixes, raw)
			continue
		}

		// Not an IP — treat as domain
		domains = append(domains, whitelistEntry{Raw: raw, Label: label})
	}

	return staticPrefixes, domains, nil
}
