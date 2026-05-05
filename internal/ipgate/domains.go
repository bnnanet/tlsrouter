package ipgate

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bnnanet/tlsrouter/dnsresolver"
	"github.com/therootcompany/golib/net/ipcohort"
)

const domainSetRefreshInterval = 5 * time.Minute

type domainEntry struct {
	Raw   string
	Label string
}

type DomainSet struct {
	staticPrefixes []string
	domains        []domainEntry
	resolved       atomic.Pointer[map[string][]string]
	cohort         atomic.Pointer[ipcohort.Cohort]
}

func EmptyDomainSet() *DomainSet {
	ds := &DomainSet{}
	ds.cohort.Store(&ipcohort.Cohort{})
	return ds
}

func NewDomainSet(ctx context.Context, csvPath string) (*DomainSet, error) {
	if csvPath == "" {
		return nil, nil
	}

	staticPrefixes, domains, err := parseDomainSetCSV(csvPath)
	if err != nil {
		return nil, fmt.Errorf("domain set %q: %w", csvPath, err)
	}

	ds := &DomainSet{
		staticPrefixes: staticPrefixes,
		domains:        domains,
	}

	emptyResolved := make(map[string][]string)
	ds.resolved.Store(&emptyResolved)

	ds.rebuildCohort()

	fmt.Fprintf(os.Stderr, "INFO: ipgate: domain set %s static + %s domains from %s (resolving in background)\n",
		commaify(len(staticPrefixes)), commaify(len(domains)), csvPath)

	go ds.refreshLoop(ctx)

	return ds, nil
}

func (ds *DomainSet) Contains(addr netip.Addr) bool {
	return ds.cohort.Load().ContainsAddr(addr)
}

func (ds *DomainSet) refreshLoop(ctx context.Context) {
	ds.resolveDomains(ctx)
	ds.rebuildCohort()

	ticker := time.NewTicker(domainSetRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ds.resolveDomains(ctx)
			ds.rebuildCohort()
		}
	}
}

func (ds *DomainSet) resolveDomains(ctx context.Context) {
	if len(ds.domains) == 0 {
		return
	}

	prev := *ds.resolved.Load()
	next := make(map[string][]string, len(ds.domains))

	resolver := dnsresolver.New()
	for _, entry := range ds.domains {
		ips, _, err := resolver.LookupIP(ctx, entry.Raw)

		if err != nil || len(ips) == 0 {
			if old, ok := prev[entry.Raw]; ok {
				next[entry.Raw] = old
				fmt.Fprintf(os.Stderr, "WARN: ipgate: %s: resolve failed, keeping %d prior IPs: %v\n",
					entry.Raw, len(old), err)
			} else {
				fmt.Fprintf(os.Stderr, "WARN: ipgate: %s: resolve failed (no prior data): %v\n",
					entry.Raw, err)
			}
			continue
		}

		addrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
		next[entry.Raw] = addrs
	}

	ds.resolved.Store(&next)
}

func (ds *DomainSet) rebuildCohort() {
	var all []string
	all = append(all, ds.staticPrefixes...)

	resolved := *ds.resolved.Load()
	for _, addrs := range resolved {
		for _, addr := range addrs {
			all = append(all, addr+"/32")
		}
	}

	cohort, err := ipcohort.Parse(all)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: ipgate: domain set rebuild: %v\n", err)
	}
	if cohort != nil {
		ds.cohort.Store(cohort)
	}
}

func parseDomainSetCSV(path string) (staticPrefixes []string, domains []domainEntry, err error) {
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

	firstRow := true
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

		if firstRow {
			firstRow = false
			if _, err := netip.ParseAddr(raw); err != nil {
				if _, err := netip.ParsePrefix(raw); err != nil {
					if !strings.Contains(raw, ".") {
						continue
					}
				}
			}
		}
		if raw == "" {
			continue
		}

		var label string
		if len(record) > 1 {
			label = strings.TrimSpace(record[1])
		}

		if _, err := netip.ParseAddr(raw); err == nil {
			staticPrefixes = append(staticPrefixes, raw+"/32")
			continue
		}
		if _, err := netip.ParsePrefix(raw); err == nil {
			staticPrefixes = append(staticPrefixes, raw)
			continue
		}

		domains = append(domains, domainEntry{Raw: raw, Label: label})
	}

	return staticPrefixes, domains, nil
}
