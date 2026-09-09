package ipgate

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// DomainBlocklist is a static set of blocked domain names.
type DomainBlocklist struct {
	domains map[string]struct{}
}

// NewDomainBlocklist loads a CSV of blocked domain names (one per row).
// Supports comments (lines starting with #). Domains are lowercased.
func NewDomainBlocklist(ctx context.Context, csvPath string) (*DomainBlocklist, error) {
	_ = ctx
	if csvPath == "" {
		return nil, nil
	}

	blocklist := &DomainBlocklist{domains: make(map[string]struct{})}
	file, err := os.Open(csvPath)
	if err != nil {
		return nil, fmt.Errorf("domain blocklist %q: %w", csvPath, err)
	}
	defer func() { _ = file.Close() }()

	r := csv.NewReader(file)
	r.FieldsPerRecord = -1
	r.Comment = '#'
	for {
		record, readErr := r.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("csv read: %w", readErr)
		}
		if len(record) == 0 {
			continue
		}
		domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(record[0])), "*.")
		if domain != "" {
			blocklist.domains[domain] = struct{}{}
		}
	}
	return blocklist, nil
}

// Contains checks if a domain is blocked.
// Normalises wildcard forms: "*.example.com", ".example.com", and
// "example.com" all match a blocklist entry for "example.com".
func (bl *DomainBlocklist) Contains(domain string) bool {
	if bl == nil {
		return false
	}
	domain = strings.TrimPrefix(strings.ToLower(domain), "*.")
	domain = strings.TrimPrefix(domain, ".")
	_, ok := bl.domains[domain]
	return ok
}

// Domains returns a copy of the blocked domain names.
func (bl *DomainBlocklist) Domains() []string {
	if bl == nil {
		return nil
	}
	result := make([]string, 0, len(bl.domains))
	for domain := range bl.domains {
		result = append(result, domain)
	}
	return result
}
