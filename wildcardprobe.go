package tlsrouter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/bnnanet/tlsrouter/dnsresolver"
)

// probeLabelPrefix is the leading label used for wildcard-detection lookups.
// Operators inspecting DNS query logs can recognize these and ignore them.
const probeLabelPrefix = "tlsrouter-probe-"

// parentZone returns the zone one label above name, e.g.
// "foo.apps.example.net" -> "apps.example.net". Returns "" if name has no
// dot (single-label, like a TLD) and can't be probed safely.
func parentZone(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return name[i+1:]
}

// isWildcardParent probes for a wildcard CNAME at the parent zone of name. It
// looks up a random subdomain of parentZone(name) and reports true if the
// terminal CNAME falls under one of the configured IPDomains — i.e. the
// parent is set up as `*.parent CNAME tls-X.<ipdomain>` (or similar) and any
// arbitrary subdomain would resolve into our infrastructure.
//
// A "false, nil" result means the parent is not a wildcard (the probe got
// NXDOMAIN, or the chain terminates outside our IPDomains). A non-nil error
// means we couldn't determine the answer (transient DNS failure); callers
// should fail closed.
func isWildcardParent(ctx context.Context, dns *dnsresolver.Resolver, ipDomains []string, name string) (bool, string, error) {
	parent := parentZone(name)
	if parent == "" {
		return false, "", fmt.Errorf("cannot probe parent zone of %q", name)
	}

	label, err := randomProbeLabel()
	if err != nil {
		return false, parent, err
	}
	probe := label + "." + parent

	cname, _, err := dns.LookupCNAME(ctx, probe)
	if err != nil {
		// LookupCNAME returns an error for NXDOMAIN / no-A-record terminations,
		// which is exactly the "not a wildcard" case. Distinguish that from a
		// genuine resolver failure by checking for the sentinel.
		if errors.Is(err, dnsresolver.ErrNoARecord) {
			slog.Debug("wildcard probe: no A record (not a wildcard)", "probe", probe, "domain", name)
			return false, parent, nil
		}
		return false, parent, fmt.Errorf("probe %q: %w", probe, err)
	}

	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	for _, ipDomain := range ipDomains {
		suffix := "." + strings.ToLower(ipDomain)
		if strings.HasSuffix(cname, suffix) {
			slog.Info("wildcard probe: parent zone is wildcard into IPDomain", "domain", name, "parent", parent, "probe", probe, "terminal", cname)
			return true, parent, nil
		}
	}
	slog.Debug("wildcard probe: parent resolves outside IPDomains (not our wildcard)", "probe", probe, "terminal", cname)
	return false, parent, nil
}

func randomProbeLabel() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return probeLabelPrefix + hex.EncodeToString(b), nil
}
