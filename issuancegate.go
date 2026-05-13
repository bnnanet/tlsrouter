package tlsrouter

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// staticMatch is the result of walking the static config for an issuance name.
type staticMatch int

const (
	staticNoMatch  staticMatch = iota // not present in backends.csv at all
	staticExplicit                    // exact (non-wildcard) match
	staticWildcard                    // matched a *.example.com row
)

// classifyStatic walks the loaded Config for name and reports how it matches
// static rows. For wildcard matches it also returns the AskURL configured on
// the service. Returns (staticNoMatch, "") if no static row matches.
func classifyStatic(conf *Config, name string) (staticMatch, string) {
	name = strings.ToLower(name)

	if conf == nil {
		return staticNoMatch, ""
	}

	for _, dom := range conf.AdminDNS.Domains {
		if strings.ToLower(dom) == name {
			return staticExplicit, ""
		}
	}

	for _, app := range conf.Apps {
		if app.Disabled {
			continue
		}
		for _, srv := range app.Services {
			if srv.Disabled {
				continue
			}
			for _, dom := range srv.Domains {
				dom = strings.ToLower(dom)
				if dom == name {
					return staticExplicit, ""
				}
				if rest, ok := strings.CutPrefix(dom, "*."); ok {
					if name == rest || strings.HasSuffix(name, "."+rest) {
						return staticWildcard, srv.AskURL
					}
				}
			}
		}
	}
	return staticNoMatch, ""
}

// decideIssuance is the certmagic OnDemandConfig.DecisionFunc body. It
// authorizes ACME issuance for name based on static config classification
// (explicit-pass, wildcard-via-ask_url) and a DNS-probe + rate-limit gate
// for dynamic CNAME-resolved names.
func (lc *ListenConfig) decideIssuance(ctx context.Context, name string) error {
	conf := lc.LoadConfig()

	match, askURL := classifyStatic(&conf, name)
	switch match {
	case staticExplicit:
		return nil
	case staticWildcard:
		if askURL == "" {
			slog.Warn("refusing ACME issuance for wildcard match with no ask_url", "domain", name)
			return fmt.Errorf("wildcard match for %q has no ask_url configured", name)
		}
		return askURLAllows(ctx, askURL, name)
	}

	if len(lc.ipDomains) == 0 {
		return fmt.Errorf("no static or dynamic route for %q; refusing issuance", name)
	}

	isWildcard, parent, err := isWildcardParent(ctx, lc.dns, lc.ipDomains, name)
	if err != nil {
		return fmt.Errorf("wildcard probe failed for %q: %w", name, err)
	}
	if !isWildcard {
		slog.Debug("dynamic issuance allowed: parent is not a wildcard", "domain", name, "parent", parent)
		return nil
	}

	if lc.wildcardLimiter == nil {
		return fmt.Errorf("wildcard parent zone %q detected but no rate limiter configured", parent)
	}
	lc.wildcardLimiter.RecordProbe(parent, true)
	if !lc.wildcardLimiter.Allow(parent) {
		slog.Warn("wildcard rate limit reached; refusing ACME issuance", "domain", name, "parent", parent)
		return fmt.Errorf("wildcard rate limit reached for parent zone %q", parent)
	}
	slog.Info("wildcard ACME issuance permitted under rate limit", "domain", name, "parent", parent)
	return nil
}
