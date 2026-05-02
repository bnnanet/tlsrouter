// Package dnsresolver provides a parallel DNS resolver with automatic fallback servers.
package dnsresolver

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

const QueryTimeout = 750 * time.Millisecond

var FallbackServers = []string{
	"208.67.222.123:53", // OpenDNS
	"1.1.1.3:53",        // Cloudflare
	"9.9.9.9:53",        // Quad9
}

type Resolver struct {
	Servers []string
	Timeout time.Duration
}

func New() *Resolver {
	r := &Resolver{Timeout: QueryTimeout}

	cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		for _, s := range cc.Servers {
			port := cmp.Or(cc.Port, "53")
			r.Servers = append(r.Servers, net.JoinHostPort(s, port))
		}
	}
	if len(r.Servers) == 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: could not read /etc/resolv.conf: %v, using fallback resolvers\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "WARN: /etc/resolv.conf has no nameservers, using fallback resolvers\n")
		}
		r.Servers = FallbackServers
	}

	return r
}

func (r *Resolver) LookupCNAME(ctx context.Context, domain string) (string, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)
	m.RecursionDesired = true

	resp, ttl, err := r.Exchange(ctx, m)
	if err != nil {
		return "", 0, err
	}

	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			if ttl == 0 {
				ttl = rr.Header().Ttl
			}
			return cname.Target, ttl, nil
		}
	}
	return "", 0, fmt.Errorf("no CNAME record for %s", domain)
}

func (r *Resolver) LookupSRV(ctx context.Context, service, proto, domain string) ([]*dns.SRV, uint32, error) {
	name := fmt.Sprintf("_%s._%s.%s", service, proto, dns.Fqdn(domain))
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeSRV)
	m.RecursionDesired = true

	resp, ttl, err := r.Exchange(ctx, m)
	if err != nil {
		return nil, 0, err
	}

	var srvs []*dns.SRV
	for _, rr := range resp.Answer {
		if srv, ok := rr.(*dns.SRV); ok {
			srvs = append(srvs, srv)
			if ttl == 0 {
				ttl = rr.Header().Ttl
			}
		}
	}
	if len(srvs) == 0 {
		return nil, 0, fmt.Errorf("no SRV records for %s", name)
	}
	return srvs, ttl, nil
}

func (r *Resolver) LookupIP(ctx context.Context, domain string) ([]net.IP, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true

	resp, ttl, err := r.Exchange(ctx, m)
	if err != nil {
		return nil, 0, err
	}

	var ips []net.IP
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			ips = append(ips, a.A)
			if ttl == 0 {
				ttl = rr.Header().Ttl
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no A records for %s", domain)
	}
	return ips, ttl, nil
}

type result struct {
	resp *dns.Msg
	ttl  uint32
	err  error
}

// Exchange queries all configured servers in parallel, returning the first success.
func (r *Resolver) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, uint32, error) {
	timeout := cmp.Or(r.Timeout, QueryTimeout)
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make(chan result, len(r.Servers))
	for _, server := range r.Servers {
		go func() {
			c := new(dns.Client)
			c.Timeout = timeout
			resp, _, err := c.ExchangeContext(queryCtx, m, server)
			if err != nil {
				results <- result{err: err}
				return
			}
			if resp.Rcode != dns.RcodeSuccess {
				results <- result{err: fmt.Errorf("DNS query %s: rcode %s", m.Question[0].Name, dns.RcodeToString[resp.Rcode])}
				return
			}
			var minTTLVal uint32
			for _, rr := range resp.Answer {
				t := rr.Header().Ttl
				if minTTLVal == 0 || t < minTTLVal {
					minTTLVal = t
				}
			}
			results <- result{resp: resp, ttl: minTTLVal}
		}()
	}

	var lastErr error
	for range len(r.Servers) {
		res := <-results
		if res.err != nil {
			lastErr = res.err
			continue
		}
		return res.resp, res.ttl, nil
	}
	return nil, 0, fmt.Errorf("all resolvers failed: %w", lastErr)
}
