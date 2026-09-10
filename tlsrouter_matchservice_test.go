package tlsrouter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bnnanet/tlsrouter/dnsresolver"
	"github.com/caddyserver/certmagic"
	"github.com/miekg/dns"
)

// TestCertmagicConfigMapConcurrent hammers certmagicConfigMap from many
// goroutines. Run with -race: it fails if the map is ever reverted to an
// unsynchronized plain map (the original certmagicConfMap race).
func TestCertmagicConfigMapConcurrent(t *testing.T) {
	m := newCertmagicConfigMap()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for j := range 1000 {
				domain := fmt.Sprintf("d%d.example.com", j%8)
				m.SetNew(domain, &certmagic.Config{})
				m.Get(domain)
			}
		})
	}
	wg.Wait()

	// SetNew semantics: first write wins, later writes are no-ops.
	first := &certmagic.Config{}
	second := &certmagic.Config{}
	if !m.SetNew("x.example.com", first) {
		t.Fatal("first SetNew = false, want true")
	}
	if m.SetNew("x.example.com", second) {
		t.Fatal("second SetNew = true, want false")
	}
	if got := m.Get("x.example.com"); got != first {
		t.Fatal("Get returned the second config, want the first (first write wins)")
	}
}

// TestMatchServiceNoTLSConfig exercises the error path: no networks and a
// dead DNS endpoint, so both IP and CNAME/SRV resolution fail and matchService
// must surface ErrorNoTLSConfig (the errTryNext mapping through singleflight).
func TestMatchServiceNoTLSConfig(t *testing.T) {
	// Bind then close a UDP port to get a guaranteed-refused endpoint.
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := l.LocalAddr().String()
	_ = l.Close()

	lc := &ListenConfig{
		Context: context.Background(),
		dns: &dnsresolver.Resolver{
			Servers: []string{deadAddr},
			Timeout: 500 * time.Millisecond,
		},
	}

	conf := Config{} // no Networks, no IPDomains

	_, _, err = lc.matchService(&conf, "site.example.com", []string{"http/1.1"})
	if err == nil {
		t.Fatal("matchService = nil error, want error")
	}
	var want ErrorNoTLSConfig
	if !errors.As(err, &want) {
		t.Fatalf("matchService error = %T %v, want ErrorNoTLSConfig", err, err)
	}
}

// startBarrierDNSServer starts a local UDP DNS server that answers A queries
// for "site.example.com" with a CNAME chain to target, but holds SRV queries
// until two have arrived (or timeout) — one per ALPN. This lets tests
// deterministically overlap two in-flight resolutions of the same domain.
// (LookupCNAME sends an A query and requires a terminal A record, so the
// CNAME answer must be paired with an A record.)
func startBarrierDNSServer(t *testing.T, target string) string {
	t.Helper()

	var (
		mu       sync.Mutex
		arrived  int
		released bool
		release  = make(chan struct{})
	)
	barrier := func() {
		mu.Lock()
		arrived++
		first := arrived == 1
		mu.Unlock()
		if first {
			select {
			case <-release:
			case <-time.After(3 * time.Second):
				t.Error("barrier timed out: second SRV query never arrived, overlap not exercised")
			}
			return
		}
		mu.Lock()
		if !released {
			released = true
			close(release)
		}
		mu.Unlock()
	}

	handler := func(dw dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		q := req.Question[0]
		switch {
		case q.Qtype == dns.TypeSRV: // barrier: hold until both ALPNs are in flight
			barrier()
			resp.SetRcode(req, dns.RcodeNameError)
		case q.Qtype == dns.TypeA && q.Name == "site.example.com.":
			resp.Answer = []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: target,
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.ParseIP("10.0.0.1"),
				},
			}
		default:
			resp.SetRcode(req, dns.RcodeNameError)
		}
		_ = dw.WriteMsg(resp)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler:    dns.HandlerFunc(handler),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestMatchServiceConcurrentDistinctALPNs proves the singleflight key fix.
//
// Two simultaneous first connections to the same dynamic domain with
// different ALPNs (ssh vs http/1.1) must each get their own ALPN's backend.
// The barrier server holds both resolutions in flight at the same time:
// without the ALPN in the singleflight key, the second caller shares the
// first caller's result and this test fails (http/1.1 client routed to the
// ssh backend).
func TestMatchServiceConcurrentDistinctALPNs(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")

	dnsAddr := startBarrierDNSServer(t, "tcp-10-0-0-1.vms.example.com.")

	lc := &ListenConfig{
		Context: context.Background(),
		dns: &dnsresolver.Resolver{
			Servers: []string{dnsAddr},
			Timeout: 5 * time.Second,
		},
		serviceBySNIALPN:     make(map[SNIALPN]*dnsCacheEntry),
		slowACMETLS1ByDomain: make(map[string]*Backend),
	}

	conf := Config{
		Networks:  []net.IPNet{*ipNet},
		IPDomains: []string{"vms.example.com"},
	}

	const domain = "site.example.com"

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs = [2]error{}
		svcs = [2]*ConfigService{}
	)
	resolve := func(idx int, alpn string) {
		_, svc, err := lc.matchService(&conf, domain, []string{alpn})
		mu.Lock()
		errs[idx], svcs[idx] = err, svc
		mu.Unlock()
	}

	wg.Go(func() { resolve(0, "ssh") })
	time.Sleep(100 * time.Millisecond) // let the ssh resolution reach the barrier
	wg.Go(func() { resolve(1, "http/1.1") })
	wg.Wait()

	for i, alpn := range []string{"ssh", "http/1.1"} {
		if errs[i] != nil {
			t.Fatalf("matchService(%s) error: %v", alpn, errs[i])
		}
		if svcs[i] == nil {
			t.Fatalf("matchService(%s) returned nil service", alpn)
		}
	}

	if got := svcs[0].ALPNs[0]; got != "ssh" {
		t.Fatalf("ssh caller ALPN = %q, want ssh", got)
	}
	if got := svcs[0].Backends[0].Port; got != 44322 {
		t.Fatalf("ssh caller backend port = %d, want 44322", got)
	}
	if got := svcs[1].ALPNs[0]; got != "http/1.1" {
		t.Fatalf("http/1.1 caller ALPN = %q, want http/1.1 (got the ssh resolution — singleflight key missing ALPN?)", got)
	}
	if got := svcs[1].Backends[0].Port; got != 443 {
		t.Fatalf("http/1.1 caller backend port = %d, want 443", got)
	}
}

// TestRefreshCacheEntryConcurrentDistinctALPNs proves the refreshCacheEntry
// singleflight key fix.
//
// Two cache entries for the same domain but different ALPNs are both expired.
// Simultaneous matchService calls must each trigger an independent refresh via
// resolveOrExtend. The barrier DNS server holds both SRV queries until two
// have arrived — one per ALPN — proving both resolutions are in flight
// concurrently.
//
// With the old domain-only singleflight key, only one ALPN's refresh runs
// (the other caller is blocked on the shared Do). The barrier never sees the
// second SRV query and times out; the blocked caller then returns its stale
// (un-refreshed) entry with the placeholder port.
func TestRefreshCacheEntryConcurrentDistinctALPNs(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")

	dnsAddr := startBarrierDNSServer(t, "tcp-10-0-0-1.vms.example.com.")

	lc := &ListenConfig{
		Context: context.Background(),
		dns: &dnsresolver.Resolver{
			Servers: []string{dnsAddr},
			Timeout: 5 * time.Second,
		},
		serviceBySNIALPN:     make(map[SNIALPN]*dnsCacheEntry),
		slowACMETLS1ByDomain: make(map[string]*Backend),
	}

	conf := Config{
		Networks:  []net.IPNet{*ipNet},
		IPDomains: []string{"vms.example.com"},
	}

	const domain = "site.example.com"

	// Pre-populate expired cache entries with placeholder ports so we can
	// detect whether each entry was actually refreshed.
	past := time.Now().Add(-10 * time.Minute)
	for _, alpn := range []string{"ssh", "http/1.1"} {
		snialpn := NewSNIALPN(domain, alpn)
		placeholder := &ConfigService{
			Slug:     "placeholder-" + alpn,
			Domains:  []string{domain},
			ALPNs:    []string{alpn},
			Backends: []Backend{{Port: 9999}},
		}
		lc.serviceBySNIALPN[snialpn] = newCacheEntry(placeholder, past, past.Add(5*time.Minute))
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs = [2]error{}
		svcs = [2]*ConfigService{}
	)
	resolve := func(idx int, alpn string) {
		_, svc, err := lc.matchService(&conf, domain, []string{alpn})
		mu.Lock()
		errs[idx], svcs[idx] = err, svc
		mu.Unlock()
	}

	wg.Go(func() { resolve(0, "ssh") })
	time.Sleep(100 * time.Millisecond) // let the ssh refresh reach the barrier
	wg.Go(func() { resolve(1, "http/1.1") })
	wg.Wait()

	for i, alpn := range []string{"ssh", "http/1.1"} {
		if errs[i] != nil {
			t.Fatalf("matchService(%s) error: %v", alpn, errs[i])
		}
		if svcs[i] == nil {
			t.Fatalf("matchService(%s) returned nil service", alpn)
		}
	}

	// Both entries must have been refreshed (placeholder port 9999 replaced).
	if got := svcs[0].Backends[0].Port; got != 44322 {
		t.Fatalf("ssh caller backend port = %d, want 44322 (entry not refreshed — shared singleflight?)", got)
	}
	if got := svcs[1].Backends[0].Port; got != 443 {
		t.Fatalf("http/1.1 caller backend port = %d, want 443 (entry not refreshed — shared singleflight?)", got)
	}
}
