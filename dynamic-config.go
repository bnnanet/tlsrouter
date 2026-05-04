package tlsrouter

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bnnanet/tlsrouter/dnsresolver"
)

var errTryNext = fmt.Errorf("no worries, carry on")
var errIPNotInNetwork = fmt.Errorf("target IP not in any allowed network")
var errNoMatchingRecord = fmt.Errorf("no matching CNAME or SRV record")
var errBackendUnreachable = fmt.Errorf("backend unreachable")
var errDialFailed = fmt.Errorf("tcp dial failed")
var errNoDNSMatch = fmt.Errorf("no CNAME or A record matches configured domains")
var errInvalidSRVTarget = fmt.Errorf("invalid SRV target")
var errUnsupportedALPN = fmt.Errorf("unsupported ALPN or port mismatch")

// use standard ports for servers that natively handle internet traffic via TLS
var rawPortMap = map[string]uint16{
	"http":        443, // SRV shorthand
	"http/1.1":    443,
	"h2":          443,
	"ssh":         44322, // non-standard, sshttp
	"acme-tls/1":  443,
	"acme-tls":    443, // SRV shorthand
	"coap":        5684,
	"dicom":       2762,
	"dot":         853,
	"ftp":         990,
	"imap":        993,
	"irc":         6697,
	"managesieve": 4190,
	"mqtt":        8883,
	"mysql":       3306,
	"nntp":        563,
	"ntske/1":     4460,
	"ntske":       4460, // SRV shorthand
	"pop3":        995,
	"postgresql":  5432,
	"tds/8.0":     1433,
	"tds":         1433, // SRV shorthand
	"radius/1.0":  2083,
	"radius/1.1":  2083,
	"radius":      2083, // SRV shorthand
	"sip":         5061,
	"smb":         10445, // non-standard, SMB DTLS requires QUIC
	"webrtc":      443,
	"c-webrtc":    443,
	"xmpp-client": 5223, // direct tls is legacy ??
	"xmpp-server": 5270, // direct tls is legacy ??
}

// use mostly non-standard ports to prevent accidental access
var terminatedPortMap = map[string]uint16{
	"http/1.1":    3080, // non-standard, non-conflict
	"http":        3080, // SRV shorthand
	"h2c":         3080, // non-standard, testing only
	"ssh":         22,   // requires sclient
	"coap":        15683,
	"dicom":       10104,
	"dot":         10053,
	"ftp":         10021,
	"imap":        10143,
	"irc":         16667,
	"managesieve": 14190,
	"mqtt":        11883,
	"mysql":       13306,
	"nntp":        10119,
	"ntske/1":     10123,
	"ntske":       10123, // SRV shorthand
	"pop3":        10110,
	"postgresql":  15432,
	"tds/8.0":     11433,
	"tds":         11433, // SRV shorthand
	"radius/1.0":  12083,
	"radius/1.1":  12083,
	"radius":      12083, // SRV shorthand
	"sip":         15060,
	"smb":         10445, // requires sclient
	"webrtc":      10080,
	"c-webrtc":    10080,
	"xmpp-client": 15222,
	"xmpp-server": 15269,
}

type dnsRoute struct {
	IP        net.IP
	ALPN      string
	Port      uint16
	TTL       uint32
	Terminate bool
}

func dbg(tmpl string, args ...any) {
	debugMux.Lock()
	fmt.Printf(tmpl+"\n", args...)
	debugMux.Unlock()
}

func (lc *ListenConfig) resolveRoute(ctx context.Context, conf *Config, domain string, alpns []string) (*dnsRoute, error) {
	route, ipErr := getAllowedIP(conf, domain, alpns)
	if ipErr == nil {
		return route, nil
	}
	if ipErr != errTryNext && ipErr != errIPNotInNetwork {
		return nil, ipErr
	}

	route, srvErr := getAllowedSrv(ctx, lc.dns, conf, domain, alpns)
	if srvErr == nil {
		return route, nil
	}

	if ipErr == errIPNotInNetwork {
		return nil, fmt.Errorf("%s: %w; also %w", domain, ipErr, srvErr)
	}
	return nil, errTryNext
}

func (lc *ListenConfig) buildService(conf *Config, domain string, route *dnsRoute) (SNIALPN, *ConfigService) {
	serviceSlug := strings.ReplaceAll(domain, ".", "-") + "-" + strings.Split(route.ALPN, "/")[0]
	backend := Backend{
		Slug:          fmt.Sprintf("%s--%s", strings.ReplaceAll(route.IP.String(), ".", "-"), strings.Split(route.ALPN, "/")[0]),
		Host:          route.IP.String() + ":" + strconv.Itoa(int(route.Port)),
		Address:       route.IP.String(),
		Port:          route.Port,
		TerminateTLS:  route.Terminate,
		ConnectTLS:    false,
		SkipTLSVerify: false,
	}

	if route.Terminate && slices.Contains(HTTPFamilyALPNs, route.ALPN) {
		lc.setupHTTPReverseProxy(domain, &backend, conf.TabVault)
	}

	service := &ConfigService{
		Slug:                   serviceSlug,
		Domains:                []string{domain},
		ALPNs:                  []string{route.ALPN},
		Backends:               []Backend{backend},
		CurrentBackend:         new(atomic.Uint32),
		AllowedClientHostnames: []string{},
	}
	snialpn := NewSNIALPN(domain, route.ALPN)
	return snialpn, service
}

func (lc *ListenConfig) cacheService(snialpn SNIALPN, domain string, service *ConfigService, route *dnsRoute, alpns []string) error {
	now := time.Now()
	ttlDur := clampTTL(route.TTL)
	if route.TTL == 0 {
		ttlDur = defaultTTL
	}
	entry := newCacheEntry(service, now.Add(ttlDur), now.Add(ttlDur+staleTTL))

	lc.serviceMu.Lock()
	lc.serviceBySNIALPN[snialpn] = entry
	if route.Terminate {
		lc.slowCertmagicConfMap[domain] = struct{}{}
	} else {
		if route.Port == 443 && slices.Contains(HTTPFamilyALPNs, alpns[0]) {
			backend := service.Backends[0]
			lc.slowACMETLS1ByDomain[domain] = &backend
		}
	}
	lc.serviceMu.Unlock()

	if route.Terminate {
		if err := checkBackendReachable(route.IP.String(), route.Port); err != nil {
			return fmt.Errorf("%w for %s: %w", errBackendUnreachable, domain, err)
		}
		if err := lc.certmagicTLSALPNOnly.ManageSync(lc.Context, []string{domain}); err != nil {
			return err
		}
	}
	return nil
}

func checkBackendReachable(ip string, port uint16) error {
	targets := []string{net.JoinHostPort(ip, strconv.Itoa(int(port)))}
	if port != 22 {
		targets = append(targets, net.JoinHostPort(ip, "22"))
	}
	for _, addr := range targets {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
	}
	return fmt.Errorf("%w for %s on port %d and ssh", errDialFailed, ip, port)
}

func getAllowedIP(
	conf *Config,
	domain string,
	alpns []string,
) (*dnsRoute, error) {
	if len(conf.Networks) == 0 {
		fmt.Fprintf(os.Stderr, "DEBUG: %s: global config has no dynamic direct ip networks\n", domain)
		return nil, errTryNext
	}

	terminate := strings.HasPrefix(domain, "tls-")
	if !terminate && !strings.HasPrefix(domain, "tcp-") {
		return nil, errTryNext
	}

	var ip net.IP
	{
		labelEnd := strings.IndexByte(domain, '.')
		if labelEnd == -1 || len(domain) <= 6 {
			return nil, errTryNext
		}
		ipAddr := domain[4:labelEnd]
		sld := domain[1+labelEnd:]
		ipAddr = strings.ReplaceAll(ipAddr, "-", ".")
		ip = net.ParseIP(ipAddr)
		if ip == nil {
			return nil, errTryNext
		}

		if !slices.Contains(conf.IPDomains, sld) {
			return nil, errTryNext
		}
	}

	if !conf.IsAllowedIP(ip) {
		return nil, errIPNotInNetwork
	}

	var selectedALPN string
	var selectedPort uint16

	if terminate {
		for _, alpn := range alpns {
			if port, ok := terminatedPortMap[alpn]; ok {
				selectedALPN = alpn
				selectedPort = port
			}
		}
	} else {
		for _, alpn := range alpns {
			if port, ok := rawPortMap[alpn]; ok {
				selectedALPN = alpn
				selectedPort = port
			}
		}
	}
	if selectedALPN == "h2" {
		selectedALPN = "http/1.1"
	}
	if selectedALPN == "" {
		return nil, errTryNext
	}
	return &dnsRoute{
		IP:        ip,
		ALPN:      selectedALPN,
		Port:      selectedPort,
		Terminate: terminate,
	}, nil
}

// getAllowedSrv returns a route via CNAME or SRV DNS lookup.
func getAllowedSrv(
	ctx context.Context,
	dns *dnsresolver.Resolver,
	conf *Config,
	domain string,
	alpns []string,
) (*dnsRoute, error) {
	var cnameMatch bool
	var ipMatch bool
	var cnameTTL uint32

	if len(alpns) > 3 {
		alpns = alpns[:4]
	}

	alpnsLen := len(alpns)
	// options layout: [CNAME results | SRV results], same ALPN order in each half
	cnameOffset := 0
	srvOffset := alpnsLen
	options := make([]*dnsRoute, alpnsLen+alpnsLen)

	var wg sync.WaitGroup

	wg.Go(func() {
		cname, ttl, err := dns.LookupCNAME(ctx, domain)
		if err != nil {
			dbg("DEBUG: %s: CNAME lookup err: %v", domain, err)
			return
		}
		cnameTTL = ttl
		dbg("DEBUG: %s: CNAME answer %q (ttl=%d)", domain, cname, ttl)
		cname = strings.TrimSuffix(cname, ".")
		dbg("DEBUG: %s: CNAME trim %q", domain, cname)
		var ok bool
		var ipLabel string
		for _, domain := range conf.IPDomains {
			ipLabel, ok = strings.CutSuffix(cname, "."+domain)
			dbg("DEBUG: %s: CNAME ip label %q", domain, ipLabel)
			if ok {
				break
			}
		}
		if !ok {
			return
		}

		terminate := true
		prefix := "tls-"
		if !strings.HasPrefix(ipLabel, "tls-") {
			if !strings.HasPrefix(ipLabel, "tcp-") {
				return
			}
			terminate = false
			prefix = "tcp-"
		}
		ipLabel = strings.TrimPrefix(ipLabel, prefix)
		ipLabel = strings.ReplaceAll(ipLabel, "-", ".")
		ip := net.ParseIP(ipLabel)
		if ip == nil {
			return
		}

		if !conf.IsAllowedIP(ip) {
			return
		}

		portMap := terminatedPortMap
		if !terminate {
			portMap = rawPortMap
		}

		for i, alpn := range alpns {
			port, ok := portMap[alpn]
			if !ok {
				continue
			}
			cnameMatch = true
			options[cnameOffset+i] = &dnsRoute{
				IP:        ip,
				ALPN:      alpn,
				Port:      port,
				TTL:       ttl,
				Terminate: terminate,
			}
		}
		dbg("DEBUG: %s: CNAME to ip: %d ALPNs, %s, terminate: %t", domain, len(alpns), ip.String(), terminate)
	})
	wg.Go(func() {
		ips, _, err := dns.LookupIP(ctx, domain)
		if err != nil {
			dbg("DEBUG: %s: A lookup err: %v", domain, err)
			return
		}
		dbg("DEBUG: %s: A records: %d", domain, len(ips))
		for _, aIP := range ips {
			dbg("DEBUG: %s: A %q", domain, aIP.String())
			ipMatch = slices.ContainsFunc(conf.IPs, func(knownIP net.IP) bool {
				dbg("DEBUG: %s: A %q %q %t", domain, knownIP.String(), aIP.String(), knownIP.Equal(aIP))
				return knownIP.Equal(aIP)
			})
			dbg("DEBUG: %s: A match %t", domain, ipMatch)
			if ipMatch {
				break
			}
		}
	})
	for idx, alpn := range alpns {
		wg.Go(func() {
			if route, err := findSrvForALPN(ctx, dns, conf, domain, alpn); err == nil {
				options[srvOffset+idx] = route
			}
		})
	}

	wg.Wait()

	if !cnameMatch && !ipMatch {
		var ipAddrs []string
		for _, ip := range conf.IPs {
			ipAddrs = append(ipAddrs, ip.String())
		}
		return nil, fmt.Errorf("%w: %q has no CNAME matching %q, nor A record matching any of %v", errNoDNSMatch, domain, strings.Join(conf.IPDomains, ","), strings.Join(ipAddrs, ", "))
	}

	for _, best := range options {
		if best != nil {
			if best.TTL == 0 {
				best.TTL = cnameTTL
			}
			return best, nil
		}
	}
	return nil, fmt.Errorf("%w for %q with offered ALPNs", errNoMatchingRecord, domain)
}

func findSrvForALPN(
	ctx context.Context,
	dns *dnsresolver.Resolver,
	conf *Config,
	domain string,
	alpn string,
) (*dnsRoute, error) {
	service := strings.ReplaceAll(strings.ReplaceAll(alpn, "/", "_"), ".", "-")

	proto := "tcp"
	srvRecs, srvTTL, err := dns.LookupSRV(ctx, service, proto, domain)
	dbg("DEBUG: %s: %s %s: SRV len %d", domain, service, proto, len(srvRecs))

	for _, srv := range srvRecs {
		srvCompat := &net.SRV{
			Target:   srv.Target,
			Port:     srv.Port,
			Priority: srv.Priority,
			Weight:   srv.Weight,
		}
		dbg("DEBUG: %s: %s %s: SRV record %#v", domain, service, proto, srvCompat)
		route, checkErr := checkSRV(conf, srvCompat, domain, alpn)
		dbg("DEBUG: %s: %s %s: SRV check %v, %v", domain, service, proto, route, checkErr)
		if checkErr != nil {
			continue
		}
		route.TTL = srvTTL
		return route, nil
	}

	if service != alpn {
		// http/1.1 => http
		// tds/8.0 => tds
		// stun.turn => stun-turn
		service = strings.Split(alpn, "/")[0]
		// no known ALPNs have both dots in the name and in versions,
		// so this is just for future-proofing, ex: stun.turn/2.0
		service = strings.ReplaceAll(service, ".", "-")
		return findSrvForALPN(ctx, dns, conf, domain, service)
	}

	if err != nil {
		return nil, err
	}
	return nil, errTryNext
}

func checkSRV(
	conf *Config,
	srv *net.SRV,
	domain string,
	alpn string,
) (*dnsRoute, error) {
	target := strings.TrimSuffix(srv.Target, ".")
	terminate := true
	prefix := "tls-"
	if !strings.HasPrefix(target, "tls-") {
		if !strings.HasPrefix(target, "tcp-") {
			return nil, fmt.Errorf("%w: expected tls- or tcp- prefix", errInvalidSRVTarget)
		}
		terminate = false
		prefix = "tcp-"
	}

	targetParts := strings.SplitN(target, ".", 2)
	ipLabel := targetParts[0]

	if len(targetParts) < 2 {
		return nil, fmt.Errorf("%w: missing domain labels", errInvalidSRVTarget)
	}

	// Some DNS providers (at least Digital Ocean) force the target to be a subdomain:
	//   domain = "net.foo.com"
	//   target = "tls-1-2-3-4.a.bnna.net.foo.com"
	//   suffix = ".foo.com"
	//   label = "net."
	var suffix string
	var ok bool
	for _, ipDomain := range conf.IPDomains {
		suffix, ok = strings.CutPrefix(targetParts[1], ipDomain)
		if ok {
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("%w: suffix mismatch", errInvalidSRVTarget)
	}
	if len(suffix) > 0 {
		if suffix[0] != '.' {
			return nil, fmt.Errorf("%w: suffix mismatch", errInvalidSRVTarget)
		}
		label, ok := strings.CutSuffix(domain, suffix[1:])
		if !ok {
			return nil, fmt.Errorf("%w: parent domain mismatch", errInvalidSRVTarget)
		}
		if len(label) > 0 && label[len(label)-1] != '.' {
			return nil, fmt.Errorf("%w: parent domain mismatch", errInvalidSRVTarget)
		}
	}

	ipLabel = strings.TrimPrefix(ipLabel, prefix)
	ipLabel = strings.ReplaceAll(ipLabel, "-", ".")
	ip := net.ParseIP(ipLabel)
	if ip == nil {
		return nil, fmt.Errorf("%w: invalid IP", errInvalidSRVTarget)
	}

	portMap := terminatedPortMap
	if !terminate {
		portMap = rawPortMap
	}

	expectedPort, ok := portMap[alpn]
	if !ok || srv.Port != expectedPort {
		return nil, errUnsupportedALPN
	}

	if !conf.IsAllowedIP(ip) {
		return nil, errIPNotInNetwork
	}

	return &dnsRoute{
		IP:        ip,
		ALPN:      alpn,
		Port:      expectedPort,
		Terminate: terminate,
	}, nil
}
