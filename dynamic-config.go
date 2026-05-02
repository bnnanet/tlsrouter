package tlsrouter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var ErrUnknownNetwork = fmt.Errorf("the target ip is not part of a known network")
var errTryNext = fmt.Errorf("no worries, carry on")

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
	Terminate bool
}

func dbg(tmpl string, args ...any) {
	debugMux.Lock()
	fmt.Printf(tmpl+"\n", args...)
	debugMux.Unlock()
}

func (lc *ListenConfig) resolveRoute(conf *Config, domain string, alpns []string) (*dnsRoute, error) {
	route, err := getAllowedIP(conf, domain, alpns)
	if err != nil {
		if err != errTryNext {
			return nil, err
		}
		route, err = getAllowedSrv(conf, domain, alpns)
		if err != nil {
			return nil, err
		}
	}
	return route, nil
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

	// HTTP-family terminated services get a ReverseProxy so X-Forwarded-*
	// headers are re-set from the trusted inbound conn instead of passed
	// through from the untrusted client.
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
	lc.slowConfigMu.Lock()
	lc.slowConfigBySNIALPN[snialpn] = service
	if route.Terminate {
		lc.slowCertmagicConfMap[domain] = struct{}{}
	} else {
		if route.Port == 443 && slices.Contains(HTTPFamilyALPNs, alpns[0]) {
			backend := service.Backends[0]
			lc.slowACMETLS1ByDomain[domain] = &backend
		}
	}
	lc.slowConfigMu.Unlock()

	if route.Terminate {
		if err := lc.certmagicTLSALPNOnly.ManageSync(lc.Context, []string{domain}); err != nil {
			return err
		}
	}
	return nil
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

	var selectedALPN string
	var selectedPort uint16
	var match bool
	for _, ipNet := range conf.Networks {
		if ipNet.Contains(ip) {
			match = true
			fmt.Fprintf(os.Stderr, "DEBUG: %s: found matching network %q\n", domain, ipNet.String())
			break
		}
		fmt.Fprintf(os.Stderr, "DEBUG: %s: IP %q is not in network %q\n", domain, ip.String(), ipNet.String())
	}
	if !match {
		return nil, errTryNext
	}

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

func getAllowedSrv(
	conf *Config,
	domain string,
	alpns []string,
) (*dnsRoute, error) {
	var cnameMatch bool
	var ipMatch bool

	if len(alpns) > 3 {
		alpns = alpns[:4]
	}

	alpnsLen := len(alpns)
	// options layout: [CNAME results | SRV results], same ALPN order in each half
	cnameOffset := 0
	srvOffset := alpnsLen
	options := make([]*dnsRoute, alpnsLen+alpnsLen)

	var wg sync.WaitGroup
	ipQueries := 2
	wg.Add(ipQueries + alpnsLen)

	go func() {
		defer wg.Done()

		cname, _ := net.LookupCNAME(domain)
		dbg("DEBUG: %s: CNAME answer %q", domain, cname)
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

		allowed := false
		for _, ipNet := range conf.Networks {
			if ipNet.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
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
				Terminate: terminate,
			}
		}
		dbg("DEBUG: %s: CNAME to ip: %d ALPNs, %s, terminate: %t", domain, len(alpns), ip.String(), terminate)
	}()
	go func() {
		defer wg.Done()

		ips, _ := net.LookupIP(domain)
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
	}()
	for idx, alpn := range alpns {
		go func(alpn string, index int) {
			defer wg.Done()

			if route, err := findSrvForALPN(conf, domain, alpn); err == nil {
				options[srvOffset+index] = route
			}
		}(alpn, idx)
	}

	wg.Wait()

	if !cnameMatch && !ipMatch {
		var ipAddrs []string
		for _, ip := range conf.IPs {
			ipAddrs = append(ipAddrs, ip.String())
		}
		return nil, fmt.Errorf("%q has no CNAME matching %q, nor A record matching any of %v", domain, strings.Join(conf.IPDomains, ","), strings.Join(ipAddrs, ", "))
	}

	for _, best := range options {
		if best != nil {
			return best, nil
		}
	}
	return nil, errors.New("no matching SRV found for offered ALPNs")
}

func findSrvForALPN(
	conf *Config,
	domain string,
	alpn string,
) (*dnsRoute, error) {
	service := strings.ReplaceAll(strings.ReplaceAll(alpn, "/", "_"), ".", "-")

	proto := "tcp"
	_, srvAddrs, err := net.LookupSRV(service, proto, domain)
	dbg("DEBUG: %s: %s %s: SRV len %d", domain, service, proto, len(srvAddrs))

	for _, srv := range srvAddrs {
		dbg("DEBUG: %s: %s %s: SRV record %#v", domain, service, proto, srv)
		ip, terminate, port, checkErr := checkSRV(conf.IPDomains, conf.Networks, srv, domain, alpn)
		dbg("DEBUG: %s: %s %s: SRV check %s, %t, %d, %v", domain, service, proto, ip, terminate, port, checkErr)
		if checkErr != nil {
			continue
		}
		return &dnsRoute{
			IP:        ip,
			ALPN:      alpn,
			Port:      port,
			Terminate: terminate,
		}, nil
	}

	if service != alpn {
		// http/1.1 => http, tds/8.0 => tds, stun.turn => stun-turn
		service = strings.Split(alpn, "/")[0]
		service = strings.ReplaceAll(service, ".", "-")
		return findSrvForALPN(conf, domain, service)
	}

	if err != nil {
		return nil, err
	}
	return nil, errTryNext
}

func checkSRV(
	ipDomains []string,
	networks []net.IPNet,
	srv *net.SRV, domain,
	alpn string,
) (net.IP, bool, uint16, error) {
	// Validate SRV target format: [tls|tcp]-<dashed-ip>.<ip-domain>
	target := strings.TrimSuffix(srv.Target, ".")
	terminate := true
	prefix := "tls-"
	if !strings.HasPrefix(target, "tls-") {
		if !strings.HasPrefix(target, "tcp-") {
			return nil, false, 0, errors.New("invalid SRV target prefix")
		}
		terminate = false
		prefix = "tcp-"
	}

	targetParts := strings.SplitN(target, ".", 2)
	ipLabel := targetParts[0]

	if len(targetParts) < 2 {
		return nil, false, 0, errors.New("invalid SRV target labels")
	}

	// because some DNS providers (at least Digital Ocean) force the target to be a subdomain
	//   domain = "net.foo.com"
	//   target = "tls-1-2-3-4.a.bnna.net.foo.com"
	//   suffix = ".foo.com"
	//   label = "net."
	var suffix string
	var ok bool
	for _, ipDomain := range ipDomains {
		suffix, ok = strings.CutPrefix(targetParts[1], ipDomain)
		if ok {
			break
		}
	}
	if !ok {
		return nil, false, 0, errors.New("invalid SRV target suffix")
	}
	if len(suffix) > 0 {
		if suffix[0] != '.' {
			return nil, false, 0, errors.New("invalid SRV target suffix")
		}
		label, ok := strings.CutSuffix(domain, suffix[1:])
		if !ok {
			return nil, false, 0, errors.New("invalid SRV target parent domain")
		}
		if len(label) > 0 && label[len(label)-1] != '.' {
			return nil, false, 0, errors.New("invalid SRV target parent domain")
		}
	}

	// Extract and parse IP from target
	ipLabel = strings.TrimPrefix(ipLabel, prefix)
	ipLabel = strings.ReplaceAll(ipLabel, "-", ".")
	ip := net.ParseIP(ipLabel)
	if ip == nil {
		return nil, false, 0, errors.New("invalid IP in SRV target")
	}

	// Select port map based on terminate
	portMap := terminatedPortMap
	if !terminate {
		portMap = rawPortMap
	}

	// Check if ALPN is supported and port matches
	expectedPort, ok := portMap[alpn]
	if !ok || srv.Port != expectedPort {
		return nil, false, 0, errors.New("unsupported ALPN or port mismatch")
	}

	// Check if IP is in allowed networks
	allowed := false
	for _, ipNet := range networks {
		if ipNet.Contains(ip) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, false, 0, ErrUnknownNetwork
	}

	return ip, terminate, expectedPort, nil
}
