package tlsrouter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
	"github.com/mholt/acmez/v3"
)

var ErrDoNotTerminate = fmt.Errorf("a self-terminating match was found")

type ErrorNoTLSConfig string

func (e ErrorNoTLSConfig) Error() string {
	return string(e)
}

// Config holds the TLS routing configuration and hostname resolutions.
type Config struct {
	ACMEDirectoryEndpoint string            `json:"-"`
	TLSMatches            []*TLSMatch       `json:"tls_matches"`
	ACMEConfigs           []*ACMEConfig     `json:"acme,omitempty"`
	HostnameOverrides     map[string]string `json:"hostname_overrides"`
	certmagicStorage      certmagic.Storage `json:"-"` // TODO
}

// TLSMatch defines a rule for matching domains and ALPNs to backends.
type TLSMatch struct {
	Domains []string `json:"domains"`
	ALPNs   []string `json:"alpns"`
	// ALPNBackends map[string][]*Backend `json:"-"`
	CurrentBackend *atomic.Uint32
	Backends       []*Backend `json:"backends"`             // Standardizing on "backends"
	ACME           *struct{}  `json:"acme,omitempty"`       // TODO
	TLSConfig      *struct{}  `json:"tls_config,omitempty"` // TODO
}

type ACMEConfig struct {
	Domains       []string              `json:"domains"`
	DNSProvider   certmagic.DNSProvider `json:"-"`
	DNS01Provider struct {
		API    string `json:"api"`
		Config struct {
			APIToken string `json:"api_token"`
		} `json:"config"`
	} `json:"dns01_provider"`
}

// Backend defines a proxy destination.
type Backend struct {
	Host            string   `json:"-"`
	Address         string   `json:"address"`
	Port            uint16   `json:"port"`
	ALPNs           []string `json:"-"`
	PROXYProto      int      `json:"proxy_protocol,omitempty"`
	TerminateTLS    bool     `json:"terminate_tls"`
	ConnectTLS      bool     `json:"connect_tls"`
	ConnectInsecure bool     `json:"connect_insecure"`
	// IsActive        bool     `json:"-"` // In-memory only
	// activeMu        sync.RWMutex // Protects IsActive
	// ConnectSNI         string   `json:"connect_sni,omitempty"`
	// ConnectALPNs       string   `json:"connect_alpn,omitempty"`
	// ConnectCertRootPEMs [][]byte `json:"connect_cert_root_pems,omitempty"`
}

type SNIALPN string

func NewSNIALPN(sni, alpn string) SNIALPN {
	return SNIALPN(sni + ">" + alpn)
}

// ALPN returns the ALPN part of the SNIALPN (after ">")
func (s SNIALPN) ALPN() string {
	parts := strings.SplitN(string(s), ">", 2)
	if len(parts) < 2 {
		return "" // No ALPN part (malformed)
	}
	return parts[1]
}

// SNI returns the SNI part of the SNIALPN (before ">")
func (s SNIALPN) SNI() string {
	parts := strings.SplitN(string(s), ">", 2)
	if len(parts) < 1 {
		return "" // Shouldn't happen (empty string)
	}
	return parts[0]
}

// type Matchers map[string]TLSMatch

type ListenConfig struct {
	config                  Config
	alpnsByDomain           map[string][]string
	configBySNIALPN         map[SNIALPN]*TLSMatch
	Context                 context.Context
	ACMEDirectoryEndpoint   string
	DisableTLSALPNChallenge bool
	issuerConfMap           *sync.Map
	certmagicTLSOnly        *certmagic.Config
	certmagicConfMap        *sync.Map
	certmagicCache          *certmagic.Cache
	certmagicStorage        certmagic.Storage
	update                  chan struct{}
	done                    chan struct{}
	cancel                  func()
	netConf                 net.ListenConfig
}

func NewListenConfig(cfg Config) *ListenConfig {
	domainMatchers, snialpnMatchers := NormalizeConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	issuerConfMap := &sync.Map{}
	certmagicConfMap := &sync.Map{}
	certmagicStorage := cfg.certmagicStorage
	if certmagicStorage == nil {
		certmagicStorage = &certmagic.FileStorage{Path: certmagicDataDir()}
	}
	certmagicCache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			magicAny, exists := certmagicConfMap.Load(cert.Names[0]) // len(Names) > 0 is guaranteed
			if !exists {
				return nil, fmt.Errorf("impossible error: pre-configured domain %q is no longer configured", strings.Join(cert.Names, ", "))
			}
			magic := magicAny.(*certmagic.Config)
			return magic, nil
		},
		Logger: certmagic.Default.Logger,
	})

	directoryEndpoint := cfg.ACMEDirectoryEndpoint
	if len(directoryEndpoint) == 0 {
		// TODO staging vs prod
		directoryEndpoint = certmagic.LetsEncryptStagingCA
	}

	lc := &ListenConfig{
		config:                  cfg,
		alpnsByDomain:           domainMatchers,
		configBySNIALPN:         snialpnMatchers,
		Context:                 ctx,
		cancel:                  cancel,
		ACMEDirectoryEndpoint:   directoryEndpoint,
		issuerConfMap:           issuerConfMap,
		DisableTLSALPNChallenge: false,
		certmagicTLSOnly:        nil,
		certmagicConfMap:        certmagicConfMap,
		certmagicStorage:        certmagicStorage,
		certmagicCache:          certmagicCache,
		netConf: net.ListenConfig{
			Control: reusePort,
		},
	}
	lc.certmagicTLSOnly = lc.newCertmagicTLSOnly()

	// build up ACME configs
	for _, acmeConf := range cfg.ACMEConfigs {
		switch acmeConf.DNS01Provider.API {
		case "":
			continue
		case "duckdns":
			acmeConf.DNSProvider = &duckdns.Provider{
				APIToken: acmeConf.DNS01Provider.Config.APIToken,
			}
		default:
			panic(fmt.Errorf("API %q is not implemented yet", acmeConf.DNS01Provider.API))
		}

		for _, domain := range acmeConf.Domains {
			issuerConfMap.Store(domain, acmeConf)
		}
	}

	// if !acmeConf.Agreed {
	// 	fmt.Fprintf(os.Stderr, "warning: ToS has not been agreed to\n")
	// }

	// dirtySNIALPNs := []SNIALPN{}
	for snialpn, m := range snialpnMatchers {
		// dirtyBackends := []*Backend{}
		for _, backend := range m.Backends {
			if !backend.TerminateTLS {
				continue
			}

			var magic *certmagic.Config
			domain := snialpn.SNI()
			acmeConfAny, exists := issuerConfMap.Load(domain)
			if !exists {
				fmt.Fprintf(os.Stderr, "   DEBUG: will terminate TLS for %q (TLS-ALPN)\n", snialpn)
				// note: certmagic doesn't support multi-SAN
				if err := lc.certmagicTLSOnly.ManageSync(lc.Context, []string{domain}); err != nil {
					fmt.Fprintf(os.Stderr, "could not add %q to the allowlist: %s\n", domain, err)
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "   DEBUG: will terminate TLS for %q (specific config)\n", snialpn)

			acmeConf := acmeConfAny.(*ACMEConfig)
			if _, exists := lc.certmagicConfMap.Load(domain); exists {
				continue
			}

			magic = lc.newCertmagic(acmeConf.DNSProvider)
			for _, d := range acmeConf.Domains {
				lc.certmagicConfMap.Store(d, magic)
			}
			// note: certmagic doesn't support multi-SAN
			if err := magic.ManageSync(lc.Context, acmeConf.Domains); err != nil {
				fmt.Fprintf(os.Stderr, "could not add %q to the allowlist: %s\n", domain, err)
			}
		}
	}

	return lc
}

func (lc *ListenConfig) newCertmagicTLSOnly() *certmagic.Config {

	magic := certmagic.New(lc.certmagicCache, certmagic.Config{
		RenewalWindowRatio: 0.3,
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: nil, // use ManageSync() allowlist
		},
		OnEvent: func(ctx context.Context, eventName string, data map[string]any) error {
			if eventName != "cert_obtaining" {
				return nil
			}

			// 'data' is
			// renewal bool: Whether this is a renewal
			// identifier string: The name on the certificate
			// forced bool: Whether renewal is being forced (if renewal)
			// remaining time.Time: Time left on the certificate (if renewal)
			// issuer certmagic.Issuer: The previous or current issuer

			return nil
		},
		Storage: lc.certmagicStorage,
	})

	issuer := certmagic.ACMEIssuer{
		CA: lc.ACMEDirectoryEndpoint,
		// Email:                   "", // TODO XXX TODO TODO
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: false,
	}
	domainIssuer := certmagic.NewACMEIssuer(magic, issuer)
	magic.Issuers = []certmagic.Issuer{domainIssuer}

	return magic
}

func (lc *ListenConfig) newCertmagic(dnsProvider certmagic.DNSProvider) *certmagic.Config {

	magic := certmagic.New(lc.certmagicCache, certmagic.Config{
		RenewalWindowRatio: 0.3,
		OnDemand: &certmagic.OnDemandConfig{
			DecisionFunc: nil, // use ManageSync() allowlist
		},
		OnEvent: func(ctx context.Context, eventName string, data map[string]any) error {
			if eventName != "cert_obtaining" {
				return nil
			}

			// 'data' is
			// renewal bool: Whether this is a renewal
			// identifier string: The name on the certificate
			// forced bool: Whether renewal is being forced (if renewal)
			// remaining time.Time: Time left on the certificate (if renewal)
			// issuer certmagic.Issuer: The previous or current issuer

			return nil
		},
		Storage: lc.certmagicStorage,
	})

	var dns01Solver *certmagic.DNS01Solver = nil
	if dnsProvider != nil {
		dns01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider:        dnsProvider,
				TTL:                600 * time.Second,
				PropagationDelay:   0, // provider shouldn't return early
				PropagationTimeout: 2 * time.Minute,
				Resolvers:          nil,
				OverrideDomain:     "", // for setting domain to CNAME's record
				Logger:             nil,
			},
		}
	}
	issuer := certmagic.ACMEIssuer{
		CA: lc.ACMEDirectoryEndpoint,
		// Email:                   os.Getenv("DUCKDNS_EMAIL"), // TODO XXX TODO TODO
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: lc.DisableTLSALPNChallenge,
		DNS01Solver:             dns01Solver,
		// plus any other customizations you need
	}
	domainIssuer := certmagic.NewACMEIssuer(magic, issuer)
	magic.Issuers = []certmagic.Issuer{domainIssuer}

	return magic
}

func certmagicDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	baseDir := filepath.Join(home, ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "tlsrouter")
}

func reusePort(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		_ = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	})
}

func (lc *ListenConfig) ListenAndProxy(addr string) error {
	ch := make(chan net.Conn)

	netLn, err := lc.netConf.Listen(lc.Context, "tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := netLn.Accept()
			if err != nil {
				fmt.Fprintf(os.Stderr, "debug: error accepting client: %s\n", err)
				continue
			}
			ch <- conn
		}
	}()

	for {
		select {
		case conn := <-ch:
			fmt.Fprintf(os.Stderr, "debug: proxy connection\n")
			go func() {
				_, _, _ = lc.proxy(conn)
				// TODO log to error channel
			}()
		case <-lc.update:
			fmt.Fprintf(os.Stderr, "debug: update config\n")
			lc.done <- struct{}{}
		case <-lc.done:
			fmt.Fprintf(os.Stderr, "debug: stop server\n")
			netLn.Close()
			return nil
		}
	}
}

func (lc *ListenConfig) proxy(conn net.Conn) (r int64, w int64, retErr error) {
	defer func() {
		_ = conn.Close()
	}()

	var snialpn SNIALPN
	var beConn net.Conn
	var backend *Backend

	hc := newHelloConn(conn)
	// tlsConn.NetConn()
	tlsConn := tls.Server(hc, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Fprintf(os.Stderr, "ServerName (SNI): %s\n", hello.ServerName)
			fmt.Fprintf(os.Stderr, "SupportedProtos (ALPN): %s\n", hello.SupportedProtos)

			domain := strings.ToLower(hello.ServerName)
			alpns := hello.SupportedProtos
			if len(alpns) == 0 {
				alpns = append(alpns, "http/1.1")
			}

			if alpns[0] == acmez.ACMETLS1Protocol {
				// XXX TODO TODO TODO
				// iterate over ALL backends and if ANY are terminated, terminate
				panic("tls-apln challenge not supported yet")
			}

			// happy path, e.g. "example.com:h2"
			snialpn = NewSNIALPN(domain, alpns[0])
			cfg, exists := lc.configBySNIALPN[snialpn]
			if !exists {
				if len(alpns) > 1 {
					// still happy path, e.g. "example.com:http/1.1"
					snialpn = NewSNIALPN(domain, alpns[1])
					cfg, exists = lc.configBySNIALPN[snialpn]
				}
				// unhappy path
				if !exists {
					var err error
					snialpn, cfg, err = lc.slowMatch(domain, alpns)
					if err != nil {
						return nil, err
					}
				}
			}

			for i, b := range cfg.Backends {
				fmt.Printf("\n\nDEBUG cfg.Backend[%d]: %#v\n", i, b)
			}

			var inc uint32 = 1
			n := uint32(len(cfg.Backends)) - inc
			for {
				// simple round robin
				b := cfg.Backends[cfg.CurrentBackend.Load()]
				if !cfg.CurrentBackend.CompareAndSwap(n, 0) {
					cfg.CurrentBackend.Add(inc)
				}
				var err error
				// ctx, cancel := context.WithCancel(lc.Context)
				beConn, err = getBackendConn(lc.Context, b.Host)
				if err != nil {
					// TODO mark as inactive and try next
					return nil, fmt.Errorf("could not connect to backend %q", backend.Host)
				}
				if beConn != nil {
					backend = b
					break
				}
			}

			if !backend.TerminateTLS {
				fmt.Println("DEBUG: No terminate TLS...")
				return nil, ErrDoNotTerminate
			}

			fmt.Println("DEBUG: TERMINATE THE TLS!!")
			_ = hc.Passthru()

			magicAny, exists := lc.certmagicConfMap.Load(domain)
			if !exists {
				panic(fmt.Errorf("impossible error: missing certmagic config configured domain"))
			}
			magic := magicAny.(*certmagic.Config)

			// TODO check snialpn support wildcards via config
			// TODO get the cert directly
			// TODO preconfigure as map on load
			return &tls.Config{
				// Certificates: []tls.Certificate{*tlsCert},
				GetCertificate: magic.GetCertificate,
				NextProtos:     []string{snialpn.ALPN()},
			}, nil
		},
	})

	if err := tlsConn.Handshake(); err != nil {
		if errors.Is(err, ErrDoNotTerminate) {
			fmt.Println("DEBUG 1: No terminate TLS...")
			return hc.copyConn(beConn)
		}

		var errNoCfg ErrorNoTLSConfig
		if errors.As(err, &errNoCfg) {
			// TODO error log channel
			log.Printf("no tls config: %s", err)
			return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), err
		}

		// TODO error log channel
		log.Printf("unknown tls handshake failure: %s", err)
		return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), err
	}

	_ = hc.Passthru() // Why call this here too?
	if backend.PROXYProto > 0 {
		panic(fmt.Errorf("PROXY protocol is not implemented yet"))
	}

	cConn := NewTLSConn(tlsConn)
	_, _, retErr = CopyConn(cConn, beConn)
	return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), retErr
}

// CopyConn is a bi-directional copy, calling io.Copy for both connections
func CopyConn(cConn net.Conn, beConn net.Conn) (r int64, w int64, retErr error) {
	var rErr error
	var wErr error

	defer func() {
		if rErr != nil {
			retErr = rErr
		} else if wErr != nil {
			retErr = wErr
		}

		_ = cConn.Close()
		_ = beConn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		var err error
		r, err = io.Copy(beConn, cConn)
		if err != nil {
			rErr = err
			fmt.Fprintf(os.Stderr, "debug: error copying client to backend: %v\n", err)
		}

		if c, ok := beConn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()

		var err error
		w, err = io.Copy(cConn, beConn)
		if err != nil {
			wErr = err
			fmt.Fprintf(os.Stderr, "debug: error copying backend to client: %v\n", err)
		}

		if c, ok := cConn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()

	wg.Wait()

	return r, w, retErr
}

func (hc *tlsHelloConn) copyConn(beConn net.Conn) (r int64, w int64, retErr error) {
	var rErr error
	var wErr error

	defer func() {
		if rErr != nil {
			retErr = rErr
		} else if wErr != nil {
			retErr = wErr
		}

		_ = hc.Close()
		_ = beConn.Close()
	}()

	conn := hc.Conn
	var wg sync.WaitGroup
	wg.Add(2)

	buffers := hc.Passthru()
	go func() {
		defer wg.Done()

		// copy peeked data
		for _, buf := range buffers {
			_, _ = beConn.Write(buf)
		}
		buffers = nil

		_, err := io.Copy(beConn, conn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "debug: error copying client to backend: %v\n", err)
		}

		if c, ok := beConn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()

		_, err := io.Copy(conn, beConn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "debug: error copying backend to client: %v\n", err)
		}

		if c, ok := conn.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()

	wg.Wait()

	return r, w, retErr
}

func getBackendConn(ctx context.Context, backendAddr string) (net.Conn, error) {
	d := net.Dialer{
		Timeout:       3 * time.Second,
		LocalAddr:     nil,
		FallbackDelay: 300 * time.Millisecond,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 15 * time.Second,
			Count:    2, // default 9 (2m 15s)
		},
		Resolver:       nil,
		ControlContext: nil,
		//ignored
		// Deadline: time.Time,
		// KeepAlive:     15 * time.Second,
		//deprecated
		// Control: nil,
		// DualStack: true,
		// Cancel: nil,
	}

	return d.DialContext(ctx, "tcp", backendAddr)
}

func (lc *ListenConfig) slowMatch(domain string, alpns []string) (SNIALPN, *TLSMatch, error) {
	parentDomain := domain

	// we already checked the first two, if any
	if len(alpns) > 2 {
		knownAlpns := lc.alpnsByDomain[domain]

		for _, alpn := range alpns[2:] {
			if slices.Contains(knownAlpns, alpn) {
				snialpn := NewSNIALPN(domain, alpn)
				return snialpn, lc.configBySNIALPN[snialpn], nil
			}
		}
		if slices.Contains(knownAlpns, "*") {
			snialpn := NewSNIALPN(domain, "*")
			return snialpn, lc.configBySNIALPN[snialpn], nil
		}
	}

	for {
		nextDot := strings.IndexByte(domain, '.')
		if nextDot == -1 {
			return "", nil, ErrorNoTLSConfig(fmt.Sprintf(
				"no tls config matched for domain %q to backend for any of %q",
				parentDomain,
				strings.Join(alpns, ", "),
			))
		}

		domain = domain[nextDot:]
		knownAlpns := lc.alpnsByDomain[domain]
		for _, alpn := range alpns {
			if slices.Contains(knownAlpns, alpn) {
				snialpn := NewSNIALPN(domain, alpn)
				return snialpn, lc.configBySNIALPN[snialpn], nil
			}
		}
		if slices.Contains(knownAlpns, "*") {
			snialpn := NewSNIALPN(domain, "*")
			return snialpn, lc.configBySNIALPN[snialpn], nil
		}

		domain = domain[1:]
	}
}

func newHelloConn(nc net.Conn) *tlsHelloConn {
	c := &tlsHelloConn{
		Conn:         nc,
		buffers:      make([][]byte, 0, 1),
		passthru:     false,
		Connected:    time.Now(),
		BytesRead:    new(atomic.Uint64),
		BytesWritten: new(atomic.Uint64),
	}

	return c
}

type tlsHelloConn struct {
	net.Conn
	passthru     bool
	buffers      [][]byte
	Connected    time.Time
	BytesRead    *atomic.Uint64
	BytesWritten *atomic.Uint64
}

func (hc *tlsHelloConn) Passthru() [][]byte {
	bufs := hc.buffers
	hc.buffers = nil
	hc.passthru = true
	return bufs
}

func (hc *tlsHelloConn) Read(b []byte) (int, error) {
	n, err := hc.Conn.Read(b)
	hc.BytesRead.Add(uint64(n))
	if hc.passthru {
		return n, err
	}

	hc.buffers = append(hc.buffers, b[0:n])
	return n, err
}

func (hc *tlsHelloConn) Write(b []byte) (int, error) {
	if hc.passthru {
		n, err := hc.Conn.Write(b)
		hc.BytesWritten.Add(uint64(n))
		return n, err
	}

	fmt.Fprintf(os.Stderr, "Handshake: %x\n", b)
	return 0, fmt.Errorf("sanity fail: tlsHelloConn does not support Write")
}

func (hc *tlsHelloConn) Close() error {
	if hc.passthru {
		return hc.Conn.Close()
	}

	panic(fmt.Errorf("sanity fail: tlsHelloConn does not support Close"))
}

type TLSConn struct {
	*tls.Conn
	Connected    time.Time
	BytesRead    *atomic.Uint64
	BytesWritten *atomic.Uint64
}

func NewTLSConn(tc *tls.Conn) *TLSConn {
	c := &TLSConn{
		Conn:         tc,
		Connected:    time.Now(),
		BytesRead:    new(atomic.Uint64),
		BytesWritten: new(atomic.Uint64),
	}

	return c
}

func (tc *TLSConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	tc.BytesRead.Add(uint64(n))
	return n, err
}

func (tc *TLSConn) Write(b []byte) (int, error) {
	n, err := tc.Conn.Write(b)
	tc.BytesWritten.Add(uint64(n))
	return n, err
}

func NormalizeConfig(cfg Config) (map[string][]string, map[SNIALPN]*TLSMatch) {
	domainALPNMatchers := map[string][]string{}
	snialpnMatchers := map[SNIALPN]*TLSMatch{}

	for _, m := range cfg.TLSMatches {
		if len(m.Backends) == 0 {
			fmt.Println("debug: warn: empty backends")
			continue
		}

		for _, domain := range m.Domains {
			// Example.com => example.com
			domain = strings.ToLower(domain)

			// *.example.com => .example.com
			domain = strings.TrimPrefix(domain, "*")

			alpns := domainALPNMatchers[domain]
			for _, alpn := range m.ALPNs {
				if !slices.Contains(alpns, alpn) {
					alpns = append(alpns, alpn)
					domainALPNMatchers[domain] = alpns
				}

				snialpn := NewSNIALPN(domain, alpn)

				tlsMatch := snialpnMatchers[snialpn]
				if tlsMatch == nil {
					tlsMatch = &TLSMatch{
						CurrentBackend: new(atomic.Uint32),
						ACME:           m.ACME,
						TLSConfig:      m.TLSConfig,
					}
					snialpnMatchers[snialpn] = tlsMatch
				}

				for _, b := range m.Backends {
					// fmt.Printf("\n\nDEBUG: m.Backends[i] %#v\n", b)
					b.Host = fmt.Sprintf("%s:%d", b.Address, b.Port)
					tlsMatch.Backends = append(tlsMatch.Backends, b)
				}
			}
		}
	}

	return domainALPNMatchers, snialpnMatchers
}

func LintConfig(cfg Config, allowedAlpns []string) error {
	if len(cfg.TLSMatches) == 0 {
		return fmt.Errorf("error: 'tls_matches' is empty")
	}

	for _, match := range cfg.TLSMatches {
		snialpns := strings.Join(match.Domains, ",") + "; " + strings.Join(match.ALPNs, ",")

		for _, domain := range match.Domains {
			d := strings.ToLower(domain)

			if domain != d {
				return fmt.Errorf("lint: domain is not lowercase: %q\n", domain)
			}

			if strings.HasPrefix(domain, "*") {
				if !strings.HasPrefix(domain, "*.") {
					return fmt.Errorf("lint: invalid use of wildcard %q (must be '*.')", domain)
				}
			}
		}

		if len(allowedAlpns) > 0 {
			for _, alpn := range match.ALPNs {
				if !slices.Contains(allowedAlpns, alpn) {
					if alpn != "*" {
						return fmt.Errorf("lint: unknown alpn %q", alpn)
					}
				}
			}
		}

		if len(match.ALPNs) == 0 {
			return fmt.Errorf("domains set %q have no 'alpns' defined", snialpns)
		}

		if len(match.Backends) == 0 {
			return fmt.Errorf("domains+alpns set %q have no 'backends' defined", snialpns)
		}

		for i, b := range match.Backends {
			if b.Address == "" {
				return fmt.Errorf("target %d in set %q has empty 'address'", i, snialpns)
			}
			if b.Port == 0 {
				return fmt.Errorf("target %d in set %q has empty 'port'", i, snialpns)
			}
		}
	}

	return nil
}
