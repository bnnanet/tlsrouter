package tlsrouter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bnnanet/tlsrouter/netcap"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
	"github.com/mholt/acmez/v3"
	proxyproto "github.com/pires/go-proxyproto"
)

var ErrDoNotTerminate = fmt.Errorf("a self-terminating match was found")

type ErrorNoTLSConfig string

func (e ErrorNoTLSConfig) Error() string {
	return string(e)
}

// Config holds the TLS routing configuration and hostname resolutions.
type Config struct {
	ACMEDirectoryEndpoint string            `json:"-"`
	AdminMatch            TLSMatch          `json:"admin"`
	TLSMatches            []*TLSMatch       `json:"tls_matches"`
	ACMEConfigs           []*ACMEConfig     `json:"acme,omitempty"`
	certmagicStorage      certmagic.Storage `json:"-"`
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
	// Active          *atomic.Bool `json:"-"`
	Tunnel          netcap.TunnelListener
	Host            string   `json:"-"`
	Address         string   `json:"address"`
	Port            uint16   `json:"port"`
	ALPNs           []string `json:"-"`
	PROXYProto      int      `json:"proxy_protocol,omitempty"`
	TerminateTLS    bool     `json:"terminate_tls"`
	ForceHTTP       bool     `json:"force_http,omitempty"`
	ConnectTLS      bool     `json:"connect_tls"`
	ConnectInsecure bool     `json:"connect_insecure"`
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
	adminTunnel             netcap.TunnelListener
	Conns                   sync.Map
	alpnsByDomain           map[string][]string
	configBySNIALPN         map[SNIALPN]*TLSMatch
	Context                 context.Context
	ACMEDirectoryEndpoint   string
	DisableTLSALPNChallenge bool
	issuerConfMap           map[string]*ACMEConfig
	certmagicTLSALPNOnly    *certmagic.Config
	certmagicConfs          map[string]*certmagic.Config
	certmagicCache          *certmagic.Cache
	certmagicStorage        certmagic.Storage
	done                    chan struct{}
	Close                   func()
	netConf                 net.ListenConfig
}

// TODO move to *Listener
func (lc *ListenConfig) Shutdown() {
	lc.done <- struct{}{}
}

func NewListenConfig(conf Config) *ListenConfig {
	domainMatchers, snialpnMatchers := NormalizeConfig(conf)

	ctx, cancel := context.WithCancel(context.Background())

	issuerConfMap := make(map[string]*ACMEConfig)
	certmagicConfs := make(map[string]*certmagic.Config)
	certmagicStorage := conf.certmagicStorage
	if certmagicStorage == nil {
		certmagicStorage = &certmagic.FileStorage{Path: certmagicDataDir()}
	}
	certmagicCache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			magic, exists := certmagicConfs[cert.Names[0]] // len(Names) > 0 is guaranteed
			if !exists {
				return nil, fmt.Errorf("impossible error: pre-configured domain %q is no longer configured", strings.Join(cert.Names, ", "))
			}
			return magic, nil
		},
		Logger: certmagic.Default.Logger,
	})

	directoryEndpoint := conf.ACMEDirectoryEndpoint
	if len(directoryEndpoint) == 0 {
		// TODO staging vs prod
		directoryEndpoint = certmagic.LetsEncryptStagingCA
	}

	lc := &ListenConfig{
		config:                  conf,
		adminTunnel:             netcap.NewListener(ctx),
		Conns:                   sync.Map{},
		alpnsByDomain:           domainMatchers,
		configBySNIALPN:         snialpnMatchers,
		Context:                 ctx,
		Close:                   cancel,
		ACMEDirectoryEndpoint:   directoryEndpoint,
		issuerConfMap:           issuerConfMap,
		DisableTLSALPNChallenge: false,
		certmagicTLSALPNOnly:    nil,
		certmagicConfs:          certmagicConfs,
		certmagicStorage:        certmagicStorage,
		certmagicCache:          certmagicCache,
		done:                    make(chan struct{}),
		netConf: net.ListenConfig{
			Control: reusePort,
		},
	}
	lc.certmagicTLSALPNOnly = lc.newCertmagicTLSALPNOnly()

	// build up ACME configs
	// (works for internal config too)
	for _, acmeConf := range conf.ACMEConfigs {
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
			issuerConfMap[domain] = acmeConf
		}
	}

	// if !acmeConf.Agreed {
	// 	fmt.Fprintf(os.Stderr, "warning: ToS has not been agreed to\n")
	// }

	// setup and remap matchers
	for snialpn, m := range snialpnMatchers {
		for _, backend := range m.Backends {
			if !backend.TerminateTLS {
				continue
			}

			domain := snialpn.SNI()
			acmeConf, exists := issuerConfMap[domain]
			if !exists {
				fmt.Fprintf(os.Stderr, "   DEBUG: will terminate TLS for %q (TLS-ALPN)\n", snialpn)
				// note: certmagic doesn't support multi-SAN
				if err := lc.certmagicTLSALPNOnly.ManageSync(lc.Context, []string{domain}); err != nil {
					fmt.Fprintf(os.Stderr, "could not add %q to the allowlist: %s\n", domain, err)
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "   DEBUG: will terminate TLS for %q (specific config)\n", snialpn)

			if _, exists := lc.certmagicConfs[domain]; !exists {
				magic := lc.newCertmagic(acmeConf.DNSProvider)
				for _, d := range acmeConf.Domains {
					lc.certmagicConfs[d] = magic
				}
				// note: certmagic doesn't support multi-SAN
				if err := magic.ManageSync(lc.Context, acmeConf.Domains); err != nil {
					fmt.Fprintf(os.Stderr, "could not add %q to the allowlist: %s\n", domain, err)
				}
			}

			if backend.PROXYProto > 0 {
				// cannot have backend.ForceHTTP with PROXYProto
				continue
			}

			// Setting up single Proxy instance for all connections
			alpn := snialpn.ALPN()
			if alpn == "h2" || alpn == "h3" || alpn == "http/1.1" || backend.ForceHTTP {
				backend.Tunnel = netcap.NewListener(lc.Context)

				target := &url.URL{
					Scheme: "http",
					Host:   backend.Host,
				}
				if backend.ConnectTLS {
					target.Scheme = "https"
				}

				proxy := &httputil.ReverseProxy{
					Rewrite: func(r *httputil.ProxyRequest) {
						r.SetURL(target)
						r.Out.Host = r.In.Host // preserve Host header
						r.SetXForwarded()
						r.Out.Header["X-Forwarded-For"] = []string{"https"} // preserve https
					},
				}

				protocols := &http.Protocols{}
				protocols.SetHTTP1(true)
				protocols.SetHTTP2(true)
				protocols.SetUnencryptedHTTP2(true)

				// default transport https://pkg.go.dev/net/http#DefaultTransport
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				transport := &http.Transport{
					Proxy:                 http.ProxyFromEnvironment,
					DialContext:           dialer.DialContext,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}

				// custom
				transport.Protocols = protocols

				// I'll trust the Go authors' choice of ciphers:
				// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/cipher_suites.go;l=56
				// hasAES := cpu.X86.HasAES || cpu.ARM64.HasAES || cpu.ARM.HasAES || cpu.S390X.HasAES || cpu.RISCV64.HasZvkn
				transport.TLSClientConfig = &tls.Config{}
				if backend.ConnectInsecure {
					transport.TLSClientConfig.InsecureSkipVerify = true
				}
				proxy.Transport = transport

				server := &http.Server{
					Handler: proxy,
					BaseContext: func(_ net.Listener) context.Context {
						return lc.Context
					},
					ConnContext: nil,
					Protocols:   protocols,
				}
				go func() {
					// TODO track state to be able to close
					_ = server.Serve(backend.Tunnel)
				}()
			}
		}
	}

	return lc
}

func (lc *ListenConfig) newCertmagicTLSALPNOnly() *certmagic.Config {

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

	go func() {
		protocols := &http.Protocols{}
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
		protocols.SetUnencryptedHTTP2(true)

		server := &http.Server{
			Handler: nil, // TODO THIS IS NEXT AJ!!!
			BaseContext: func(_ net.Listener) context.Context {
				return lc.Context
			},
			ConnContext: nil,
			Protocols:   protocols,
		}
		_ = server.Serve(lc.adminTunnel)
	}()

	netLn, err := lc.netConf.Listen(lc.Context, "tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := netLn.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
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
		case <-lc.Context.Done():
			lc.done <- struct{}{}
		case <-lc.done:
			fmt.Fprintf(os.Stderr, "\n[[[[debug: stop server]]]]\n\n")
			_ = netLn.Close()
			return nil
		}
	}
}

func (lc *ListenConfig) proxy(conn net.Conn) (r int64, w int64, retErr error) {
	var snialpn SNIALPN
	var beConn net.Conn
	var backend *Backend
	fmt.Fprintf(os.Stderr, "\n")

	hc := newHelloConn(conn)
	// tlsConn.Conn()
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
			mcfg, exists := lc.configBySNIALPN[snialpn]
			if !exists {
				if len(alpns) > 1 {
					// still happy path, e.g. "example.com:http/1.1"
					snialpn = NewSNIALPN(domain, alpns[1])
					mcfg, exists = lc.configBySNIALPN[snialpn]
				}
				// unhappy path
				if !exists {
					var err error
					snialpn, mcfg, err = lc.slowMatch(domain, alpns)
					if err != nil {
						if slices.Contains(lc.config.AdminMatch.Domains, domain) {
							// TLS will be terminated
							backend = &Backend{
								// TODO AJ RIGHT HERE !!!
								TerminateTLS: true,
								Tunnel:       lc.adminTunnel,
							}
							_ = hc.Passthru()
							return &tls.Config{
								// Certificates: []tls.Certificate{*tlsCert},
								GetCertificate: lc.certmagicConfs[domain].GetCertificate,
								NextProtos:     []string{"h2", "http/1.1"}, // TODO h3
							}, nil
						}
						return nil, err
					}
				}
			}

			for i, b := range mcfg.Backends {
				fmt.Printf("\n\nDEBUG mcfg.Backend[%d]: %#v\n", i, b)
			}

			var inc uint32 = 1
			n := uint32(len(mcfg.Backends)) - inc
			for {
				// simple round robin
				b := mcfg.Backends[mcfg.CurrentBackend.Load()]
				if !mcfg.CurrentBackend.CompareAndSwap(n, 0) {
					mcfg.CurrentBackend.Add(inc)
				}
				if b.Tunnel == nil && b.PROXYProto == 0 {
					backend = b
					break
				}
				var err error
				beConn, err = getBackendConn(lc.Context, b.Host)
				if err != nil {
					// TODO mark as inactive and try next
					return nil, fmt.Errorf("could not connect to backend %q", b.Host)
				}
				if beConn != nil {
					backend = b
					break
				}
			}

			if !backend.TerminateTLS {
				// We DO NOT enable passthru unless TLS will be terminated
				// (tlsConn.Handshake() writes an error code on error here)
				fmt.Println("DEBUG: No terminate TLS...")
				return nil, ErrDoNotTerminate
			} else {
				fmt.Println("DEBUG: TERMINATE THE TLS!!")
			}

			// TODO check snialpn support wildcards via config
			// TODO preconfigure as map on load
			_ = hc.Passthru()
			return &tls.Config{
				// Certificates: []tls.Certificate{*tlsCert},
				GetCertificate: lc.certmagicConfs[domain].GetCertificate,
				NextProtos:     []string{snialpn.ALPN()},
			}, nil
		},
	})

	if err := tlsConn.Handshake(); err != nil {
		if errors.Is(err, ErrDoNotTerminate) {
			fmt.Println("DEBUG 1: No terminate TLS...")
			if backend.PROXYProto == 1 || backend.PROXYProto == 2 {
				header := &proxyproto.Header{
					Version:           byte(backend.PROXYProto),
					Command:           proxyproto.PROXY,
					TransportProtocol: proxyproto.TCPv4,
					SourceAddr:        tlsConn.RemoteAddr().(*net.TCPAddr),
					DestinationAddr:   beConn.LocalAddr().(*net.TCPAddr),
				}
				if _, err = header.WriteTo(beConn); err != nil {
					return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), err
				}
			}
			// handles connection until it ends
			lc.StoreAcceptedConn(hc)
			return hc.copyConn(beConn) // enables passthru mode
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

	fmt.Println("do the next thing...")
	if backend.PROXYProto == 1 || backend.PROXYProto == 2 {
		fmt.Println("PROXY PROTO...")
		header := &proxyproto.Header{
			Version:           byte(backend.PROXYProto),
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        tlsConn.RemoteAddr().(*net.TCPAddr),
			DestinationAddr:   beConn.LocalAddr().(*net.TCPAddr),
		}
		if _, err := header.WriteTo(beConn); err != nil {
			return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), err
		}
	}

	fmt.Println("PLAIN CONN...")
	cConn := NewTLSConn(tlsConn)
	hc.TLSConn = cConn
	lc.StoreAcceptedConn(hc)
	if backend.Tunnel != nil {
		fmt.Println("backend.Tunnel.Inject")
		// doesn't block TODO how to know its done?
		retErr = backend.Tunnel.Inject(cConn)
	} else {
		fmt.Println("CopyConn(cConn, beConn)")
		_, _, retErr = CopyConn(cConn, beConn) // handles connection until it ends
		_ = conn.Close()
	}
	fmt.Println("done")
	return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), retErr
}

func (lc *ListenConfig) StoreAcceptedConn(hc *tlsHelloConn) {
	now := time.Now()
	ipAndPort := hc.RemoteAddr().String()
	tcpOrUDP := hc.RemoteAddr().Network()
	addr := fmt.Sprintf("%s:%s:%d", ipAndPort, tcpOrUDP, now.UnixMilli())
	lc.Conns.Store(addr, hc)
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
	TLSConn      *TLSConn
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

func NormalizeConfig(conf Config) (map[string][]string, map[SNIALPN]*TLSMatch) {
	domainALPNMatchers := map[string][]string{}
	snialpnMatchers := map[SNIALPN]*TLSMatch{}

	for _, m := range conf.TLSMatches {
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

func LintConfig(conf Config, allowedAlpns []string) error {
	if len(conf.TLSMatches) == 0 {
		return fmt.Errorf("error: 'tls_matches' is empty")
	}

	for _, match := range conf.TLSMatches {
		snialpns := strings.Join(match.Domains, ",") + "; " + strings.Join(match.ALPNs, ",")

		for _, domain := range match.Domains {
			d := strings.ToLower(domain)

			if domain != d {
				return fmt.Errorf("lint: domain is not lowercase: %q", domain)
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
