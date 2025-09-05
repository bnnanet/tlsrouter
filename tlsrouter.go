package tlsrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

	"golang.org/x/sys/unix"

	"github.com/bnnanet/tlsrouter/net/tun"
	"github.com/bnnanet/tlsrouter/tabvault"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
	"github.com/mholt/acmez/v3"
	proxyproto "github.com/pires/go-proxyproto"
)

var ErrDoNotTerminate = fmt.Errorf("a self-terminating match was found")

var HTTPFamilyALPNs = []string{
	"h3",
	"h2",
	"h2c",
	"http/0.9",
	"http/1.0",
	"http/1.1",
}

type ErrorNoTLSConfig string

func (e ErrorNoTLSConfig) Error() string {
	return string(e)
}

// Config holds the TLS routing configuration and hostname resolutions.
// Note: JSON keys are encoded in a consistent order, as per struct-order,
// and generic map keys are sorted.
type Config struct {
	Revision              string             `json:"rev,omitempty"`
	Hash                  string             `json:"hash,omitempty"`
	Handler               *http.ServeMux     `json:"-"`
	ACMEDirectoryEndpoint string             `json:"-"`
	FilePath              string             `json:"-"`
	FileTime              time.Time          `json:"-"` // from file date
	sigChan               chan os.Signal     `json:"-"`
	TabVault              *tabvault.TabVault `json:"-"`
	AdminDNS              ConfigAdmin        `json:"admin"`
	Apps                  []ConfigApp        `json:"apps"`
	certmagicStorage      certmagic.Storage  `json:"-"`
}

// ShortSHA2 is not safe for use after atomic Store()
func (c *Config) ShortSHA2() string {
	// TODO use mutex to make concurrency-safe
	rev := c.Revision
	c.Revision = ""
	hash := c.Hash
	c.Hash = ""
	defer func() {
		c.Revision = rev
		c.Hash = hash
	}()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(c)
	h := sha256.Sum256(buf.Bytes())

	return "h" + hex.EncodeToString(h[:4])[:7]
}

func (c *Config) SetSigChan(sigChan chan os.Signal) {
	if c.sigChan != nil {
		panic("'sigChan' can only be set once")
	}
	c.sigChan = sigChan
}

func (c *Config) Reincarnate() {
	c.sigChan <- syscall.SIGUSR1
}

// Save must not be called after the atomic Store()
func (c *Config) Save() error {
	hash := c.Hash
	c.Hash = ""
	defer func() {
		c.Hash = hash
	}()

	file, err := os.OpenFile(c.FilePath, os.O_WRONLY, 0640)
	if err != nil {
		return err
	}

	if err := c.ToCSV(file); err != nil {
		return err
	}
	// enc := json.NewEncoder(file)
	// enc.SetEscapeHTML(false)
	// enc.SetIndent("", "   ")
	// if err := enc.Encode(c); err != nil {
	// 	return err
	// }

	// don't wait for os cache to flush
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	return nil
}

// ConfigApp describes an arbitrarily relationship between services
type ConfigApp struct {
	Label        string          `json:"label"`
	Slug         string          `json:"slug"`
	Comment      string          `json:"comment,omitempty"`
	Disabled     bool            `json:"disabled,omitempty"`
	DNSProviders []ConfigDNS     `json:"dns_providers,omitempty"`
	Services     []ConfigService `json:"services"`
}

// ConfigService defines a rule for matching domains and ALPNs to backends.
type ConfigService struct {
	Slug                   string         `json:"slug"`
	Comment                string         `json:"comment,omitempty"`
	Disabled               bool           `json:"disabled,omitempty"`
	Domains                []string       `json:"domains"`
	ALPNs                  []string       `json:"alpns,omitempty"`
	Backends               []Backend      `json:"backends"`
	CurrentBackend         *atomic.Uint32 `json:"-"`
	AllowedClientHostnames []string       `json:"allowed_client_hostnames,omitempty"`
}

func (srv *ConfigService) GenSlug() string {
	alpn := srv.ALPNs[0]
	if slices.Contains(HTTPFamilyALPNs, alpn) {
		alpn = "http"
	}
	alpn = strings.Split(alpn, "/")[0]
	domain := strings.ReplaceAll(srv.Domains[0], ".", "-")
	domain = strings.ReplaceAll(domain, "*", "wild-")
	if strings.HasPrefix(domain, "-") {
		domain = "wild-" + domain
	}

	slug := domain + "-" + alpn
	return slug
}

type ConfigAdmin struct {
	ConfigDNS
	AdminUser  string `json:"admin_username"`
	AdminToken string `json:"admin_token"`
}

// ConfigDNS defines libdns-style DNS API options
type ConfigDNS struct {
	Slug     string   `json:"slug"`
	Comment  string   `json:"comment,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
	Domains  []string `json:"domains,omitempty"`
	XDomains []string `json:"excluded_domains,omitempty"`
	API      string   `json:"api"`
	APIToken string   `json:"api_token"`
}

type ACMEDNS struct {
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
	Slug            string             `json:"slug"`
	Comment         string             `json:"comment,omitempty"`
	Disabled        bool               `json:"disabled,omitempty"`
	ALPNs           []string           `json:"alpns,omitempty"`
	Address         string             `json:"address"`
	Port            uint16             `json:"port"`
	Host            string             `json:"-"`
	HTTPTunnel      tun.InjectListener `json:"-"`
	PROXYProto      int                `json:"proxy_protocol,omitempty"`
	TerminateTLS    bool               `json:"terminate_tls"`
	ForceHTTP       bool               `json:"force_http,omitempty"`
	ConnectTLS      bool               `json:"connect_tls"`
	ConnectInsecure bool               `json:"connect_insecure"`
	// Healthy         *atomic.Bool       `json:"-"`
	// ConnectSNI      string             `json:"connect_sni,omitempty"`
	// ConnectALPNs    string             `json:"connect_alpn,omitempty"`
	// ConnectCertRootPEMs [][]byte       `json:"connect_cert_root_pems,omitempty"`
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

// type Matchers map[string]ConfigService

type ListenConfig struct {
	config                atomic.Value
	newConfig             atomic.Pointer[Config]
	newMu                 sync.Mutex
	adminTunnel           tun.InjectListener
	Conns                 sync.Map
	TLSMismatches         sync.Map
	alpnsByDomain         map[string][]string
	configBySNIALPN       map[SNIALPN]*ConfigService
	Context               context.Context
	ACMEDirectoryEndpoint string
	issuerConfMap         map[string]*ACMEDNS
	certmagicTLSALPNOnly  *certmagic.Config
	certmagicConfMap      map[string]*certmagic.Config
	certmagicCache        *certmagic.Cache
	certmagicStorage      certmagic.Storage
	done                  chan context.Context
	Close                 func()
	netConf               net.ListenConfig
	adminServer           *http.Server
	netLn                 net.Listener
}

// TODO move to *Listener
func (lc *ListenConfig) Shutdown(ctx context.Context) {
	_ = lc.netLn.Close()
	// TODO create a context with a 5 second timeout and
	_ = lc.adminServer.Shutdown(ctx)
	lc.done <- ctx
}

func NewListenConfig(conf Config) *ListenConfig {
	domainMatchers, snialpnMatchers := NormalizeConfig(&conf)

	ctx, cancel := context.WithCancel(context.Background())

	issuerConfMap := make(map[string]*ACMEDNS)
	certmagicConfMap := make(map[string]*certmagic.Config)
	certmagicStorage := conf.certmagicStorage
	if certmagicStorage == nil {
		certmagicStorage = &certmagic.FileStorage{Path: certmagicDataDir()}
	}
	certmagicCache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			magic, exists := certmagicConfMap[cert.Names[0]] // len(Names) > 0 is guaranteed
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
		// directoryEndpoint = certmagic.LetsEncryptStagingCA
		directoryEndpoint = certmagic.LetsEncryptProductionCA
	}

	lc := &ListenConfig{
		adminTunnel:           tun.NewListener(ctx),
		Conns:                 sync.Map{},
		TLSMismatches:         sync.Map{},
		alpnsByDomain:         domainMatchers,
		configBySNIALPN:       snialpnMatchers,
		Context:               ctx,
		Close:                 cancel,
		ACMEDirectoryEndpoint: directoryEndpoint,
		issuerConfMap:         issuerConfMap,
		certmagicTLSALPNOnly:  nil,
		certmagicConfMap:      certmagicConfMap,
		certmagicStorage:      certmagicStorage,
		certmagicCache:        certmagicCache,
		done:                  make(chan context.Context),
		netConf: net.ListenConfig{
			Control: reusePort,
		},
	}
	lc.certmagicTLSALPNOnly = lc.newCertmagicTLSALPNOnly()

	// build up ACME configs
	dnsConfByDomain := make(map[string]*ConfigDNS)

	// setup admin acme
	if len(conf.AdminDNS.Domains) == 0 {
		fmt.Fprintf(os.Stderr, "[warn] no (internal) admin domains\n")
	}
	if len(conf.AdminDNS.API) == 0 ||
		len(conf.AdminDNS.APIToken) == 0 ||
		conf.AdminDNS.Disabled {
		fmt.Fprintf(
			os.Stderr,
			"[warn] no ACME config for (internal) admin domains %s\n",
			strings.Join(conf.AdminDNS.Domains, ", "),
		)
	} else {
		newDNSTokenURI, err := conf.TabVault.ToVaultURI(conf.AdminDNS.APIToken)
		if err != nil {
			panic("admin DNS API Token could not be written to TabVault")
		}
		if newDNSTokenURI != conf.AdminDNS.APIToken {
			conf.AdminDNS.APIToken = newDNSTokenURI
			if err := conf.Save(); err != nil {
				panic(err)
			}
		}

		configDNS := conf.AdminDNS.ConfigDNS
		adminDNS := &configDNS
		for _, domain := range conf.AdminDNS.Domains {
			dnsConfByDomain[domain] = adminDNS
		}
	}
	if len(conf.AdminDNS.AdminUser) > 0 &&
		len(conf.AdminDNS.AdminToken) > 0 {
		newAdminTokenURI, err := conf.TabVault.ToVaultURI(conf.AdminDNS.AdminToken)
		if err != nil {
			panic("admin Internal API Token could not be written to TabVault")
		}
		if newAdminTokenURI != conf.AdminDNS.AdminToken {
			conf.AdminDNS.AdminToken = newAdminTokenURI
			if err := conf.Save(); err != nil {
				panic(err)
			}
		}
	}

	// setup app acme
	emptyDNSConf := new(ConfigDNS)
	for _, app := range conf.Apps {
		appSlugs := make(map[string]string)

		// TODO
		// - check that all ACME DNS Domains are used by a service in the app
		// - check that domains aren't duplicated (for admin too)

		wildDNSConf := emptyDNSConf
		for _, dnsConf := range app.DNSProviders {
			kindOfThing, exists := appSlugs[dnsConf.Slug]
			if exists {
				fmt.Fprintf(
					os.Stderr,
					"conflicting duplicate slug %q, already used by %q\n",
					dnsConf.Slug,
					kindOfThing,
				)
			} else {
				appSlugs[dnsConf.Slug] = "DNSConfig"
			}

			if len(dnsConf.Domains) == 0 {
				dnsConf.Domains = []string{"*"}
			}
			if wildDNSConf == emptyDNSConf {
				wildDNSConf = &dnsConf
				continue
			}
			fmt.Fprintf(
				os.Stderr,
				"ignoring duplicate wildcard DNS provider %q, already provided by %q\n",
				dnsConf.Slug,
				wildDNSConf.Slug,
			)
		}

		for _, dnsConf := range app.DNSProviders {
			if len(dnsConf.XDomains) > 0 {
				if dnsConf.Domains[0] == "*" {
					for _, xdomain := range dnsConf.XDomains {
						oldDNSConf, exists := dnsConfByDomain[xdomain]
						if !exists {
							dnsConfByDomain[xdomain] = emptyDNSConf
							continue
						}
						if oldDNSConf == emptyDNSConf {
							continue
						}
						fmt.Fprintf(
							os.Stderr,
							"ignoring domain exclude for %q which is included by %q\n",
							xdomain,
							oldDNSConf.Slug,
						)
					}
				} else {
					fmt.Fprintf(
						os.Stderr,
						"ignoring 'excluded_domains' for non-wildcard dns provider %q\n",
						dnsConf.Slug,
					)
				}
			}
			for _, domain := range dnsConf.Domains {
				oldDNSConf, exists := dnsConfByDomain[domain]
				if !exists {
					dnsConfByDomain[domain] = &dnsConf
					continue
				}
				if oldDNSConf == emptyDNSConf {
					fmt.Fprintf(
						os.Stderr,
						"ignoring domain exclude for %q which is included by %q\n",
						domain,
						dnsConf.Slug,
					)
					dnsConfByDomain[domain] = &dnsConf
				}
				if oldDNSConf.API == dnsConf.API &&
					oldDNSConf.APIToken == dnsConf.APIToken {
					continue
				}
				fmt.Fprintf(
					os.Stderr,
					"duplicate dns provider for %q: %q (selected), %q (ignored)\n",
					domain,
					oldDNSConf.Slug,
					dnsConf.Slug,
				)
			}
		}

		for _, srv := range app.Services {
			for _, domain := range srv.Domains {
				_, exists := dnsConfByDomain[domain]
				if !exists {
					dnsConfByDomain[domain] = wildDNSConf
				}
			}
		}
	}

	// build up all acme configs for all configured domains
	for domain, dnsConf := range dnsConfByDomain {
		switch dnsConf.API {
		case "":
			continue
		case "duckdns":
			apiToken := dnsConf.APIToken
			if id, ok := strings.CutPrefix(apiToken, "vault://"); ok {
				apiToken = conf.TabVault.Get(id)
			}
			issuerConfMap[domain] = &ACMEDNS{
				DNSProvider: &duckdns.Provider{
					APIToken: apiToken,
				},
			}
		default:
			panic(fmt.Errorf("API %q is not implemented yet", dnsConf.API))
		}
	}

	registerACMEDomain := func(domain string) error {
		if _, exists := lc.certmagicConfMap[domain]; exists {
			return nil
		}

		// note: to stop managing a certificate:
		// lc.certmagicCache.RemoveManaged([]certmagic.SubjectIssuer{{Subject: domain}})

		if acmeConf, hasDNSConf := issuerConfMap[domain]; hasDNSConf {
			fmt.Fprintf(os.Stderr, "   DEBUG: will terminate TLS for %q (DNS config)\n", domain)
			// note: would be better to have certmagic per-provider, maybe
			magic := lc.newCertmagic(acmeConf.DNSProvider)
			lc.certmagicConfMap[domain] = magic
			// note: certmagic's domain array creates a config for each - it doesn't support multi-SAN
			return magic.ManageSync(lc.Context, []string{domain})
		}

		fmt.Fprintf(os.Stderr, "   DEBUG: will terminate TLS for domain %q (TLS-ALPN)\n", domain)
		lc.certmagicConfMap[domain] = lc.certmagicTLSALPNOnly
		return lc.certmagicTLSALPNOnly.ManageSync(lc.Context, []string{domain})
	}

	for _, domain := range conf.AdminDNS.Domains {
		if err := registerACMEDomain(domain); err != nil {
			fmt.Fprintf(os.Stderr, "could not add %q to the allowlist: %s\n", domain, err)
			continue
		}
	}

	// if !acmeConf.Agreed {
	// 	fmt.Fprintf(os.Stderr, "warning: ToS has not been agreed to\n")
	// }

	for snialpn, m := range snialpnMatchers {
		for beIndex, backend := range m.Backends {
			if !backend.TerminateTLS {
				continue
			}

			domain := snialpn.SNI()
			if err := registerACMEDomain(domain); err != nil {
				fmt.Fprintf(os.Stderr, "could not add %q to the allowlist: %s\n", domain, err)
				continue
			}

			if backend.PROXYProto > 0 {
				// cannot have backend.ForceHTTP with PROXYProto
				continue
			}

			alpn := snialpn.ALPN()
			fmt.Fprintf(os.Stderr, "DEBUG: incoming snialpn %s", alpn)
			if alpn == "h2" || alpn == "h3" || alpn == "http/1.1" || backend.ForceHTTP {
				backend.HTTPTunnel = tun.NewListener(lc.Context)

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

				// default transport https://pkg.go.dev/net/http#DefaultTransport
				dialer := &net.Dialer{
					// Timeout:       30 * time.Second,
					Timeout:       400 * time.Millisecond, // TODO check internal/external, make user-configurable
					FallbackDelay: 300 * time.Millisecond,
					KeepAlive:     30 * time.Second,
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
				protocols := &http.Protocols{}
				protocols.SetHTTP1(true)
				protocols.SetHTTP2(true)
				protocols.SetUnencryptedHTTP2(true)
				transport.Protocols = protocols

				// I'll trust the Go authors' choice of ciphers:
				// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/tls/cipher_suites.go;l=56
				// hasAES := cpu.X86.HasAES || cpu.ARM64.HasAES || cpu.ARM.HasAES || cpu.S390X.HasAES || cpu.RISCV64.HasZvkn
				transport.TLSClientConfig = &tls.Config{}
				if backend.ConnectInsecure {
					transport.TLSClientConfig.InsecureSkipVerify = true
				}
				proxy.Transport = transport

				// TODO track these for shutdown (to call Shutdown() and Close() on each)
				proxyServer := &http.Server{
					Handler: proxy,
					BaseContext: func(_ net.Listener) context.Context {
						return lc.Context
					},
					ConnContext: nil,
					Protocols:   protocols,
				}
				go func() {
					_ = proxyServer.Serve(backend.HTTPTunnel)
				}()
				m.Backends[beIndex] = backend
			}
		}
	}

	// Now we must never modify conf again!!
	lc.StoreConfig(conf)
	return lc
}

func (lc *ListenConfig) StoreConfig(conf Config) {
	lc.config.Store(conf)
}

func (lc *ListenConfig) LoadConfig() Config {
	return lc.config.Load().(Config)
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
		DisableTLSALPNChallenge: dns01Solver != nil,
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
		_ = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
}

func (lc *ListenConfig) ListenAndProxy(addr string, mux *http.ServeMux) error {
	ch := make(chan net.Conn)

	mux.HandleFunc("GET /api/config/current", lc.RouteGetConfig)
	mux.HandleFunc("GET /api/config/new", lc.RouteGetNewConfig)
	mux.HandleFunc("PUT /api/config/new/{HashOrRev}", lc.RouteSetNewConfig)
	mux.HandleFunc("GET /api/services", lc.RouteListServices)
	mux.HandleFunc("POST /api/services", lc.RouteSetService)
	mux.HandleFunc("GET /api/connections", lc.RouteListConnections)
	mux.HandleFunc("DELETE /api/remotes/{RemoteAddr}", lc.RouteCloseRemotes)
	mux.HandleFunc("DELETE /api/clients/{Service}", lc.RouteCloseClients)

	go func() {
		protocols := &http.Protocols{}
		protocols.SetHTTP1(true)
		protocols.SetHTTP2(true)
		protocols.SetUnencryptedHTTP2(true)

		lc.adminServer = &http.Server{
			Handler: mux,
			BaseContext: func(_ net.Listener) context.Context {
				return lc.Context
			},
			ConnContext: nil,
			Protocols:   protocols,
		}
		_ = lc.adminServer.Serve(lc.adminTunnel)
	}()

	var err error
	lc.netLn, err = lc.netConf.Listen(lc.Context, "tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := lc.netLn.Accept()
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
			fmt.Fprintf(os.Stderr, "debug: accepted connection: %v\n", conn.RemoteAddr())
			go func() {
				_, _, err = lc.proxy(conn)
				if err != nil {
					// TODO log to error channel
					_ = conn.Close()
				}
			}()
		case <-lc.Context.Done():
			lc.done <- context.Background()
		case <-lc.done:
			fmt.Fprintf(os.Stderr, "\n[[[[debug: stop server]]]]\n\n")
			// TODO hard close Conn
			_ = lc.netLn.Close()
			_ = lc.adminServer.Close()
			return net.ErrClosed
		}
	}
}

func (lc *ListenConfig) proxy(conn net.Conn) (r int64, w int64, retErr error) {
	fmt.Fprintf(os.Stderr, "\n")

	var snialpn SNIALPN
	var beConn net.Conn
	var backend *Backend

	wconn := newWrappedConn(conn)
	defer func() {
		lc.Conns.Delete(wconn.ConnID())
	}()

	// tlsConn.NetConn()
	tlsConn := tls.Server(wconn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			conf := lc.LoadConfig()

			fmt.Fprintf(os.Stderr, "ServerName (SNI): %s\n", hello.ServerName)
			fmt.Fprintf(os.Stderr, "SupportedProtos (ALPN): %s\n", hello.SupportedProtos)

			domain := strings.ToLower(hello.ServerName)
			alpns := hello.SupportedProtos
			if len(alpns) == 0 {
				alpns = append(alpns, "http/1.1")
			}

			if alpns[0] == acmez.ACMETLS1Protocol {
				// note: certmagicConfMap only holds backends that terminate
				magic := lc.certmagicConfMap[domain]
				if magic == lc.certmagicTLSALPNOnly {
					snialpn = NewSNIALPN(domain, alpns[0])
					_ = wconn.Passthru()
					return magic.TLSConfig(), nil
				}
				snialpn = ""
				return nil, fmt.Errorf("TLSALPN challenge for unknown domain %q", domain)
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
					trackMismatch := func() {
						key := domain + ":" + alpns[0]
						vAny, ok := lc.TLSMismatches.Load(key)
						if !ok {
							vAny = &atomic.Int32{}
							lc.TLSMismatches.Store(key, vAny)
						}
						v := vAny.(*atomic.Int32)
						v.Add(1)
					}

					var err error
					snialpn, mcfg, err = lc.slowMatch(domain, alpns)
					if err != nil {
						if !slices.Contains(conf.AdminDNS.Domains, domain) {
							trackMismatch()
							snialpn = ""
							return nil, err
						}

						var clientALPN string
						adminALPNs := []string{"h2", "http/1.1"}
						for _, alpn := range hello.SupportedProtos {
							if slices.Contains(adminALPNs, alpn) {
								clientALPN = alpn
								break
							}
						}
						if len(clientALPN) == 0 {
							trackMismatch()
							snialpn = ""
							return nil, err
						}

						snialpn = NewSNIALPN(domain, alpns[0])
						backend = &Backend{
							TerminateTLS: true,
							HTTPTunnel:   lc.adminTunnel,
						}
						_ = wconn.Passthru()
						if lc.certmagicConfMap[domain] == nil {
							return nil, fmt.Errorf("SANITY FAIL: missing ACME config for domain %q", domain)
						}
						return &tls.Config{
							GetCertificate: lc.certmagicConfMap[domain].GetCertificate,
							NextProtos:     []string{clientALPN},
						}, nil
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

				// Note: this complexity currently doesn't help us
				//       but in the future we do need a way to mark
				//       a backend as active or inactive

				backend = &b

				var err error
				beConn, err = getBackendConn(lc.Context, b.Host)
				if err != nil {
					// TODO mark as inactive and try next
					//backend = nil
					fmt.Fprintf(os.Stderr, "could not connect to backend %q\n", b.Host)
				}

				usesTunnel := b.HTTPTunnel != nil
				if usesTunnel {
					if beConn != nil {
						_ = beConn.Close()
					}
					beConn = nil // we can't use raw beConn with internal or proxy tunnel
					break
				}

				hideAlwaysTrueFromLinterWhileDeving := beConn == nil || beConn != nil
				if hideAlwaysTrueFromLinterWhileDeving {
					break
				}
			}

			if !backend.TerminateTLS {
				fmt.Println("DEBUG: No terminate TLS...")
				return nil, ErrDoNotTerminate
			}

			fmt.Println("DEBUG: passthru (TERMINATE THE TLS!!)", domain, lc.certmagicConfMap[domain])
			_ = wconn.Passthru()

			// TODO check snialpn support wildcards via config
			// TODO get the cert directly
			// TODO preconfigure as map on load
			return &tls.Config{
				// Certificates: []tls.Certificate{*tlsCert},
				GetCertificate: lc.certmagicConfMap[domain].GetCertificate,
				NextProtos:     []string{snialpn.ALPN()},
			}, nil
		},
	})

	terminate := true
	if err := tlsConn.Handshake(); err != nil {
		if !errors.Is(err, ErrDoNotTerminate) {
			var errNoTLSConf ErrorNoTLSConfig
			if errors.As(err, &errNoTLSConf) {
				// TODO error log channel
				log.Printf("no tls config: %s", err)
				return int64(wconn.BytesRead.Load()), int64(wconn.BytesWritten.Load()), err
			}

			// TODO error log channel
			log.Printf("unknown tls handshake failure: %v: %s", conn.RemoteAddr(), err)
			return int64(wconn.BytesRead.Load()), int64(wconn.BytesWritten.Load()), err
		}

		terminate = false
	} else if backend == nil {
		if snialpn.SNI() == acmez.ACMETLS1Protocol {
			fmt.Println("solve(d)? TLS ALPN...")
			return
		}
	}
	if backend == nil {
		// TODO this is panic-worthy (leaving in for testing)
		fmt.Println("no backend for sni:alpn=", snialpn)
		return
	}

	fmt.Println("DEBUG: handle with selected backend...")
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
			return int64(wconn.BytesRead.Load()), int64(wconn.BytesWritten.Load()), err
		}
	}

	wconn.SNIALPN = snialpn
	if terminate {
		fmt.Println("DEBUG 1a: PLAIN CONN...")
		cConn := NewPlainConn(tlsConn)
		wconn.PlainConn = cConn
	}

	lc.Conns.Store(wconn.ConnID(), wconn)

	if !terminate {
		fmt.Println("DEBUG 1b: No terminate TLS...")
		if beConn != nil {
			return wconn.tunnelTCPConn(beConn)
		}
		return int64(wconn.BytesRead.Load()), int64(wconn.BytesWritten.Load()), fmt.Errorf("bad gateway: no active backend available")
	}

	if backend.HTTPTunnel != nil {
		fmt.Println("backend.HTTPTunnel.Inject")
		// doesn't block
		retErr = backend.HTTPTunnel.Inject(wconn.PlainConn)
		wconn.wg.Wait()
	} else if beConn != nil {
		fmt.Println("TunnelTCPConn(cConn, beConn)")
		_, _, retErr = TunnelTCPConn(wconn.PlainConn, beConn)
		_ = conn.Close()
	} else {
		// TODO
		// - debug info (last seen)
		// - respect content type (html, json)
		msg := "502 Bad Gateway\n"
		n := len(msg)
		text := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", n, msg)
		_, _ = wconn.PlainConn.Write([]byte(text))
		_ = conn.Close()
		fmt.Println("DEBUG: bad gateway")

	}
	fmt.Println("DEBUG: closed")
	return int64(wconn.BytesRead.Load()), int64(wconn.BytesWritten.Load()), retErr
}

// TunnelTCPConn is a bi-directional copy, calling io.Copy for both connections
func TunnelTCPConn(cConn net.Conn, beConn net.Conn) (r int64, w int64, retErr error) {
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

func (wconn *wrappedConn) tunnelTCPConn(beConn net.Conn) (r int64, w int64, retErr error) {
	var rErr error
	var wErr error

	defer func() {
		if rErr != nil {
			retErr = rErr
		} else if wErr != nil {
			retErr = wErr
		}

		_ = wconn.Close()
		_ = beConn.Close()
	}()

	conn := wconn.Conn
	var wg sync.WaitGroup
	wg.Add(2)

	buffers := wconn.Passthru()
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
		// Timeout:       3 * time.Second,
		Timeout:       400 * time.Millisecond,
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

func (lc *ListenConfig) slowMatch(domain string, alpns []string) (SNIALPN, *ConfigService, error) {
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

func newWrappedConn(conn net.Conn) *wrappedConn {
	wconn := &wrappedConn{
		Conn:      conn,
		buffers:   make([][]byte, 0, 1),
		Connected: time.Now(),
	}
	wconn.wg.Add(1)

	return wconn
}

type wrappedConn struct {
	net.Conn
	passthru     bool
	buffers      [][]byte
	SNIALPN      SNIALPN
	PlainConn    *PlainConn
	Connected    time.Time
	BytesRead    atomic.Uint64
	BytesWritten atomic.Uint64
	LastRead     atomic.Int64
	LastWrite    atomic.Int64
	wg           sync.WaitGroup
	once         sync.Once
}

func (wconn *wrappedConn) ConnID() string {
	ipAndPort := wconn.RemoteAddr().String()
	tcpOrUDP := wconn.RemoteAddr().Network()
	return fmt.Sprintf("%s:%s:%d", ipAndPort, tcpOrUDP, wconn.Connected.UnixMilli())
}

func (wconn *wrappedConn) Passthru() [][]byte {
	bufs := wconn.buffers
	wconn.buffers = nil
	wconn.passthru = true
	return bufs
}

func (wconn *wrappedConn) Read(b []byte) (int, error) {
	n, err := wconn.Conn.Read(b)
	wconn.BytesRead.Add(uint64(n))
	wconn.LastRead.Store(time.Now().UnixMilli())

	if err != nil {
		wconn.once.Do(wconn.wg.Done)
	}
	if wconn.passthru {
		return n, err
	}

	wconn.buffers = append(wconn.buffers, b[0:n])
	return n, err
}

func (wconn *wrappedConn) Write(b []byte) (int, error) {
	wconn.LastWrite.Store(time.Now().UnixMilli())

	if wconn.passthru {
		n, err := wconn.Conn.Write(b)
		if err != nil {
			wconn.once.Do(wconn.wg.Done)
		}
		wconn.BytesWritten.Add(uint64(n))
		return n, err
	}

	fmt.Fprintf(os.Stderr, "Handshake: %x\n", b)
	wconn.once.Do(wconn.wg.Done)
	return 0, fmt.Errorf("sanity fail: wrappedConn does not support Write")
}

func (wconn *wrappedConn) Close() error {
	wconn.once.Do(wconn.wg.Done)

	if wconn.passthru {
		return wconn.Conn.Close()
	}

	panic(fmt.Errorf("sanity fail: wrappedConn does not support Close"))
}

type PlainConn struct {
	*tls.Conn
	BytesRead    atomic.Uint64
	BytesWritten atomic.Uint64
}

func NewPlainConn(tc *tls.Conn) *PlainConn {
	c := &PlainConn{
		Conn:         tc,
		BytesRead:    atomic.Uint64{},
		BytesWritten: atomic.Uint64{},
	}

	return c
}

func (tc *PlainConn) Read(b []byte) (int, error) {
	n, err := tc.Conn.Read(b)
	tc.BytesRead.Add(uint64(n))
	return n, err
}

func (tc *PlainConn) Write(b []byte) (int, error) {
	n, err := tc.Conn.Write(b)
	tc.BytesWritten.Add(uint64(n))
	return n, err
}
