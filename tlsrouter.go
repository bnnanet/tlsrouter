package tlsrouter

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrDoNotTerminate = fmt.Errorf("a self-terminating match was found")

type ErrorNoTLSConfig string

func (e ErrorNoTLSConfig) Error() string {
	return string(e)
}

// Config holds the TLS routing configuration and hostname resolutions.
type Config struct {
	TLSMatches        []*TLSMatch       `json:"tls_matches"`
	HostnameOverrides map[string]string `json:"hostname_overrides"`
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

// Backend defines a proxy destination.
type Backend struct {
	Address         string   `json:"address"`
	Port            uint16   `json:"port"`
	ALPNs           []string `json:"-"`
	TerminateTLS    bool     `json:"terminates_tls"`
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

// type Matchers map[string]TLSMatch

type ListenConfig struct {
	config          Config
	alpnsByDomain   map[string][]string
	configBySNIALPN map[SNIALPN]*TLSMatch
	context         context.Context
	update          chan struct{}
	done            chan struct{}
	cancel          func()
	netConf         net.ListenConfig
}

func NewListenConfig(cfg Config) *ListenConfig {
	domainMatchers, snialpnMatchers := NormalizeConfig(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	lc := &ListenConfig{
		config:          cfg,
		alpnsByDomain:   domainMatchers,
		configBySNIALPN: snialpnMatchers,
		context:         ctx,
		cancel:          cancel,
		netConf: net.ListenConfig{
			Control: reusePort,
		},
	}
	return lc
}

func reusePort(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		_ = syscall.SetsockoptInt(int(descriptor), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	})
}

func (lc *ListenConfig) ListenAndProxy(addr string) error {
	ch := make(chan net.Conn)

	netLn, err := lc.netConf.Listen(lc.context, "tcp", addr)
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
			go lc.proxy(conn)
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

func (lc *ListenConfig) proxy(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	var snialpn SNIALPN

	hc := NewHelloConn(conn)
	tlsConn := tls.Server(hc, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Fprintf(os.Stderr, "ServerName (SNI): %s\n", hello.ServerName)
			fmt.Fprintf(os.Stderr, "SupportedProtos (ALPN): %s\n", hello.SupportedProtos)

			domain := strings.ToLower(hello.ServerName)
			alpns := hello.SupportedProtos
			if len(alpns) == 0 {
				alpns = append(alpns, "http/1.1")
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

			// simple round robin
			n := uint32(len(cfg.Backends))
			b := cfg.Backends[cfg.CurrentBackend.Load()]
			cfg.CurrentBackend.Add(1)
			cfg.CurrentBackend.CompareAndSwap(n, 0)

			if !b.TerminateTLS {
				return nil, ErrorNoTLSConfig(fmt.Sprintf("found config %q", snialpn))
			}

			return nil, ErrDoNotTerminate
		},
	})

	// hc.Peeking = true
	if err := tlsConn.Handshake(); err != nil {
		var errNoCfg *ErrorNoTLSConfig
		if errors.As(err, errNoCfg) {
			hc.Conn.Close()
			return
		}

		if errors.Is(err, ErrDoNotTerminate) {
			// TODO pipe encrypted tls
			hc.Conn.Close()
			return
		}

		// TODO error log channel
		log.Printf("tls handshake failed: %s", err)
		hc.Conn.Close()
		return
	}

	c := NewConn(hc)
	log.Printf("BytesRead: %d", c.BytesRead.Load())
	// TODO pipe terminated (plaintext) conn
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
			return "", nil, fmt.Errorf(
				"could not match domain %q to backend for any of %q",
				parentDomain,
				strings.Join(alpns, ", "),
			)
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

func NewConn(hc *HelloConn) *Conn {
	c := &Conn{
		Conn:         hc.Conn,
		buffers:      nil,
		Connected:    time.Now(),
		BytesRead:    new(atomic.Uint64),
		BytesWritten: new(atomic.Uint64),
	}
	if len(hc.buffers) > 0 {
		c.buffers = hc.buffers
		for _, b := range hc.buffers {
			_ = c.BytesRead.Add(uint64(len(b)))
		}
	}

	return c
}

type Conn struct {
	net.Conn
	buffers      [][]byte
	Connected    time.Time
	BytesRead    *atomic.Uint64
	BytesWritten *atomic.Uint64
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.buffers == nil {
		n, err := c.Conn.Read(b)
		_ = c.BytesRead.Add(uint64(n))
		return n, err
	}

	buf := c.buffers[0]
	c.buffers = c.buffers[1:]
	if len(c.buffers) == 0 {
		c.buffers = nil
	}
	n := len(buf)
	copy(b, buf)
	return n, nil
}

func NewHelloConn(nc net.Conn) *HelloConn {
	c := &HelloConn{
		Conn:    nc,
		buffers: make([][]byte, 0, 1),
	}

	return c
}

type HelloConn struct {
	net.Conn
	buffers [][]byte
}

func (hc *HelloConn) Read(b []byte) (int, error) {
	n, err := hc.Conn.Read(b)
	hc.buffers = append(hc.buffers, b[0:n])
	return n, err
}

func (hc *HelloConn) Write(b []byte) (int, error) {
	fmt.Fprintf(os.Stderr, "Handshake: %x\n", b)
	return 0, fmt.Errorf("sanity fail: HelloConn does not support Write")
}

func (hc *HelloConn) Close() error {
	panic(fmt.Errorf("sanity fail: HelloConn does not support Close"))
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

				tlsMatch.Backends = append(tlsMatch.Backends, m.Backends...)
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
