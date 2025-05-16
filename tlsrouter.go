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
	"slices"
	"strings"
	"sync"
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
	Host            string   `json:"-"`
	Address         string   `json:"address"`
	Port            uint16   `json:"port"`
	ALPNs           []string `json:"-"`
	PROXYProto      int      `json:"proxy_protocol,omitempty"`
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
	Context         context.Context
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
		Context:         ctx,
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
	var backend Backend

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

			for {
				// simple round robin
				n := uint32(len(cfg.Backends))
				backend := cfg.Backends[cfg.CurrentBackend.Load()]
				cfg.CurrentBackend.Add(1)
				cfg.CurrentBackend.CompareAndSwap(n, 0)
				var err error
				// ctx, cancel := context.WithCancel(lc.Context)
				beConn, err = getBackendConn(lc.Context, backend.Host)
				if err != nil {
					// TODO mark as inactive and try next
					return nil, fmt.Errorf("could not connect to backend %q", backend.Host)
				}
				if beConn != nil {
					break
				}
			}

			if !backend.TerminateTLS {
				return nil, ErrDoNotTerminate
			}

			_ = hc.Passthru()
			panic(fmt.Errorf("found config %q but termination is not implemented", snialpn))
		},
	})

	if err := tlsConn.Handshake(); err != nil {
		if errors.Is(err, ErrDoNotTerminate) {
			return hc.copyConn(beConn)
		}

		var errNoCfg ErrorNoTLSConfig
		if errors.As(err, &errNoCfg) {
			// TODO error log channel
			log.Printf("no tls config: %s", err)
			return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), err
		}

		// TODO error log channel
		log.Printf("unknown tls failure: %s", err)
		return int64(hc.BytesRead.Load()), int64(hc.BytesWritten.Load()), err
	}

	_ = hc.Passthru()
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
			Count:    9,
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
