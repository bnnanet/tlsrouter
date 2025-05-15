package tlsrouter

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type DomainConfig struct {
	Domain    string         `json:"domain,omitempty"`
	Targets   []TargetConfig `json:"targets"`
	ACME      *struct{}      `json:"acme,omitempty"`       // TODO
	TLSConfig *struct{}      `json:"tls_config,omitempty"` // TODO
}

type TargetConfig struct {
	ALPNs           []string `json:"alpns,omitempty"`
	Addr            string   `json:"address,omitempty"` // TODO should resolve to private IP
	Port            uint16   `json:"port,omitempty"`
	TerminateTLS    bool     `json:"tls_terminate"`
	ConnectTLS      bool     `json:"connect_tls"`
	ConnectInsecure bool     `json:"connect_insecure"`
	// ConnectSNI  string
	// ConnectALPNs  string
	// ConnectCertRootPEMs [][]byte
}

type Config = map[string]DomainConfig

type ListenConfig struct {
	config  Config
	context context.Context
	cancel  func()
	netConf net.ListenConfig
}

func NewListenConfig(cfgs Config) *ListenConfig {
	config := NormalizeConfig(cfgs)

	ctx, cancel := context.WithCancel(context.Background())
	lc := &ListenConfig{
		config:  config,
		context: ctx,
		cancel:  cancel,
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
	netLn, err := lc.netConf.Listen(lc.context, "tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := netLn.Accept()
		if err != nil {
			log.Printf("Error: %#v", err)
			continue
		}
		go lc.proxy(conn)
	}
}

func (lc *ListenConfig) proxy(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	hc := NewHelloConn(conn)
	tlsConn := tls.Server(hc, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fmt.Printf("ServerName (SNI): %s\n", hello.ServerName)
			fmt.Printf("SupportedProtos (ALPN): %s\n", hello.SupportedProtos)

			domain := strings.ToLower(hello.ServerName)
			cfg, exists := lc.config[domain]
			if !exists {
				for {
					nextDot := strings.IndexByte(domain, '.')
					if nextDot == -1 {
						return nil, fmt.Errorf("no matching domain found in config")
					}

					domain = domain[nextDot:]
					if cfg, exists = lc.config[domain]; exists {
						break
					}

					domain = domain[1:]
				}

				if !exists {
					return nil, fmt.Errorf("no matching domain found in config")
				}
			}

			targets := []TargetConfig{}
			for _, t := range cfg.Targets {
				for _, alpn := range t.ALPNs {
					if slices.Contains(hello.SupportedProtos, alpn) {
						targets = append(targets, t)
					} else if slices.Contains(hello.SupportedProtos, "*") {
						targets = append(targets, t)
					}
				}
			}

			if len(targets) == 0 {
				return nil, fmt.Errorf("no target supports the given alpn")
			}

			return nil, fmt.Errorf("found config %q", cfg.Domain)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
	}

	c := NewConn(hc)
	log.Printf("%d", c.BytesRead.Load())
	// TODO pipe
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
	fmt.Printf("Handshake: %x\n", b)
	return 0, fmt.Errorf("sanity fail: HelloConn does not support Write")
}

func (hc *HelloConn) Close() error {
	panic(fmt.Errorf("sanity fail: HelloConn does not support Close"))
}

func NormalizeConfig(cfgs Config) Config {
	config := make(map[string]DomainConfig)

	for domain, cfg := range cfgs {
		cfg.Domain = domain

		// Example.com => example.com
		domain = strings.ToLower(domain)

		// *.example.com => .example.com
		domain = strings.TrimPrefix(domain, "*")

		for i, t := range cfg.Targets {
			if len(t.ALPNs) == 0 {
				t.ALPNs = []string{"h2", "http/1.1"}
				// t.ALPNs = []string{"*"}
			}
			cfg.Targets[i] = t
		}

		config[domain] = cfg
	}

	return config
}

func LintConfig(cfgs Config) error {
	if len(cfgs) == 0 {
		return fmt.Errorf("empty config\n")
	}

	config := make(map[string]DomainConfig)

	for domain, cfg := range cfgs {
		cfg.Domain = domain
		domain = strings.ToLower(domain)

		if domain != cfg.Domain {
			return fmt.Errorf("invalid casing for for domain %q\n", cfg.Domain)
		}

		if _, exists := config[domain]; exists {
			return fmt.Errorf("duplicate config entry for domain %q\n", cfg.Domain)
		}

		if strings.HasPrefix(domain, "*") {
			if !strings.HasPrefix(domain, "*.") {
				return fmt.Errorf("invalid domain %q", domain)
			}
		}

		if len(cfg.Targets) == 0 {
			return fmt.Errorf("domain %q has no 'targets' defined", domain)
		}

		for i, host := range cfg.Targets {
			if host.Addr == "" {
				return fmt.Errorf("target %d in domain %q has empty 'address'", i, domain)
			}
			if host.Port == 0 {
				return fmt.Errorf("target %d in domain %q has empty 'port'", i, domain)
			}
		}
	}

	return nil
}
