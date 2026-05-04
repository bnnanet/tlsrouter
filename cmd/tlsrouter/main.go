package main

import (
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bnnanet/tlsrouter"
	"github.com/bnnanet/tlsrouter/ianaalpn"
	"github.com/bnnanet/tlsrouter/tabvault"

	"github.com/joho/godotenv"
)

const (
	name         = "tlsrouter"
	licenseYear  = "2025"
	licenseOwner = "AJ ONeal"
	licenseType  = "MPL-2.0"
)

// set by GoReleaser via ldflags
var (
	version     = ""
	commit      = ""
	date        = ""
	serverStart = time.Now()
)

// workaround for `tinygo` ldflag replacement handling not allowing default values
// See <https://github.com/tinygo-org/tinygo/issues/2976>
func init() {
	if len(version) == 0 {
		version = "0.0.0-dev"
	}
	if len(date) == 0 {
		date = "0001-01-01T00:00:00Z"
	}
	if len(commit) == 0 {
		commit = "0000000"
	}
}

// printVersion displays the version, commit, and build date.
func printVersion() {
	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

type MainConfig struct {
	showVersion  bool
	ipDomainList string
	networkList  string
	port         int
	plainPort    int
	bind         string
	confPath     string
	vaultPath    string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		os.Exit(runHashPassword())
		return
	}

	if err := godotenv.Load(".env"); err != nil {
		if err != os.ErrNotExist {
			log.Printf("could not read .env: %s", err)
		}
	}

	cfg := MainConfig{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	fs.BoolVar(&cfg.showVersion, "version", false, "Print version and exit")
	fs.StringVar(&cfg.ipDomainList, "ip-domains", cmp.Or(os.Getenv("DYNAMIC_IP_DOMAIN"), "example.localdomain"), "enable dynamic ip urls (ex: tls-192-168-1-101.vm.example.com) with these comma-separated base URLs")
	fs.StringVar(&cfg.networkList, "networks", cmp.Or(os.Getenv("DYNAMIC_HOST_NETWORKS"), "169.254.0.0/16"), "enable dynamic ip url proxying (see --ip-domain) for these networks")
	fs.IntVar(&cfg.port, "port", envOrInt("PORT", 443), "TLS port to listen on. -1 to disable.")
	fs.IntVar(&cfg.plainPort, "plain-port", envOrInt("PLAIN_PORT", 80), "Plain (HTTP) port to listen on (for redirects). -1 to disable.")
	fs.StringVar(&cfg.bind, "bind", cmp.Or(os.Getenv("BIND"), "0.0.0.0"), "Address to bind to")
	fs.StringVar(&cfg.confPath, "config", cmp.Or(os.Getenv("CONFIG_FILE"), "tlsrouter.csv"), "Path to config CSV file")
	fs.StringVar(&cfg.vaultPath, "vault", cmp.Or(os.Getenv("VAULT_FILE"), "secrets.tsv"), "Path to vault TSV file")

	fs.Usage = func() {
		printVersion()
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter [options]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter --networks 10.1.1.0/24 --bind 0.0.0.0 --port 443\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "OPTIONS\n")
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion()
			return
		case "help", "-help", "--help":
			fs.Usage()
			os.Exit(0)
			return
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if cfg.showVersion {
		printVersion()
		return
	}

	if cfg.plainPort >= 0 {
		log.Printf("HTTP redirect listener starting on :%d → HTTPS (HTML meta)", cfg.plainPort)
		go func() {
			plainAddr := fmt.Sprintf("%s:%d", cfg.bind, cfg.plainPort)
			if err := tlsrouter.ListenAndRedirectPlainHTTP(plainAddr); err != http.ErrServerClosed {
				log.Fatalf("HTTP redirect server error: %v", err)
			}
		}()
		if cfg.port < 0 {
			select {}
		}
	}
	if cfg.port < 0 {
		log.Printf("closing because neither --port nor --plain-port are positive")
		return
	}

	ipDomains := splitList(cfg.ipDomainList)

	var networks []net.IPNet
	for _, cidr := range splitList(cfg.networkList) {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid network %q: %v\n", cidr, err)
			os.Exit(1)
		}
		networks = append(networks, *ipNet)
	}

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)

	tabVault, err := tabvault.OpenOrCreate(cfg.vaultPath)
	if err != nil {
		log.Fatalf("Vault Error: %q\n%s\n", cfg.vaultPath, err)
	}
	conf, err := ReadConfig(cfg.confPath, tabVault, ipDomains, networks)
	if err != nil {
		log.Fatalf("Config Error: %q\n%s\n", cfg.confPath, err)
	}

	conf.SetSigChan(sigChan)

	mux := http.NewServeMux()
	setupRouter(conf, mux)
	lc := tlsrouter.NewListenConfig(conf)

	var wg sync.WaitGroup
	addr := fmt.Sprintf("%s:%d", cfg.bind, cfg.port)
	_ = Start(&wg, lc, addr, mux)

	go func() {
		for {
			sig := <-sigChan
			switch sig {
			case syscall.SIGUSR1:
				log.Println("Received SIGUSR1, reloading config")

				// TODO kill connections to management
				tabVault, err := tabvault.OpenOrCreate(cfg.vaultPath)
				if err != nil {
					log.Fatalf("Vault Error: %q\n%s\n", cfg.vaultPath, err)
				}
				conf, err := ReadConfig(cfg.confPath, tabVault, ipDomains, networks)
				if err != nil {
					log.Fatalf("Config Error: %q\n%s\n", cfg.confPath, err)
				}
				conf.SetSigChan(sigChan)
				mux := http.NewServeMux()
				setupRouter(conf, mux)
				lc2 := tlsrouter.NewListenConfig(conf)
				_ = Start(&wg, lc2, addr, mux)

				// Gracefully shutdown old server
				go lc.Shutdown(context.Background())

				// Update server reference
				lc = lc2
			case syscall.SIGINT:
				log.Println("Received SIGINT, shutting down (5s)")
				lc.Shutdown(context.Background())
				time.Sleep(5 * time.Second)
				os.Exit(1)
			case syscall.SIGTERM:
				log.Println("Received SIGTERM, shutting down (5s)")
				lc.Shutdown(context.Background())
				time.Sleep(5 * time.Second)
				os.Exit(1)
			default:
				log.Printf("Received unhandled signal %s", sig)
			}
		}
	}()

	wg.Wait()
}

func envOrInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		fmt.Fprintf(os.Stderr, "warn: invalid %s=%q, using default %d\n", key, v, fallback)
		return fallback
	}
	return n
}

func splitList(s string) []string {
	s = strings.ReplaceAll(s, " ", ",")
	s = strings.ReplaceAll(s, ",,", ",")
	s = strings.TrimRight(s, ",")
	if len(s) == 0 {
		return nil
	}
	return strings.Split(s, ",")
}

func Start(wg *sync.WaitGroup, lc *tlsrouter.ListenConfig, addr string, mux *http.ServeMux) error {
	wg.Add(1)
	go func() {
		defer wg.Done()

		log.Printf("\nListening on %s...", addr)
		if err := lc.ListenAndProxy(addr, mux); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("Server error: %v", err)
		}
		log.Printf("Closed\n")
	}()
	return nil
}

// ReadConfig reads and parses a JSON config file into a Config.
func ReadConfig(filePath string, tabVault *tabvault.TabVault, ipDomains []string, networks []net.IPNet) (tlsrouter.Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return tlsrouter.Config{}, err
	}
	defer func() { _ = file.Close() }()

	reader := csv.NewReader(file)
	//reader.Comma = '\t'
	conf, err := tlsrouter.ReadCSVToConfig(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading CSV: %v\n", err)
		os.Exit(1)
	}
	conf.FilePath = filePath
	conf.TabVault = tabVault
	conf.Networks = networks
	conf.IPDomains = ipDomains
	for _, domain := range conf.IPDomains {
		if strings.HasSuffix(domain, ".local") {
			continue
		}

		ips, err := net.LookupIP(domain)
		if err != nil {
			return tlsrouter.Config{}, err
		}
		for _, ip := range ips {
			var found bool
			for _, existingIP := range conf.IPs {
				if existingIP.String() == ip.String() {
					found = true
					break
				}
			}
			if !found {
				conf.IPs = append(conf.IPs, ip)
			}
		}

		fmt.Fprintf(os.Stderr, "INFO resolved ip domain IPs: %#v\n", conf.IPs)
	}

	customAlpns := []string{"ssh"}
	knownAlpns := ianaalpn.Names

	for _, alpn := range customAlpns {
		if !slices.Contains(knownAlpns, alpn) {
			knownAlpns = append(knownAlpns, alpn)
		}
	}

	if err := tlsrouter.LintConfig(conf, knownAlpns); nil != err {
		return *conf, err
	}

	// alpnsByDomain, configByALPN := tlsrouter.NormalizeConfig(conf)
	_, _ = tlsrouter.NormalizeConfig(conf)

	for _, app := range conf.Apps {
		for _, srv := range app.Services {
			snialpns := strings.Join(srv.Domains, ",") + "; " + strings.Join(srv.ALPNs, ",")
			fmt.Printf("   %s\n", snialpns)
			for _, b := range srv.Backends {
				fmt.Printf("      %s:%d\n", b.Address, b.Port)
			}
		}
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return *conf, fmt.Errorf("config file disappeared %s: %w", filePath, err)
	}
	conf.FileTime = info.ModTime()

	conf.Hash = conf.ShortSHA2()
	return *conf, nil
}

func setupRouter(conf tlsrouter.Config, mux *http.ServeMux) {
	handleStatus := createHandleStatus(conf, time.Now())

	mux.HandleFunc("GET /version", handleVersion)
	mux.HandleFunc("GET /api/version", handleVersion)
	mux.HandleFunc("GET /api/public/version", handleVersion)

	mux.HandleFunc("GET /status", handleStatus)
	mux.HandleFunc("GET /api/status", handleStatus)
	mux.HandleFunc("GET /api/public/status", handleStatus)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(
		w,
		"{\n   \"name\": %q,\n   \"version\": %q,\n   \"commit\": %q,\n   \"date\": %q\n}\n",
		name, version, commit, date,
	)
}

type UptimeResponse struct {
	ConfigHash     string             `json:"config_hash"`
	ConfigDate     tlsrouter.JSONTime `json:"config_date"`
	ConfigRevision string             `json:"config_version"`
	SystemSeconds  float64            `json:"system_seconds"`
	SystemUptime   string             `json:"system_uptime"`
	APISeconds     float64            `json:"api_seconds"`
	APIUptime      string             `json:"api_uptime"`
}

func createHandleStatus(conf tlsrouter.Config, apiStart time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		systemUptime := time.Since(serverStart)
		sysSecs, _ := strconv.ParseFloat(fmt.Sprintf("%.3f", systemUptime.Seconds()), 64)
		apiUptime := time.Since(apiStart)
		apiSecs, _ := strconv.ParseFloat(fmt.Sprintf("%.3f", apiUptime.Seconds()), 64)

		response := UptimeResponse{
			ConfigRevision: conf.Revision,
			ConfigDate:     tlsrouter.JSONTime(conf.FileTime),
			ConfigHash:     conf.Hash,
			SystemSeconds:  sysSecs,
			SystemUptime:   formatDuration(systemUptime),
			APISeconds:     apiSecs,
			APIUptime:      formatDuration(apiUptime),
		}

		data, _ := json.MarshalIndent(response, "", "   ")
		_, _ = fmt.Fprintf(w, "%s\n", data)
	}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d / time.Second)

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if len(parts) > 0 || hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if len(parts) > 0 || minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if len(parts) > 0 || seconds > 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	if len(parts) == 0 {
		d -= time.Duration(seconds) * time.Second
		millis := int(d / time.Millisecond)
		parts = append(parts, fmt.Sprintf("%dms", millis))
	}

	return strings.Join(parts, " ")
}
