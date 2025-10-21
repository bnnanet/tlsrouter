package main

import (
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

func main() {
	if err := godotenv.Load(".env"); err != nil {
		if err != os.ErrNotExist {
			log.Printf("could not read .env: %s", err)
		}
	}

	mainFlags := flag.NewFlagSet("", flag.ContinueOnError)

	// --version
	var showVersion bool
	mainFlags.BoolVar(&showVersion, "version", false, "Print version and exit")

	// Check DYNAMIC_IP_BASE_URL environment variable, override default if set
	var ipDomain string
	defaultIPBaseURL := "example.localdomain"
	if envNetworks := os.Getenv("DYNAMIC_IP_DOMAIN"); envNetworks != "" {
		defaultIPBaseURL = envNetworks
	}
	mainFlags.StringVar(&ipDomain, "ip-domain", defaultIPBaseURL, "enable dynamic ip urls (ex: tls-192-168-1-101.vm.example.com) with this base")

	// Check DYNAMIC_HOST_NETWORKS environment variable, override default if set
	var networkList string
	defaultNetworkList := "169.254.0.0/16"
	if envNetworks := os.Getenv("DYNAMIC_HOST_NETWORKS"); envNetworks != "" {
		defaultNetworkList = envNetworks
	}
	mainFlags.StringVar(&networkList, "networks", defaultNetworkList, "enable dynamic ip url proxying (see --ip-domain) for these networks")

	// Check PORT environment variable, override default if set
	var port int
	defaultPort := 443
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			defaultPort = p
		} else {
			fmt.Fprintf(os.Stderr, "warn: invalid PORT environment variable value: %s, using default or flag value\n", envPort)
		}
	}
	mainFlags.IntVar(&port, "port", defaultPort, "Port to listen on")

	// Check BIND environment variable, override default if set
	var bind string
	defaultBind := "0.0.0.0"
	if envBind := os.Getenv("BIND"); envBind != "" {
		defaultBind = envBind
	}
	mainFlags.StringVar(&bind, "bind", defaultBind, "Address to bind to")

	// Check BIND environment variable, override default if set
	var confPath string
	defaultConfPath := "tlsrouter.csv"
	if envConfPath := os.Getenv("CONFIG_FILE"); envConfPath != "" {
		defaultConfPath = envConfPath
	}
	mainFlags.StringVar(&confPath, "config", defaultConfPath, "Path to JSON config file")

	// Check BIND environment variable, override default if set
	var vaultPath string
	defaultVaultPath := "secrets.tsv"
	if envVaultPath := os.Getenv("VAULT_FILE"); envVaultPath != "" {
		defaultVaultPath = envVaultPath
	}
	mainFlags.StringVar(&vaultPath, "vault", defaultVaultPath, "Path to vault TSV (Tab CSV) file")

	// usage
	mainFlags.Usage = func() {
		printVersion()
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter [options]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter --networks 10.1.1.0/24 --bind 0.0.0.0 --port 443\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "OPTIONS\n")
		mainFlags.PrintDefaults()
	}

	// pre-parse
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "version", "--version":
			printVersion()
			return
		}
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "--help":
			mainFlags.Usage()
			os.Exit(0)
			return
		}
	}

	// parse
	if err := mainFlags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)

		mainFlags.Usage()
		os.Exit(1)
		return
	}

	// Handle --version flag after parsing
	if showVersion {
		printVersion()
		return
	}

	// enabled dynamic ip networks
	var networks []net.IPNet
	var cidrs []string
	if len(networkList) > 0 {
		networkList = strings.ReplaceAll(strings.ReplaceAll(networkList, " ", ","), ",,", ",")
		cidrs = strings.Split(networkList, ",")
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid network %q: %v\n", cidr, err)
			os.Exit(1)
		}
		networks = append(networks, *ipNet)
	}

	// Signal handling (must be have a buffer of at least 1)
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)

	tabVault, err := tabvault.OpenOrCreate(vaultPath)
	if err != nil {
		log.Fatalf("Vault Error: %q\n%s\n", vaultPath, err)
	}
	conf, err := ReadConfig(confPath, tabVault, ipDomain, networks)
	if err != nil {
		log.Fatalf("Config Error: %q\n%s\n", confPath, err)
	}

	conf.SetSigChan(sigChan)
	mux := http.NewServeMux()
	setupRouter(conf, mux)
	lc := tlsrouter.NewListenConfig(conf)

	var wg sync.WaitGroup
	addr := fmt.Sprintf("%s:%d", bind, port)
	_ = Start(&wg, lc, addr, mux)

	go func() {
		for {
			sig := <-sigChan
			switch sig {
			case syscall.SIGUSR1:
				log.Println("Received SIGUSR1, reloading config")

				// TODO kill connections to management
				tabVault, err := tabvault.OpenOrCreate(vaultPath)
				if err != nil {
					log.Fatalf("Vault Error: %q\n%s\n", vaultPath, err)
				}
				conf, err := ReadConfig(confPath, tabVault, ipDomain, networks)
				if err != nil {
					log.Fatalf("Config Error: %q\n%s\n", confPath, err)
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
func ReadConfig(filePath string, tabVault *tabvault.TabVault, ipDomain string, networks []net.IPNet) (tlsrouter.Config, error) {
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
	conf.IPDomain = ipDomain

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
