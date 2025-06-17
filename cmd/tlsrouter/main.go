package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/bnnanet/tlsrouter"
	"github.com/bnnanet/tlsrouter/ianaalpn"
	"github.com/bnnanet/tlsrouter/net/tun"

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
	version = ""
	commit  = ""
	date    = ""
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

	var showVersion bool
	mainFlags.BoolVar(&showVersion, "version", false, "Print version and exit")

	defaultPort := 443
	// Check PORT environment variable, override default if set
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			defaultPort = p
		} else {
			fmt.Fprintf(os.Stderr, "warn: invalid PORT environment variable value: %s, using default or flag value\n", envPort)
		}
	}
	port := defaultPort
	mainFlags.IntVar(&port, "port", defaultPort, "Port to listen on")

	defaultBind := "0.0.0.0"
	// Check BIND environment variable, override default if set
	if envBind := os.Getenv("BIND"); envBind != "" {
		defaultBind = envBind
	}
	bind := defaultBind
	mainFlags.StringVar(&bind, "bind", defaultBind, "Address to bind to")

	defaultConfPath := "tlsrouter.json"
	// Check BIND environment variable, override default if set
	if envConfPath := os.Getenv("CONFIG_FILE"); envConfPath != "" {
		defaultConfPath = envConfPath
	}
	confPath := defaultConfPath
	mainFlags.StringVar(&confPath, "config", defaultConfPath, "Path to JSON config file")

	mainFlags.Usage = func() {
		printVersion()
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter [options]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "EXAMPLES\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter --bind 0.0.0.0 --port 443\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "OPTIONS\n")
		mainFlags.PrintDefaults()
	}

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

	var wg sync.WaitGroup
	addr := fmt.Sprintf("%s:%d", bind, port)

	conf, err := ReadConfig(confPath)
	if err != nil {
		log.Fatalf("Config Error: %q\n%s\n", confPath, err)
	}
	lc := tlsrouter.NewListenConfig(conf)
	_ = Start(&wg, lc, addr)

	// Signal handling (must be have a buffer of at least 1)
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, syscall.SIGUSR1, syscall.SIGTERM)

	for {
		sig := <-sigChan
		switch sig {
		case syscall.SIGUSR1:
			log.Println("Received SIGUSR1, reloading config")

			conf, err := ReadConfig(confPath)
			if err != nil {
				log.Fatalf("Config Error: %q\n%s\n", confPath, err)
			}
			lc2 := tlsrouter.NewListenConfig(conf)
			_ = Start(&wg, lc2, addr)

			// Gracefully shutdown old server
			go lc.Shutdown()

			// Update server reference
			lc = lc2
		case syscall.SIGTERM:
			log.Println("Received SIGTERM, shutting down")
			lc.Shutdown()
		default:
			log.Printf("Received unhandled signal %s", sig)
		}
	}
}

func Start(wg *sync.WaitGroup, lc *tlsrouter.ListenConfig, addr string) error {
	wg.Add(1)
	go func() {
		defer wg.Done()

		log.Printf("\nListening on %s...", addr)
		if err := lc.ListenAndProxy(addr); err != nil && err != tun.ErrListenerClosed {
			log.Printf("Server error: %v", err)
		}
	}()
	return nil
}

// ReadConfig reads and parses a JSON config file into a Config.
func ReadConfig(filePath string) (conf tlsrouter.Config, err error) {
	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return conf, fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	if err := json.Unmarshal(data, &conf); err != nil {
		return conf, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	customAlpns := []string{"ssh"}
	alpns := ianaalpn.Names

	for _, alpn := range customAlpns {
		if !slices.Contains(alpns, alpn) {
			alpns = append(alpns, alpn)
		}
	}

	if err := tlsrouter.LintConfig(conf, alpns); nil != err {
		return conf, err
	}

	// alpnsByDomain, configByALPN := tlsrouter.NormalizeConfig(conf)
	_, _ = tlsrouter.NormalizeConfig(conf)

	for _, site := range conf.TLSMatches {
		snialpns := strings.Join(site.Domains, ",") + "; " + strings.Join(site.ALPNs, ",")
		fmt.Printf("   %s\n", snialpns)
		for _, b := range site.Backends {
			fmt.Printf("      %s:%d\n", b.Address, b.Port)
		}
	}

	return conf, nil
}
