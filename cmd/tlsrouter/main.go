package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/bnnanet/tlsrouter"
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
	mainFlags := flag.NewFlagSet("", flag.ContinueOnError)

	var showVersion bool
	mainFlags.BoolVar(&showVersion, "version", false, "Print version and exit")

	defaultPort := 443
	// Check PORT environment variable, override default if set
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			defaultPort = p
		} else {
			log.Printf("warn: invalid PORT environment variable value: %s, using default or flag value\n", envPort)
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

	defaultCfgPath := "tlsrouter.json"
	// Check BIND environment variable, override default if set
	if envCfgPath := os.Getenv("CONFIG_FILE"); envCfgPath != "" {
		defaultCfgPath = envCfgPath
	}
	cfgPath := defaultCfgPath
	mainFlags.StringVar(&cfgPath, "config", defaultCfgPath, "Path to JSON config file")

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

	cfg, err := ReadConfig(cfgPath)
	if err != nil {
		log.Fatalf("Error: %q\n%s\n", cfgPath, err)
	}

	// Use the bind address and port
	addr := fmt.Sprintf("%s:%d", bind, port)
	log.Printf("Listening on %s...", addr)
	for _, site := range cfg {
		fmt.Printf("   %s\n", site.Domain)
		for _, t := range site.Targets {
			fmt.Printf("      %s:%d (%s)\n", t.Addr, t.Port, strings.Join(t.ALPNs, ","))
		}
	}

	lnCfg := tlsrouter.NewListenConfig(cfg)
	log.Fatalf("Error:\n%s\n", lnCfg.ListenAndProxy(addr))
}

// ReadConfig reads and parses a JSON config file into a Config.
func ReadConfig(filePath string) (tlsrouter.Config, error) {
	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filePath, err)
	}

	var config tlsrouter.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if err := tlsrouter.LintConfig(config); nil != err {
		return nil, err
	}

	return tlsrouter.NormalizeConfig(config), nil
}
