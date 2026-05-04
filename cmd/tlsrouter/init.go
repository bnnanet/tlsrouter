package main

import (
	"cmp"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/bnnanet/tlsrouter/tabvault"
)

func runInit() int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)

	var confPath string
	var vaultPath string
	var whitelistPath string
	var blacklistDir string
	var blacklistRepo string
	var adminDomain string

	fs.StringVar(&confPath, "config", cmp.Or(os.Getenv("CONFIG_FILE"), filepath.Join(defaultConfigDir(), "backends.csv")), "Path to backends config CSV file")
	fs.StringVar(&vaultPath, "vault", cmp.Or(os.Getenv("VAULT_FILE"), filepath.Join(defaultConfigDir(), "secrets.tsv")), "Path to vault TSV file")
	fs.StringVar(&whitelistPath, "ip-whitelist", filepath.Join(defaultConfigDir(), "allowed.csv"), "Path to IP whitelist CSV file")
	fs.StringVar(&blacklistDir, "ip-blacklist-dir", defaultBlocklistPath(), "Path to IP blacklist data directory")
	fs.StringVar(&blacklistRepo, "ip-blacklist-repo", defaultBlocklistRepo, "Git repo URL for IP blacklist, or 'none' to disable")
	fs.StringVar(&adminDomain, "admin-domain", "", "Admin domain (e.g. mgmt.example.com)")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE\n")
		fmt.Fprintf(os.Stderr, "   tlsrouter init [options]\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Creates config directory and empty config files with headers.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "OPTIONS\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[2:]); err != nil {
		return 1
	}

	configDir := filepath.Dir(confPath)

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		log.Printf("error: create config dir %q: %v", configDir, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "  config dir: %s\n", configDir)

	if err := initBackendsCSV(confPath, adminDomain); err != nil {
		log.Printf("error: %v", err)
		return 1
	}

	if err := initWhitelistCSV(whitelistPath); err != nil {
		log.Printf("error: %v", err)
		return 1
	}

	if _, err := tabvault.OpenOrCreate(vaultPath); err != nil {
		log.Printf("error: vault %q: %v", vaultPath, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "  vault:      %s (ok)\n", vaultPath)

	if blacklistRepo != "none" {
		if err := initBlacklist(blacklistDir, blacklistRepo); err != nil {
			log.Printf("error: %v", err)
			return 1
		}
	} else {
		fmt.Fprintf(os.Stderr, "  blacklist:  disabled (--ip-blacklist-repo 'none')\n")
	}

	fmt.Fprintf(os.Stderr, "\ndone. run 'tlsrouter' to start.\n")
	return 0
}

func initBackendsCSV(path string, adminDomain string) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "  backends:   %s (exists, skipping)\n", path)
		return nil
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create backends csv %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"app_slug",
		"domain",
		"alpn",
		"backend_address",
		"backend_port",
		"terminate_tls",
		"connect_tls",
		"rewrite_host",
		"skip_tls_verify",
		"auth",
		"allowed_client_hostnames",
	}); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}

	if adminDomain != "" {
		if err := w.Write([]string{
			"_admin",
			adminDomain,
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
		}); err != nil {
			return fmt.Errorf("write admin row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  backends:   %s (created)\n", path)
	return nil
}

func initWhitelistCSV(path string) error {
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "  whitelist:  %s (exists, skipping)\n", path)
		return nil
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create whitelist %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	_, err = fmt.Fprintf(f, "# IP whitelist: IPs, CIDRs, or domains that bypass the blacklist\n# ip_or_domain,label\n")
	if err != nil {
		return fmt.Errorf("write whitelist header: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  whitelist:  %s (created)\n", path)
	return nil
}

func initBlacklist(dataDir string, repoURL string) error {
	if _, err := os.Stat(filepath.Join(dataDir, ".git")); err == nil {
		fmt.Fprintf(os.Stderr, "  blacklist:  %s (exists, skipping)\n", dataDir)
		return nil
	}

	fmt.Fprintf(os.Stderr, "  blacklist:  cloning %s ...\n", repoURL)

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create blacklist dir %q: %w", dataDir, err)
	}

	// Use the gitshallow package to do the initial clone
	// For init we just verify the dir exists; the refresh loop handles the clone at startup
	fmt.Fprintf(os.Stderr, "  blacklist:  %s (ready, will clone on first run)\n", dataDir)
	return nil
}
