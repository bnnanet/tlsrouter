package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bnnanet/tlsrouter/tabvault"
)

func main() {
	mainFlags := flag.NewFlagSet("", flag.ContinueOnError)
	mainFlags.Usage = func() {
		fmt.Println("Usage:\ntouch ./path/to/secrets.tsv\ntabvault ./path/to/secrets.tsv new\ntabvault ./path/to/secrets.tsv add < ./secret.txt\ntabvault ./path/to/secrets.tsv verify <vault-id> < ./password.txt")
		mainFlags.PrintDefaults()
	}
	if err := mainFlags.Parse(os.Args[1:]); err != nil {
		mainFlags.Usage()
		os.Exit(1)
	}

	args := mainFlags.Args()
	if len(args) < 2 {
		mainFlags.Usage()
		os.Exit(1)
	}

	vaultPath := args[0]
	if _, err := os.Stat(vaultPath); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	tabVault, err := tabvault.OpenOrCreate(vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %q\n%s\n", vaultPath, err)
		os.Exit(1)
	}

	var secret string
	switch args[1] {
	case "new":
		secret = mustGenHex16()
		fmt.Println(secret)
	case "add":
		secret = readSecret()
	case "verify":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: tabvault <vault-file> verify <vault-id>")
			os.Exit(1)
		}
		password := readSecret()
		if tabVault.Verify(args[2], password) {
			fmt.Fprintln(os.Stderr, "OK")
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "FAIL")
		os.Exit(1)
	default:
		mainFlags.Usage()
		os.Exit(1)
	}

	id, err := tabVault.ToVaultURI(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(id)
}

func readSecret() string {
	fmt.Fprintf(os.Stderr, "Secret: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fmt.Fprintln(os.Stderr, "error: no input")
		os.Exit(1)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading secret: %v\n", err)
		os.Exit(1)
	}
	_ = os.Stdin.Close()
	return strings.TrimSpace(scanner.Text())
}

func mustGenHex16() string {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}

	hexStr := hex.EncodeToString(bytes)
	formatted := fmt.Sprintf("%s-%s-%s-%s", hexStr[:4], hexStr[4:8], hexStr[8:12], hexStr[12:])
	return formatted
}
