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
		fmt.Println("Usage:\ntouch ./path/to/secrets.tsv\ntabvault ./path/to/secrets.tsv new\ntabvault ./path/to/secrets.tsv add < ./secret.txt")
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

	var secret string
	switch args[1] {
	case "new":
		secret = mustGenHex16()
		fmt.Println(secret)
	case "add":
		fmt.Fprintf(os.Stderr, "Secret: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			secret = scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "error reading secret: %v\n", err)
			os.Exit(1)
		}
		_ = os.Stdin.Close()
		secret = strings.TrimSpace(secret)
	}

	tabVault, err := tabvault.OpenOrCreate(vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %q\n%s\n", vaultPath, err)
		os.Exit(1)
	}

	id, err := tabVault.ToVaultURI(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(id)
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
