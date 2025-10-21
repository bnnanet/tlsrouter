package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bnnanet/tlsrouter"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <csv-file>\n", os.Args[0])
		os.Exit(1)
	}

	file, _ := os.Open(os.Args[1])
	defer func() { _ = file.Close() }()

	reader := csv.NewReader(file)
	reader.Comma = '\t'
	config, err := tlsrouter.ReadCSVToConfig(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading CSV: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "   ")
	_ = enc.Encode(config)
}
