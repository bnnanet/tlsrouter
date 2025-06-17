package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	ianaalpn "github.com/bnnanet/tlsrouter/ianaalpn"
)

const (
	cacheFile   = "alpn-protocol-ids.csv"
	cacheDir    = ".cache"
	cacheMaxAge = 24 * time.Hour
)

var ErrCacheInvalid = fmt.Errorf("cache invalid")

// isCacheValid checks if the cached file exists and is less than 24 hours old
func isCacheValid(cachePath string, cacheMaxAge time.Duration) error {
	info, err := os.Stat(cachePath)
	if os.IsNotExist(err) {
		return ErrCacheInvalid
	}
	if err != nil {
		return fmt.Errorf("checking cache: %v", err)
	}

	if time.Since(info.ModTime()) > cacheMaxAge {
		return ErrCacheInvalid
	}

	return nil
}

// downloadCSV downloads the CSV from IANA
func downloadCSV() ([]byte, error) {
	resp, err := http.Get(ianaalpn.CSVURL)
	if err != nil {
		return nil, fmt.Errorf("downloading CSV: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// saveToCache saves the CSV data to the cache
func saveToCache(cachePath string, data []byte) error {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("creating cache dir: %v", err)
	}

	return os.WriteFile(cachePath, data, 0644)
}

// checkBytesAndName checks if the byte sequence matches the name (if provided)
func checkBytesAndName(buf []byte, name string) error {
	if name == "" {
		return nil // No name to validate against
	}

	if string(buf) != name {
		return fmt.Errorf(
			"bytes 0x%x %q do not match name %q",
			buf,
			string(buf),
			name,
		)
	}

	return nil
}

func main() {
	// Step 1: Check local cache
	cachePath := filepath.Join(cacheDir, cacheFile)

	// Step 2: Try downloading CSV, fallback to cache
	var csvBytes []byte
	if err := isCacheValid(cachePath, cacheMaxAge); err != nil {
		fmt.Println("Cache is invalid or expired, downloading CSV...")
		csvBytes, err = downloadCSV()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error downloading CSV: %v\n", err)
			fmt.Println("Falling back to cache...")
		} else {
			if err := saveToCache(cachePath, csvBytes); err != nil {
				fmt.Fprintf(os.Stderr, "Error updating cache: %v\n", err)
				os.Exit(1)
			}
		}
	}

	csvBytes, err := os.ReadFile(cachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading cache: %v\n", err)
		os.Exit(1)
	}

	entries, err := parseCsv(csvBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	// Print JSON
	fmt.Println(string(jsonData))
}

func parseCsv(data []byte) ([]ianaalpn.Entry, error) {
	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var entries []ianaalpn.Entry
	for i, record := range records[1:] { // Skip header
		if len(record) < 3 {
			fmt.Fprintf(os.Stderr, "Skipping malformed record at line %d: %v\n", i+2, record)
			continue
		}
		proto, idSeq, ref := record[0], record[1], record[2]

		entry, err := ianaalpn.ParseCSVEntry(proto, idSeq, ref)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse %q: %v\n", idSeq, err)
			continue
		}

		if err := checkBytesAndName(entry.Bytes, entry.Name); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %q: %v\n", idSeq, err)
			entry.Name = string(entry.Bytes)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
