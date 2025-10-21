package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/therootcompany/golib/io/transform/gsheet2csv"
)

type CSVReader interface {
	Read() ([]string, error)
	ReadAll() ([][]string, error)
}

type CSVWriter interface {
	Write([]string) error
	WriteAll([][]string) error
	Flush()
	Error() error
}

func main() {
	var commentArg string
	format := "CSV"
	delim := ','
	if strings.Contains(os.Args[0], "tsv") {
		delim = '\t'
		format = "TSV"
	}

	// Parse command-line flags
	flag.StringVar(&commentArg, "comment", "#", "treat lines beginning with this rune as comments, 0 to disable (which may cause read errors)")
	outputFile := flag.String("o", "", "Output "+format+" file (default: stdout)")
	readDelimString := flag.String("read-delimiter", ",", "field delimiter to use for input file ('\\t' for tab, '^_' for Unit Separator, etc)")
	delimString := flag.String("d", string(delim), "field delimiter to use for output file ('\\t' for tab, '^_' for Unit Separator, etc)")
	useCRLF := flag.Bool("crlf", false, "use CRLF (\\r\\n) as record separator")
	urlOnly := flag.Bool("print-url", false, "don't download, just print the Google Sheet URL")
	parseOnly := flag.Bool("print-ids", false, "don't download, just print the Doc ID and Sheet ID (gid)")
	rawOnly := flag.Bool("raw", false, "don't parse, just download")
	noReadComments := flag.Bool("strip-comments", false, "strip comments when reading (gsheet-only, control rfc behavior with --comment)")
	readStyle := flag.String("read-style", "gsheet", "'gsheet' or 'rfc' to read either as a gsheet or rfc CSV")
	writeStyle := flag.String("write-style", "rfc", "'gsheet' or 'rfc' to write either for gsheet import or rfc CSV read")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <google-sheet-url-or-file-path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Converts a Google Sheet to %s format.\n\n", format)
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -o output.tsv 'https://docs.google.com/spreadsheets/d/1KdNsc63pk0QRerWDPcIL9cMnGQlG-9Ue9Jlf0PAAA34/edit?gid=559037238#gid=559037238'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -o output.tsv 'file://gsheet.csv'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -o output.tsv './gsheet.csv'\n", os.Args[0])
	}
	flag.Parse()

	// Check for URL argument
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "Error: exactly one Google Sheet URL is required\n")
		flag.Usage()
		os.Exit(1)
	}
	url := flag.Args()[0]

	// Prepare output writer
	var out *os.File
	if *outputFile != "" {
		var err error
		out, err = os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = out.Close() }()
	} else {
		out = os.Stdout
	}

	inputDelim, err := gsheet2csv.DecodeDelimiter(*readDelimString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding input delimiter: %v\n", err)
		os.Exit(1)
	}

	delim, err = gsheet2csv.DecodeDelimiter(*delimString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding output delimiter: %v\n", err)
		os.Exit(1)
	}

	var rc io.ReadCloser
	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		docid, gid := gsheet2csv.ParseIDs(url)
		if *parseOnly {
			fmt.Printf("docid=%s\ngid=%s\n", docid, gid)
		} else {
			fmt.Fprintf(os.Stderr, "docid=%s\ngid=%s\n", docid, gid)
		}

		sheetURL := gsheet2csv.ToCSVURL(docid, gid)
		if *urlOnly {
			fmt.Printf("%s\n", sheetURL)
		} else {
			fmt.Fprintf(os.Stderr, "downloading %s\n", sheetURL)
		}

		if !*urlOnly {
			resp, err := gsheet2csv.GetSheet(docid, gid)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting url: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = resp.Body.Close() }()
			rc = resp.Body
		}
	} else {
		url = strings.TrimPrefix(url, "file://")
		fmt.Fprintf(os.Stderr, "opening %s\n", url)
		f, err := os.Open(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		rc = f
	}

	if out == os.Stdout {
		fmt.Fprintf(os.Stderr, "\n")
	}

	if *urlOnly || *parseOnly {
		os.Exit(0)
		return
	}

	if *rawOnly {
		if _, err := io.Copy(out, rc); err != nil {
			fmt.Fprintf(os.Stderr, "Error getting url body: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var comment rune
	if commentArg == "0" {
		comment = 0
	} else {
		comment, _ = utf8.DecodeRuneInString(commentArg)
	}

	// Create a reader for the Google Sheet
	var csvr CSVReader
	if *readStyle == "rfc" {
		rfcr := csv.NewReader(rc)
		rfcr.Comma = inputDelim
		rfcr.Comment = comment
		rfcr.FieldsPerRecord = -1 // Google Sheets is consistent, but our commented files are not
		csvr = rfcr
	} else {
		gsr := gsheet2csv.NewReader(rc)
		gsr.Comma = inputDelim
		if *noReadComments {
			gsr.Comment = comment
		} else {
			gsr.Comment = 0
		}
		gsr.ReuseRecord = true
		csvr = gsr
	}

	// Create CSV writer
	var csvw CSVWriter
	// if *writeStyle == "gsheet"
	{
		gsw := gsheet2csv.NewWriter(out)
		gsw.QuoteAmbiguousComments = *writeStyle == "gsheet"
		gsw.Comment = comment
		gsw.Comma = delim // Set delimiter to tab for TSV
		gsw.UseCRLF = *useCRLF
		csvw = gsw
	}
	// else {
	// 	rfcw := csv.NewWriter(out)
	// 	rfcw.Comma = delim
	// 	rfcw.UseCRLF = *useCRLF
	// 	csvw = rfcw
	// }

	for {
		// Convert each record
		record, err := csvr.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			fmt.Fprintf(os.Stderr, "Error reading "+format+": %v\n", err)
			os.Exit(1)
			return
		}

		if err := csvw.Write(record); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing "+format+": %v\n", err)
			os.Exit(1)
			return
		}
	}
	csvw.Flush()
	if err := csvw.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing "+format+" writer: %v\n", err)
		os.Exit(1)
	}

	if out != os.Stdout {
		fmt.Fprintf(os.Stderr, "wrote %s\n", *outputFile)
	}
}
