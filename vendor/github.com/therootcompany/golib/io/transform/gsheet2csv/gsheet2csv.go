// Authored in 2025 by AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

package gsheet2csv

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	fileSeparator   = '\x1c'
	groupSeparator  = '\x1d'
	recordSeparator = '\x1e'
	unitSeparator   = '\x1f'
)

var ErrHTTPGet = errors.New("did not get 200 OK when downloading from URL")

// For mocking for tests
var httpGet = http.Get

type Reader struct {
	*csv.Reader
	DocID   string
	GID     string
	URL     string
	Comment rune
	r       io.Reader
	resp    *http.Response
	close   bool
	err     error
}

func NewReaderFrom(urlOrPath string) *Reader {
	if strings.HasPrefix(urlOrPath, "https://") || strings.HasPrefix(urlOrPath, "http://") {
		return NewReaderFromURL(urlOrPath)
	}

	urlOrPath = strings.TrimPrefix(urlOrPath, "file://")
	f, err := os.Open(urlOrPath)
	r := NewReader(f)
	r.URL = urlOrPath
	if err != nil {
		r.err = err
	}

	return r
}

func NewReaderFromURL(url string) *Reader {
	docid, gid := ParseIDs(url)

	return NewReaderFromIDs(docid, gid)
}

func NewReaderFromIDs(docid, gid string) *Reader {
	resp, err := GetSheet(docid, gid)
	if err != nil {
		r := NewReader(nil)
		r.err = err
		return r
	}

	r := NewReader(resp.Body)
	r.URL = ToCSVURL(docid, gid)
	r.DocID = docid
	r.GID = gid
	r.resp = resp
	r.close = true
	return r
}

func ToCSVURL(docid, gid string) string {
	return fmt.Sprintf("https://docs.google.com/spreadsheets/d/%s/export?format=csv&usp=sharing&gid=%s", docid, gid)
}

func GetSheet(docid, gid string) (*http.Response, error) {
	downloadURL := ToCSVURL(docid, gid)

	resp, err := httpGet(downloadURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, ErrHTTPGet
	}

	return resp, nil
}

func NewReader(r io.Reader) *Reader {
	csvr := csv.NewReader(r)
	csvr.Comma = ','
	csvr.Comment = 0          // to allow distinguishing between quoted comments and fields
	csvr.FieldsPerRecord = -1 // Google Sheets is consistent, but our commented files are not
	csvr.LazyQuotes = false   // fields that need quotes use them correctly
	csvr.TrimLeadingSpace = false
	csvr.ReuseRecord = false
	return &Reader{
		Reader:  csvr,
		Comment: '#',
		r:       r,
	}
}

func DecodeDelimiter(delimString string) (rune, error) {
	switch delimString {
	case "^_", "\\x1f":
		delimString = string(unitSeparator)
	case "^^", "\\x1e":
		delimString = string(recordSeparator)
	case "^]", "\\x1d":
		delimString = string(groupSeparator)
	case "^\\", "\\x1c":
		delimString = string(fileSeparator)
	case "^L", "\\f":
		delimString = "\f"
	case "^K", "\\v":
		delimString = "\v"
	case "^I", "\\t":
		delimString = "	"
	}
	delim, _ := utf8.DecodeRuneInString(delimString)
	return delim, nil
}

func (r *Reader) Read() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}

	for {
		record, err := r.Reader.Read()
		if err != nil {
			if r.close {
				_ = r.resp.Body.Close()
			}
			return nil, err
		}

		if r.Comment > 0 {
			if rv, _ := utf8.DecodeRuneInString(record[0]); rv == r.Comment {
				last := len(record) - 1
				for len(record[last]) == 0 {
					last -= 1
				}
				if last == 0 {
					continue
				}
			}
		}
		return record, nil
	}
}

func (r *Reader) ReadAll() ([][]string, error) {
	var records [][]string

	for {
		record, err := r.Read()
		if nil != err {
			if errors.Is(err, io.EOF) {
				return records, nil
			}
			return records, err
		}
		records = append(records, record)
	}
}

func ParseIDs(urlStr string) (docid string, gid string) {
	// Find key: look for /spreadsheets/d/{key}
	const prefix = "/spreadsheets/d/"
	startIdx := strings.Index(urlStr, prefix)
	if startIdx == -1 {
		return "", gid
	}
	startIdx += len(prefix)

	// Find end of key (next / or end of string)
	endIdx := strings.Index(urlStr[startIdx:], "/")
	if endIdx == -1 {
		endIdx = len(urlStr)
	} else {
		endIdx += startIdx
	}

	docid = urlStr[startIdx:endIdx]
	if docid == "" {
		return "", ""
	}

	// Find gid: look for gid= and take until #, &, ?, /, or end
	gidIdx := strings.Index(urlStr, "gid=")
	if gidIdx != -1 {
		gidStart := gidIdx + len("gid=")
		endChars := "#&?/"
		gidEnd := strings.IndexAny(urlStr[gidStart:], endChars)
		if gidEnd == -1 {
			gid = urlStr[gidStart:]
		} else {
			gid = urlStr[gidStart : gidStart+gidEnd]
		}
	}

	if len(gid) == 0 {
		gid = "0"
	}
	return docid, gid
}

type Writer struct {
	*csv.Writer
	Comment                rune
	QuoteAmbiguousComments bool
	w                      io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{
		Writer:  csv.NewWriter(w),
		Comment: '#',
		w:       w,
	}
}

func (w *Writer) Write(record []string) error {
	// Not handling comments? Move along.
	if w.Comment == 0 || len(record) == 0 {
		return w.Writer.Write(record)
	}

	// First char not a comment char? Move along.
	if rv1, _ := utf8.DecodeRuneInString(record[0]); rv1 != w.Comment {
		return w.Writer.Write(record)
	}

	// Is this a true comment? Or data that should be quoted that begins with the comment char?
	lastNonEmpty := len(record) - 1
	if lastNonEmpty > -1 {
		for len(record[lastNonEmpty]) == 0 {
			lastNonEmpty -= 1
		}
	}

	// We will be doing custom writes ahead
	w.Flush()
	var newline = "\n"
	if w.UseCRLF {
		newline = "\r\n"
	}

	// Write true comments out plain
	first := 0
	if lastNonEmpty == 0 {
		record = record[:1]
		if !w.QuoteAmbiguousComments {
			if _, err := w.w.Write([]byte(record[0] + newline)); err != nil {
				return err
			}
			return nil
		}
		// Quote the comment iff it contains quotes or commas, not universally
		first = -1
	}

	// Quote if
	// - the line contains quotes or commas
	// - there are multiple fields and the first starts with a comment character
	//   (but NOT a single-field comment with no quotes or commas)
	for i, f := range record {
		if i == first || strings.Contains(f, `"`) || strings.Contains(f, string(w.Comma)) {
			f = strings.ReplaceAll(f, `"`, `""`)
			record[i] = `"` + f + `"`
		}
	}
	line := strings.Join(record, string(w.Comma))
	if _, err := w.w.Write([]byte(line + newline)); err != nil {
		return err
	}
	return nil
}

func (w *Writer) WriteAll(records [][]string) error {
	for _, r := range records {
		if err := w.Write(r); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
