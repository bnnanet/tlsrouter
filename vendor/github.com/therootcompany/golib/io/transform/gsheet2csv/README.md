# gsheet2csv

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/io/transform/gsheet2csv.svg)](https://pkg.go.dev/github.com/therootcompany/golib/io/transform/gsheet2csv)

A simple wrapper around `encoding/csv` to read Google Sheet CSVs from URL, or a given Reader.

This does surprisingly little - you should probably just handle the boilerplate yourself. However, these are the problems it solves for us:

- works with Google Sheet URLs, regardless of URL format
   - Edit URL: <https://docs.google.com/spreadsheets/d/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/edit?gid=0000000000#gid=0000000000>
   - Share URL (Sheet 1): <https://docs.google.com/spreadsheets/d/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/edit?usp=sharing>
   - CSV Export URL: <https://docs.google.com/spreadsheets/d/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/export?format=csv&usp=sharing&gid=0000000000>
   - anything with a path like `/spreadsheets/d/{docid}/` and (optionally) a hash or query param like `gid={gid}`
- can write out for import to gsheet (comments containing quotes or commas are quoted), \
  or in RFC form (comments are never quoted, but values beginning with a comment character are)
- swaps `\r` (Windows) for `\n` (Unix) and ensures trailing newline (a la `encoding/csv`)

Note:

- The Google Sheet must be shared to **Anyone with the link**.
- Read and write in 'gsheet' style for reciprocity of comment handling
- Be careful about single-column CSVs \
  (all comment-like lines are comments, same as with `encoding/csv` and empty lines)

# Usage

Same as `encoding/csv` (embedded), but with two extra options:

```go
package main

import (
	"fmt"
	"os"

	"github.com/therootcompany/golib/io/transform/gsheet2csv"
)

func main() {
	switch len(os.Args) {
	case 2:
		break
	case 1:
		fmt.Fprintf(os.Stderr, "Usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}
	urlOrPath := os.Args[1]

	gsr := gsheet2csv.NewReaderFrom(urlOrPath)
	records, err := gsr.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from %s: %v\n", gsr.URL, err)
		os.Exit(1)
	}

	csvw := gsheet2csv.NewWriter(os.Stdout)
	csvw.Comment = gsr.Comment
	if err := csvw.WriteAll(records); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing csv %v\n", err)
		os.Exit(1)
	}
}
```

# CLI

There are a few convenience utilities:

- `gsheet2csv` (also `gsheet2tsv`)
- `gsheet2env`

## gsheet2csv

They're only slightly different from a direct export of a Google CSV in that they reformat comments and newlines.

The alterable behavior is almost exclusively for testing.

### Installation

```sh
go get github.com/therootcompany/golib/io/transform/gsheet2csv
```

### Usage

```sh
gsheet2csv -raw -o ./gsheet.csv 'https://docs.google.com/spreadsheets/...'

gsheet2csv -d '\t' --write-style 'gsheet' ./gsheet.csv > ./gsheet.tsv

gsheet2csv --strip-comments ./gsheet.csv > ./sheet.csv
```

```text
--raw               download without processing
--print-ids         print ids to stdout without download
--print-url         print url to stdout without downloading
-o <filepath>       write records to file (default: stdout)
-d                  field delimiter (for output)
--read-delimiter    input field delimiter (for testing reciprocity)
--crlf              write using CRLF (\r\n) as the record separator
--comment '#'       treat lines starting with # as comments
--strip-comments    ignore single-field data beginning with a comment character
--read-style        'gsheet' (preserves comments as single-field records)
                    or 'rfc' (ignore lines starting with comment character)
--write-style       'gsheet' (quote single-field comments containing quotes or commas)
                    or 'rfc' (only quote values starting with a comment character)
```

### ASCII Delimiters

```
,   comma
\t  tab (or a normal tab)
    space (just a normal space)
:   colon
;   semicolon
|   pipe
^_  unit separator
^^  record separator
^]  group separator
^\  file separator
\f  form feed (also ^L)
\v  vertical tab (also ^K)
```

## gsheet2env

Converts a Google Sheet to an ENV file.

### Installation

```sh
go get github.com/therootcompany/golib/io/transform/gsheet2env
```

### Usage

```sh
gsheet2env --no-shebang --no-header --no-export ./fixtures/gsheet-env-readme.csv
```

### Example

```csv
# DO NOT put SECRETS here. Anyone with a link can see this. Use for config ONLY!
LOCAL_TIMEZONE,America/Denver,"Seatle PT, Denver MT, Arizona MST, Chicago CT, Detroit ET"

# to show that escapes are handled
FIRST_LETTER,A,
MONEY_SYMBOL,$,
SINGLE_QUOTE,',
DOUBLE_QUOTE,"""",

# to show that newlines are handled
TRIFORCE,"wisdom
courage
power","Zelda
Link
Ganon"
```

```sh
# DO NOT put SECRETS here. Anyone with a link can see this. Use for config ONLY!
# Seatle PT, Denver MT, Arizona MST, Chicago CT, Detroit ET
LOCAL_TIMEZONE='America/Denver'
# to show that escapes are handled
FIRST_LETTER='A'
MONEY_SYMBOL='$'
SINGLE_QUOTE=''"'"''
DOUBLE_QUOTE='"'
# to show that newlines are handled
# Zelda
# Link
# Ganon
TRIFORCE='wisdom
courage
power'
```
