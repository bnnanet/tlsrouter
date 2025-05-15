package ianaalpn

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// URL is the location to view the list of registered ALPNs on the web
	URL = "https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids"
	// CSVURL is the location of the CSV-formatted list.
	// Note that as of 2025-05-15 smart quotes are mistakenly used for mqtt
	CSVURL = "https://www.iana.org/assignments/tls-extensiontype-values/alpn-protocol-ids.csv"
	// ComplaintURL can be used to submit issues with the IANA ALPN registration
	ComplaintURL = "https://www.iana.org/form/complaint"
)

//go:embed alpn.json
var alpnJSON embed.FS
var Entries []Entry
var Names []string

// reads in the embedded package data
func init() {
	entriesJSON, _ := alpnJSON.ReadFile("alpn.json")
	if err := json.Unmarshal(entriesJSON, &Entries); err != nil {
		panic(err)
	}

	for _, entry := range Entries {
		Names = append(Names, entry.Name)
	}
}

// Entry represents a parsed ALPN protocol entry from
// https://www.iana.org/assignments/tls-extensiontype-values/alpn-protocol-ids.csv
type Entry struct {
	Protocol  string   `json:"protocol,omitempty"`
	Reserved  bool     `json:"reserved,omitempty"`
	Name      string   `json:"name,omitempty"`
	Bytes     HexBytes `json:"bytes"`
	Reference string   `json:"reference"`
}

// HexBytes is a custom type for byte slices with hex JSON marshaling
type HexBytes []byte

// MarshalJSON implements custom JSON marshaling for HexBytes
func (h HexBytes) MarshalJSON() ([]byte, error) {
	hexStr := hex.EncodeToString(h)
	return json.Marshal(hexStr)
}

// UnmarshalJSON implements custom JSON unmarshaling for HexBytes
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return fmt.Errorf("unmarshaling HexBytes: %v", err)
	}

	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("decoding hex string: %v", err)
	}
	*h = bytes

	return nil
}

// ParseCSVEntry splits the identification sequence into bytes and name
func ParseCSVEntry(proto, idSeq, ref string) (Entry, error) {
	entry := Entry{
		Protocol:  proto,
		Reference: ref,
	}
	if entry.Protocol == "Reserved" {
		entry.Protocol = ""
		entry.Reserved = true
	}

	var nameHex string
	fields := strings.SplitSeq(idSeq, " ")
	for field := range fields {
		if strings.HasPrefix(field, "(") {
			field = strings.TrimPrefix(field, "(\"")
			field = strings.TrimPrefix(field, "(“")
			field = strings.TrimSuffix(field, "\")")
			field = strings.TrimSuffix(field, "”)")
			entry.Name = field
		} else {
			field = strings.TrimPrefix(field, "0x")
			nameHex = nameHex + field
		}
	}
	nameHex = strings.ToLower(nameHex)

	buf, err := hex.DecodeString(nameHex)
	if err != nil {
		return entry, fmt.Errorf("decoding hex bytes: %w", err)
	}
	entry.Bytes = buf

	return entry, nil
}
