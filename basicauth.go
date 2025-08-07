package tlsrouter

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
)

type BasicAuthVerifier interface {
	Verify(string, string) bool
}

type BasicAuthPassword string

// JSONError represents an API error response
type JSONError struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// jsonError writes a JSON error response
func jsonError(w http.ResponseWriter, status int, code, errorMsg, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(JSONError{
		Error:  errorMsg,
		Code:   code,
		Detail: detail,
	})
}

// see also: logapid
func (p BasicAuthPassword) Verify(_, password string) bool {
	known := sha256.Sum256([]byte(p))
	digest := sha256.Sum256([]byte(password))

	return bytes.Equal(known[:], digest[:])
}
