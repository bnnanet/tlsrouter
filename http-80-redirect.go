package tlsrouter

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// ListenAndRedirectPlainHTTP starts an HTTP listener on :80 that redirects to HTTPS
func ListenAndRedirectPlainHTTP(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", HandleHTTPSRedirect)

	srv := &http.Server{
		Addr:         ":80",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	return srv.ListenAndServe()
}

// EscapeAndRenderURL uses both querystring and html escape for the appropriate style - hrefURL is the safest
func EscapeAndRenderURL(r *http.Request) (properURL, htmlURL, attrURL, redirectBody string) {
	// 0. Human-readable debuggable version
	path := r.URL.RequestURI()
	properURL = "https://" + r.Host + path

	// 1. Human-readable version – only HTML-escaped
	attrURL = "https://" + html.EscapeString(url.QueryEscape(r.Host)+path)

	htmlURL, _ = url.QueryUnescape(properURL)
	htmlURL = html.EscapeString(htmlURL)

	// Multi-line HTML body: no indentation, human-readable in curl/debuggers
	redirectBody = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
   <meta charset="utf-8">
   <meta http-equiv="refresh" content="0; url=%s">
   <link rel="canonical" href="%s">
   <title>Redirecting...</title>
</head>
<body>
   <p>Redirecting to <a href="%s">%s</a>...</p>
</body>
</html>
`, attrURL, attrURL, attrURL, htmlURL)

	return properURL, htmlURL, attrURL, redirectBody
}

// HandleHTTPSRedirect issues a client-side redirect via HTML meta refresh.
// - If the client accepts text/html (browser-like), includes <link rel="canonical">.
// - All clients receive 200 OK with HTML body containing meta refresh and link.
// - Uses the same status, headers, and logic regardless of Accept.
// - If Host header is missing, returns 400 Bad Request.
func HandleHTTPSRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "Bad Request: missing Host header", http.StatusBadRequest)
		return
	}

	// Reconstruct the target URL: https://<host><path>?query
	properURL, _, _, redirectBody := EscapeAndRenderURL(r)
	logURL, _ := url.QueryUnescape(properURL)
	fmt.Fprintf(os.Stderr, "DEBUG: %s: redirect %s\n", r.Host, logURL)

	// Determine if client accepts text/html
	isBrowser := slices.ContainsFunc(
		strings.Split(r.Header.Get("Accept"), ","),
		func(acceptable string) bool {
			mediaType := strings.TrimSpace(strings.SplitN(acceptable, ";", 2)[0])
			return mediaType == "text/html"
		},
	)

	// Set headers
	if isBrowser {
		w.Header().Set("Location", properURL)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusMovedPermanently)

	_, _ = fmt.Fprint(w, redirectBody)
}
