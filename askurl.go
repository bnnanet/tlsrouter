package tlsrouter

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// askURLClient is the HTTP client used for ask_url checks. It deliberately
// has no redirect follower and a short timeout — the policy endpoint should
// answer synchronously with a status code.
var askURLClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// askURLAllows asks an external endpoint whether an ACME certificate may be
// issued for name. It performs GET <askURL>?domain=<name> and treats only
// HTTP 200 as "allow". Any other status or network error is "deny".
func askURLAllows(ctx context.Context, askURL, name string) error {
	if askURL == "" {
		return fmt.Errorf("ask_url not configured for wildcard issuance of %q", name)
	}

	u, err := url.Parse(askURL)
	if err != nil {
		return fmt.Errorf("invalid ask_url %q: %w", askURL, err)
	}
	q := u.Query()
	q.Set("domain", name)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("build ask request: %w", err)
	}

	resp, err := askURLClient.Do(req)
	if err != nil {
		slog.Warn("ask_url request failed", "domain", name, "ask_url", askURL, "err", err)
		return fmt.Errorf("ask_url request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		slog.Info("ask_url allowed issuance", "domain", name, "ask_url", askURL)
		return nil
	}
	slog.Warn("ask_url denied issuance", "domain", name, "ask_url", askURL, "status", resp.StatusCode)
	return fmt.Errorf("ask_url denied issuance for %q (status %d)", name, resp.StatusCode)
}
