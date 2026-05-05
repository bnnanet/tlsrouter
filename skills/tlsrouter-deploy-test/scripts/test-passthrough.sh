#!/bin/sh
set -e

# Test passthrough (non-TLS-terminating) connections through tlsrouter.
# Usage: ./scripts/test-passthrough.sh <domain> [resolve-host]
#
# Example:
#   ./scripts/test-passthrough.sh pbs1.m.bnna.net tls2.slc1.bnna.net

if test -z "$1"; then
	echo "Usage: $0 <domain> [resolve-host]" >&2
	echo "  domain:       passthrough domain (terminate_tls=false)" >&2
	echo "  resolve-host: optional, force resolution to this host" >&2
	exit 1
fi

g_domain="$1"
g_resolve_host="$2"
g_pass=0
g_fail=0

g_resolve_flag=""
if test -n "$g_resolve_host"; then
	g_resolve_ip=$(dig +short "$g_resolve_host" A | head -1)
	if test -z "$g_resolve_ip"; then
		echo "FAIL: could not resolve $g_resolve_host" >&2
		exit 1
	fi
	g_resolve_flag="--resolve ${g_domain}:443:${g_resolve_ip}"
fi

check() {
	b_label="$1"
	b_extra_flags="$2"
	# shellcheck disable=SC2086
	b_code=$(curl -sS --max-time 5 -k $g_resolve_flag $b_extra_flags -o /dev/null -w "%{http_code}" "https://${g_domain}/" 2> /dev/null || echo "000")

	if test "$b_code" = "200"; then
		echo "OK  $b_label: $b_code"
		g_pass=$((g_pass + 1))
	else
		echo "FAIL  $b_label: got $b_code, expected 200"
		g_fail=$((g_fail + 1))
	fi
}

echo "# Passthrough tests for $g_domain"
if test -n "$g_resolve_host"; then
	echo "# (resolving via $g_resolve_host → $g_resolve_ip)"
fi
echo ""

check "passthrough (h2 + http/1.1 ALPN)" "--http2"
check "passthrough (http/1.1 only ALPN)" "--http1.1"
check "passthrough (no ALPN)" "--no-alpn --http1.1"

echo ""
echo "Results: $g_pass passed, $g_fail failed"

if test "$g_fail" -gt 0; then
	exit 1
fi
