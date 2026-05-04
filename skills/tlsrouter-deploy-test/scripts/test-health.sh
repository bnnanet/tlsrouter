#!/bin/sh
set -e

# Test tlsrouter service health on a deployed host.
# Usage: ./scripts/test-health.sh <domain>

if test -z "$1"; then
	echo "Usage: $0 <domain>" >&2
	exit 1
fi

g_domain="$1"
g_pass=0
g_fail=0

check() {
	b_label="$1"
	b_expect="$2"
	b_url="$3"
	b_code=$(curl -sS --connect-timeout 3 -o /dev/null -w "%{http_code}" "$b_url" 2> /dev/null || echo "000")

	if test "$b_code" = "$b_expect"; then
		echo "OK  $b_label: $b_code"
		g_pass=$((g_pass + 1))
	else
		echo "FAIL  $b_label: got $b_code, expected $b_expect"
		g_fail=$((g_fail + 1))
	fi
}

echo "# Health checks for $g_domain"
echo ""

check "HTTPS reachable" "200" "https://${g_domain}/version"
check "HTTP redirect" "301" "http://${g_domain}/"

echo ""
echo "Results: $g_pass passed, $g_fail failed"

if test "$g_fail" -gt 0; then
	exit 1
fi
