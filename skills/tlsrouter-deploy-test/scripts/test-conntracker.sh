#!/bin/sh
set -e

# Test connection tracker on a deployed tlsrouter host.
# Usage: ./scripts/test-conntracker.sh <host> <domain>
#
# Verifies that connections are tracked and flushed to TSV on shutdown.

if test -z "$2"; then
	echo "Usage: $0 <host> <domain>" >&2
	echo "  host:   SSH target" >&2
	echo "  domain: reachable TLS domain to generate traffic" >&2
	exit 1
fi

g_host="$1"
g_domain="$2"
g_pass=0
g_fail=0

g_tsv_path='$HOME/.local/share/tlsrouter/connections.tsv'

echo "# Connection tracker test"
echo "# Host: $g_host"
echo "# Domain: $g_domain"
echo ""

echo "## Generate traffic..."
curl -sS --max-time 5 "https://${g_domain}/" -o /dev/null -w "%{http_code}" > /dev/null 2>&1 || true
curl -sS --max-time 5 "https://${g_domain}/" -o /dev/null -w "%{http_code}" > /dev/null 2>&1 || true

echo "## Restart to trigger flush..."
ssh "$g_host" "sudo systemctl restart tlsrouter"
sleep 3

echo "## Checking connections.tsv..."
b_content=$(ssh "$g_host" "cat ${g_tsv_path} 2>/dev/null || echo 'MISSING'")

if echo "$b_content" | grep -q "MISSING"; then
	echo "FAIL  connections.tsv not found"
	g_fail=$((g_fail + 1))
else
	echo "OK  connections.tsv exists"
	g_pass=$((g_pass + 1))
fi

if echo "$b_content" | grep -q "domain"; then
	echo "OK  has header row"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  missing header row"
	g_fail=$((g_fail + 1))
fi

if echo "$b_content" | grep -q "$g_domain"; then
	echo "OK  contains tracked domain: $g_domain"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  domain $g_domain not found in tracker"
	g_fail=$((g_fail + 1))
fi

echo ""
echo "Results: $g_pass passed, $g_fail failed"

if test "$g_fail" -gt 0; then
	exit 1
fi
