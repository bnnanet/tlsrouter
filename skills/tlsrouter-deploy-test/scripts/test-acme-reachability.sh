#!/bin/sh
set -e

# Test ACME reachability check on a deployed tlsrouter host.
# Usage: ./scripts/test-acme-reachability.sh <host> <domain> <reachable-ip> <unreachable-ip>
#
# Tests that reachable backends get ACME certs and unreachable ones are
# blocked before ACME attempt. IPs must be within the configured --networks.

if test -z "$4"; then
	echo "Usage: $0 <host> <domain> <reachable-ip> <unreachable-ip>" >&2
	echo "  host:           SSH target" >&2
	echo "  domain:         base domain (e.g. proxy.example.com)" >&2
	echo "  reachable-ip:   IP with a running backend (in allowed network)" >&2
	echo "  unreachable-ip: IP with no backend (in allowed network)" >&2
	exit 1
fi

g_host="$1"
g_domain="$2"
g_reachable="$3"
g_unreachable="$4"

g_reachable_dashed=$(echo "$g_reachable" | tr '.' '-')
g_unreachable_dashed=$(echo "$g_unreachable" | tr '.' '-')
g_pass=0
g_fail=0

echo "# ACME reachability test"
echo "# Host: $g_host"
echo "# Domain: $g_domain"
echo "# Reachable: $g_reachable (tls-${g_reachable_dashed}.${g_domain})"
echo "# Unreachable: $g_unreachable (tls-${g_unreachable_dashed}.${g_domain})"
echo ""

echo "## Reachable backend (expect 200)..."
b_code=$(curl -sS --connect-timeout 15 -o /dev/null -w "%{http_code}" "https://tls-${g_reachable_dashed}.${g_domain}/" 2> /dev/null || echo "000")
if test "$b_code" = "200"; then
	echo "OK  tls-${g_reachable_dashed}: $b_code"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  tls-${g_reachable_dashed}: got $b_code, expected 200"
	g_fail=$((g_fail + 1))
fi

echo ""
echo "## Unreachable backend in allowed network (expect SSL error)..."
b_code=$(curl -sS --connect-timeout 10 -o /dev/null -w "%{http_code}" "https://tls-${g_unreachable_dashed}.${g_domain}/" 2> /dev/null || echo "000")
if test "$b_code" = "000"; then
	echo "OK  tls-${g_unreachable_dashed}: connection failed (expected)"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  tls-${g_unreachable_dashed}: got $b_code, expected connection failure"
	g_fail=$((g_fail + 1))
fi

b_log=$(ssh "$g_host" "sudo journalctl -u tlsrouter --since '30 sec ago' --no-pager 2>/dev/null | grep 'unreachable' | head -1")
if echo "$b_log" | grep -q "unreachable"; then
	echo "OK  log confirms: backend unreachable, skipping ACME"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  no 'unreachable' log found"
	g_fail=$((g_fail + 1))
fi

echo ""
echo "## IP outside allowed networks (expect SSL error)..."
b_code=$(curl -sS --connect-timeout 10 -o /dev/null -w "%{http_code}" "https://tls-10-249-249-249.${g_domain}/" 2> /dev/null || echo "000")
if test "$b_code" = "000"; then
	echo "OK  tls-10-249-249-249: connection failed (expected)"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  tls-10-249-249-249: got $b_code, expected connection failure"
	g_fail=$((g_fail + 1))
fi

b_log=$(ssh "$g_host" "sudo journalctl -u tlsrouter --since '30 sec ago' --no-pager 2>/dev/null | grep 'not in any allowed' | head -1")
if echo "$b_log" | grep -q "not in any allowed"; then
	echo "OK  log confirms: target IP not in any allowed network"
	g_pass=$((g_pass + 1))
else
	echo "FAIL  no 'not in any allowed' log found"
	g_fail=$((g_fail + 1))
fi

echo ""
echo "Results: $g_pass passed, $g_fail failed"

if test "$g_fail" -gt 0; then
	exit 1
fi
