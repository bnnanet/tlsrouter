#!/bin/sh
set -e

# Test IP filtering on a deployed tlsrouter host.
# Usage: ./scripts/test-ip-filtering.sh <host> <domain> <test-ip>
#
# Requires: the test-ip to be your current public IP (or an IP you can
# connect from). Creates a local git blocklist repo, reconfigures the
# service to use it, verifies rejection, then restores production config.

if test -z "$3"; then
	echo "Usage: $0 <host> <domain> <test-ip>" >&2
	echo "  host:    SSH target (e.g. deploy.example.com)" >&2
	echo "  domain:  TLS domain to test against" >&2
	echo "  test-ip: IP to add to blocklist (your public IP)" >&2
	exit 1
fi

g_host="$1"
g_domain="$2"
g_test_ip="$3"

echo "# IP filtering test"
echo "# Host: $g_host"
echo "# Domain: $g_domain"
echo "# Test IP: $g_test_ip"
echo ""

echo "## Creating test blocklist repo on $g_host..."
ssh "$g_host" "rm -rf /tmp/test-blocklist /tmp/test-blocklist-clone && \
  mkdir -p /tmp/test-blocklist/tables/inbound && \
  cd /tmp/test-blocklist && git init && \
  git config user.email 'test@test.com' && git config user.name 'test' && \
  echo '$g_test_ip' > tables/inbound/single_ips.txt && \
  touch tables/inbound/networks.txt && \
  git add -A && git commit -m 'test blocklist'" > /dev/null 2>&1
echo "OK  blocklist repo created with $g_test_ip"

echo ""
echo "## Reconfiguring service to use test blocklist..."
echo "   (save current ExecStart first)"
g_old_exec=$(ssh "$g_host" "grep '^ExecStart=' /etc/systemd/system/tlsrouter.service")
echo "   saved: ${g_old_exec}"

ssh "$g_host" "~/.local/bin/serviceman add --daemon --name tlsrouter -- \
  ~/bin/tlsrouter \
  --ip-domains $g_domain \
  --networks 10.0.0.0/8 \
  --config ~/.config/tlsrouter/backends.csv \
  --vault ~/.config/tlsrouter/secrets.tsv \
  --bind 0.0.0.0 \
  --ip-whitelist /tmp/test-ip-whitelist.csv \
  --ip-blacklist-dir /tmp/test-blocklist-clone \
  --ip-blacklist-repo file:///tmp/test-blocklist" > /dev/null 2>&1

echo "   waiting for blocklist to load..."
sleep 4

echo ""
echo "## Testing blocklist rejection..."
b_code=$(curl -sS --connect-timeout 5 -o /dev/null -w "%{http_code}" "https://${g_domain}/version" 2> /dev/null || echo "000")
if test "$b_code" = "000"; then
	echo "OK  connection rejected (code: $b_code)"
else
	echo "FAIL  expected rejection, got HTTP $b_code"
fi

b_log=$(ssh "$g_host" "sudo journalctl -u tlsrouter --since '30 sec ago' --no-pager 2>/dev/null | grep 'rejected' | head -1")
if echo "$b_log" | grep -q "rejected"; then
	echo "OK  log confirms: $b_log"
else
	echo "WARN  no rejection log found"
fi

echo ""
echo "## Cleanup: restoring production config..."
ssh "$g_host" "rm -rf /tmp/test-blocklist /tmp/test-blocklist-clone /tmp/test-ip-whitelist.csv"

echo ""
echo "MUST: Restore production config with serviceman now."
echo "The previous ExecStart was:"
echo "  $g_old_exec"
