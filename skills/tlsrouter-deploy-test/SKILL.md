---
name: tlsrouter-deploy-test
description: Deploy and test tlsrouter on a systemd target. Use when deploying a new build, testing IP filtering, or verifying service health. Covers cross-compile, scp deploy, systemd service update, and IP blacklist/whitelist verification.
---

# Deploy and Test tlsrouter

## Prerequisites

- SSH access to target host
- Target runs systemd with `tlsrouter.service`
- Service file at `/etc/systemd/system/tlsrouter.service`
- Binary deployed to `~/bin/tlsrouter` (as service user)
- Check `memory/reference_deploy_targets.md` for host-specific service manager (systemd vs OpenRC)

## 1. Build

Cross-compile for target architecture (typically linux/amd64):

```sh
LDFLAGS="-X main.version=$(git describe --tags --always) -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o ./agents/tmp/tlsrouter-linux-amd64 ./cmd/tlsrouter/
```

VERIFY: file exists and is linux binary
```sh
file ./agents/tmp/tlsrouter-linux-amd64
# expect: ELF 64-bit LSB executable, x86-64
```

## 2. Deploy binary

```sh
scp ./agents/tmp/tlsrouter-linux-amd64 TARGET_HOST:~/bin/tlsrouter.new
ssh TARGET_HOST "mv ~/bin/tlsrouter.new ~/bin/tlsrouter && chmod +x ~/bin/tlsrouter"
```

VERIFY: version matches on remote
```sh
ssh TARGET_HOST "~/bin/tlsrouter --version"
# expect: tlsrouter vX.Y.Z-N-gCOMMIT COMMIT (DATE)
```

## 3. Update systemd service (if flags changed)

MUST: Use `serviceman` to update the service file — never raw sed on ExecStart.

```sh
ssh TARGET_HOST "~/.local/bin/serviceman add --daemon --name tlsrouter -- \
  ~/bin/tlsrouter \
  --ip-domains proxy.example.com \
  --networks 10.0.0.0/24 \
  --config ~/.config/tlsrouter/backends.csv \
  --vault ~/.config/tlsrouter/secrets.tsv \
  --bind 0.0.0.0 \
  --ip-whitelist ~/.config/tlsrouter/ip-whitelist.csv \
  --ip-blacklist-dir ~/.local/share/bitwire-it/ipblocklist \
  --ip-blacklist-repo https://github.com/ORG/ipblocklist.git"
```

serviceman handles daemon-reload, enable, and restart automatically.

NEVER: Edit the service file with sed — broken quoting or stray comments will break the service.

## 4. Restart and verify

```sh
ssh TARGET_HOST "sudo systemctl restart tlsrouter"
sleep 2
ssh TARGET_HOST "sudo systemctl status tlsrouter --no-pager | head -10"
```

VERIFY: Active (running), correct PID, correct ExecStart flags

## 5. Test service health

```sh
curl -sS --connect-timeout 3 https://TARGET_DOMAIN/api/version
curl -sS --connect-timeout 3 https://TARGET_DOMAIN/api/status
```

VERIFY: version JSON matches deployed commit, status returns uptime

## 6. Test HTTP redirect

```sh
curl -sS --connect-timeout 3 -o /dev/null -w "%{http_code}" http://TARGET_DOMAIN/
# expect: 301
```

## 7. Test IP filtering

### 7a. Fatal on missing whitelist

Run binary with a non-existent whitelist path and active blacklist repo:

```sh
ssh TARGET_HOST "timeout 10 ~/bin/tlsrouter \
  --ip-whitelist /tmp/nonexistent.csv \
  --ip-blacklist-repo https://example.com/blocklist.git \
  --ip-blacklist-dir /path/to/blocklist \
  --config ~/.config/tlsrouter/backends.csv \
  --vault ~/.config/tlsrouter/secrets.tsv \
  --ip-domains proxy.example.com \
  --networks 10.0.0.0/24 \
  --port 0 --plain-port -1 2>&1; echo EXIT=\$?"
```

VERIFY: output contains `blacklist requires a whitelist for anti-lockout` and `EXIT=1`

### 7b. Blocked IP gets rejected

Create a local git repo with a test IP in the blocklist:

```sh
ssh TARGET_HOST "rm -rf /tmp/test-blocklist /tmp/test-blocklist-clone && \
  mkdir -p /tmp/test-blocklist/tables/inbound && \
  cd /tmp/test-blocklist && git init && \
  git config user.email 'test@test.com' && git config user.name 'test' && \
  echo '203.0.113.50' > tables/inbound/single_ips.txt && \
  touch tables/inbound/networks.txt && \
  git add -A && git commit -m 'test'"
```

Update service to use test blocklist via serviceman:

```sh
ssh TARGET_HOST "~/.local/bin/serviceman add --daemon --name tlsrouter -- \
  ~/bin/tlsrouter \
  --ip-domains proxy.example.com \
  --networks 10.0.0.0/24 \
  --config ~/.config/tlsrouter/backends.csv \
  --vault ~/.config/tlsrouter/secrets.tsv \
  --bind 0.0.0.0 \
  --ip-whitelist /tmp/test-ip-whitelist.csv \
  --ip-blacklist-dir /tmp/test-blocklist-clone \
  --ip-blacklist-repo file:///tmp/test-blocklist"
sleep 4
curl -sS --connect-timeout 5 https://TARGET_DOMAIN/api/version
# expect: "Connection reset by peer" or timeout
```

VERIFY: journalctl shows `INFO: rejected 203.0.113.50 (blacklisted)`
```sh
ssh TARGET_HOST "sudo journalctl -u tlsrouter --since '30 sec ago' --no-pager | grep rejected"
```

### 7c. Whitelisted IP bypasses blacklist

With the test blocklist still active, add a DNS hostname or IP to the whitelist that resolves to the blocked test IP. Restart and connect again.

VERIFY: connection succeeds (200 response), no rejection in logs

### 7d. Cleanup

MUST: Restore production config after testing:

```sh
ssh TARGET_HOST "~/.local/bin/serviceman add --daemon --name tlsrouter -- \
  ~/bin/tlsrouter \
  --ip-domains proxy.example.com \
  --networks 10.0.0.0/24 \
  --config ~/.config/tlsrouter/backends.csv \
  --vault ~/.config/tlsrouter/secrets.tsv \
  --bind 0.0.0.0 \
  --ip-whitelist ~/.config/tlsrouter/ip-whitelist.csv \
  --ip-blacklist-dir ~/.local/share/bitwire-it/ipblocklist \
  --ip-blacklist-repo https://github.com/ORG/ipblocklist.git"
ssh TARGET_HOST "rm -rf /tmp/test-blocklist /tmp/test-blocklist-clone /tmp/test-ip-whitelist.csv"
```

VERIFY: production service healthy
```sh
curl -sS --connect-timeout 3 https://TARGET_DOMAIN/api/version
```

## Notes

- Port 8443 or other non-standard ports may be firewalled. Test on the production port (443) with controlled blocklist data.
- The blocklist loads asynchronously (~2-15s depending on data size). Wait for `INFO: ipgate: prefix set loaded N entries` in logs before testing.
- Git-managed blocklist directories get overwritten on fetch. Use a local `file://` repo for controlled testing.
- NEVER: Leave test blocklist config in production. Always restore and verify.
