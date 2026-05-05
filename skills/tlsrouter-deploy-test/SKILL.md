---
name: tlsrouter-deploy-test
description: Deploy and test tlsrouter on a systemd target. Use when deploying a new build, testing IP filtering, or verifying service health. Covers cross-compile, scp deploy, systemd service update, and IP blacklist/whitelist verification.
---

# Deploy and Test tlsrouter

## Prerequisites

- SSH access to target host
- Target runs systemd with `tlsrouter.service`
- Binary deployed to `~/bin/tlsrouter` (as service user)
- Check `memory/reference_deploy_targets.md` for host-specific service manager (systemd vs OpenRC)

## 1. Build and deploy

```sh
./skills/tlsrouter-deploy-test/scripts/build-and-deploy.sh TARGET_HOST
```

VERIFY: script prints remote version matching current commit

## 2. Update systemd service (if flags changed)

MUST: Use `serviceman` to update the service file — never raw sed on ExecStart.

Ask user for the full flag set, then run on the target:

```sh
ssh TARGET_HOST "~/.local/bin/serviceman add --daemon --name tlsrouter -- ~/bin/tlsrouter [FLAGS]"
```

serviceman handles daemon-reload, enable, and restart automatically.

NEVER: Edit the service file with sed — broken quoting or stray comments will break the service.

## 3. Test service health

```sh
./skills/tlsrouter-deploy-test/scripts/test-health.sh TARGET_DOMAIN
```

VERIFY: script prints `OK` for HTTPS reachable and HTTP redirect

## 4. Test IP filtering

```sh
./skills/tlsrouter-deploy-test/scripts/test-ip-filtering.sh TARGET_HOST TARGET_DOMAIN TEST_IP
```

Where TEST_IP is the IP to blocklist (typically your current public IP).

MUST: After the script finishes, restore production config with serviceman.
The script prints the previous ExecStart for reference.

### Fatal on missing whitelist (manual)

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

### Whitelisted IP bypasses blacklist (manual)

With the test blocklist still active, add a DNS hostname or IP to the whitelist
that resolves to the blocked test IP. Restart and connect again.

VERIFY: connection succeeds (200 response), no rejection in logs

## 5. Test ACME reachability check

```sh
./skills/tlsrouter-deploy-test/scripts/test-acme-reachability.sh TARGET_HOST TARGET_DOMAIN REACHABLE_IP UNREACHABLE_IP
```

Where:
- REACHABLE_IP: an IP within `--networks` with a running backend (e.g. 10.0.2.21)
- UNREACHABLE_IP: an IP within `--networks` with no backend (e.g. 10.0.2.249)

The script also tests an IP outside allowed networks (10.249.249.249).

VERIFY: script prints all `OK` — reachable gets 200, unreachable logs show
`backend unreachable ... skipping ACME`, outside-network logs show
`target IP not in any allowed network`

## 6. Test passthrough (no TLS termination)

```sh
./skills/tlsrouter-deploy-test/scripts/test-passthrough.sh PASSTHROUGH_DOMAIN [RESOLVE_HOST]
```

Where:
- PASSTHROUGH_DOMAIN: a domain configured with `terminate_tls=false` (e.g. pbs1.m.bnna.net)
- RESOLVE_HOST: optional, force DNS resolution to this host (e.g. tls2.slc1.bnna.net)

VERIFY: script prints `OK` for both plain and explicit ALPN connections (200 response, no TLS alert error)

## 7. Test connection tracker

```sh
./skills/tlsrouter-deploy-test/scripts/test-conntracker.sh TARGET_HOST TARGET_DOMAIN
```

VERIFY: script prints all `OK` — connections.tsv exists, has header, contains tracked domain

## Notes

- Port 8443 or other non-standard ports may be firewalled. Test on the production port (443) with controlled blocklist data.
- The blocklist loads asynchronously (~2-15s depending on data size). Wait for `level=INFO msg="prefix set loaded" ipgate.entries=N` in logs before testing.
- Git-managed blocklist directories get overwritten on fetch. Use a local `file://` repo for controlled testing.
- NEVER: Leave test blocklist config in production. Always restore and verify.
