# AGENTS.md — tlsrouter

TLS reverse proxy for SNI and ALPN routing with static and dynamic backends.

## Build & Deploy

- MUST: Build from `./cmd/tlsrouter/`, not root (root is `package tlsrouter` library)
- MUST: Use `CGO_ENABLED=0` for cross-compilation

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v2 ./bin/build.sh ./agents/tmp/tlsrouter
```

`bin/build.sh` injects version info via ldflags (`-X main.version`, `-X main.commit`, `-X main.date`).
Uses commit date when worktree is clean, current time when dirty. Verify with:

```sh
./agents/tmp/tlsrouter --version
```

Deploy to a host:

```sh
ssh vms.example.com "sudo systemctl stop tlsrouter"
scp ./agents/tmp/tlsrouter vms.example.com:~/bin/tlsrouter
ssh vms.example.com "sudo systemctl start tlsrouter"
```

- MUST: Stop the service before scp — binary is running, overwrite fails otherwise
- Verify: `ssh vms.example.com "sudo systemctl is-active tlsrouter"` → `active`

Install with serviceman (first time):

```sh
serviceman add --name tlsrouter -- ~/bin/tlsrouter daemon
```

## Directory Layout

| Path | Purpose |
| ---- | ------- |
| `cmd/tlsrouter/` | Main entry point |
| `cmd/tabvault/` | Vault CLI (hash-password, etc.) |
| `cmd/alpn-get/` | IANA ALPN registry fetcher |
| `ianaalpn/` | Embedded ALPN registry data |
| `tlsrouter.go` | Core proxy logic, PlainConn, wrappedConn |
| `api.go` | Admin API handlers, connection reporting |
| `configfile.go` | CSV config parser |
| `dynamic-config.go` | CNAME/SRV-based dynamic routing |

Server paths:

| Path | Purpose |
| ---- | ------- |
| `~/.config/tlsrouter/backends.csv` | Static backend config |
| `~/.config/tlsrouter/secrets.tsv` | Vault secrets (auth tokens) |
| `~/bin/tlsrouter` | Binary |

## Static Config (backends.csv)

Headers: `app_slug,domain,alpn,backend_address,backend_port,terminate_tls,connect_tls,skip_tls_verify,auth,allowed_client_hostnames`

```csv
_admin,vms.example.com,admin,vault://5d7d83f3...,,,,,
myapp,site.example.com,ssh,127.0.0.1,22,false,false,false,
myapp,site.example.com,http/1.1,172.16.0.1,443,true,true,true,vault://a1b2c3...,
```

- `_admin` app_slug with `alpn=admin` → admin API backend (still HTTP on the wire; `admin` is a config shim, not a real ALPN)
- `terminate_tls=true` → tlsrouter terminates TLS
- `connect_tls=true` → re-encrypts to backend
- `auth` → vault entry reference, MUST fail closed if missing
- Multiple rows per domain for different ALPNs (ssh, http/1.1)

## Dynamic DNS Config

IP domain pattern: `<layer4>-<ipv4-octets>.<ip-domain>`

| Layer4 | Behavior |
| ------ | -------- |
| `tls` | TLS terminated, decrypted traffic to backend |
| `tcp` | Raw TCP passthrough, traffic stays encrypted |

### CNAME routing

```text
# TLS terminated (decrypted to backend port 3080)
CNAME   site.example.com   tls-10-11-2-21.vms.example.com   300

# OR raw TCP passthrough (stays encrypted, backend port 443)
CNAME   site.example.com   tcp-10-11-2-21.vms.example.com   300
```

Only one CNAME can be active per domain — choose `tls-` or `tcp-`, not both.

### SRV routing (for apex domains or additional protocols)

```text
A                  example.com                              123.1.2.3  300
SRV     _http._tcp.example.com   10 3080 tls-10-11-2-21.vms.example.com  300
SRV      _ssh._tcp.example.com   10   22 tls-10-11-2-21.vms.example.com  300
```

CLI flags: `--ip-domains` (which domains are IP-pattern domains), `--networks` (allowed CIDRs)

## Key Architecture

### HTTPTunnel

- `backend.HTTPTunnel.Inject(wconn.PlainConn)` — feeds connection to http.Server
- MUST inject PlainConn (not raw `*tls.Conn`) to preserve byte counters
- See PlainConn comments in `tlsrouter.go` for h2/connectionStater constraints

## Updating ALPN Registry Data

```sh
go run ./cmd/alpn-get/ > ./agents/tmp/alpn-new.json 2>./agents/tmp/alpn-warnings.txt
cp ./agents/tmp/alpn-new.json ./ianaalpn/alpn.json
```

Check warnings in `./agents/tmp/alpn-warnings.txt` for byte/name mismatches.
Direct human to report registry errors via https://www.iana.org/form/complaint.

## Testing

```sh
# h2 (admin path)
curl --http2 https://vms.example.com/version

# h1.1
curl --http1.1 https://app.example.com/

# Auth-gated (expect 401)
curl https://app.example.com/

# Logs
ssh vms.example.com "sudo journalctl -u tlsrouter --no-pager -n 20"
```

## Port Table (key entries)

| ALPN | Raw Port | Decrypted Port |
| ---- | -------: | -------------: |
| http/1.1 | 443 | 3080 |
| ssh | 44322 | 22 |
| h2 | 443 | - |
| postgresql | 5432 | 15432 |
| tds/8.0 | 1433 | 11433 |
| mysql | 3306 | 13306 |
