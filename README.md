# tlsrouter

A TLS Reverse Proxy for SNI and ALPN routing.

Supports both static and dynamic TLS routing.

```sh
tlsrouter \
   --config ~/.config/tlsrouter/backends.csv \
   --vault ~/.config/tlsrouter/secrets.tsv \
   --ip-domains vm.example.com \
   --networks 192.168.1.0/24 \
   --bind 0.0.0.0 \
   --port 443
```

Configured backends are loaded statically, while URLs like <https://tls-192-168-1-100.vm.example.com> are dynamically proxied -
provided that the ip domain and ip-as-subdomain addresses match the allowed domain and networks.

If `--ip-domains` is set, the `--config` file is optional — tlsrouter can run in
dynamic-only mode with no `backends.csv`. Each `--ip-domains` base domain is
also resolved via DNS at startup (and on reload) and the resulting IPs are
added to the set of allowed target IPs (`.local` suffix domains are skipped).

- `--config` — Path to backends config CSV file (default: `~/.config/tlsrouter/backends.csv`)
- `--vault` — Path to vault TSV file (default: `~/.config/tlsrouter/secrets.tsv`)
- `--ip-domains` — Comma-separated base domains for dynamic IP URLs (default: `example.localdomain`)
- `--networks` — Allowed networks for dynamic IP proxying (default: `169.254.0.0/16`)
- `--bind` — Address to bind to (default: `0.0.0.0`)
- `--port` — TLS port to listen on; `-1` to disable (default: `443`)
- `--plain-port` — Plain HTTP port for redirects; `-1` to disable (default: `80`)
- `--ip-whitelist` — TSV/CSV file or HTTP(S) URL of IPs, CIDRs, or domains that bypass IP blocking (default: `~/.config/tlsrouter/allowed.csv`)
- `--ip-blacklist-extra` — TSV/CSV file or HTTP(S) URL of extra IPs, CIDRs, or domains to block (default: empty)
- `--ip-blacklist-repo` — git repo URL for the base IP blacklist, or `none` to disable (default: `https://github.com/bitwire-it/ipblocklist.git`)
- `--ip-blacklist-dir` — local directory for the base git blacklist checkout (default: `~/.local/share/bitwire-it/ipblocklist`)
- `--verbose` — Enable debug trace output (default: `false`)
- `--version` — Print version and exit

IP policy sources use the first column of each TSV/CSV row. For example:

```tsv
# host\tcomment
127.0.0.1\t# ip
example.com\t# domain
https://infra.example.com/list.tsv\t# nested source
```

Blank lines and lines starting with `#` are ignored; later columns are ignored
metadata. An optional header row with `network` or `source` as the first
column is recognized and skipped (case-insensitive).
Nested HTTP(S) sources use the same format and are supported up to
two levels. URL userinfo supplies Basic Auth. Whitelist entries take
precedence over blacklist entries.

If a whitelist cannot be read, fetched, parsed, or loaded from its cache, all
blacklists are disabled. This fail-open behavior avoids catastrophic lockout
during transient errors in this critical service. URL-list cache data is stored
under `$XDG_CACHE_HOME/tlsrouter/iplist/` or `~/.cache/tlsrouter/iplist/`.
The git blacklist checkout uses the separate `--ip-blacklist-dir` directory.

## Environment Variables

All runtime flags can be set via environment variables (flags take precedence).
`--version` is not env-settable (it is not a runtime option).

| Flag | Env Var | Default |
| :--- | :------ | :------ |
| `--port` | `PORT` | `443` (`-1` to disable) |
| `--plain-port` | `PLAIN_PORT` | `80` (`-1` to disable) |
| `--bind` | `BIND` | `0.0.0.0` |
| `--config` | `CONFIG_FILE` | `~/.config/tlsrouter/backends.csv` |
| `--vault` | `VAULT_FILE` | `~/.config/tlsrouter/secrets.tsv` |
| `--ip-domains` | `DYNAMIC_IP_DOMAIN` | `example.localdomain` |
| `--networks` | `DYNAMIC_HOST_NETWORKS` | `169.254.0.0/16` |
| `--verbose` | `VERBOSE` | `false` |
| `--ip-whitelist` | `WHITELIST` | `~/.config/tlsrouter/allowed.csv` |
| `--ip-blacklist-extra` | `BLACKLIST_EXTRA` | _(empty)_ |
| `--ip-blacklist-repo` | `BLACKLIST_REPO` | `https://github.com/bitwire-it/ipblocklist.git` |
| `--ip-blacklist-dir` | `BLACKLIST_DIR` | `~/.local/share/bitwire-it/ipblocklist` |

A `.env` file in the working directory is loaded automatically.

## DNS Authorization

Sites are configured through DNS.

### CNAME (for subdomains)

Both `http/1.1` and `ssh` (terminated) can be enabled by setting a CNAME to the direct IP domain:

```text
# terminates https to 3080
CNAME   site-a.whatever.com  tls-192-168-1-100.vm.example.net   300

# proxies non-terminated to 443
CNAME   site-a.whatever.com  tcp-192-168-1-100.vm.example.net   300
```

If you'd like to use a CNAME for convenience for multiple records, use `cname.<ip-domain>`, such as `cname.vm.example.net`.

```text
CNAME   sites.whatever.com               cname.vm.example.net   300
```

Note: all ports in the table below are public and you should bind to localhost or use a firewall if you wish to run things on those ports privately.

### A + SRV (for apex domains)

```text
A                  whatever.com                              123.1.2.3  300
SRV     _http._tcp.whatever.com     10 3080 tls-10-11-1-123.a.bnna.net  300 10
SRV      _ssh._tcp.whatever.com     10   22 tls-10-11-1-123.a.bnna.net  300 10
```

Note: ports must be selected according to the table below. Arbitrary ports are not allowed for security reasons (anyone can set records on their domain to your IP address).

### SRV (to enable more protocols)

Whether using CNAME or A records, SRV records will enable additional proxying.

```text
SRV             _h2._tcp.whatever.com   10  443 tcp-10-11-1-123.a.bnna.net  300 10
SRV     _postgresql._tcp.whatever.com   10 3080 tls-10-11-1-123.a.bnna.net  300 10
```

ALPN names can be translated to service names in one of two ways:

1. replace all `.` (periods) with `-`, and replace `/` with `_`
2. drop anything after `/` and replace all `.` (periods) with `-`

For example: `http` and `http_1-1` are both valid for `http/1.1`

Note: ports must be selected according to the table below. Arbitrary ports are not allowed for security reasons (anyone can set records on their domain to your IP address).

## Dynamic IP URL Mapping

There are two URL patterns:

- `<layer4>-<ipv4-octets>-<ip-domain>` — template
- `tls-192-168-1-100.example.com` — Handles / Terminates TLS
- `tcp-192-168-1-100.example.com` — Raw TCP Passthrough / Non-Terminating

ALL TRAFFIC uses port 443 externally.

If the _Raw TCP URL_ is used, then the _Raw Port_ will be used - proxied traffic will remain encrypted.

If the _Terminating URL_ is used, then the _Decrypted Port_ will be used.

**Why non-standard ports?** So that unencrypted services, which may have been intended for private networking,
aren't exposed to the Internet by default.

**Port notation:** The Decrypted Port is `10000 + <normal plain port>` in most
cases. The `*N*` markers show the prefix from 10000 concatenated with the
plain port.

| ALPN        |    Raw Port | Decrypted Port | Comment                                                      |
| :---------- | ----------: | -------------: | :----------------------------------------------------------- |
| http/1.1    |         443 |           3080 | 3080 to be familiar, but non-default like 3000, 8080, and 80 |
| ssh         |     443*22* |             22 | sshd can't handle sclient tls directly, hence 44322 for tls  |
| ---         |         --- |            --- | _special protocols_                                          |
| acme-tls/1  |         443 |              - | for ACME / Let's Encrypt TLS SNI ALPN challenges             |
| h2          |         443 |              - | proper HTTP/2 requires raw passthrough and has no plain port |
| h2c         |           - |           3080 | plain HTTP/2, for testing/debugging                          |
| ---         |         --- |            --- | _10,000 is added to the default ports below_                 |
| coap        |        5684 |        *1*5683 | IoT, plain port is 5683                                      |
| dicom       |        2762 |        *10*104 | biomedical imaging, plain port is 104                        |
| dot         |         853 |        *100*53 | dns-over-tls, normal plain port is 53 (udp and tcp)          |
| ftp         |         990 |        *100*21 | normal plain port is 21, but it's more complicated than that |
| imap        |         993 |        *10*143 | normal plain port is 143                                     |
| irc         |        6697 |        *1*6667 | normal plain port is 6667                                    |
| managesieve |        4190 |        *1*4190 | for mail filtering, plain is also 4190                       |
| mqtt        |        8883 |        *1*1883 | normal plain port is 1883                                    |
| mysql       |        3306 |        *1*3306 | MySQL, direct TLS                                            |
| nntp        |         563 |        *10*119 | for News Servers, plain port is 119                          |
| ntske/1     |        4460 |        *10*123 | for NTP, normal plain port is 123                            |
| pop3        |         995 |        *10*110 | normal plain port is 110                                     |
| postgresql  |        5432 |        *1*5432 | Postgres 17+ supports direct TLS                             |
| tds/8.0     |        1433 |        *1*1433 | MS SQL 2025+ supports direct TLS                             |
| radius/1.0  |        2083 |        *1*2083 | legacy TLS optional                                          |
| radius/1.1  |        2083 |        *1*2083 | direct TLS required                                          |
| sip         |        5061 |        *1*5060 | normal plain port is 5060 (or 5080)                          |
| smb         |     *10*445 |        *10*445 | Either use requires tunneling (native SMB TLS requires QUIC) |
| webrtc      |         443 |        *100*80 | 10080 to be familiar, but not 18080, 8080, 8081, or 9000     |
| c-webrtc    |         443 |        *100*80 | "                                                            |
| xmpp-client |        5223 |        *1*5222 | client-to-server communication, default 5222 (plain)         |
| xmpp-server |        5270 |        *1*5269 | server-to-server communication, default 5269 (plain)         |

For all registered ALPNs, see <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml>.

Excluded:
- `co` is UDP-only
- `doq` DNS over QUIC is UDP-only
- `http/0.9`, `http/1.0` superseded by `http/1.1`
- `h3` HTTP over QUIC is UDP-only
- `nnsp` has no port designation (and isn't actually referenced in the RFC)
- `spdy/*` superseded by `h2`
- `stun.turn` has more complex implications that I'm ready to consider
- `stun.nat-discovery` (same)
- `sunrpc` probably not relevant

## Static Config (`backends.csv`)

The config file is a CSV with the following header row (order does not matter;
columns are matched by name):

```csv
app_slug,domain,alpn,backend_address,backend_port,terminate_tls,connect_tls,rewrite_host,skip_tls_verify,auth,allowed_client_hostnames
```

Example:

```csv
_admin,vms.example.com,admin,vault://5d7d83f3...,,,,,,,
myapp,site.example.com,ssh,127.0.0.1,22,false,false,false,,,
myapp,site.example.com,http/1.1,172.16.0.1,443,true,true,true,,vault://a1b2c3...,
```

| Field | Description |
| ----- | ----------- |
| `app_slug` | Application group; `_admin` with `alpn=admin` enables the admin API |
| `domain` | SNI domain to match (wildcards via `*.example.com`) |
| `alpn` | ALPN to match (e.g. `http/1.1`, `ssh`, `h2`); omitted defaults to `http/1.1` |
| `backend_address` | Backend host or IP |
| `backend_port` | Backend port |
| `terminate_tls` | `true` → tlsrouter terminates TLS and decrypts traffic |
| `connect_tls` | `true` → re-encrypts to backend (upstream TLS) |
| `rewrite_host` | Host header value to set when proxying HTTP |
| `skip_tls_verify` | `true` → skip backend TLS certificate verification |
| `auth` | Vault entry reference (`vault://<id>`); fails closed if missing |
| `allowed_client_hostnames` | Comma-separated client hostnames allowed to connect |

Multiple rows per domain enable different ALPNs (e.g. `ssh` and `http/1.1`).

## Vault & Password Hashing

The `--vault` file (`secrets.tsv`) stores auth secrets referenced by `vault://<id>`
in the config. Use the `tabvault` CLI to manage it:

```sh
# Create the vault file first
touch ~/.config/tlsrouter/secrets.tsv

# Generate a new random secret and store it
tabvault ~/.config/tlsrouter/secrets.tsv add

# Append a token to an existing vault entry
tabvault ~/.config/tlsrouter/secrets.tsv append <vault-id>

# Verify a password against a vault entry
tabvault ~/.config/tlsrouter/secrets.tsv verify <vault-id>
```

For HTTP Basic Auth backends, generate a PBKDF2 password hash with the
`hash-password` subcommand:

```sh
# Interactive (prompts twice for confirmation)
tlsrouter hash-password

# Non-interactive (from stdin)
echo -n 'my-password' | tlsrouter hash-password
```

This outputs a `$pbkdf2-sha256$10000$<salt>$<key>` hash suitable for the vault.

## HTTP API

tlsrouter exposes HTTP endpoints on the admin domain(s) configured via
`_admin` in `backends.csv`:

### Public endpoints

| Method & Path | Description |
| ------------- | ----------- |
| `GET /version` | Version info (also at `/api/version`, `/api/public/version`) |
| `GET /status` | Uptime and config hash (also at `/api/status`, `/api/public/status`) |

### Admin API

| Method & Path | Description |
| ------------- | ----------- |
| `GET /api/config/current` | Current running config |
| `GET /api/config/new` | Pending/staged config |
| `PUT /api/config/new/{HashOrRev}` | Activate a staged config |
| `GET /api/services` | List configured services |
| `POST /api/services` | Create or update a service |
| `GET /api/connections` | List active connections |
| `DELETE /api/remotes/{RemoteAddr}` | Close connections from a remote |
| `DELETE /api/clients/{Service}` | Close connections to a service |

## Signals

| Signal | Behavior |
| ------ | -------- |
| `SIGUSR1` | Reload `backends.csv` and the vault without restart; starts a new listener with a fresh DNS cache and gracefully shuts down the old |
| `SIGINT` | Graceful shutdown (5s grace period), then exit |
| `SIGTERM` | Graceful shutdown (5s grace period), then exit |
