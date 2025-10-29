# tlsrouter

A TLS Reverse Proxy for SNI and ALPN routing.

Supports both static and dynamic TLS routing.

```sh
go run ./cmd/tlsrouter/ \
   --config ~/.config/tlsrouter/backends.csv \
   --vault ~/.config/tlsrouter/secrets.tsv \
   --ip-domains vm.example.com \
   --networks 192.168.1.0/24 \
   --bind 0.0.0.0 \
   --port 443
```

Configured backends are loaded statically, while URLs like <https://tls-192-168-1-100.vm.example.com> are dynamically proxied -
provided that the ip domain and ip-as-subdomain addresses match the allowed domain and networks.

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

The URL pattern is There are two URL patterns:
- `<layer4>-<ipv4-octets>-<ip-domain>`
- tls-192-168-1-100.example.com (Handles / Terminates TLS)
- tcp-192-168-1-100.example.com (Raw TCP Passthrough / Non-Terminating)

ALL TRAFFIC uses port 443 externally.

If the _Raw TCP URL_ is used, then the _Raw Port_ will be used - proxied traffic will remain encrypted.

If the _Terminating URL_ is used, then the _Decrypted Port_ will be used.

**Why non-standard ports?** So that unencrypted services, which may have been intended for private networking,
aren't exposed to the Internet by default.


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
