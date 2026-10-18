# SOCKS5 Proxy Server

A production-grade SOCKS5 proxy server with user management, tier-based access control, rate limiting, and real-time monitoring dashboards.

Deploys on any PaaS, including the ones that expose only a single HTTP endpoint.

## Features

- **SOCKS5 Protocol** - Full SOCKS5 proxy support with username/password authentication
- **SOCKS5 UDP** - `UDP ASSOCIATE` relay for Telegram, QUIC and DNS-over-UDP, on the SOCKS5 port and through REALITY
- **Single-Port Multiplexing** - SOCKS5, TLS, dashboards and the tunnel share one port, so it runs on Render/Koyeb/Heroku/Northflank where raw TCP never reaches the app
- **WebSocket Tunnel** - Carries SOCKS5 over an HTTP upgrade for platforms whose edge terminates TLS; ships with a matching client
- **REALITY** - Xray front door that presents a real website's certificate to an active prober; sessions still land in the SOCKS5 pipeline
- **MTProto** - Telegram's own protocol on its own port, with per-phone secrets managed in the dashboard, in plain obfuscated2 or fake TLS
- **VLESS Client Management** - Add, disable and revoke REALITY UUIDs from the dashboard; xray is reloaded in place, no restart
- **Client Mode** - Same binary exposes a local SOCKS5 port that relays through the tunnel
- **User Management** - Create, update, delete users with tier-based limits
- **Tier System** - Free, Basic, Pro, and Unlimited tiers with connection/data/bandwidth limits
- **Rate Limiting** - Token-bucket rate limiting with configurable RPS
- **Hashed Passwords** - PBKDF2-HMAC-SHA256 in the database; a stolen file is not a list of credentials
- **Message Padding** - Optional uniform-size framing so a 2-byte SOCKS5 reply is indistinguishable from bulk traffic
- **Security Headers** - CSP, XSS protection, frame options, and more
- **Admin Dashboard** - Full management UI with charts and user CRUD
- **Metrics Dashboard** - Real-time monitoring with Chart.js visualizations
- **Prometheus Metrics** - `/prometheus` endpoint for monitoring integration
- **HTTP Proxy** - `CONNECT` and absolute-form forwarding on the same port
- **SQLite Persistence** - Configuration and user data survive restarts
- **Docker Ready** - Multi-stage Dockerfile with non-root user

## Quick Start

### Binary

```bash
go build -o socks5-proxy .
./socks5-proxy config.json
```

### Build the image yourself

```bash
docker build -t socks5-proxy .
# Three ports, as on a VPS with raw TCP
docker run -p 1080:1080 -p 8080:8080 -p 9090:9090 socks5-proxy
# One port, as on a PaaS
docker run -e PORT=8080 -p 8080:8080 socks5-proxy
# A REALITY front door on 443, as on a VPS with a dedicated IP (see below)
docker run --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  -p 443:443 -p 1080:1080 -p 8080:8080 -p 9090:9090 \
  -e REALITY_ENABLED=true -e REALITY_PUBLIC_HOST=proxy.example.com socks5-proxy
```

`PORT` is deliberately not baked into the image, so the image works in both
layouts. Supplying it switches on single-port mode.

### Setting your own variables

Nothing secret is baked into the image — no password, no token, no key. Your
values are supplied at run time, on the machine that runs it, so the same build
works for every operator.

```bash
# 1. write your secrets on the server (this file is gitignored)
cp .env.example .env
chmod 600 .env
$EDITOR .env        # PROXY_USER, PROXY_PASS, ADMIN_USER, ADMIN_PASS,
                    # TUNNEL_TOKEN, or REALITY_* if you enable REALITY

# 2. run it, reading that file
docker run --env-file .env \
  -p 1080:1080 -p 8080:8080 -p 9090:9090 \
  socks5-proxy
```

Three equivalent ways to pass variables, in increasing order of precedence over
the image's own `config.json`:

| Method | Example | Notes |
|---|---|---|
| Edit `config.json` in a volume | `-v /srv/socks5/config.json:/app/config.json:ro` | For values you never rotate |
| `--env-file` | `docker run --env-file .env …` | Secrets stay in one file on the server, `chmod 600` |
| `-e` per variable | `docker run -e PROXY_PASS=… -e PORT=8080 …` | Convenient for one-off or PaaS-injected values like `PORT` |

`.env` is excluded from the build context, so it cannot end up inside the image
even if you leave it in the source tree.

The binary does not read `.env` itself — that is docker's and compose's job, and
the container only sees what they pass in.

With compose, `env_file: .env` in `docker-compose.yml` already does this, and
PaaS platforms that inject `PORT` work with no configuration at all.

You can also pin the REALITY keypair without installing xray on the host, since
the binary is inside the image:

```bash
docker run --rm --entrypoint xray socks5-proxy x25519
# PrivateKey: ...            -> REALITY_PRIVATE_KEY
# Password (PublicKey): ...  -> what clients configure as "public key"
```

**How precedence actually resolves**, last one winning:

```
built-in defaults  <  config.json  <  database <  environment
```

The database holds only the 10 settings the dashboard can save: `max_connections`,
`proxy_user`, `proxy_pass`, `auth_enabled`, `admin_username`, `admin_pass`,
`admin_auth_enabled`, `security_headers_enabled`, `rate_limit_enabled` and
`rate_limit_rps`. The environment sits above it, so an explicit `.env` value is
never quietly overwritten by something saved from the browser three weeks ago —
that used to happen, and it made editing `.env` look broken.

To hand a setting back to the database instead, unset it from `.env` and change
it in the dashboard. To clear stored settings entirely, stop the container first
and remove all three files, since SQLite runs in WAL mode:

```bash
docker compose down
rm -f data/socks5.db data/socks5.db-wal data/socks5.db-shm
```

That also drops users and usage history, so copy `data/socks5.db` out first if you
want them. `TUNNEL_*`, `REALITY_*`, timeouts and limits are never stored, so they
always come from your file or environment.

### Docker Compose

```bash
cp .env.example .env      # then edit the passwords
docker compose up -d
```

SQLite is kept on a named volume, so it survives rebuilds.

## Protocols

The server speaks four protocols. In single-port mode all of them share one
port, dispatched on the first byte or request shape. A fifth, REALITY, arrives
separately on port 443 via xray.

| Protocol | Endpoint | Used by |
|---|---|---|
| **SOCKS5** | `:1080` | Native SOCKS5 clients, on hosts that permit raw TCP |
| **SOCKS5 UDP** | `:1080` | `UDP ASSOCIATE` for Telegram, QUIC and UDP DNS |
| **SOCKS5 over WebSocket** | `/api/v1/tunnel` | SOCKS5 clients where raw TCP is blocked, via the bundled client |
| **HTTP proxy** — `CONNECT` and absolute-form | single port | Browsers and any HTTP client with proxy support |
| **HTTPS** | single port | TLS-wrapped access to any of the above |
| **VLESS + REALITY** | `:443` via xray | Clients on a VPS where the front door must look like a website |
| **MTProto** | `$MTPROTO_BIND` (default `:8443`) | Telegram, which speaks neither SOCKS5 nor HTTP |

Authentication is username/password throughout, taken from `PROXY_USER` and
`PROXY_PASS` for the proxy protocols, and `ADMIN_USER`/`ADMIN_PASS` for the
dashboards.

Cloudflare's edge answers `CONNECT` with `400 Bad Request` without forwarding it
to the origin, so HTTP proxying requires a directly reachable host. The
WebSocket tunnel is unaffected and is the intended path on Render, Koyeb, Heroku
and Northflank.

## UDP

The SOCKS5 port speaks `UDP ASSOCIATE`, so Telegram, QUIC and DNS-over-UDP work
without anything special on the client. It needs no configuration; the relay
picks an ephemeral port, tells the client about it, and opens one socket per
destination as datagrams need it. The TCP control connection is the lifetime of
the association: close it and the relay tears down.

UDP flows through REALITY too, so the generated `reality-client.json` offers it.

```bash
# a DNS query over UDP, through the proxy on 127.0.0.1:1080
dig @8.8.8.8 example.com +tcp=no +proxy
```

Two limits worth knowing: the WebSocket tunnel is TCP-only, so a client on the
tunnel gets TCP only. And a client that asks to be told an address of `0.0.0.0`
must send to the proxy host it is already connected to, which every mainstream
SOCKS5 client does.

## Telegram (MTProto)

Telegram does not speak SOCKS5 or HTTP, so it needs a front door of its own.
Set `MTPROTO_ENABLED=true`, leave the first secret to be generated, and paste it
into the phone: **Settings → Data and Storage → Proxy**.

Each secret is one phone. The dashboard's **Telegram** panel adds, disables and
revokes them, and a change applies immediately — a revoked phone stops working
at once, with no restart.

### Two kinds of secret

| Prefix | Transport | What a prober sees |
|---|---|---|
| `dd…` | obfuscated2 | Random-looking bytes, which is what every Telegram proxy looks like |
| `ee…` | fake TLS | A TLS handshake with a real certificate, then the same stream inside it |

Both are managed the same way, and one port serves both: the client says which
it wants in the secret's prefix. `MTPROTO_SECRET_KIND=ee` makes newly generated
secrets fake TLS; `MTPROTO_FAKE_HOST` sets the domain the reply is built around
when a client does not name one.

The fake TLS certificate is generated per domain rather than shipped as a
constant — a hardcoded certificate is a key everybody shares, and the client does
not validate the chain in this mode.

Two honest limits:

- **Without an `ee` secret the port looks like noise.** That is the same as every
  Telegram proxy. For a port that must look like a real site, use an `ee` secret
  — and know that it is fake TLS, so a censor comparing it against the real site
  it claims to be can still tell the difference.
- **Telegram's addresses are compiled in**, which is what every MTProxy does.
  If they are unreachable from your network, `MTPROTO_DCS` points them
  somewhere else.

## Why the tunnel exists

Render forwards inbound traffic to **one HTTP port** and terminates TLS at its load balancer. Koyeb, Heroku and Northflank behave the same way. A SOCKS5 client opening a raw socket against those hosts never reaches the container, and an in-process reverse proxy cannot help: the edge rejects the bytes before any process sees them.

Two deployment modes, selected by one environment variable:

| Mode | When | How |
|---|---|---|
| **Multi-port** (default) | VPS, anything with raw TCP | Leave `PORT`/`SINGLE_PORT` unset. Ports 1080/8080/9090 as before. |
| **Single-port** | Render, Koyeb, Heroku, Northflank | Set `SINGLE_PORT` (or let `PORT` be injected). One port sniffs the first byte: `0x05` SOCKS5, `0x16` TLS, `A-Z` HTTP. |

Where raw TCP is blocked entirely, enable the tunnel and run the client:

```bash
# server: refuses to start without a token, so a fork cannot become an open proxy
TUNNEL_ENABLED=true TUNNEL_TOKEN=$(openssl rand -hex 32) SINGLE_PORT=8080 ./socks5-proxy config.json

# client machine: expose a local SOCKS5 port that relays through the tunnel.
# Use 1081, not 1080, when the client runs on the same host as the server --
# the server already holds 1080 for raw SOCKS5.
./socks5-proxy client \
  -url wss://your-app.onrender.com/api/v1/tunnel \
  -token "$TUNNEL_TOKEN" \
  -listen 127.0.0.1:1081
```

Point Telegram (Android, iOS, Desktop), Signal Desktop, a browser, or any SOCKS5-capable app at `127.0.0.1:1081`. The client parses no SOCKS5 itself — the local handshake travels inside the tunnel, making it a transparent byte pipe, like `ssh -D`.

### Deploying

| Platform | Raw TCP to app | What to set |
|---|---|---|
| **Koyeb** | Yes, via TCP Proxy (`--proxy-ports 1080:tcp`, public preview) | Nothing; use raw SOCKS5 |
| **VPS** | Yes | Nothing; or `REALITY_ENABLED=true` if the front door must be unfingerprintable |
| **Render** | No (Cloudflare, HTTP only) | `TUNNEL_ENABLED=true` + `TUNNEL_TOKEN` |
| **Northflank** | No (public HTTP on 80/443) | `SINGLE_PORT` + `TUNNEL_ENABLED=true` + `TUNNEL_TOKEN` |
| **Heroku** | No | `TUNNEL_ENABLED=true` + `TUNNEL_TOKEN` |
| **Fly.io** | Yes, with `force_https=false` | Nothing, or single-port for one URL |

On Koyeb, TCP Proxy means no tunnel is needed at all:

```bash
koyeb app init socks5 --docker -i small \
  --ports 1080:tcp --proxy-ports 1080:tcp \
  --env PROXY_USER=user --env PROXY_PASS=secret
```

## REALITY (Xray)

Two front doors, for two different networks:

| | Tunnel | REALITY |
|---|---|---|
| Transport | WebSocket over HTTPS | VLESS + REALITY over raw TCP |
| Needs | Any HTTPS-reachable host | VPS, dedicated IP, DNS-only A record |
| Behind a CDN | Yes, that is the point | **No** — impossible, see below |
| Active prober sees | Whatever an unknown path answers, byte for byte | The camouflage site's real certificate |
| Use on | Render, Koyeb, Heroku, Northflank | A VPS you control |

REALITY is an Xray transport that is indistinguishable from a real website.
The server holds a private key and, for unauthenticated connections, relays the
handshake to a real site and presents *its* certificate. A prober scanning your
port sees a live website, not a proxy. An authenticated client is equally
invisible: same certificate, same handshake, same site.

Check it yourself:

```bash
openssl s_client -connect YOUR_IP:443 -servername www.lovelive-anime.jp </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer
# subject=CN=*.lovelive-anime.jp    <- a real site's certificate, not the proxy's
```

This service stays the proxy brain. Xray terminates REALITY and forwards every
session to the SOCKS5 port here, so users, tiers, rate limits, metrics and
destination statistics all behave exactly as they do on the raw port.

Xray runs as a supervised child process rather than being reimplemented, because
REALITY needs uTLS and certificate relay. That keeps the build CGO-free and the
dependency list unchanged. The Docker image ships a pinned, checksum-verified
xray; elsewhere install it or set `XRAY_BIN`.

### Deploying

Requirements, all of them: a VPS with **one dedicated IP**, TCP 443 open to the
world, and a domain whose DNS record is **grey cloud** (DNS-only, no CDN proxy).

```bash
# .env
REALITY_ENABLED=true
REALITY_PUBLIC_HOST=proxy.example.com
REALITY_DEST=www.lovelive-anime.jp:443
PROXY_PASS=...   ADMIN_PASS=...

docker compose up -d      # with the "443:443" port block uncommented
```

`docker-compose.yml` builds from source and reads `.env` for its variables, so
`docker compose up -d` is usually all that is needed.

Port 443 is privileged and the image runs as a non-root user, so the xray child
cannot bind it without help. `docker-compose.yml` already sets
`sysctls: net.ipv4.ip_unprivileged_port_start: "0"` for that reason; with a plain
`docker run`, pass the same flag:

```bash
docker run --sysctl net.ipv4.ip_unprivileged_port_start=0 \
  -p 443:443 -p 1080:1080 -p 8080:8080 -p 9090:9090 \
  -e REALITY_ENABLED=true -e REALITY_PUBLIC_HOST=proxy.example.com socks5-proxy
```

Without it xray logs `permission denied` and the proxy refuses to start.

The generated keypair, short id and client id are printed on startup and reused
from the database afterwards. A client config is written to `reality-client.json`.

```bash
# client machine: point apps at 127.0.0.1:1081
./socks5-proxy reality-client -config reality-client.json
# or -server proxy.example.com to override the address the server guessed
```

That file is an ordinary Xray client config, so Hiddify, v2rayN, Nekoray or any
other REALITY-capable client can import the same parameters instead:

| Field | Value |
|---|---|
| Address / port | Your server IP or domain, 443 |
| UUID | `client_id` from the startup log |
| Public key | `public_key` from the startup log |
| Short ID | `short_id` from the startup log |
| SNI | `server_name`, i.e. the camouflage host |
| Fingerprint | `chrome` |
| Flow | none |

Give each device its own UUID so one can be revoked without disturbing the
others. The dashboard's **REALITY Clients** panel is the usual way: add a client,
and the UUID reaches xray immediately. Revoking one takes effect within a second
and needs no restart.

Setting `REALITY_CLIENT_IDS` still works, and pins the list from configuration:
while it is set the panel says so and refuses changes rather than accepting edits
that would quietly do nothing.

`REALITY_BIND` defaults to `0.0.0.0:443`, which is IPv4 only. On an IPv6-only
host set it to `[::]:443`.

Pick the camouflage site with care: it must speak TLS 1.3 with X25519, be
reachable from the server, and resolve to a real CDN. Xray itself warns against
apple/icloud targets, and a target that is an obvious outlier can get your IP
blocked. Do not put `SINGLE_PORT=443` alongside REALITY — this service and xray
would fight over the port.

### Why REALITY cannot be behind a CDN

The whole mechanism depends on the TLS handshake reaching the server that holds
the private key. A CDN edge terminates that handshake itself and re-originates
plain HTTP, so the client completes the handshake with the edge and the origin
never sees it. No configuration of this binary changes that; it is the edge's
behaviour, not a setting.

So the two deployment paths are mutually exclusive by physics, not by choice:
dedicated IP plus raw TCP for REALITY, CDN plus HTTP for the tunnel. Run
both if you want both — they are separate front doors on separate ports.

## Limitations

What is still true after all of the above:

- **REALITY needs a dedicated IP.** Shared hosting, NAT port forwarding and CDN
  edges are all out, for the reason above. Behind a CDN, use the tunnel.
- **Padding equalises message sizes, nothing more.** `TUNNEL_PADDING` rounds
  every WebSocket frame to a fixed size with random filler. It does not hide
  traffic volume, timing or direction, and it cannot survive an observer who
  measures them. It is not a defence against traffic analysis.
- **The raw TLS listener is Go's TLS.** Without `TLS_CERT_FILE` the certificate
  is self-signed and regenerated on restart, which is fingerprintable. There is
  no uTLS here; that is what REALITY is for, so put anything that must not be
  fingerprinted behind it.
- **The camouflage site's certificate is only as good as its uptime.** If the
  target site is down or slow, handshakes suffer visibly.
- **UDP is not available through the WebSocket tunnel.** UDP works on the
  SOCKS5 port and through REALITY, but the tunnel is a TCP-only stream, so a
  client on the tunnel gets TCP only.

## Configuration

Edit `config.json` or use environment variables (env vars override config file):

| Env Variable | Default | Description |
|---|---|---|
| `PORT` | unset | Injected by Render/Koyeb/Heroku. Enables single-port mode automatically. Does **not** move the SOCKS5 port |
| `SINGLE_PORT` | unset | Explicit single-port port. Takes precedence over `PORT`; needed on Northflank |
| `PROXY_PORT` | 1080 | SOCKS5 proxy port. Ignored when it equals `SINGLE_PORT`, since the mux already serves SOCKS5 |
| `ADMIN_PORT` | 8080 | Admin dashboard port (multi-port mode) |
| `METRICS_PORT` | 9090 | Metrics dashboard port (multi-port mode) |
| `PROXY_USER` | changeme | SOCKS5 username, also the HTTP proxy user |
| `PROXY_PASS` | changeme | SOCKS5 password, also the HTTP proxy password |
| `AUTH_ENABLED` | true | Enable SOCKS5 and HTTP proxy authentication |
| `UDP_ENABLED` | true | SOCKS5 `UDP ASSOCIATE`. Set false for TCP only |
| `MTPROTO_ENABLED` | false | Telegram front door; generates its first secret on first start |
| `MTPROTO_BIND` | 0.0.0.0:8443 | Telegram port. Avoid 443 when REALITY has it |
| `MTPROTO_DCS` | unset | `dc=address,dc=address`, only when Telegram's own addresses are unreachable |
| `MTPROTO_SECRET_KIND` | dd | Kind of secret to generate: `dd` obfuscated2, `ee` fake TLS |
| `MTPROTO_FAKE_HOST` | www.cloudflare.com | Domain the fake TLS reply is built around |
| `MAX_CONNECTIONS` | 1000 | Max simultaneous connections |
| `ADMIN_USER` | admin | Admin dashboard username |
| `ADMIN_PASS` | changeme | Admin dashboard password |
| `ADMIN_AUTH_ENABLED` | true | Enable admin dashboard auth |
| `READ_TIMEOUT_SECONDS` | 30 | Handshake read deadline |
| `WRITE_TIMEOUT_SECONDS` | 30 | Reply write deadline |
| `IDLE_TIMEOUT_SECONDS` | 300 | Deadline on an **established** proxy session. Raise it if clients idle longer |
| `SECURITY_HEADERS_ENABLED` | true | Enable security headers |
| `RATE_LIMIT_ENABLED` | true | Enable rate limiting on admin endpoints |
| `RATE_LIMIT_RPS` | 30 | Admin requests per second **per client**, keyed by IP. One client cannot spend another's budget. Clients behind one carrier NAT share a bucket |
| `TUNNEL_ENABLED` | false | Enable the WebSocket tunnel. Refused at startup without a token |
| `TUNNEL_TOKEN` | empty | Shared secret for the tunnel path and the client |
| `TUNNEL_PATH` | /api/v1/tunnel | Tunnel URL path |
| `TUNNEL_PADDING` | 256 | Message padding size; 0 or 1 disables |
| `TUNNEL_RATE_LIMIT_RPS` | 5 | Tunnel handshakes per second. Raise for bursty clients |
| `REALITY_ENABLED` | false | Serve a REALITY front door. Needs xray and a dedicated IP; refuses to start without the binary |
| `REALITY_BIND` | 0.0.0.0:443 | Address xray's REALITY listener binds. Keep it off any port used elsewhere, including `SINGLE_PORT` |
| `REALITY_DEST` | www.lovelive-anime.jp:443 | Camouflage site. Its certificate is what a prober sees, so it must be reachable, TLS 1.3 + X25519, and on a real CDN |
| `REALITY_SERVER_NAMES` | dest host | SNI values to impersonate, comma separated |
| `REALITY_PRIVATE_KEY` | generated | REALITY private key. Generated once and reused from the database when empty; `xray x25519` prints a pair |
| `REALITY_SHORT_IDS` | generated | Short ids, comma separated. Up to 16 hex characters; rotating locks out existing clients |
| `REALITY_CLIENT_IDS` | generated | VLESS UUIDs, comma separated. Pins the list and disables panel management |
| `REALITY_PUBLIC_HOST` | empty | This host's IP or domain, written into the generated client config so it is usable as-is |
| `XRAY_BIN` | xray | Path to the xray binary |
| `REALITY_CLIENT_FILE` | reality-client.json | Where the generated client config is written |
| `TLS_CERT_FILE` | empty | Certificate path; empty generates a self-signed cert in memory |
| `TLS_KEY_FILE` | empty | Private key path; empty generates a self-signed cert in memory |

> **Tuning note:** `TUNNEL_RATE_LIMIT_RPS` doubles as a burst limit, not just a
> rate. Telegram and Signal open many connections at once; a value of 5 will
> reject legitimate bursts. 50–100 is a reasonable starting point.
> `IDLE_TIMEOUT_SECONDS` must exceed the interval at which your clients send
> keepalives, or healthy idle sessions get dropped.

## Ports

Multi-port mode (default):

| Port | Service |
|---|---|
| 1080 | SOCKS5 Proxy |
| 8080 | Admin Dashboard |
| 9090 | Metrics Dashboard + Prometheus |

Single-port mode serves all of these on `$SINGLE_PORT` (or `$PORT`), plus the
tunnel path and `/tls-cert`. When `$SINGLE_PORT` equals `$PROXY_PORT` the extra
SOCKS5 listener is skipped, because the mux already serves SOCKS5 on that port.

With `REALITY_ENABLED=true` xray also binds 443 (`$REALITY_BIND`) for the
REALITY front door. That port is never shared with the Go service.

## Commands

```
socks5-proxy                    # server, config.json
socks5-proxy config.json        # server, explicit config
socks5-proxy server [cfg.json]  # server, explicit keyword
socks5-proxy client -flags      # tunnel client
socks5-proxy reality-client -flags  # REALITY client, using the config the server wrote
socks5-proxy version
```

Client flags: `-url` (required; `https://` is accepted and mapped to `wss://`, and a bare host gets the default tunnel path), `-token` (or `TUNNEL_TOKEN`), `-listen` (default `127.0.0.1:1080`), `-keepalive` (default `30s`), `-padding` (0 = follow the server), `-insecure` (VPS self-signed certs only).

`reality-client` flags: `-config` (default `reality-client.json`), `-server` (override the server address, `host` or `host:port`), `-listen` (override the local SOCKS5 address, default `127.0.0.1:1081`), `-bin` (xray binary).

## Backup and restore

```bash
# Take a backup. Works while the server is running.
socks5-proxy backup -out socks5-20261017.tar.gz

# Encrypt it. A backup holds password hashes and, with REALITY enabled, the
# private key -- so encryption is worth the passphrase.
socks5-proxy backup -out socks5-20261017.tar.gz -passphrase 'a good passphrase'

# Look inside without restoring anything.
socks5-proxy restore -in socks5-20261017.tar.gz -list

# Restore. Stop the server first.
socks5-proxy restore -in socks5-20261017.tar.gz
```

The archive holds `socks5.db`, `config.json` and, when REALITY is enabled,
`reality-client.json`. **Restoring the same archive keeps every REALITY client
working**, because the keypair travels with it and the managed VLESS UUIDs and
MTProto secrets live in the database; restoring an older or different one
invalidates every client you have imported.
working**, because the keypair travels with it and the managed VLESS UUIDs live
in the database; restoring an older or different one invalidates every client you
have imported.

`restore` refuses to run while the server is up, because replacing a database
that another process still has open is how SQLite ends up cleaning up the wrong
file. It detects that through a pid file the server writes at startup, and a pid
left behind by a crash does not count as running. `-force` overrides it.

The current database is kept as `socks5.db.pre-restore-<timestamp>` before
anything is replaced, so a restore is undoable by hand.

Snapshots are taken with SQLite's `VACUUM INTO`, never by copying the file.
This database runs in WAL mode, so the most recent commits live in the `-wal`
sidecar: a file copy can produce a backup that restores cleanly and silently
loses data.

Nightly, with the volume mounted:

```bash
0 3 * * * cd /srv/socks5-proxy && ./socks5-proxy backup -out "backup-$(date +%F).tar.gz" -passphrase "$BACKUP_PASSPHRASE" && find . -name 'backup-*.tar.gz' -mtime +14 -delete
```

## Tests

```bash
go test ./...
```

Covers single-port multiplexing (SOCKS5, TLS and HTTP on one port), `CONNECT`
proxying and its auth, absolute-form forward proxying, tunnel auth and
round-trip, the real client against the real server end to end, handler merging,
padding framing, config/env resolution, and non-TCP conn handling.

The REALITY end-to-end test runs the real xray binary through the real proxy and
skips when xray is not installed:

```bash
go test -run TestRealityEndToEnd -v ./...   # needs xray on PATH
```

## Security notes

- **Change `PROXY_PASS`, `ADMIN_PASS` and `TUNNEL_TOKEN` before exposing the
  service.** The shipped defaults are `changeme`.
- The server **refuses to start** if `TUNNEL_ENABLED` is set without
  `TUNNEL_TOKEN`, so a misconfigured fork cannot become an open relay. With
  `TUNNEL_ENABLED=false` the tunnel path is not even registered, regardless of
  any token left in the config.
- A refused tunnel attempt answers exactly what a path that does not exist
  answers — status, challenge header and body. A disabled tunnel, a wrong token
  and the rate limiter are therefore indistinguishable from each other, so none
  of them can be used to locate the tunnel or to enumerate tokens.
- The server **refuses to start** if `REALITY_ENABLED` is set without the xray
  binary. The rendered config is validated with `xray run --test` before xray is
  launched, so a broken setup fails at startup rather than leaving a dead front
  door.
- The REALITY private key and the proxy credentials are written to a `0600` temp
  file for xray, and deleted when xray is stopped. The private key is never
  returned by `/api/config`; the generated client config holds the **public**
  key, but is still written `0600` because it contains the VLESS UUIDs.
- xray is supervised: it is restarted with backoff if it dies, and asked to exit
  on shutdown. Its own log lines are relayed into this server's log.
- `whitelist` and `blacklist` apply to the SOCKS5 port, the HTTP proxy
  (`CONNECT` and forward) and the tunnel alike.
- User passwords are stored as **PBKDF2-HMAC-SHA256 hashes** (600k iterations,
  per-user salt), never as text, so a database file or a backup does not hand
  over working credentials. Accounts created before hashing existed keep
  working: their password is verified against the old value and the row is
  rewritten on the next successful login, so an install upgrades itself one
  account at a time with no migration to run.
- `PROXY_USER`/`PROXY_PASS` and `ADMIN_USER`/`ADMIN_PASS` come from the
  environment or config file and stay as they are — there is nothing in the
  database to hash, and the file is already a secret you control.
- A backup contains password **hashes**, not passwords, plus the REALITY private
  key when it is enabled. The key is the reason to use `-passphrase` for
  anything that leaves the machine; keep the passphrase somewhere other than the
  backup directory.
- `/health` is the only endpoint reachable without admin credentials, and it
  returns `{"status":"ok"}` with no uptime or version: on a public port it is
  the one thing a scanner can read, so it says nothing. `/metrics`,
  `/prometheus`, `/api/live` and `/tls-cert` take the admin credentials, and the
  metrics port (`:9090`) applies them too rather than serving an open dashboard.
- The tunnel path carries its own token and skips admin auth; every attempt on
  it, successful or not, answers exactly what an unknown path answers.
- The HTTP proxy reuses the SOCKS5 credentials and is only served in
  single-port mode.
- On a public PaaS, put the admin dashboard behind a second hostname or an
  access layer if you do not want it publicly reachable at all.

## User Tiers

| Tier | Max Conns | Bandwidth | Data Limit | Expiry |
|---|---|---|---|---|
| Free | 1 | 1 Mbps | 1 GB | 7 days |
| Basic | 5 | 5 Mbps | 50 GB | 30 days |
| Pro | 20 | 50 Mbps | Unlimited | 90 days |
| Unlimited | Unlimited | Unlimited | Unlimited | Never |

Bandwidth is enforced per direction on every session: a Free-tier session moves
at most 1 Mbps each way, with a one-second burst allowance so short transfers
are not penalised. A user's limit is captured when the account is created, so
changing a tier later does not retroactively re-rate existing accounts. Sessions
authenticated with the single `PROXY_USER`/`PROXY_PASS` pair, and the HTTP proxy
paths that share it, run unrestricted — there is no per-user tier to apply.

## API Endpoints

Reachable in both modes; in single-port mode they are all on the one port.

### Always public (no admin credentials)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | `{"status":"ok"}` and nothing else. Load balancers and the container health check use it |

### Metrics (admin credentials)

These are diagnostics, not load balancers, so they take the same basic auth as
the dashboard. They used to be public, and `/metrics` is an HTML page that names
the software — one request identified a deployment as a proxy. Point Prometheus
at `/prometheus` with `basic_auth` configured.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/metrics` | Metrics dashboard (HTML) |
| GET | `/prometheus` | Prometheus exposition |
| GET | `/api/live` | Live counters for the charts |
| GET | `/tls-cert` | Active TLS certificate, PEM. Single-port mode only |

### Tunnel

| Method | Endpoint | Description |
|---|---|---|
| GET (Upgrade) | `$TUNNEL_PATH` | WebSocket tunnel. Auth via `?token=` or `Authorization: Bearer` |

### Admin (basic auth)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/stats` | Proxy statistics, including top destinations |
| GET | `/api/config` | Configuration, with the proxy password masked |
| PUT | `/api/config` | Update configuration |
| GET | `/api/tiers` | Tier definitions and limits |
| GET | `/api/users` | List users |
| POST | `/api/users` | Create user |
| PUT | `/api/users/:id` | Update user |
| DELETE | `/api/users/:id` | Delete user |
| POST | `/api/users/:id/reset` | Reset a user's data usage |
| GET | `/api/mtproto-secrets` | Telegram secrets, with the listener's bind address |
| POST | `/api/mtproto-secrets` | Add a secret; it is generated for you |
| PUT | `/api/mtproto-secrets/:id` | Relabel, or enable/disable, a secret |
| DELETE | `/api/mtproto-secrets/:id` | Revoke a phone, effective immediately |
| GET | `/api/vless-clients` | REALITY client UUIDs, and whether they can be managed |
| POST | `/api/vless-clients` | Add a client; the UUID is generated if omitted |
| PUT | `/api/vless-clients/:id` | Relabel, or enable/disable, a client |
| DELETE | `/api/vless-clients/:id` | Revoke a client, effective immediately |
| GET | `/api/top-destinations?n=10` | Most-visited destinations |
| GET | `/api/history/stats?n=60` | Historical connection/byte counters |
| GET | `/api/history/destinations` | Destination history |
| GET | `/api/history/top-alltime` | All-time top destinations |
| GET | `/chart.min.js` | Chart.js, served locally |
| GET | `/` | Admin dashboard |

## Tech Stack

- **Go 1.24** - Standard library HTTP server and TLS
- **SQLite** (modernc.org/sqlite) - Pure-Go SQLite driver
- **Prometheus** - Metrics collection and exposition
- **coder/websocket** - Pure-Go WebSocket with `NetConn`, the only third-party addition
- **Chart.js** - Dashboard visualizations (bundled locally)

## License

MIT
