# SOCKS5 Proxy Server

A production-grade SOCKS5 proxy server with user management, tier-based access control, rate limiting, and real-time monitoring dashboards.

Deploys on any PaaS, including the ones that expose only a single HTTP endpoint.

## Features

- **SOCKS5 Protocol** - Full SOCKS5 proxy support with username/password authentication
- **Single-Port Multiplexing** - SOCKS5, TLS, dashboards and the tunnel share one port, so it runs on Render/Koyeb/Heroku/Northflank where raw TCP never reaches the app
- **WebSocket Tunnel** - Carries SOCKS5 over an HTTP upgrade for platforms whose edge terminates TLS; ships with a matching client
- **Client Mode** - Same binary exposes a local SOCKS5 port that relays through the tunnel
- **User Management** - Create, update, delete users with tier-based limits
- **Tier System** - Free, Basic, Pro, and Unlimited tiers with connection/data/bandwidth limits
- **Rate Limiting** - Token-bucket rate limiting with configurable RPS
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

### Docker

```bash
docker build -t socks5-proxy .
# Three ports, as on a VPS with raw TCP
docker run -p 1080:1080 -p 8080:8080 -p 9090:9090 socks5-proxy
# One port, as on a PaaS
docker run -e PORT=8080 -p 8080:8080 socks5-proxy
```

`PORT` is deliberately not baked into the image, so the image works in both
layouts. Supplying it switches on single-port mode.

### Docker Compose

```bash
cp .env.example .env      # then edit the passwords
docker compose up -d
```

SQLite is kept on a named volume, so it survives rebuilds.

## Protocols

The server speaks four protocols. In single-port mode all of them share one
port, dispatched on the first byte or request shape.

| Protocol | Endpoint | Used by |
|---|---|---|
| **SOCKS5** | `:1080` | Native SOCKS5 clients, on hosts that permit raw TCP |
| **SOCKS5 over WebSocket** | `/tunnel` | SOCKS5 clients where raw TCP is blocked, via the bundled client |
| **HTTP proxy** — `CONNECT` and absolute-form | single port | Browsers and any HTTP client with proxy support |
| **HTTPS** | single port | TLS-wrapped access to any of the above |

Authentication is username/password throughout, taken from `PROXY_USER` and
`PROXY_PASS` for the proxy protocols, and `ADMIN_USER`/`ADMIN_PASS` for the
dashboards.

Cloudflare's edge answers `CONNECT` with `400 Bad Request` without forwarding it
to the origin, so HTTP proxying requires a directly reachable host. The
WebSocket tunnel is unaffected and is the intended path on Render, Koyeb, Heroku
and Northflank.

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
| **VPS** | Yes | Nothing |
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

## Limitations

- `TUNNEL_PADDING` equalises message sizes. It does not affect TLS
  fingerprints or resist active probing.
- Fingerprint-resistant transports such as Xray/REALITY require raw TCP and a
  dedicated IP, so they cannot be used behind a shared CDN edge.

## Configuration

Edit `config.json` or use environment variables (env vars override config file):

| Env Variable | Default | Description |
|---|---|---|
| `PORT` | unset | Injected by Render/Koyeb/Heroku. Enables single-port mode automatically |
| `SINGLE_PORT` | unset | Explicit single-port port. Takes precedence over `PORT`; needed on Northflank |
| `PROXY_PORT` | 1080 | SOCKS5 proxy port (multi-port mode) |
| `ADMIN_PORT` | 8080 | Admin dashboard port (multi-port mode) |
| `METRICS_PORT` | 9090 | Metrics dashboard port (multi-port mode) |
| `PROXY_USER` | changeme | SOCKS5 username, also the HTTP proxy user |
| `PROXY_PASS` | changeme | SOCKS5 password, also the HTTP proxy password |
| `AUTH_ENABLED` | true | Enable SOCKS5 and HTTP proxy authentication |
| `MAX_CONNECTIONS` | 1000 | Max simultaneous connections |
| `ADMIN_USER` | admin | Admin dashboard username |
| `ADMIN_PASS` | changeme | Admin dashboard password |
| `ADMIN_AUTH_ENABLED` | true | Enable admin dashboard auth |
| `READ_TIMEOUT_SECONDS` | 30 | Handshake read deadline |
| `WRITE_TIMEOUT_SECONDS` | 30 | Reply write deadline |
| `IDLE_TIMEOUT_SECONDS` | 300 | Deadline on an **established** proxy session. Raise it if clients idle longer |
| `SECURITY_HEADERS_ENABLED` | true | Enable security headers |
| `RATE_LIMIT_ENABLED` | true | Enable rate limiting on admin endpoints |
| `RATE_LIMIT_RPS` | 30 | Admin requests per second per client |
| `TUNNEL_ENABLED` | false | Enable the WebSocket tunnel. Refused at startup without a token |
| `TUNNEL_TOKEN` | empty | Shared secret for `/tunnel` and the client |
| `TUNNEL_PATH` | /api/v1/tunnel | Tunnel URL path |
| `TUNNEL_PADDING` | 256 | Message padding size; 0 or 1 disables |
| `TUNNEL_RATE_LIMIT_RPS` | 5 | Tunnel handshakes per second. Raise for bursty clients |
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

Single-port mode serves all of these on `$SINGLE_PORT` (or `$PORT`), plus `/tunnel` and `/tls-cert`. Port 1080 stays bound even in this mode, so direct SOCKS5 keeps working wherever the host allows raw TCP.

## Commands

```
socks5-proxy                    # server, config.json
socks5-proxy config.json        # server, explicit config
socks5-proxy server [cfg.json]  # server, explicit keyword
socks5-proxy client -flags      # tunnel client
socks5-proxy version
```

Client flags: `-url` (required; `https://` is accepted and mapped to `wss://`, and a bare host gets the default tunnel path), `-token` (or `TUNNEL_TOKEN`), `-listen` (default `127.0.0.1:1080`), `-keepalive` (default `30s`), `-padding` (0 = follow the server), `-insecure` (VPS self-signed certs only).

## Tests

```bash
go test ./...
```

Covers single-port multiplexing (SOCKS5, TLS and HTTP on one port), `CONNECT`
proxying and its auth, absolute-form forward proxying, tunnel auth and
round-trip, the real client against the real server end to end, handler merging,
padding framing, config/env resolution, and non-TCP conn handling.

## Security notes

- **Change `PROXY_PASS`, `ADMIN_PASS` and `TUNNEL_TOKEN` before exposing the
  service.** The shipped defaults are `changeme`.
- The server **refuses to start** if `TUNNEL_ENABLED` is set without
  `TUNNEL_TOKEN`, so a misconfigured fork cannot become an open relay.
- `/health`, `/metrics`, `/prometheus`, `/api/live`, `/tls-cert` and the tunnel
  are reachable without admin credentials. Everything else needs basic auth.
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

## API Endpoints

Reachable in both modes; in single-port mode they are all on the one port.

### Always public (no admin credentials)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check, used by load balancers and the container health check |
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
