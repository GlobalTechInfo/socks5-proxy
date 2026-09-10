# SOCKS5 Proxy Server

A production-grade SOCKS5 proxy server with user management, tier-based access control, rate limiting, and real-time monitoring dashboards.

## Features

- **SOCKS5 Protocol** - Full SOCKS5 proxy support with username/password authentication
- **User Management** - Create, update, delete users with tier-based limits
- **Tier System** - Free, Basic, Pro, and Unlimited tiers with connection/data/bandwidth limits
- **Rate Limiting** - Token-bucket rate limiting with configurable RPS
- **Security Headers** - CSP, XSS protection, frame options, and more
- **Admin Dashboard** (port 8080) - Full management UI with charts and user CRUD
- **Metrics Dashboard** (port 9090) - Real-time monitoring with Chart.js visualizations
- **Prometheus Metrics** - `/metrics` endpoint for monitoring integration
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
docker run -p 1080:1080 -p 8080:8080 -p 9090:9090 socks5-proxy
```

### Docker Compose

```bash
docker compose up -d
```

## Configuration

Edit `config.json` or use environment variables (env vars override config file):

| Env Variable | Default | Description |
|---|---|---|
| `PROXY_PORT` | 1080 | SOCKS5 proxy port |
| `ADMIN_PORT` | 8080 | Admin dashboard port |
| `METRICS_PORT` | 9090 | Metrics dashboard port |
| `PROXY_USER` | changeme | SOCKS5 username |
| `PROXY_PASS` | changeme | SOCKS5 password |
| `MAX_CONNECTIONS` | 1000 | Max simultaneous connections |
| `ADMIN_USER` | admin | Admin dashboard username |
| `ADMIN_PASS` | changeme | Admin dashboard password |
| `AUTH_ENABLED` | true | Enable SOCKS5 authentication |
| `ADMIN_AUTH_ENABLED` | true | Enable admin dashboard auth |
| `SECURITY_HEADERS_ENABLED` | true | Enable security headers |
| `RATE_LIMIT_ENABLED` | true | Enable rate limiting |
| `RATE_LIMIT_RPS` | 30 | Requests per second limit |

## Ports

| Port | Service |
|---|---|
| 1080 | SOCKS5 Proxy |
| 8080 | Admin Dashboard |
| 9090 | Metrics Dashboard + Prometheus |

## User Tiers

| Tier | Max Conns | Bandwidth | Data Limit | Expiry |
|---|---|---|---|---|
| Free | 1 | 1 Mbps | 1 GB | 7 days |
| Basic | 5 | 5 Mbps | 50 GB | 30 days |
| Pro | 20 | 50 Mbps | Unlimited | 90 days |
| Unlimited | Unlimited | Unlimited | Unlimited | Never |

## API Endpoints

### Admin (port 8080)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/api/stats` | Proxy statistics |
| GET | `/api/config` | Get configuration |
| PUT | `/api/config` | Update configuration |
| GET | `/api/users` | List users |
| POST | `/api/users` | Create user |
| PUT | `/api/users/:id` | Update user |
| DELETE | `/api/users/:id` | Delete user |
| POST | `/api/users/:id/reset` | Reset user data usage |
| GET | `/api/history/stats` | Historical stats |
| GET | `/api/history/top-alltime` | Top destinations |

### Metrics (port 9090)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Metrics dashboard |
| GET | `/metrics` | Prometheus metrics |
| GET | `/api/live` | Live stats |
| GET | `/api/history/stats` | Historical stats |
| GET | `/api/history/top-alltime` | Top destinations |

## Tech Stack

- **Go 1.24** - Standard library HTTP server
- **SQLite** (modernc.org/sqlite) - Pure-Go SQLite driver
- **Prometheus** - Metrics collection and exposition
- **Chart.js** - Dashboard visualizations (bundled locally)

## License

MIT
