# syntax=docker/dockerfile:1

# ─── Build ─────────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Dependencies are copied first so the module cache layer survives source edits.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static binary: CGO off so it runs on a scratch-like base with no libc.
# -trimpath keeps build paths out of the binary; the ldflags strip debug info.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w" \
      -o /out/socks5-proxy .

# Fail the build rather than ship something that will not start.
RUN /out/socks5-proxy version

# ─── Xray (REALITY) ─────────────────────────────────────────────────────────
# REALITY needs the real xray binary: it uses uTLS and certificate relay, which
# are not reimplementable from crypto/tls. It runs as a child process and this
# proxy stays the SOCKS5 brain behind it.
#
# Pinned on purpose, and verified: an unpinned download from a release URL is a
# supply-chain hole in an image people run on a public IP. To update, bump
# XRAY_VERSION and the two SHA2-256 values from the release's .dgst files:
#   https://github.com/XTLS/Xray-core/releases/download/v<X>/Xray-linux-64.zip.dgst
FROM alpine:3.22 AS xray

ARG TARGETARCH=amd64
ARG XRAY_VERSION=v26.3.27

RUN apk add --no-cache curl unzip

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) asset=Xray-linux-64.zip; \
             sha=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;; \
      arm64) asset=Xray-linux-arm64-v8a.zip; \
             sha=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;; \
      *) echo "no pinned xray build for architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/$asset"; \
    curl -fsSL -o /tmp/xray.zip "$url"; \
    echo "$sha  /tmp/xray.zip" | sha256sum -c -; \
    unzip -q /tmp/xray.zip -d /out; \
    chmod +x /out/xray; \
    /out/xray version | head -1

# ─── Runtime ───────────────────────────────────────────────────────────────
FROM alpine:3.22

LABEL org.opencontainers.image.title="socks5-proxy" \
      org.opencontainers.image.description="SOCKS5 proxy with single-port multiplexing, HTTP proxying and a WebSocket tunnel" \
      org.opencontainers.image.source="https://github.com/OWNER/socks5-proxy" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# wget is used by the health check; ca-certificates for outbound TLS.
RUN apk add --no-cache ca-certificates wget \
 && addgroup -S appgroup \
 && adduser -S appuser -G appgroup

COPY --from=builder /out/socks5-proxy ./socks5-proxy
# The binary plus geoip.dat/geosite.dat, which xray resolves relative to
# XRAY_LOCATION_ASSET.
COPY --from=xray /out/ /usr/local/share/xray/
RUN ln -s /usr/local/share/xray/xray /usr/local/bin/xray
COPY config.json .
COPY web ./web
# MIT requires the notice to travel with distributed copies.
COPY LICENSE .

# SQLite lives here. Created and owned up front so the non-root user can write.
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

# REALITY binds this one; it is only used when REALITY_ENABLED=true.
ENV XRAY_LOCATION_ASSET=/usr/local/share/xray

# Default multi-port layout. Single-port mode is enabled by supplying PORT or
# SINGLE_PORT, which is what PaaS providers inject automatically:
#
#   docker run -e PORT=8080 -p 8080:8080 socks5-proxy      # one port, anywhere
#   docker run -p 1080:1080 -p 8080:8080 -p 9090:9090 ...  # three ports, VPS
#
# PORT is deliberately NOT baked in: setting it would force single-port mode on
# every local run and silently stop listening on 9090. Supply it at run time to
# opt into single-port mode (PaaS providers inject it automatically).
#
# 443 is the REALITY port. The image runs as a non-root user, so xray needs
# help to bind it: run with --sysctl net.ipv4.ip_unprivileged_port_start=0 (the
# compose file does this) or REALITY_BIND will fail with "permission denied".
EXPOSE 1080 8080 9090 443

# /health is always reachable without admin credentials. The probe mirrors the
# precedence in LoadConfig: SINGLE_PORT wins over PORT, which wins over 8080.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q --spider "http://localhost:${SINGLE_PORT:-${PORT:-8080}}/health" || exit 1

CMD ["./socks5-proxy", "config.json"]
