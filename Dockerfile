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
COPY config.json .
COPY web ./web
# MIT requires the notice to travel with distributed copies.
COPY LICENSE .

# SQLite lives here. Created and owned up front so the non-root user can write.
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

# Default multi-port layout. Single-port mode is enabled by supplying PORT or
# SINGLE_PORT, which is what PaaS providers inject automatically:
#
#   docker run -e PORT=8080 -p 8080:8080 socks5-proxy      # one port, anywhere
#   docker run -p 1080:1080 -p 8080:8080 -p 9090:9090 ...  # three ports, VPS
#
# PORT is deliberately NOT baked in: setting it would force single-port mode on
# every local run and silently stop listening on 9090. Supply it at run time to
# opt into single-port mode (PaaS providers inject it automatically).
EXPOSE 1080 8080 9090

# /health is always reachable without admin credentials. The probe mirrors the
# precedence in LoadConfig: SINGLE_PORT wins over PORT, which wins over 8080.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q --spider "http://localhost:${SINGLE_PORT:-${PORT:-8080}}/health" || exit 1

CMD ["./socks5-proxy", "config.json"]
