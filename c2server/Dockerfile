# ARES C2 Server — Multi-stage Docker Build
FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ares-c2 ./cmd/main.go

# ── Runtime ──
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 ares

WORKDIR /app
COPY --from=builder /ares-c2 /app/ares-c2
COPY --from=builder /build/internal/database/migrations /app/migrations

RUN mkdir -p /data && chown ares:ares /data

USER ares

EXPOSE 8443 9090 9091 1080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost:8443/health || exit 1

ENTRYPOINT ["/app/ares-c2"]
CMD ["--bind", "0.0.0.0", "--port", "8443", "--data", "/data"]
