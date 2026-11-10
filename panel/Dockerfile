# ARES Panel — Multi-stage Docker Build (React + Nginx)
FROM node:20-alpine AS builder

WORKDIR /build
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ── Runtime ──
FROM nginx:alpine

COPY --from=builder /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://localhost/ || exit 1
