package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var (
	idsURL     = envOr("IDS_API_URL", "http://10.10.6.238:8765")
	listenAddr = envOr("AGENT_ADDR", ":8766")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- Hub: broadcast tới cả WebSocket lẫn SSE clients ---

type Hub struct {
	mu         sync.RWMutex
	wsClients  map[*websocket.Conn]struct{}
	sseClients map[chan []byte]struct{}
}

var hub = &Hub{
	wsClients:  make(map[*websocket.Conn]struct{}),
	sseClients: make(map[chan []byte]struct{}),
}

func (h *Hub) broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.wsClients {
		_ = c.WriteMessage(websocket.TextMessage, msg)
	}
	for ch := range h.sseClients {
		select {
		case ch <- msg:
		default: // slow client — skip, don't block
		}
	}
}

func (h *Hub) addWS(c *websocket.Conn) {
	h.mu.Lock()
	h.wsClients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) removeWS(c *websocket.Conn) {
	h.mu.Lock()
	delete(h.wsClients, c)
	h.mu.Unlock()
}

func (h *Hub) addSSE(ch chan []byte) {
	h.mu.Lock()
	h.sseClients[ch] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) removeSSE(ch chan []byte) {
	h.mu.Lock()
	delete(h.sseClients, ch)
	h.mu.Unlock()
}

// --- Handlers ---

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	hub.addWS(conn)
	defer func() { hub.removeWS(conn); conn.Close() }()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// eventsHandler: SSE endpoint cho Next.js proxy
func eventsHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan []byte, 64)
	hub.addSSE(ch)
	defer hub.removeSSE(ch)

	// Gửi event "connected" ngay để browser biết stream đang live
	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	log.Printf("SSE client connected (total sse=%d)", len(hub.sseClients))

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n") // SSE comment, giữ connection sống
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func proxyGet(w http.ResponseWriter, targetURL string) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		json.NewEncoder(w).Encode(map[string]string{"status": "offline"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, resp.Body)
}

func healthHandler(w http.ResponseWriter, r *http.Request) { proxyGet(w, idsURL+"/health") }

func alertsHandler(w http.ResponseWriter, r *http.Request) {
	url := idsURL + "/alerts"
	if last := r.URL.Query().Get("last"); last != "" {
		url += "?last=" + last
	}
	proxyGet(w, url)
}

// --- SSE bridge từ Suricata → hub, polling fallback ---

func runBridge() {
	sseFails := 0
	for {
		if err := consumeSSE(); err != nil {
			sseFails++
			log.Printf("SSE [%d]: %v — retry 3s", sseFails, err)
			if sseFails >= 5 {
				log.Println("Switching to polling mode")
				runPoller()
				return
			}
		} else {
			sseFails = 0
		}
		time.Sleep(3 * time.Second)
	}
}

func consumeSSE() error {
	resp, err := (&http.Client{}).Get(idsURL + "/stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	log.Printf("SSE upstream connected: %s/stream", idsURL)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		if data == "" || data == "heartbeat" {
			continue
		}
		hub.broadcast([]byte(data))
	}
	return scanner.Err()
}

func runPoller() {
	log.Println("Polling mode — 2s interval")
	var lastCount int
	client := &http.Client{Timeout: 5 * time.Second}
	for range time.NewTicker(2 * time.Second).C {
		resp, err := client.Get(fmt.Sprintf("%s/alerts?last=100", idsURL))
		if err != nil {
			continue
		}
		var data map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		count := int(data["count"].(float64))
		alerts, _ := data["alerts"].([]interface{})
		if count > lastCount && lastCount > 0 {
			newN := count - lastCount
			if newN > len(alerts) {
				newN = len(alerts)
			}
			for _, a := range alerts[len(alerts)-newN:] {
				msg, _ := json.Marshal(a)
				hub.broadcast(msg)
			}
		}
		lastCount = count
	}
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	log.Printf("IDS Agent — upstream: %s  listen: %s", idsURL, listenAddr)
	go runBridge()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/alerts", alertsHandler)
	mux.HandleFunc("/ws", wsHandler)
	mux.HandleFunc("/events", eventsHandler) // SSE cho Next.js proxy

	log.Fatal(http.ListenAndServe(listenAddr, cors(mux)))
}
