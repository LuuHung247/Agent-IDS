package main

import (
	"bufio"
	"bytes"
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
	sfURL      = envOr("SF_API_URL", "http://10.10.6.238:9090")
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
		default:
		}
	}
}

func (h *Hub) addWS(c *websocket.Conn)      { h.mu.Lock(); h.wsClients[c] = struct{}{}; h.mu.Unlock() }
func (h *Hub) removeWS(c *websocket.Conn)   { h.mu.Lock(); delete(h.wsClients, c); h.mu.Unlock() }
func (h *Hub) addSSE(ch chan []byte)         { h.mu.Lock(); h.sseClients[ch] = struct{}{}; h.mu.Unlock() }
func (h *Hub) removeSSE(ch chan []byte)      { h.mu.Lock(); delete(h.sseClients, ch); h.mu.Unlock() }

// --- Auto-block state ---

var (
	autoBlockMu      sync.Mutex
	autoBlockEnabled bool
	blockedIPs       = make(map[string]bool) // src_ip → already pushed
)

// pushBlockRule sends a DROP rule to Secure Framework via REST API.
func pushBlockRule(srcIP, ruleID, reason string) ([]byte, error) {
	if ruleID == "" {
		safe := strings.NewReplacer(".", "-", "/", "-").Replace(srcIP)
		ruleID = "agent-" + safe
	}
	cidr := srcIP
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	payload := map[string]interface{}{
		"rule_id":  ruleID,
		"action":   "DROP",
		"src_ip":   cidr,
		"priority": 50,
		"source":   "agent",
		"comment":  reason,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(sfURL+"/api/rules", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("SF %d: %s", resp.StatusCode, string(result))
	}
	return result, nil
}

// tryAutoBlock is called on each new Suricata alert when auto-block is enabled.
// Only blocks on severity 1 (P1 CRITICAL) and 2 (P2 HIGH).
func tryAutoBlock(data string) {
	var alert map[string]interface{}
	if err := json.Unmarshal([]byte(data), &alert); err != nil {
		return
	}
	alertData, _ := alert["alert"].(map[string]interface{})
	if alertData == nil {
		return
	}
	severity, _ := alertData["severity"].(float64)
	if severity > 2 {
		return
	}
	srcIP, _ := alert["src_ip"].(string)
	if srcIP == "" {
		return
	}

	autoBlockMu.Lock()
	if blockedIPs[srcIP] {
		autoBlockMu.Unlock()
		return
	}
	blockedIPs[srcIP] = true
	autoBlockMu.Unlock()

	sig, _ := alertData["signature"].(string)
	reason := fmt.Sprintf("auto-block: %s", sig)

	go func() {
		if _, err := pushBlockRule(srcIP, "", reason); err != nil {
			log.Printf("[AutoBlock] FAILED %s: %v", srcIP, err)
			autoBlockMu.Lock()
			delete(blockedIPs, srcIP)
			autoBlockMu.Unlock()
		} else {
			log.Printf("[AutoBlock] BLOCKED %s (%s)", srcIP, sig)
		}
	}()
}

// --- HTTP Handlers ---

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

	fmt.Fprintf(w, "data: {\"type\":\"connected\"}\n\n")
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
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

// rulesProxyHandler proxies /rules → SF /api/rules (GET only)
func rulesProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", 405)
		return
	}
	proxyGet(w, sfURL+"/api/rules")
}

// autoblockHandler handles GET (status) and POST (manual block).
func autoblockHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		autoBlockMu.Lock()
		enabled := autoBlockEnabled
		count := len(blockedIPs)
		autoBlockMu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled":          enabled,
			"blocked_ip_count": count,
			"sf_url":           sfURL,
		})
		return
	}

	if r.Method == http.MethodPost {
		// Manual block: POST /autoblock {src_ip, rule_id?, reason?}
		var req struct {
			SrcIP  string `json:"src_ip"`
			RuleID string `json:"rule_id"`
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.SrcIP == "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "src_ip required"})
			return
		}
		if req.Reason == "" {
			req.Reason = "manual block via IDS Agent"
		}
		result, err := pushBlockRule(req.SrcIP, req.RuleID, req.Reason)
		if err != nil {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Write(result)
		return
	}

	http.Error(w, "GET or POST only", 405)
}

// autoblockEnableHandler: POST /autoblock/enable  or  POST /autoblock/disable
func autoblockEnableHandler(enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		autoBlockMu.Lock()
		autoBlockEnabled = enable
		if !enable {
			blockedIPs = make(map[string]bool)
		}
		autoBlockMu.Unlock()

		action := map[bool]string{true: "enabled", false: "disabled"}[enable]
		log.Printf("[AutoBlock] %s", action)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": enable,
			"message": "auto-block " + action,
		})
	}
}

// unblockHandler: DELETE /autoblock/unblock/{rule_id}
func unblockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "DELETE or POST only", 405)
		return
	}
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	ruleID := parts[len(parts)-1]
	if ruleID == "" || ruleID == "unblock" {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule_id required"})
		return
	}
	hclient := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest(http.MethodDelete, sfURL+"/api/rules/"+ruleID, nil)
	resp, err := hclient.Do(req)
	if err != nil {
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(result)
}

// --- SSE bridge từ Suricata → hub ---

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
		autoBlockMu.Lock()
		enabled := autoBlockEnabled
		autoBlockMu.Unlock()
		if enabled {
			tryAutoBlock(data)
		}
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
				autoBlockMu.Lock()
				enabled := autoBlockEnabled
				autoBlockMu.Unlock()
				if enabled {
					tryAutoBlock(string(msg))
				}
			}
		}
		lastCount = count
	}
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	log.Printf("IDS Agent — IDS: %s  SF: %s  listen: %s", idsURL, sfURL, listenAddr)
	go runBridge()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/alerts", alertsHandler)
	mux.HandleFunc("/ws", wsHandler)
	mux.HandleFunc("/events", eventsHandler)
	mux.HandleFunc("/rules", rulesProxyHandler)
	mux.HandleFunc("/autoblock", autoblockHandler)
	mux.HandleFunc("/autoblock/enable", autoblockEnableHandler(true))
	mux.HandleFunc("/autoblock/disable", autoblockEnableHandler(false))
	mux.HandleFunc("/autoblock/unblock/", unblockHandler)

	log.Fatal(http.ListenAndServe(listenAddr, cors(mux)))
}
