package ws

import (
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// TokenValidator 校验 WebSocket 连接携带的 token。
// 返回 nil 表示通过；非 nil 表示拒绝。
type TokenValidator func(token string) error

var (
	validator      TokenValidator
	allowedOrigins []string // 额外允许的 Origin（Host 或完整 origin）
)

// SetTokenValidator 注入 token 校验器（由 main.go 在启动时设置）
func SetTokenValidator(v TokenValidator) { validator = v }

// SetAllowedOrigins 设置允许的额外 Origin 白名单（除同源外）。
// 传空表示仅允许同源。
func SetAllowedOrigins(origins []string) { allowedOrigins = origins }

// checkOrigin Origin 校验（防跨站 WebSocket 劫持）
//
// 规则：
//   - 无 Origin 头（非浏览器客户端）→ 允许
//   - Origin 的 Host 与请求 Host 一致 → 允许（同源）
//   - Origin 命中白名单 → 允许
//   - 其余 → 拒绝
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Host == r.Host {
		return true
	}
	for _, o := range allowedOrigins {
		if o == origin || o == u.Host {
			return true
		}
	}
	return false
}

var upgrader = websocket.Upgrader{
	CheckOrigin: checkOrigin,
}

// Hub WebSocket 连接管理
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
}

var hub = &Hub{
	clients: make(map[*websocket.Conn]bool),
}

// Broadcast 广播消息给所有客户端
func Broadcast(messageType string, data interface{}) {
	hub.mu.RLock()
	defer hub.mu.RUnlock()

	for conn := range hub.clients {
		conn.WriteJSON(map[string]interface{}{
			"type": messageType,
			"data": data,
		})
	}
}

// HandleWS WebSocket 处理器（需鉴权）
//
// token 来源（按优先级）：
//  1. URL 查询参数 ?token=xxx（浏览器 WebSocket 无法自定义 header）
//  2. Authorization: Bearer xxx（非浏览器客户端）
func HandleWS(w http.ResponseWriter, r *http.Request) {
	if validator == nil {
		log.Printf("⚠️ WebSocket 未配置 token 校验器，拒绝连接")
		http.Error(w, "服务未就绪", http.StatusServiceUnavailable)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = auth[7:]
		}
	}
	if token == "" {
		http.Error(w, "未认证", http.StatusUnauthorized)
		return
	}
	if err := validator(token); err != nil {
		log.Printf("🔒 WebSocket 认证失败 (%s): %v", r.RemoteAddr, err)
		http.Error(w, "token 无效", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket 升级失败: %v", err)
		return
	}

	hub.mu.Lock()
	hub.clients[conn] = true
	hub.mu.Unlock()

	log.Printf("🔌 WebSocket 连接: %s (当前%d个连接)", r.RemoteAddr, len(hub.clients))

	defer func() {
		hub.mu.Lock()
		delete(hub.clients, conn)
		hub.mu.Unlock()
		conn.Close()
		log.Printf("🔌 WebSocket 断开: %s", r.RemoteAddr)
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}
