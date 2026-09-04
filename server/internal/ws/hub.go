package ws

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
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

// HandleWS WebSocket 处理器
func HandleWS(w http.ResponseWriter, r *http.Request) {
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
