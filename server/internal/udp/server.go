package udp

import (
	"encoding/json"
	"log"
	"net"
	"sync"
	"fmt"
)

type UDPEvent struct {
	AgentID   string `json:"agent_id"`
	EventType string `json:"event_type"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Filename  string `json:"filename"`
	Timestamp uint64 `json:"timestamp"`
	Data      string `json:"data,omitempty"`
}

type UDPServer struct {
	conn    *net.UDPConn
	events  []UDPEvent
	mu      sync.RWMutex
	onEvent func(UDPEvent)
}

func NewUDPServer(port int, callback func(UDPEvent)) *UDPServer {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("⚠️ UDP地址解析失败: %v", err)
		return nil
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("⚠️ UDP监听失败: %v", err)
		return nil
	}

	s := &UDPServer{
		conn:    conn,
		events:  make([]UDPEvent, 0, 1000),
		onEvent: callback,
	}

	log.Printf("📡 eBPF UDP接收端启动 :%d", port)
	go s.listen()
	return s
}

func (s *UDPServer) listen() {
	buf := make([]byte, 1500)
	for {
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		var evt UDPEvent
		if err := json.Unmarshal(buf[:n], &evt); err != nil {
			log.Printf("⚠️ UDP解析失败: %v", err)
			continue
		}

		s.mu.Lock()
		s.events = append(s.events, evt)
		if len(s.events) > 1000 {
			s.events = s.events[len(s.events)-500:]
		}
		s.mu.Unlock()

		log.Printf("📡 UDP事件: %s PID=%d %s %s", evt.AgentID, evt.PID, evt.Comm, evt.Filename)

		if s.onEvent != nil {
			s.onEvent(evt)
		}
	}
}

func (s *UDPServer) GetEvents() []UDPEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make([]UDPEvent, len(s.events))
	copy(events, s.events)
	return events
}

func (s *UDPServer) Close() {
	s.conn.Close()
}
