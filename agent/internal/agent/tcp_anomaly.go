package agent

import (
	"sync"
	"time"
)

// TCPAnomalyDetector 检测 TCP 连接突变
// 60秒窗口内同一 PID 连接 ≥3 个敏感端口 或 ≥4 个不同 IP → 触发
type TCPAnomalyDetector struct {
	mu sync.Mutex

	windowSec       int      // 窗口大小（秒）
	portThreshold   int      // 端口多样性阈值
	ipThreshold     int      // IP 多样性阈值
	sensitivePorts  map[uint16]bool // 敏感端口集合

	// PID → 窗口内连接记录
	connRecords map[uint32]*ConnWindow
}

type ConnWindow struct {
	Ports     map[uint16]bool // 窗口内出现过的端口
	IPs       map[uint32]bool // 窗口内出现过的 IP
	LastSeen  time.Time
}

func NewTCPAnomalyDetector(windowSec, portThreshold, ipThreshold int, sensitivePorts []uint16) *TCPAnomalyDetector {
	sp := make(map[uint16]bool)
	for _, p := range sensitivePorts {
		sp[p] = true
	}
	return &TCPAnomalyDetector{
		windowSec:      windowSec,
		portThreshold:  portThreshold,
		ipThreshold:    ipThreshold,
		sensitivePorts: sp,
		connRecords:    make(map[uint32]*ConnWindow),
	}
}

// RecordConnection 记录一次连接，返回是否触发突变
func (d *TCPAnomalyDetector) RecordConnection(pid uint32, port uint16, ip uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// 清理过期窗口
	for p, w := range d.connRecords {
		if now.Sub(w.LastSeen) > time.Duration(d.windowSec)*time.Second {
			delete(d.connRecords, p)
		}
	}

	// 获取或创建窗口
	window, ok := d.connRecords[pid]
	if !ok {
		window = &ConnWindow{
			Ports:    make(map[uint16]bool),
			IPs:      make(map[uint32]bool),
			LastSeen: now,
		}
		d.connRecords[pid] = window
	}

	// 只记录敏感端口
	if d.sensitivePorts[port] {
		window.Ports[port] = true
	}
	window.IPs[ip] = true
	window.LastSeen = now

	// 端口突变检测
	sensitivePortCount := len(window.Ports)
	if sensitivePortCount >= d.portThreshold {
		return true // 横向移动/端口扫描
	}

	// IP 突变检测
	if len(window.IPs) >= d.ipThreshold {
		return true // 内网探测/批量外联
	}

	return false
}
