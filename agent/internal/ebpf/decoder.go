package ebpf

import (
	"encoding/binary"
	"fmt"
)

// SentinelEventHeader 对应 C 端 sentinel_common.h 的 sentinel_event_header
// 使用 packed 布局，Go 端手动解析避免内存对齐差异
type SentinelEventHeader struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	EventType  uint32
	Timestamp  uint64
	Comm       string
	ParentComm string
	Data       string
}

// HeaderSize 是 sentinel_event_header 在 C 端的固定大小
// 4+4+4+4+8+16+16+256 = 312 字节
const HeaderSize = 312

// DecodeEvent 从 ring buffer 的原始字节解析事件
// 安全：先检查长度，杜绝越界
func DecodeEvent(raw []byte) (*SentinelEventHeader, error) {
	if len(raw) < HeaderSize {
		return nil, fmt.Errorf("数据长度不足: got %d, want >= %d", len(raw), HeaderSize)
	}

	evt := &SentinelEventHeader{
		PID:       binary.LittleEndian.Uint32(raw[0:4]),
		PPID:      binary.LittleEndian.Uint32(raw[4:8]),
		UID:       binary.LittleEndian.Uint32(raw[8:12]),
		EventType: binary.LittleEndian.Uint32(raw[12:16]),
		Timestamp: binary.LittleEndian.Uint64(raw[16:24]),
		Comm:      cstringSafe(raw[24:40]),
		ParentComm: cstringSafe(raw[40:56]),
		Data:      cstringSafe(raw[56:312]),
	}
	return evt, nil
}

// cstringSafe 从固定字节数组读取 C 字符串，安全截断
func cstringSafe(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// EventTypeName 返回事件类型的可读名称
func EventTypeName(eventType uint32) string {
	switch eventType {
	case 1:
		return "exec"
	case 2:
		return "bash"
	case 3:
		return "tcp"
	case 4:
		return "xdp"
	default:
		return "unknown"
	}
}
