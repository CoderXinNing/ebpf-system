package v3_loader

import (
	"encoding/binary"
	"fmt"
	"log"
)

// SentinelEventHeader V3 统一事件头（304 字节）
type SentinelEventHeader struct {
	PID            uint32
	PPID           uint32
	UID            uint32
	EventType      uint32
	Timestamp      uint64
	Comm           [16]byte
	ParentComm     [16]byte
	Data           [256]byte
	CorrelationKey uint64
}

// TCPConnDetail TCP 五元组（20 字节，内联在 Data[0:20]）
type TCPConnDetail struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Padding  [3]uint8
}

// HeaderSize V3 统一事件头大小
const HeaderSize = 304

// DecodeEvent 解码 Ring Buffer 原始数据
// 硬性校验：len(rawSample) >= 304
// 只读前 304 字节，超出的安全截断
func DecodeEvent(rawSample []byte) (*SentinelEventHeader, error) {
	if len(rawSample) < HeaderSize {
		log.Printf("❌ 短包丢弃: got=%d, want=%d", len(rawSample), HeaderSize)
		return nil, fmt.Errorf("短包: got=%d, want=%d", len(rawSample), HeaderSize)
	}

	// 只读前 304 字节
	data := rawSample[:HeaderSize]

	header := &SentinelEventHeader{
		PID:            binary.LittleEndian.Uint32(data[0:4]),
		PPID:           binary.LittleEndian.Uint32(data[4:8]),
		UID:            binary.LittleEndian.Uint32(data[8:12]),
		EventType:      binary.LittleEndian.Uint32(data[12:16]),
		Timestamp:      binary.LittleEndian.Uint64(data[16:24]),
	}
	copy(header.Comm[:], data[24:40])
	copy(header.ParentComm[:], data[40:56])
	copy(header.Data[:], data[56:312])
	header.CorrelationKey = binary.LittleEndian.Uint64(data[312:320])

	return header, nil
}

// ParseTCPDetail 从 Data[0:20] 解析 TCP 五元组
func ParseTCPDetail(data [256]byte) *TCPConnDetail {
	return &TCPConnDetail{
		SrcIP:    binary.BigEndian.Uint32(data[0:4]),
		DstIP:    binary.BigEndian.Uint32(data[4:8]),
		SrcPort:  binary.BigEndian.Uint16(data[8:10]),
		DstPort:  binary.BigEndian.Uint16(data[10:12]),
		Protocol: data[12],
	}
}

// CString 将固定长度字节数组转换为字符串（截断到 \0）
func CString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
