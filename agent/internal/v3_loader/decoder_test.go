package v3_loader

import (
	"encoding/binary"
	"testing"
)

func TestDecodeEvent_CorrelationKey(t *testing.T) {
	raw := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(raw[0:4], 1234)
	binary.LittleEndian.PutUint64(raw[16:24], 999999)
	copy(raw[24:40], []byte("test_comm"))
	copy(raw[56:312], []byte("/bin/true"))
	binary.LittleEndian.PutUint64(raw[312:320], 0xDEADBEEFCAFEBABE)

	h, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent 失败: %v", err)
	}
	if h.PID != 1234 {
		t.Errorf("PID: got %d, want 1234", h.PID)
	}
	if h.Timestamp != 999999 {
		t.Errorf("Timestamp: got %d, want 999999", h.Timestamp)
	}
	if h.CorrelationKey != 0xDEADBEEFCAFEBABE {
		t.Errorf("CorrelationKey: got 0x%x, want 0xDEADBEEFCAFEBABE", h.CorrelationKey)
	}
}

func TestDecodeEvent_ShortPacket(t *testing.T) {
	raw := make([]byte, HeaderSize-1)
	if _, err := DecodeEvent(raw); err == nil {
		t.Error("短包应该报错")
	}
}
