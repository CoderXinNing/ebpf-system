package handler

import (
	"strconv"
)

// GetSecuritySetting 获取安全设置
func (h *Handler) GetSecuritySetting(key string, defaultVal int) int {
	return h.GetIntSetting(key, defaultVal)
}

// GetIntSetting 获取整数设置
func (h *Handler) GetIntSetting(key string, defaultVal int) int {
	if h.Store == nil {
		return defaultVal
	}
	val, err := h.Store.GetLogSetting(key)
	if err != nil || val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return n
}

// SetIntSetting 设置整数配置
func (h *Handler) SetIntSetting(key string, val int) {
	if h.Store == nil {
		return
	}
	h.Store.SetLogSetting(key, strconv.Itoa(val))
}
