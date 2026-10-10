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
	var val string
	var err error

	if h.GetSettingFunc != nil {
		val, err = h.GetSettingFunc(key)
	} else {
		return defaultVal
	}

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
	if h.SetSettingFunc != nil {
		h.SetSettingFunc(key, strconv.Itoa(val))
	}
}

// GetStringSetting 获取字符串设置
func (h *Handler) GetStringSetting(key, defaultVal string) string {
	if h.GetSettingFunc != nil {
		v, err := h.GetSettingFunc(key)
		if err == nil && v != "" {
			return v
		}
	}
	return defaultVal
}

// SetStringSetting 设置字符串
func (h *Handler) SetStringSetting(key, val string) {
	if h.SetSettingFunc != nil {
		h.SetSettingFunc(key, val)
	}
}
