package collector

import (
	"strconv"
	"strings"
)

func splitLines(data []byte) []string {
	return strings.Split(string(data), "\n")
}

func splitColon(s string) []string {
	return strings.Split(s, ":")
}

func parseUint(s string) (int, bool) {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return v, true
}
