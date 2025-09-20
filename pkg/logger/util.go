package logger

import (
	"encoding/json"
	"strings"
)

func ifZero[T ~int](value, defaultValue T) T {
	if value == 0 {
		return defaultValue
	}
	return value
}

func dirOf(p string) string {
	if p == "" {
		return "."
	}
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}

func SafeJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
