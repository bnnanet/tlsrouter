package ipgate

import (
	"log/slog"
	"strconv"
	"strings"
)

func log() *slog.Logger { return slog.Default().WithGroup("ipgate") }

func commaify(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return "-" + commaify(-n)
	}
	if len(s) <= 3 {
		return s
	}

	rem := len(s) % 3
	if rem == 0 {
		rem = 3
	}

	var result strings.Builder
	result.WriteString(s[:rem])
	for i := rem; i < len(s); i += 3 {
		result.WriteString("," + s[i:i+3])
	}
	return result.String()
}
