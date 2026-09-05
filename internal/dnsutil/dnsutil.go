package dnsutil

import (
	"strings"
	"unicode/utf8"
)

// DecodeDNSName converts a DNS presentation-format domain name back to its
// proper UTF-8 representation. DNS libraries escape non-ASCII bytes as \DDD
// (decimal), so we need to decode them for proper display in metrics and SSE
// events. For example, \230\181\139\232\175\149.com becomes 测试.com
func DecodeDNSName(name string) string {
	// Fast-path: if there is no backslash, no escaped bytes exist.
	if !strings.Contains(name, "\\") {
		return name
	}

	var result strings.Builder
	result.Grow(len(name))

	for i := 0; i < len(name); i++ {
		if name[i] == '\\' && i+3 < len(name) {
			// Try to parse the next three characters as a decimal byte value
			if num, ok := parseDecimal3(name[i+1 : i+4]); ok {
				result.WriteByte(byte(num))
				i += 3
				continue
			}
		}
		result.WriteByte(name[i])
	}

	decoded := result.String()
	// Try to interpret as UTF-8; if invalid, return the original
	if !utf8.ValidString(decoded) {
		return name
	}
	return decoded
}

// parseDecimal3 parses exactly 3 decimal digits.
// Input must have at least 3 characters.
func parseDecimal3(s string) (int, bool) {
	if s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' || s[2] < '0' || s[2] > '9' {
		return 0, false
	}
	return int(s[0]-'0')*100 + int(s[1]-'0')*10 + int(s[2]-'0'), true
}
