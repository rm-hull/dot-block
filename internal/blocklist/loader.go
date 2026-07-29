package blocklist

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strings"
)

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)
var prefixes = [][]byte{[]byte("0.0.0.0 "), []byte("*."), []byte("www.")}

type ScannerFunc func([]byte) bool

// countNewlines reads through an io.Reader and counts newline characters,
// providing a fast, low-memory estimate of the number of lines (and thus
// approximate number of hosts) in a blocklist file.
func countNewlines(r io.Reader) (uint, error) {
	var count uint
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		for i := range n {
			if buf[i] == '\n' {
				count++
			}
		}
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

func stream(r io.Reader, handler ScannerFunc) (map[string]string, error) {
	metadata := make(map[string]string)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		if after, ok := bytes.CutPrefix(line, []byte("# ")); ok {
			if key, value, found := bytes.Cut(after, []byte(": ")); found {
				metadata[snakeCase(string(key))] = string(value)
				continue
			}
		}

		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}

		for _, prefix := range prefixes {
			if after, ok := bytes.CutPrefix(line, prefix); ok {
				line = after
			}
		}
		if handler(line) {
			break
		}
	}

	return metadata, scanner.Err()
}

func snakeCase(s string) string {
	s = strings.ToLower(s)
	s = nonAlphanumeric.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}
