package blocklist

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"
)

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)
var prefixes = [][]byte{[]byte("0.0.0.0 "), []byte("*."), []byte("www.")}

type ScannerFunc func([]byte) bool

func countLines(path string) (uint, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	var count uint
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Skip comments and metadata
		if bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		count++
	}
	return count, scanner.Err()
}

// stream processes a blocklist file, parsing metadata headers first, then
// scanning the rest of the file for hostnames.
func stream(path string, handler ScannerFunc) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	metadata := make(map[string]string)
	scanner := bufio.NewScanner(file)

	// 1. Parse Metadata
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if bytes.Equal(line, []byte("#")) {
			break // end of metadata header
		}
		if !bytes.HasPrefix(line, []byte("#")) {
			// Hit actual data, stop metadata parsing
			break
		}
		after, ok := bytes.CutPrefix(line, []byte("# "))
		if !ok {
			continue
		}
		if key, value, found := bytes.Cut(after, []byte(": ")); found {
			metadata[snakeCase(string(key))] = string(value)
		}
	}

	// 2. Parse Hostnames
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
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
