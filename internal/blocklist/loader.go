package blocklist

import (
	"bufio"
	"bytes"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)
var prefixes = [][]byte{[]byte("0.0.0.0 "), []byte("*."), []byte("www.")}

type ScannerFunc func([]byte) bool

func scanBlocklist(file *os.File, logger *slog.Logger, handler ScannerFunc) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if bytes.HasPrefix(line, []byte("# ")) {
			if logger != nil {
				logger.Info("Blocklist", "comment", string(line))
			}
			continue
		} else if len(bytes.Trim(line, "# ")) == 0 || bytes.HasPrefix(line, []byte("## ")) {
			continue // ignore double-octothorpe and empty comments
		} else {
			for _, prefix := range prefixes {
				if after, ok := bytes.CutPrefix(line, prefix); ok {
					line = after
				}
			}
			if handler(line) { // finish early?
				break
			}
		}
	}
	return scanner.Err()
}

func countFromFile(path string) (uint, error) {
	var count uint
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	err = scanBlocklist(file, nil, func(_ []byte) bool {
		count++
		return false
	})
	return count, err
}

func streamFromFile(path string, logger *slog.Logger, handler ScannerFunc) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	return scanBlocklist(file, logger, handler)
}

func extractMetadata(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	metadata := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "#" {
			break // end of metadata header
		}
		if line != "" && !strings.HasPrefix(line, "#") {
			break
		}
		after, ok := strings.CutPrefix(line, "# ")
		if !ok {
			continue
		}
		if key, value, found := strings.Cut(after, ": "); found {
			metadata[snakeCase(key)] = value
		}
	}
	return metadata, scanner.Err()
}

func snakeCase(s string) string {
	s = strings.ToLower(s)
	s = nonAlphanumeric.ReplaceAllString(s, "_")
	return strings.Trim(s, "_")
}
