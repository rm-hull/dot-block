package blocklist

import (
	"bufio"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

var nonAlphanumeric = regexp.MustCompile(`[^a-z0-9]+`)
var prefixes = []string{"0.0.0.0 ", "*.", "www."}

type ScannerFunc func(string) bool

func scanBlocklist(file *os.File, logger *slog.Logger, handler ScannerFunc) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# ") && logger != nil {
			logger.Info("Blocklist", "comment", line)
		} else if len(strings.Trim(line, "# ")) == 0 || strings.HasPrefix(line, "## ") {
			continue // ignore double-octothorpe and empty comments
		} else {
			for _, prefix := range prefixes {
				if after, ok := strings.CutPrefix(line, prefix); ok {
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
	err = scanBlocklist(file, nil, func(_ string) bool {
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
