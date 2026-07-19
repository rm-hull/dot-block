package blocklist

import (
	"bufio"
	"log/slog"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
)

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
		return 0, errors.Wrap(err, "failed to open blocklist file for counting")
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
		return errors.Wrap(err, "failed to open blocklist file for streaming")
	}
	defer func() { _ = file.Close() }()
	return scanBlocklist(file, logger, handler)
}
