package blocklist

import (
	"bufio"
	"log/slog"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
)

var prefixes = []string{"0.0.0.0 ", "*.", "www."}

func scanBlocklist(file *os.File, logger *slog.Logger, handler func(string)) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# ") {
			logger.Info("Blocklist", "comment", line)
		} else if len(strings.Trim(line, "# ")) == 0 || strings.HasPrefix(line, "## ") {
			continue // ignore double-octothorpe and empty comments
		} else {
			for _, prefix := range prefixes {
				if after, ok := strings.CutPrefix(line, prefix); ok {
					line = after
				}
			}
			handler(line)
		}
	}
	return scanner.Err()
}

func countFromFile(path string, logger *slog.Logger) (uint, error) {
	var count uint
	file, err := os.Open(path)
	if err != nil {
		return 0, errors.Wrap(err, "failed to open blocklist file for counting")
	}
	defer func() { _ = file.Close() }()
	err = scanBlocklist(file, logger, func(_ string) {
		count++
	})
	return count, err
}

func streamFromFile(path string, logger *slog.Logger, handler func(string)) error {
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "failed to open blocklist file for streaming")
	}
	defer func() { _ = file.Close() }()
	return scanBlocklist(file, logger, handler)
}

// func streamHosts(url string, logger *slog.Logger, handler func(string)) error {
// 	return downloader.TransientDownload(logger, "", "blocklist-stream", url, "", func(tmpFile string, header http.Header) error {
// 		return streamFromFile(tmpFile, logger, handler)
// 	})
// }
