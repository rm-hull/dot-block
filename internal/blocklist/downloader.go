package blocklist

import (
	"bufio"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/dustin/go-humanize"
)

func DownloadBlocklist(url string, logger *slog.Logger) ([]string, error) {

	logger.Info("Retrieving blocklist", "url", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}

	req.Header.Add("User-Agent", "dot-block downloader (https://github.com/rm-hull/dot-block)")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to fetch from %s", url)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Error("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode > 299 {
		return nil, errors.Newf("error response from %s: %s", url, resp.Status)
	}

	lastModified := resp.Header.Get("Last-Modified")
	if lastModified == "" {
		lastModified = "unknown"
	}
	logger.Info("Remote last modified", "last_modified", lastModified)

	filesize := "unknown size"
	if resp.ContentLength >= 0 {
		filesize = humanize.Bytes(uint64(resp.ContentLength))
	}
	logger.Info("Downloading content", "filesize", filesize)

	blocklist := make([]string, 0, 100_000)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# ") {
			logger.Info("Blocklist", "comment", line)
		} else if len(strings.Trim(line, "# ")) == 0 {
			continue
		} else {
			blocklist = append(blocklist, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Wrap(err, "error reading response body")
	}

	logger.Info("Blocklist loaded successfully", "count", len(blocklist))
	return blocklist, nil
}
