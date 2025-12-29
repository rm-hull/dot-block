package downloader

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/dustin/go-humanize"
)

func isValidUrl(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func TransientDownload(logger *slog.Logger, purpose string, uri string, redact string, handler func(tmpfile string, header http.Header) error) error {
	if !isValidUrl(uri) {
		return handler(uri, http.Header{})
	}

	redactedUri := uri
	if redact != "" {
		redactedUri = strings.ReplaceAll(uri, redact, "********")
	}
logger.Info("Retrieving file", "purpose", purpose, "uri", redactedUri)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Add("User-Agent", "dot-block downloader (https://github.com/rm-hull/dot-block)")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
return errors.Wrapf(err, "failed to fetch from %s", redactedUri)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Error("failed to close body", "error", err)
		}
	}()

	if resp.StatusCode > 299 {
return fmt.Errorf("error response from %s: %s", redactedUri, resp.Status)
	}

	tmp, err := os.CreateTemp("", fmt.Sprintf("dot-block-%s-download-*", purpose))
	if err != nil {
		return err
	}
	tmpfile := tmp.Name()

	lastModified := resp.Header.Get("Last-Modified")
	if lastModified == "" {
		lastModified = "unknown"
	}
	logger.Info(fmt.Sprintf("Remote last modified: %s", lastModified))

	filesize := "unknown size"
	if resp.ContentLength >= 0 {
		filesize = humanize.Bytes(uint64(resp.ContentLength))
	}
	logger.Info(fmt.Sprintf("Downloading content (%s) to %s", filesize, tmpfile))

	defer func() {
		logger.Info(fmt.Sprintf("Removing temporary file: %s", tmpfile))
		if err := os.Remove(tmpfile); err != nil {
			logger.Info(fmt.Sprintf("failed to remove file %s: %v", tmpfile, err))
		}
	}()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		_ = tmp.Close()
		return errors.Wrapf(err, "failed to copy response body")
	}

	if err := tmp.Close(); err != nil {
		return errors.Wrapf(err, "failed to close temporary file")
	}
	return handler(tmpfile, resp.Header)
}
