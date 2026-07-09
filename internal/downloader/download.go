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

func isValidFile(uri string) (string, bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" {
		return "", false
	}

	path := u.Path
	if u.Host != "" && u.Host != "localhost" {
		path = u.Host + path
	}
	return path, true
}

func isValidUrl(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "file")
}

func Download(logger *slog.Logger, dataDir, purpose, uri, redact string) (string, http.Header, bool, error) {
	if path, ok := isValidFile(uri); ok {
		return path, http.Header{}, false, nil
	}

	if !isValidUrl(uri) {
		return "", nil, false, fmt.Errorf("invalid URL: %s", uri)
	}

	redactedUri := uri
	if redact != "" {
		redactedUri = strings.ReplaceAll(uri, redact, "********")
	}
	logger.Info("Retrieving file", "purpose", purpose, "uri", redactedUri)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return "", nil, false, errors.Wrapf(err, "failed to create request")
	}

	req.Header.Add("User-Agent", "dot-block downloader (https://github.com/rm-hull/dot-block)")
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, false, errors.Wrapf(err, "failed to fetch from %s", redactedUri)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Error("failed to close body", "error", err)
		}
	}()

	if resp.StatusCode > 299 {
		return "", nil, false, fmt.Errorf("error response from %s: %s", redactedUri, resp.Status)
	}

	tmp, err := os.CreateTemp(dataDir, fmt.Sprintf("dot-block-%s-download-*", purpose))
	if err != nil {
		return "", nil, false, err
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

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		_ = tmp.Close()
		return "", nil, false, errors.Wrapf(err, "failed to copy response body")
	}

	if err := tmp.Close(); err != nil {
		return "", nil, false, errors.Wrapf(err, "failed to close temporary file")
	}
	return tmpfile, resp.Header, true, nil
}

func TransientDownload(logger *slog.Logger, dataDir, purpose, uri, redact string, handler func(tmpfile string, header http.Header) error) error {
	tmpfile, header, isTemp, err := Download(logger, dataDir, purpose, uri, redact)
	if err != nil {
		return err
	}

	defer func() {
		if isTemp {
			logger.Info(fmt.Sprintf("Removing temporary file: %s", tmpfile))
			if err := os.Remove(tmpfile); err != nil {
				logger.Info(fmt.Sprintf("failed to remove file %s: %v", tmpfile, err))
			}
		}
	}()

	return handler(tmpfile, header)
}
