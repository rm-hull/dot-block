package geoblock

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/dustin/go-humanize"
	"github.com/rm-hull/dot-block/internal/downloader"
)

type Ip2LocationUpdater struct {
	logger  *slog.Logger
	url     string
	dataDir string
}

func NewIp2LocationUpdaterCronJob(logger *slog.Logger, fileId string, dataDir string) *Ip2LocationUpdater {
	return &Ip2LocationUpdater{
		logger:  logger,
		url:     url,
		dataDir: dataDir,
	}
}

func (job *Ip2LocationUpdater) Run() {
	_, err := Fetch(job.url, job.dataDir, job.logger)
	if err != nil {
		job.logger.Error("failed to download ip2location list for cron reload", "error", err)
	}
}

func Fetch(fileId string, dataDir string, logger *slog.Logger) ([]string, error) {

	token := os.Getenv("IP2LOCATION_TOKEN")
	if token == "" {
		return nil, errors.New("IP2LOCATION_TOKEN not set in environment")
	}
	url := fmt.Sprintf("https://www.ip2location.com/download/?token=%s&file=%s", token, fileId)

	dataDir += "/ip2location"
if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, errors.Wrapf(err, "failed to create data directory %q", dataDir)
	}

	files := make([]string, 0)
	err := downloader.TransientDownload(logger, "ip2location", url, token, func(zipPath string, header http.Header) error {
		r, err := zip.OpenReader(zipPath)
		if err != nil {
			return errors.Wrapf(err, "failed to open zip file")
		}
		defer func() {
			if err := r.Close(); err != nil {
logger.Warn("error closing zip file", "error", err)
			}
		}()

		for _, f := range r.File {
			if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".BIN") {
				continue
			}

			filename, err := extractZipFile(f, dataDir, logger)
			if err != nil {
				return errors.Wrapf(err, "failed to extract file from zip")
			}
			files = append(files, filename)
		}

		return nil
	})

	return files, err
}

func extractZipFile(f *zip.File, toFolder string, logger *slog.Logger) (string, error) {
destPath := filepath.Join(toFolder, path.Base(f.Name))
	logger.Info(fmt.Sprintf("Extracting file (%s) from zip", humanize.Bytes(uint64(f.FileInfo().Size()))),
		"to", destPath,
	)

	rc, err := f.Open()
	if err != nil {
		return "", errors.Wrapf(err, "failed to open file in zip")
	}
	defer func() {
		if err := rc.Close(); err != nil {
			logger.Error("error closing file in zip", "error", err)
		}
	}()

	outFile, err := os.Create(destPath)
	if err != nil {
		return "", errors.Wrapf(err, "failed to create output file")
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			logger.Error("error closing output file", "error", err)
		}
	}()

	_, err = io.Copy(outFile, rc)
	if err != nil {
		return "", errors.Wrapf(err, "failed to copy file contents")
	}
	return destPath, nil
}
