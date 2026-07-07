package geoblock

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"

	"github.com/cockroachdb/errors"
	"github.com/rm-hull/dot-block/internal/downloader"
)

type IpinfoUpdater struct {
	logger      *slog.Logger
	fileName    string
	geoIpLookup GeoIpLookup
}

func NewIpinfoUpdaterCronJob(logger *slog.Logger, fileName string, geoIpLookup GeoIpLookup) *IpinfoUpdater {
	return &IpinfoUpdater{
		logger:      logger,
		fileName:    fileName,
		geoIpLookup: geoIpLookup,
	}
}

func (job *IpinfoUpdater) Run() {
	if _, err := Fetch(job.fileName, job.logger); err != nil {
		job.logger.Error("failed to download ip2location list for cron reload", "error", err)
	}

	if err := job.geoIpLookup.Reopen(); err != nil {
		job.logger.Error("failed to reopen geoblock database after update", "error", err)
	}
}

func Fetch(fileName string, logger *slog.Logger) ([]string, error) {

	token := os.Getenv("IPINFO_TOKEN")
	if token == "" {
		return nil, errors.New("IPINFO_TOKEN not set in environment")
	}
	url := fmt.Sprintf("https://ipinfo.io/data/ipinfo_lite.mmdb?_src=frontend&token=%s", token)

	dataDir := path.Dir(fileName)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, errors.Wrapf(err, "failed to create data directory %q", dataDir)
	}

	files := make([]string, 0)
	err := downloader.TransientDownload(logger, "ipinfo", url, token, func(srcPath string, header http.Header) error {
		logger.Info("Copying downloaded file to data directory", "to", fileName)
		if err := copyFile(srcPath, fileName); err != nil {
			return errors.Wrapf(err, "failed to copy file from %q to %q", srcPath, fileName)
		}
		files = append(files, fileName)

		return nil
	})

	return files, err
}

func copyFile(src, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return errors.Wrapf(err, "failed to open source file %q", src)
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return errors.Wrapf(err, "failed to create destination file %q", dest)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		return errors.Wrapf(err, "failed to copy file from %q to %q", src, dest)
	}
	return nil
}
