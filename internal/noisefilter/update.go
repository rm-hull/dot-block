package noisefilter

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/rm-hull/dot-block/internal/downloader"
)

type NoiseFilterUpdater struct {
	NoiseFilter *NoiseFilter
	URLs        []string
	Logger      *slog.Logger
}

func NewNoiseFilterUpdater(nf *NoiseFilter, urls []string, logger *slog.Logger) *NoiseFilterUpdater {
	return &NoiseFilterUpdater{
		NoiseFilter: nf,
		URLs:        urls,
		Logger:      logger,
	}
}

func (job *NoiseFilterUpdater) Run() {
	for _, url := range job.URLs {
		err := Fetch(url, job.NoiseFilter, job.Logger)
		if err != nil {
			job.Logger.Error("failed to download noise filter for cron reload", "error", err, "url", url)
			continue
		}
	}
}

func Fetch(url string, nf *NoiseFilter, logger *slog.Logger) error {
	err := downloader.TransientDownload(logger, "noisefilter", url, "", func(tmpFile string, header http.Header) error {
		f, err := os.Open(tmpFile)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := nf.Load(f); err != nil {
			return err
		}

		return nil
	})

	if err == nil {
		logger.Info("Noise filter loaded successfully")
	}
	return err
}
