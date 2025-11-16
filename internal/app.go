package internal

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Depado/ginprom"
	"github.com/cockroachdb/errors"
	"github.com/earthboundkid/versioninfo/v2"
	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/forwarder"
	"github.com/rm-hull/godx"
	"github.com/robfig/cron/v3"
	sloggin "github.com/samber/slog-gin"
	healthcheck "github.com/tavsec/gin-healthcheck"
	hc_config "github.com/tavsec/gin-healthcheck/config"
	"golang.org/x/crypto/acme/autocert"
)

const CACHE_SIZE = 1_000_000

type App struct {
	Upstreams    []string
	CertCacheDir string
	BlockListUrl string
	DevMode      bool
	HttpPort     int
	AllowedHosts []string
	MetricsAuth  string
	CronSchedule struct {
		Downloader  string
		CacheReaper string
	}
	Logger *slog.Logger
}

func (app *App) RunServer() error {
	if err := godotenv.Load(); err != nil {
		app.Logger.Warn("No .env file found")
	}
	godx.GitVersion()
	godx.EnvironmentVars()
	godx.UserInfo()

	err := sentry.Init(sentry.ClientOptions{
		Dsn:         os.Getenv("SENTRY_DSN"),
		Debug:       app.DevMode,
		Release:     versioninfo.Revision[:7],
		Environment: app.environment(),
	})
	if err != nil {
		app.Logger.Error("sentry.Init failed", "error", err)
	}
	defer sentry.Flush(2 * time.Second)

	timeout := 3 * time.Second
	dnsClient, err := forwarder.NewRoundRobinClient(timeout, app.Upstreams...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize upstream DNS client")
	}

	hosts, err := blocklist.DownloadBlocklist(app.BlockListUrl, app.Logger)
	if err != nil {
		return errors.Wrap(err, "failed to download blocklist")
	}

	blockList := blocklist.NewBlockList(hosts, 0.0001, app.Logger)

	adapter := &SlogAdapter{prefix: "Cron ", logger: app.Logger}
	crontab := cron.New(cron.WithChain(cron.Recover(adapter)), cron.WithLogger(adapter))
	crontab.Start()
	defer crontab.Stop()

	app.Logger.Info("Creating blocklist cron job", "schedule", app.CronSchedule)
	if _, err = crontab.AddJob(app.CronSchedule.Downloader, blocklist.NewDownloaderCronJob(blockList, app.BlockListUrl)); err != nil {
		return errors.Wrap(err, "failed to create blocklist cron job")
	}

	manager := &autocert.Manager{
		Cache:      autocert.DirCache(app.CertCacheDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(app.AllowedHosts...),
	}

	if _, err := app.startHttpServer(dnsClient, manager); err != nil {
		return errors.Wrap(err, "failed to start HTTP server")
	}

	dispatcher, err := forwarder.NewDNSDispatcher(dnsClient, blockList, CACHE_SIZE, app.Logger)
	if err != nil {
		return errors.Wrap(err, "failed to create dispatcher")
	}
	app.Logger.Info("Creating cache reaper cron job", "schedule", app.CronSchedule.CacheReaper)
	if _, err = crontab.AddJob(app.CronSchedule.CacheReaper, forwarder.NewCacheReaperCronJob(dispatcher)); err != nil {
		return errors.Wrap(err, "failed to create cache reaper cron job")
	}

	if app.DevMode {
		dnsServer := &dns.Server{
			Addr:    ":8053",
			Net:     "tcp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest),
		}

		app.Logger.Info("Starting DNS server in DEV mode", "port", 8053, "tls", false)
		if err := dnsServer.ListenAndServe(); err != nil {
			return errors.Wrap(err, "failed to start DNS server in dev mode")
		}
		return nil
	}

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"dot"}, // important for DNS-over-TLS
		GetCertificate: manager.GetCertificate,
	}

	dnsServer := &dns.Server{
		Addr:      ":853",
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   dns.HandlerFunc(dispatcher.HandleDNSRequest),
	}

	app.Logger.Info("Starting DNS-over-TLS server", "port", 853)
	if err := dnsServer.ListenAndServe(); err != nil {
		return errors.Wrap(err, "failed to start DoT server")
	}
	return nil
}

func (app *App) startHttpServer(dnsClient *forwarder.RoundRobinClient, manager *autocert.Manager) (*gin.Engine, error) {
	if !app.DevMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	if app.DevMode {
		app.Logger.Warn("pprof endpoints are enabled and exposed. Do not run with this flag in production.")
		pprof.Register(r)
	}

	prometheus := ginprom.New(
		ginprom.Path("/metrics"),
		ginprom.Ignore("/healthz", "/metrics"),
	)

	r.Use(
		sentrygin.New(sentrygin.Options{
			Repanic:         true,
			WaitForDelivery: false,
			Timeout:         5 * time.Second,
		}),
		gin.Recovery(),
		sloggin.NewWithFilters(app.Logger, sloggin.IgnorePath("/healthz", "/metrics")),
		prometheus.Instrument(),
		sentryErrorHandler(),
	)

	if err := healthcheck.New(r, hc_config.DefaultConfig(), dnsClient.Healthchecks()); err != nil {
		return nil, errors.Wrap(err, "failed to initialize healthcheck")
	}

	if app.MetricsAuth == "" {
		app.Logger.Warn("Metrics endpoint is not protected by basic auth")
		r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	} else {
		parts := strings.SplitN(app.MetricsAuth, ":", 2)
		if len(parts) == 2 {
			app.Logger.Info("Protecting /metrics endpoint with basic auth")
			user := parts[0]
			pass := parts[1]
			authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
				user: pass,
			}))
			authorized.GET("/metrics", gin.WrapH(promhttp.Handler()))

		} else {
			return nil, errors.Newf("invalid metrics-auth value: %s", app.MetricsAuth)
		}
	}

	r.Any("/.well-known/acme-challenge/*path", gin.WrapH(manager.HTTPHandler(nil)))

	go func() {
		app.Logger.Info("Starting HTTP server for ACME challenge, metrics & healthcheck", "port", app.HttpPort)
		port := fmt.Sprintf(":%d", app.HttpPort)
		if err := r.Run(port); err != nil {
			app.Logger.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	return r, nil
}

func (app *App) environment() string {
	if app.DevMode {
		return "DEVELOPMENT"
	}
	return "PRODUCTION"
}

func sentryErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			hub := sentrygin.GetHubFromContext(c)
			for _, e := range c.Errors {
				if hub != nil {
					hub.CaptureException(e.Err)
				} else {
					sentry.CaptureException(e.Err)
				}
			}
		}
	}
}
