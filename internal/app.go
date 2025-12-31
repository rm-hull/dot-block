package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Depado/ginprom"
	"github.com/caddyserver/certmagic"
	"github.com/cockroachdb/errors"
	"github.com/earthboundkid/versioninfo/v2"
	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/ip2location/ip2location-go/v9"
	"github.com/joho/godotenv"
	"github.com/libdns/cloudflare"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/forwarder"
	"github.com/rm-hull/dot-block/internal/logging"
	"github.com/rm-hull/dot-block/internal/mobileconfig"
	"github.com/rm-hull/godx"
	"github.com/robfig/cron/v3"
	sloggin "github.com/samber/slog-gin"
	healthcheck "github.com/tavsec/gin-healthcheck"
	hc_config "github.com/tavsec/gin-healthcheck/config"
	"golang.org/x/sync/errgroup"
)

const CACHE_SIZE = 1_000_000

type App struct {
	Upstreams    []string
	DataDir      string
	BlockListUrl string
	DevMode      bool
	HttpPort     int
	DnsPort      int
	DotPort      int
	AllowedHosts []string
	MetricsAuth  string
	CronSchedule struct {
		Downloader  string
		CacheReaper string
	}
	Logger       *slog.Logger
	NoDnsLogging bool
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

	// _, err = geoblock.Fetch("DB1LITEBIN", app.DataDir, app.Logger)
	// if err != nil {
	// 	return errors.Wrap(err, "failed to download geoblock database")
	// }
	geolocationDb := fmt.Sprintf("%s/ip2location/IP2LOCATION-LITE-DB1.BIN", app.DataDir)
	app.Logger.Info("Loading geolocation database", "file", geolocationDb)
	geoIpDb, err := ip2location.OpenDB(geolocationDb)
	if err != nil {
		return errors.Wrap(err, "failed to open geoblock database")
	}

	hosts, err := blocklist.Fetch(app.BlockListUrl, app.Logger)
	if err != nil {
		return errors.Wrap(err, "failed to download blocklist")
	}

	blockList := blocklist.NewBlockList(hosts, 0.0001, app.Logger)

	adapter := logging.NewCronLoggerAdapter(app.Logger, "cron")
	crontab := cron.New(cron.WithChain(cron.Recover(adapter)), cron.WithLogger(adapter))
	crontab.Start()
	defer crontab.Stop()

	app.Logger.Info("Creating blocklist cron job", "schedule", app.CronSchedule)
	if _, err = crontab.AddJob(app.CronSchedule.Downloader, blocklist.NewBlocklistUpdaterCronJob(blockList, app.BlockListUrl)); err != nil {
		return errors.Wrap(err, "failed to create blocklist downloader cron job")
	}

	certCacheDir := fmt.Sprintf("%s/certcache", app.DataDir)
	if err := os.MkdirAll(certCacheDir, 0700); err != nil {
		return errors.Wrap(err, "failed to create certcache directory")
	}

	// certmagic setup
	zapLogger := logging.NewZapLoggerAdapter(app.Logger, "certmagic")
	certmagic.Default.Logger = zapLogger
	certmagic.DefaultACME.Logger = zapLogger
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = os.Getenv("ACME_EMAIL")
	certmagic.Default.Storage = &certmagic.FileStorage{Path: certCacheDir}

	var magic *certmagic.Config

	if !app.DevMode {
		token := os.Getenv("CLOUDFLARE_API_TOKEN")
		if token == "" {
			return errors.New("CLOUDFLARE_API_TOKEN environment variable is required for DNS-01 challenge")
		}

		certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
			DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflare.Provider{
					APIToken: token,
				},
			},
		}

		magic = certmagic.NewDefault()
		if err := magic.ManageSync(context.Background(), app.AllowedHosts); err != nil {
			return errors.Wrap(err, "failed to manage certificates")
		}
	}

	r, err := app.startHttpServer(dnsClient)
	if err != nil {
		return errors.Wrap(err, "failed to initialize HTTP server")
	}

	dispatcher, err := forwarder.NewDNSDispatcher(dnsClient, blockList, geoIpDb, CACHE_SIZE, app.Logger, app.NoDnsLogging)
	if err != nil {
		return errors.Wrap(err, "failed to create dispatcher")
	}
	app.Logger.Info("Creating cache reaper cron job", "schedule", app.CronSchedule.CacheReaper)
	if _, err = crontab.AddJob(app.CronSchedule.CacheReaper, forwarder.NewCacheReaperCronJob(dispatcher)); err != nil {
		return errors.Wrap(err, "failed to create cache reaper cron job")
	}

	dnsPort := fmt.Sprintf(":%d", app.DnsPort)
	dotPort := fmt.Sprintf(":%d", app.DotPort)

	var group errgroup.Group

	group.Go(func() error {
		app.Logger.Info("Starting HTTP server for mobileconfig, metrics & healthcheck", "port", app.HttpPort)
		return r.Run(fmt.Sprintf(":%d", app.HttpPort))
	})

	group.Go(func() error {
		app.Logger.Info("Starting UDP DNS server", "port", app.DnsPort)
		srv := &dns.Server{Addr: dnsPort, Net: "udp", Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest)}
		return srv.ListenAndServe()
	})

	group.Go(func() error {
		app.Logger.Info("Starting TCP DNS server", "port", app.DnsPort)
		srv := &dns.Server{Addr: dnsPort, Net: "tcp", Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest)}
		return srv.ListenAndServe()
	})

	group.Go(func() error {
		var tlsConfig *tls.Config
		logMessage := "Starting DoT server (plain TCP) in DEV mode"
		dotNet := "tcp"
		if !app.DevMode {
			logMessage = "Starting DNS-over-TLS server"
			dotNet = "tcp-tls"
			tlsConfig = &tls.Config{
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"dot"}, // important for DNS-over-TLS
				GetCertificate: magic.GetCertificate,
			}
		}
		app.Logger.Info(logMessage, "port", app.DotPort)
		srv := &dns.Server{Addr: dotPort, Net: dotNet, TLSConfig: tlsConfig, Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest)}
		return srv.ListenAndServe()
	})

	return group.Wait()
}

func (app *App) startHttpServer(dnsClient *forwarder.RoundRobinClient) (*gin.Engine, error) {
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

	if len(app.AllowedHosts) == 0 {
		return nil, errors.New("cannot create mobileconfig handler: at least one hostname must be configured via --allowed-host")
	}
	serverName := app.AllowedHosts[0]
	r.GET("/.mobileconfig", mobileconfig.NewHandler(serverName))

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
