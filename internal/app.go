package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
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
	"github.com/joho/godotenv"
	"github.com/libdns/cloudflare"
	"github.com/miekg/dns"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/forwarder"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/logging"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/mobileconfig"
	"github.com/rm-hull/godx"
	"github.com/robfig/cron/v3"
	sloggin "github.com/samber/slog-gin"
	healthcheck "github.com/tavsec/gin-healthcheck"
	hc_config "github.com/tavsec/gin-healthcheck/config"
	"golang.org/x/sync/errgroup"
)

type App struct {
	Logger        *slog.Logger `json:"-"`
	LogLevel      string       `json:"log_level"`
	DevMode       bool         `json:"dev_mode"`
	DataDir       string       `json:"data_dir"`
	HttpPort      int          `json:"http_port"`
	DnsPort       int          `json:"dns_port"`
	DotPort       int          `json:"dot_port"`
	Upstreams     []string     `json:"upstreams"`
	BlockListURLs []string     `json:"blocklist_urls"`
	AllowedHosts  []string     `json:"allowed_hosts"`
	MetricsAuth   string       `json:"-"`
	MaxCacheSize  int          `json:"max_cache_size"`
	CronSchedule  struct {
		Downloader  string `json:"downloader"`
		CacheReaper string `json:"cache_reaper"`
		IP2Location string `json:"ip2location"`
	} `json:"cron_schedule"`
	CacheTtlFloor        time.Duration `json:"cache_ttl_floor"`
	ConnectionTimeout    time.Duration `json:"connection_timeout"`
	ConnectionPoolSize   int           `json:"connection_pool_size"`
	RequireProxyProtocol bool          `json:"require_proxy_protocol"`
	TrustedProxies       []string      `json:"trusted_proxies,omitempty"`
}

func (app *App) LogValue() slog.Value {
	m := make(map[string]any)
	v := reflect.ValueOf(app).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}

		name := field.Name
		if tag != "" {
			name = strings.Split(tag, ",")[0]
		}

		val := v.Field(i)
		if dur, ok := val.Interface().(time.Duration); ok {
			m[name] = dur.String()
		} else {
			m[name] = val.Interface()
		}
	}

	return slog.Any("temp", m).Value
}

func (app *App) RunServer() error {
	if err := godotenv.Load(); err != nil {
		app.Logger.Warn("No .env file found")
	}
	godx.Diagnostics(app.Logger)
	app.Logger.Info("Configuation on startup", "app", app)

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

	adapter := logging.NewCronLoggerAdapter(app.Logger, "cron")
	crontab := cron.New(cron.WithChain(cron.Recover(adapter)), cron.WithLogger(adapter))
	crontab.Start()
	defer crontab.Stop()

	geolocationDb := fmt.Sprintf("%s/ip2location/IP2LOCATION-LITE-DB1.BIN", app.DataDir)
	if _, err := os.Stat(geolocationDb); os.IsNotExist(err) {
		app.Logger.Info("Geolocation database not found, downloading...")
		_, err = geoblock.Fetch("DB1LITEBIN", app.DataDir, app.Logger)
		if err != nil {
			return errors.Wrap(err, "failed to download geoblock database")
		}
	}

	app.Logger.Info("Loading geolocation database", "file", geolocationDb)
	geoIpLookup, err := geoblock.NewGeoIpLookup(geolocationDb)
	if err != nil {
		return errors.Wrap(err, "failed to open geoblock database")
	}

	app.Logger.Info("Creating IP2Location updater cron job", "schedule", app.CronSchedule.IP2Location)
	if _, err = crontab.AddJob(app.CronSchedule.IP2Location, geoblock.NewIp2LocationUpdaterCronJob(app.Logger, "DB1LITEBIN", app.DataDir, geoIpLookup)); err != nil {
		return errors.Wrap(err, "failed to create IP2Location updater cron job")
	}

	allHosts := make([]string, 0)
	for _, url := range app.BlockListURLs {
		hosts, err := blocklist.Fetch(url, app.Logger)
		if err != nil {
			return errors.Wrapf(err, "failed to download blocklist: %s", url)
		}

		allHosts = append(allHosts, hosts...)
	}

	blockList := blocklist.NewBlockList(allHosts, 0.0001, app.Logger)

	app.Logger.Info("Creating blocklist downloader cron job", "schedule", app.CronSchedule.Downloader)
	blocklistUpdater := blocklist.NewBlocklistUpdater(blockList, app.BlockListURLs)
	if _, err = crontab.AddJob(app.CronSchedule.Downloader, blocklistUpdater); err != nil {
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

	cache := forwarder.NewDNSCache(app.MaxCacheSize, app.Logger)
	metrics, err := metrics.NewDNSMetrics(cache, geoIpLookup)
	if err != nil {
		return errors.Wrap(err, "failed to initialize metrics")
	}
	dnsClient, err := forwarder.NewRoundRobinClient(metrics, app.ConnectionTimeout, app.ConnectionPoolSize, app.Logger, app.Upstreams...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize upstream DNS client")
	}

	r, err := app.startHttpServer(dnsClient, blocklistUpdater)
	if err != nil {
		return errors.Wrap(err, "failed to initialize HTTP server")
	}

	dispatcher, err := forwarder.NewDNSDispatcher(cache, metrics, dnsClient, blockList, app.CacheTtlFloor, app.Logger)
	if err != nil {
		return errors.Wrap(err, "failed to create dispatcher")
	}
	defer dispatcher.Close()

	app.Logger.Info("Creating cache reaper cron job", "schedule", app.CronSchedule.CacheReaper)
	if _, err = crontab.AddJob(app.CronSchedule.CacheReaper, forwarder.NewCacheReaperCronJob(dispatcher)); err != nil {
		return errors.Wrap(err, "failed to create cache reaper cron job")
	}

	var group errgroup.Group

	group.Go(func() error {
		app.Logger.Info("Starting HTTP server for mobileconfig, metrics & healthcheck", "port", app.HttpPort)
		return r.Run(fmt.Sprintf(":%d", app.HttpPort))
	})

	group.Go(func() error {
		if app.DnsPort == 0 {
			app.Logger.Warn("Skipping UDP DNS server: dns-port not specified")
			return nil
		}
		app.Logger.Info("Starting UDP DNS server", "port", app.DnsPort)
		return (&dns.Server{
			Addr:    fmt.Sprintf(":%d", app.DnsPort),
			Net:     "udp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceUDP)),
		}).ListenAndServe()
	})

	group.Go(func() error {
		if app.DnsPort == 0 {
			app.Logger.Warn("Skipping TCP DNS server: dns-port not specified")
			return nil
		}
		app.Logger.Info("Starting TCP DNS server", "port", app.DnsPort)
		return (&dns.Server{
			Addr:    fmt.Sprintf(":%d", app.DnsPort),
			Net:     "tcp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceTCP)),
		}).ListenAndServe()
	})

	group.Go(func() error {
		dotPort := fmt.Sprintf(":%d", app.DotPort)
		listener, err := net.Listen("tcp", dotPort)
		if err != nil {
			return errors.Wrap(err, "failed to create DoT listener")
		}
		defer func() {
			err := listener.Close()
			if err != nil {
				app.Logger.Warn("error closing DoT listener", "error", err)
			}
		}()

		if app.DevMode {
			app.Logger.Info("Starting DoT server (plain TCP) in DEV mode", "port", app.DotPort)
		} else {
			app.Logger.Info("Starting DNS-over-TLS server", "port", app.DotPort)

			proxyListener, err := app.newProxyListener(listener)
			if err != nil {
				return err
			}

			listener = tls.NewListener(proxyListener, &tls.Config{
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"dot"},
				GetCertificate: magic.GetCertificate,
			})
		}

		return (&dns.Server{
			Addr:     dotPort,
			Net:      "tcp",
			Listener: listener,
			Handler:  dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceDoT)),
		}).ActivateAndServe()
	})

	return group.Wait()
}

func (app *App) newProxyListener(base net.Listener) (*proxyproto.Listener, error) {
	var proxyListener *proxyproto.Listener
	if len(app.TrustedProxies) > 0 {
		// If trusted proxies are specified, use a whitelist policy
		app.Logger.Info("Using PROXY protocol with trusted proxy whitelist", "trusted_proxies", app.TrustedProxies)
		policy, err := proxyproto.ConnStrictWhiteListPolicy(app.TrustedProxies)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create trusted proxy whitelist policy")
		}
		proxyListener = &proxyproto.Listener{
			Listener:   base,
			ConnPolicy: policy,
		}
	} else if app.RequireProxyProtocol {
		// If no trusted proxies specified but requirement is on, use REQUIRE policy
		proxyListener = &proxyproto.Listener{
			Listener: base,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}
	} else {
		// If requirement is off, use USE policy (optional)
		app.Logger.Warn("Running with PROXY protocol optional; client IPs may be spoofed if not behind a trusted proxy")
		proxyListener = &proxyproto.Listener{
			Listener: base,
			Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
				return proxyproto.USE, nil
			},
		}
	}
	return proxyListener, nil
}

func (app *App) startHttpServer(dnsClient *forwarder.RoundRobinClient, blocklistUpdater *blocklist.BlocklistUpdater) (*gin.Engine, error) {
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
		sloggin.NewWithConfig(app.Logger, *newStructuredLoggingConfig()),
		prometheus.Instrument(),
		sentryErrorHandler(),
	)

	if err := healthcheck.New(r, hc_config.DefaultConfig(), dnsClient.Healthchecks()); err != nil {
		return nil, errors.Wrap(err, "failed to initialize healthcheck")
	}

	if app.MetricsAuth == "" {
		app.Logger.Warn("Metrics & reload endpoints are not protected by basic auth")
		r.GET("/metrics", gin.WrapH(promhttp.Handler()))
		r.GET("/reload", blocklistUpdater.NewHandler())

	} else {
		parts := strings.SplitN(app.MetricsAuth, ":", 2)
		if len(parts) == 2 {
			app.Logger.Info("Protecting /metrics and /reload endpoints with basic auth")
			user := parts[0]
			pass := parts[1]
			authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
				user: pass,
			}))
			authorized.GET("/metrics", gin.WrapH(promhttp.Handler()))
			authorized.GET("/reload", blocklistUpdater.NewHandler())

		} else {
			return nil, errors.Newf("invalid metrics-auth value: %s", app.MetricsAuth)
		}
	}

	if len(app.AllowedHosts) == 0 {
		return nil, errors.New("cannot create mobileconfig handler: at least one hostname must be configured via --allowed-host")
	}
	serverName := app.AllowedHosts[0]
	r.GET("/.mobileconfig", mobileconfig.NewHandler(serverName))

	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "https://github.com/rm-hull/dot-block/blob/main/README.md")
	})

	r.GET("/robots.txt", func(c *gin.Context) {
		c.String(http.StatusOK, "User-agent: *\nDisallow: /\n")
	})

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

func newStructuredLoggingConfig() *sloggin.Config {
	config := sloggin.DefaultConfig()
	config.WithUserAgent = true
	config.WithClientIP = true
	config.Filters = append(config.Filters, sloggin.IgnorePath("/healthz", "/metrics"))

	return &config
}
