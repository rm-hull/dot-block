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
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/rm-hull/dot-block/internal/http/middlewares"
	"github.com/rm-hull/dot-block/internal/http/routes"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/logging"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/noisefilter"
	"github.com/rm-hull/dot-block/internal/telemetry"
	"github.com/rm-hull/godx"
	"github.com/robfig/cron/v3"
	sloggin "github.com/samber/slog-gin"
	healthcheck "github.com/tavsec/gin-healthcheck"
	hc_config "github.com/tavsec/gin-healthcheck/config"
	"golang.org/x/sync/errgroup"
)

type App struct {
	Logger         *slog.Logger `json:"-"`
	LogLevel       string       `json:"log_level"`
	DevMode        bool         `json:"dev_mode"`
	DataDir        string       `json:"data_dir"`
	HttpPort       int          `json:"http_port"`
	DnsPort        int          `json:"dns_port"`
	DotPort        int          `json:"dot_port"`
	Upstreams      []string     `json:"upstreams"`
	BlockListURLs  []string     `json:"blocklist_urls"`
	AllowedHosts   []string     `json:"allowed_hosts"`
	NoiseFilterURL string       `json:"noise_filter_url"`
	MetricsAuth    string       `json:"-"`
	MaxCacheSize   int          `json:"max_cache_size"`
	DisableIpinfo  bool         `json:"disable_ipinfo"`
	CronSchedule   struct {
		Downloader  string `json:"downloader"`
		CacheReaper string `json:"cache_reaper"`
		IPInfo      string `json:"ipinfo"`
	} `json:"cron_schedule"`
	CacheTtlFloor        time.Duration `json:"cache_ttl_floor"`
	RequireProxyProtocol bool          `json:"require_proxy_protocol"`
	TrustedProxies       []string      `json:"trusted_proxies,omitempty"`
	EnableECS            bool          `json:"enable_ecs"`
	Timeouts             struct {
		Read  time.Duration `json:"read"`
		Write time.Duration `json:"write"`
		Dial  time.Duration `json:"dial"`
	} `json:"timeouts"`
}

// LogValue implements slog.LogValuer to ensure nested durations are formatted as strings.
func (app *App) LogValue() slog.Value {
	return slog.AnyValue(structToMap(app))
}

func structToMap(obj any) any {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return obj
	}
	m := make(map[string]any)
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
		val := v.Field(i).Interface()
		// If the field is a struct (and not time.Time), recursively convert it to a map
		// so that ReplaceAttr can recurse into it.
		if reflect.TypeOf(val).Kind() == reflect.Struct && reflect.TypeOf(val) != reflect.TypeFor[time.Time]() {
			m[name] = structToMap(val)
		} else {
			m[name] = val
		}
	}
	return m
}

func (app *App) monitorShutdown(ctx context.Context, name string, shutdownFn func() error) {
	go func() {
		<-ctx.Done()
		if err := shutdownFn(); err != nil {
			app.Logger.Error(name+" failed to shut down", "error", err)
		} else {
			app.Logger.Info(name + " shut down successfully")
		}
	}()
}

func (app *App) RunServer(ctx context.Context) error {
	if err := godotenv.Load(); err != nil {
		app.Logger.Warn("No .env file found")
	}
	godx.Diagnostics(app.Logger)
	app.Logger.Info("Configuation on startup", "app", app)
	shutdownTracer, err := telemetry.InitTracer(app.Logger, "dot-block")
	if err != nil {
		app.Logger.Error("failed to initialize tracing", "error", err)
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := shutdownTracer(ctx); err != nil {
				app.Logger.Error("failed to shutdown tracer", "error", err)
			}
		}()
	}
	err = sentry.Init(sentry.ClientOptions{
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
	var geoIpLookup geoblock.GeoIpLookup
	if app.DisableIpinfo {
		app.Logger.Warn("GeoData lookups via ipinfo.io are disabled")
	} else {
		geoIpLookup, err = app.initMaxmind(crontab)
		if err != nil {
			return errors.Wrap(err, "failed to initialize GeoData database")
		}
	}
	blockLists, blocklistUpdater, err := app.NewBlockLists(crontab)
	if err != nil {
		return errors.Wrap(err, "failed to create blocklist(s)")
	}

	noiseFilter := noisefilter.NewNoiseFilter()
	if err := noisefilter.Fetch(app.NoiseFilterURL, noiseFilter, app.Logger); err != nil {
		app.Logger.Error("failed to download noise filter", "url", app.NoiseFilterURL, "error", err)
	}

	app.Logger.Info("Creating noise filter downloader cron job", "schedule", app.CronSchedule.Downloader)
	noiseFilterUpdater := noisefilter.NewNoiseFilterUpdater(noiseFilter, app.NoiseFilterURL, app.Logger)
	if _, err = crontab.AddJob(app.CronSchedule.Downloader, noiseFilterUpdater); err != nil {
		return errors.Wrap(err, "failed to create noise filter downloader cron job")
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
	dnsClient, err := forwarder.NewRoundRobinClient(metrics, app.Timeouts.Read, app.Timeouts.Write, app.Timeouts.Dial, app.Logger, app.Upstreams...)
	if err != nil {
		return errors.Wrap(err, "failed to initialize upstream DNS client")
	}

	broadcaster := sse.NewBroadcaster(app.Logger)
	dispatcher, err := forwarder.NewDNSDispatcher(cache, metrics, dnsClient, blockLists, noiseFilter, broadcaster, app.CacheTtlFloor, app.Logger, app.EnableECS)
	if err != nil {
		return errors.Wrap(err, "failed to create dispatcher")
	}
	defer dispatcher.Close()

	r, err := app.startHttpServer(dnsClient, blocklistUpdater, dispatcher, geoIpLookup)
	if err != nil {
		return errors.Wrap(err, "failed to initialize HTTP server")
	}

	app.Logger.Info("Creating cache reaper cron job", "schedule", app.CronSchedule.CacheReaper)
	if _, err = crontab.AddJob(app.CronSchedule.CacheReaper, forwarder.NewCacheReaperCronJob(dispatcher)); err != nil {
		return errors.Wrap(err, "failed to create cache reaper cron job")
	}
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		app.Logger.Info("Starting HTTP server for mobileconfig, metrics & healthcheck", "port", app.HttpPort)
		srv := &http.Server{
			Addr:    fmt.Sprintf(":%d", app.HttpPort),
			Handler: r,
		}
		app.monitorShutdown(groupCtx, "HTTP server", func() error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		})
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return errors.Wrap(err, "HTTP server failed")
		}
		return nil
	})
	group.Go(func() error {
		if app.DnsPort == 0 {
			app.Logger.Warn("Skipping UDP DNS server: dns-port not specified")
			return nil
		}
		app.Logger.Info("Starting UDP DNS server", "port", app.DnsPort)
		srv := &dns.Server{
			Addr:    fmt.Sprintf(":%d", app.DnsPort),
			Net:     "udp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceUDP)),
		}
		app.monitorShutdown(groupCtx, "UDP DNS server", srv.Shutdown)
		return srv.ListenAndServe()
	})
	group.Go(func() error {
		if app.DnsPort == 0 {
			app.Logger.Warn("Skipping TCP DNS server: dns-port not specified")
			return nil
		}
		app.Logger.Info("Starting TCP DNS server", "port", app.DnsPort)
		srv := &dns.Server{
			Addr:    fmt.Sprintf(":%d", app.DnsPort),
			Net:     "tcp",
			Handler: dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceTCP)),
		}
		app.monitorShutdown(groupCtx, "TCP DNS server", srv.Shutdown)
		return srv.ListenAndServe()
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
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				NextProtos:     []string{"dot"},
				GetCertificate: magic.GetCertificate,
			})
		}
		srv := &dns.Server{
			Addr:     dotPort,
			Net:      "tcp",
			Listener: listener,
			Handler:  dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceDoT)),
		}
		app.monitorShutdown(groupCtx, "DoT server", srv.Shutdown)
		return srv.ActivateAndServe()
	})
	return group.Wait()
}

func (app *App) newProxyListener(base net.Listener) (*proxyproto.Listener, error) {
	var proxyListener *proxyproto.Listener
	if len(app.TrustedProxies) > 0 {
		// If trusted proxies are specified, use a whitelist policy
		app.Logger.Info("Using PROXY protocol with trusted proxy whitelist", "trusted_proxies", app.TrustedProxies)
		policy, err := proxyproto.PolicyFromRanges(app.TrustedProxies, proxyproto.USE, proxyproto.REJECT)
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

func (app *App) startHttpServer(
	dnsClient *forwarder.RoundRobinClient,
	blocklistUpdater *blocklist.Updater,
	dispatcher *forwarder.DNSDispatcher,
	geoIpLookup geoblock.GeoIpLookup,
) (*gin.Engine, error) {

	if !app.DevMode {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	blocklistHandler := handlers.NewBlocklistHandler(blocklistUpdater, app.Logger)
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
		middlewares.SentryErrorHandler(app.Logger),
	)
	if err := healthcheck.New(r, hc_config.DefaultConfig(), dnsClient.Healthchecks()); err != nil {
		return nil, errors.Wrap(err, "failed to initialize healthcheck")
	}

	basicAuthMiddleware, err := middlewares.RequireBasicAuth(app.MetricsAuth, app.Logger)
	if err != nil {
		return nil, errors.Wrap(err, "basic auth middleware failure")
	}
	r.GET("/metrics", basicAuthMiddleware, gin.WrapH(promhttp.Handler()))

	if len(app.AllowedHosts) == 0 {
		return nil, errors.New("cannot create mobileconfig handler: at least one hostname must be configured via --allowed-hosts")
	}
	serverName := app.AllowedHosts[0]

	requestHandler := dns.HandlerFunc(dispatcher.HandleDNSRequest(forwarder.SourceDoH))

	routes.NewPublicGroup(r, serverName,
		handlers.NewMobileconfigHandler(serverName),
		handlers.NewDoHHandler(requestHandler))

	routes.NewAdminGroup(r, "admin."+serverName, app.DevMode,
		blocklistHandler,
		dispatcher.GetBroadcaster(),
		geoIpLookup,
	)

	return r, nil
}

func (app *App) environment() string {
	if app.DevMode {
		return "DEVELOPMENT"
	}
	return "PRODUCTION"
}

func newStructuredLoggingConfig() *sloggin.Config {
	config := sloggin.DefaultConfig()
	config.WithUserAgent = true
	config.WithClientIP = true
	config.Filters = append(config.Filters, sloggin.IgnorePath("/healthz", "/metrics", "/dns-query"))
	return &config
}

func (app *App) initMaxmind(crontab *cron.Cron) (geoblock.GeoIpLookup, error) {
	geolocationDb := fmt.Sprintf("%s/maxmind/ipinfo_lite.mmdb", app.DataDir)
	if _, err := os.Stat(geolocationDb); os.IsNotExist(err) {
		app.Logger.Info("ipinfo.io database not found, downloading...")
		_, err = geoblock.Fetch(geolocationDb, app.Logger)
		if err != nil {
			return nil, errors.Wrap(err, "failed to download ipinfo.io database")
		}
	}
	app.Logger.Info("Loading maxmind database", "file", geolocationDb)
	geoIpLookup, err := geoblock.NewGeoIpLookup(geolocationDb, app.Logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open ipinfo.io database")
	}
	app.Logger.Info("Creating ipinfo.io updater cron job", "schedule", app.CronSchedule.IPInfo)
	if _, err = crontab.AddJob(app.CronSchedule.IPInfo, geoblock.NewIpinfoUpdaterCronJob(app.Logger, geolocationDb, geoIpLookup)); err != nil {
		return nil, errors.Wrap(err, "failed to create ipinfo.io updater cron job")
	}
	return geoIpLookup, nil
}

func (app *App) NewBlockLists(crontab *cron.Cron) ([]blocklist.BlockList, *blocklist.Updater, error) {
	blockLists := make([]blocklist.BlockList, 0)
	for idx, url := range app.BlockListURLs {
		blockList := blocklist.NewBlockList(fmt.Sprintf("Blocklist #%d", idx), url, 0.0001, app.Logger)
		if err := blockList.LoadFromURL(); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to load blocklist: %s", url)
		}
		blockLists = append(blockLists, *blockList)
	}
	
	app.Logger.Info("Creating blocklist downloader cron job", "schedule", app.CronSchedule.Downloader)
	updater := blocklist.NewUpdater(blockLists)
	if _, err := crontab.AddJob(app.CronSchedule.Downloader, updater); err != nil {
		return nil, nil, errors.Wrap(err, "failed to create blocklist downloader cron job")
	}

	return blockLists, updater, nil
}
