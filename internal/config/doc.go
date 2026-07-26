package config

import (
	"reflect"
	"time"

	"github.com/alecthomas/jsonschema"
)

// CommentMap provides descriptions for fields in the Config struct.
// The keys are in the format "packagepath.TypeName.FieldName".
var CommentMap = map[string]string{
	// ServerConfig
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.DevMode":      "Run server in dev mode (no TLS, plain TCP).",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.LogLevel":     "The logging level (DEBUG, INFO, WARN, ERROR).",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.DataDir":      "Directory for storing persistent data (e.g., TLS certificate cache).",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.HttpPort":     "The port to run HTTP server on.",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.DnsPort":      "The port to run regular DNS (UDP/TCP) server on.",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.DotPort":      "The port to run DNS-over-TLS server on.",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.AllowedHosts": "List of domains used for CertManager allow policy.",
	"github.com/rm-hull/dot-block/internal/config.ServerConfig.MetricsAuth":  "Credentials for basic auth on /metrics (format: user:pass).",

	// ProxyProtocolConfig
	"github.com/rm-hull/dot-block/internal/config.ProxyProtocolConfig.Enabled":        "Require PROXY protocol header for DoT connections.",
	"github.com/rm-hull/dot-block/internal/config.ProxyProtocolConfig.TrustedProxies": "Comma-separated list of trusted proxy IP addresses or CIDR ranges.",

	// DNSConfig
	"github.com/rm-hull/dot-block/internal/config.DNSConfig.Upstreams":      "Upstream DNS resolvers to forward queries to.",
	"github.com/rm-hull/dot-block/internal/config.ECSConfig.Enabled":        "Whether to enable EDNS0 Client Subnet (ECS) forwarding.",
	"github.com/rm-hull/dot-block/internal/config.CacheConfig.MaxSize":      "Maximum number of entries in the DNS cache.",
	"github.com/rm-hull/dot-block/internal/config.CacheConfig.TtlFloor":     "Minimum TTL for cached entries.",
	"github.com/rm-hull/dot-block/internal/config.CacheConfig.CronSchedule": "Cron spec for cache reaper.",
	"github.com/rm-hull/dot-block/internal/config.NoiseFilter.URL":          "URL of noise filter list (CSV format: category,rcode,domain_suffix).",
	"github.com/rm-hull/dot-block/internal/config.NoiseFilter.CronSchedule": "Cron spec for noise filter downloader.",
	"github.com/rm-hull/dot-block/internal/config.TimeoutsConfig.Read":      "Timeout for reading upstream DNS queries.",
	"github.com/rm-hull/dot-block/internal/config.TimeoutsConfig.Write":     "Timeout for writing upstream DNS queries.",
	"github.com/rm-hull/dot-block/internal/config.TimeoutsConfig.Dial":      "Timeout for establishing connections to upstream servers.",

	// BlocklistConfig
	"github.com/rm-hull/dot-block/internal/config.BlocklistConfig.Sources": "Array of blocklist sources, each with its own name, URL and cron schedule.",

	// BlocklistSource
	"github.com/rm-hull/dot-block/internal/config.BlocklistSource.Name":         "Human-readable name for the blocklist (replaces the auto-generated 'Blocklist #N').",
	"github.com/rm-hull/dot-block/internal/config.BlocklistSource.URL":          "URL of the blocklist source.",
	"github.com/rm-hull/dot-block/internal/config.BlocklistSource.CronSchedule": "Cron spec for reloading this specific blocklist. If omitted, the blocklist is not scheduled for automatic updates.",

	// GeoblockConfig
	"github.com/rm-hull/dot-block/internal/config.IpinfoConfig.Enabled":      "Whether to enable IPinfo.io geolocation lookups.",
	"github.com/rm-hull/dot-block/internal/config.IpinfoConfig.CronSchedule": "Cron spec for Ipinfo.io database downloader.",
}

// reflectorWithComments returns a Reflector configured with the CommentMap and a TypeMapper for LogLevel and time.Duration.
func reflectorWithComments() jsonschema.Reflector {
	return jsonschema.Reflector{
		AllowAdditionalProperties: true,
		DoNotReference:            true,
		CommentMap:                CommentMap,
		TypeMapper: func(t reflect.Type) *jsonschema.Type {
			if t == reflect.TypeOf(LogLevel("")) {
				return &jsonschema.Type{
					Type: "string",
					Enum: []any{"DEBUG", "INFO", "WARN", "ERROR"},
				}
			}
			if t == reflect.TypeOf(time.Duration(0)) {
				return &jsonschema.Type{
					Type:    "string",
					Format:  "duration",
					Pattern: "^([0-9]+(?:\\.[0-9]+)?(?:ns|us|µs|ms|s|m|h))+$",
				}
			}
			return nil // let reflector decide
		},
	}
}
