package config

import (
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/alecthomas/jsonschema"
)

type Config struct {
	Server    *ServerConfig    `yaml:"server,omitempty" json:"server,omitempty"`
	DNS       *DNSConfig       `yaml:"dns,omitempty" json:"dns,omitempty"`
	Blocklist *BlocklistConfig `yaml:"blocklist,omitempty" json:"blocklist,omitempty"`
	Geoblock  *GeoblockConfig  `yaml:"geoblock,omitempty" json:"geoblock,omitempty"`
}

type LogLevel string

func (LogLevel) JSONSchema() *jsonschema.Type {
	return &jsonschema.Type{
		Type: "string",
		Enum: []interface{}{"DEBUG", "INFO", "WARN", "ERROR"},
	}
}

type ServerConfig struct {
	DevMode       bool                 `yaml:"dev_mode,omitempty" json:"dev_mode,omitempty" descr:"Run server in dev mode (no TLS, plain TCP)."`
	LogLevel      LogLevel             `yaml:"log_level,omitempty" json:"log_level,omitempty" descr:"The logging level (DEBUG, INFO, WARN, ERROR)."`
	DataDir       string               `yaml:"data_dir,omitempty" json:"data_dir,omitempty" descr:"Directory for storing persistent data (e.g., TLS certificate cache)."`
	HttpPort      int                  `yaml:"http_port,omitempty" json:"http_port,omitempty" descr:"The port to run HTTP server on."`
	DnsPort       int                  `yaml:"dns_port,omitempty" json:"dns_port,omitempty" descr:"The port to run regular DNS (UDP/TCP) server on."`
	DotPort       int                  `yaml:"dot_port,omitempty" json:"dot_port,omitempty" descr:"The port to run DNS-over-TLS server on."`
	ProxyProtocol *ProxyProtocolConfig `yaml:"proxy_protocol,omitempty" json:"proxy_protocol,omitempty"`
	AllowedHosts  []string             `yaml:"allowed_hosts,omitempty" json:"allowed_hosts,omitempty" descr:"List of domains used for CertManager allow policy."`
	MetricsAuth   string               `yaml:"metrics_auth,omitempty" json:"metrics_auth,omitempty" log:"redacted" descr:"Credentials for basic auth on /metrics (format: user:pass)."`
}

type ProxyProtocolConfig struct {
	Enabled        bool     `yaml:"enabled,omitempty" json:"enabled,omitempty" descr:"Require PROXY protocol header for DoT connections."`
	TrustedProxies []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty" descr:"Comma-separated list of trusted proxy IP addresses or CIDR ranges."`
}

type DNSConfig struct {
	Upstreams   []string        `yaml:"upstreams,omitempty" json:"upstreams,omitempty" descr:"Upstream DNS resolvers to forward queries to."`
	ECS         *ECSConfig      `yaml:"ecs,omitempty" json:"ecs,omitempty"`
	Cache       *CacheConfig    `yaml:"cache,omitempty" json:"cache,omitempty"`
	NoiseFilter *NoiseFilter    `yaml:"noise_filter,omitempty" json:"noise_filter,omitempty"`
	Timeouts    *TimeoutsConfig `yaml:"timeouts,omitempty" json:"timeouts,omitempty"`
}

type ECSConfig struct {
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty" descr:"Whether to enable EDNS0 Client Subnet (ECS) forwarding."`
}

type CacheConfig struct {
	MaxSize      int           `yaml:"max_size,omitempty" json:"max_size,omitempty" descr:"Maximum number of entries in the DNS cache."`
	TtlFloor     time.Duration `yaml:"ttl_floor,omitempty" json:"ttl_floor,omitempty" descr:"Minimum TTL for cached entries."`
	CronSchedule string        `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty" descr:"Cron spec for cache reaper."`
}

type NoiseFilter struct {
	URL          string `yaml:"url,omitempty" json:"url,omitempty" descr:"URL of noise filter list (CSV format: category,rcode,domain_suffix)."`
	CronSchedule string `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty" descr:"Cron spec for noise filter downloader."`
}

type TimeoutsConfig struct {
	Read  time.Duration `yaml:"read,omitempty" json:"read,omitempty" descr:"Timeout for reading upstream DNS queries."`
	Write time.Duration `yaml:"write,omitempty" json:"write,omitempty" descr:"Timeout for writing upstream DNS queries."`
	Dial  time.Duration `yaml:"dial,omitempty" json:"dial,omitempty" descr:"Timeout for establishing connections to upstream servers."`
}

type BlocklistConfig struct {
	Sources []BlocklistSource `yaml:"sources,omitempty" json:"sources,omitempty" descr:"Array of blocklist sources, each with its own name, URL and cron schedule."`
}

type BlocklistSource struct {
	Name         string `yaml:"name,omitempty" json:"name,omitempty" descr:"Human-readable name for the blocklist (replaces the auto-generated 'Blocklist #N')."`
	URL          string `yaml:"url,omitempty" json:"url,omitempty" descr:"URL of the blocklist source."`
	CronSchedule string `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty" descr:"Cron spec for reloading this specific blocklist. If omitted, the blocklist is not scheduled for automatic updates."`
}

type GeoblockConfig struct {
	Ipinfo *IpinfoConfig `yaml:"ipinfo,omitempty" json:"ipinfo,omitempty"`
}

type IpinfoConfig struct {
	Enabled      bool   `yaml:"enabled,omitempty" json:"enabled,omitempty" descr:"Whether to enable IPinfo.io geolocation lookups."`
	CronSchedule string `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty" descr:"Cron spec for Ipinfo.io database downloader."`
}

// LogValue implements slog.LogValuer to ensure nested durations are formatted as strings.
func (config *Config) LogValue() slog.Value {
	return slog.AnyValue(structToMap(config))
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
		parts := strings.Split(tag, ",")
		name := field.Name
		if parts[0] != "" {
			name = parts[0]
		}
		if len(parts) > 1 && parts[1] == "omitempty" && v.Field(i).IsZero() {
			continue
		}
		val := v.Field(i).Interface()
		// If the field is a pointer to a struct (and not time.Time), dereference and recurse
		if v.Field(i).Kind() == reflect.Pointer {
			if v.Field(i).IsNil() {
				m[name] = nil
			} else {
				// Dereference and recurse
				elem := v.Field(i).Elem()
				if elem.Kind() == reflect.Struct && elem.Type() != reflect.TypeFor[time.Time]() {
					m[name] = structToMap(elem.Interface())
				} else {
					m[name] = val
				}
			}
		} else if reflect.TypeOf(val).Kind() == reflect.Struct && reflect.TypeOf(val) != reflect.TypeFor[time.Time]() {
			// Direct struct field (not a pointer)
			m[name] = structToMap(val)
		} else if field.Tag.Get("log") == "redacted" && !v.Field(i).IsZero() {
			m[name] = "********"
		} else if field.Type == reflect.TypeFor[time.Duration]() {
			// Convert time.Duration to string (e.g., "1h30m") for readable logging
			m[name] = val.(time.Duration).String()
		} else {
			m[name] = val
		}
	}
	return m
}
