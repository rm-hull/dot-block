package config

import (
	"time"

	"github.com/alecthomas/jsonschema"
)

type Config struct {
	Server     *ServerConfig     `yaml:"server,omitempty" json:"server,omitempty"`
	DNS        *DNSConfig        `yaml:"dns,omitempty" json:"dns,omitempty"`
	Blocklists *BlocklistsConfig `yaml:"blocklists,omitempty" json:"blocklists,omitempty"`
	Geoblock   *GeoblockConfig   `yaml:"geoblock,omitempty" json:"geoblock,omitempty"`
}

type LogLevel string

func (LogLevel) JSONSchema() *jsonschema.Type {
	return &jsonschema.Type{
		Type: "string",
		Enum: []interface{}{"DEBUG", "INFO", "WARN", "ERROR"},
	}
}

type ServerConfig struct {
	DevMode              bool     `yaml:"dev_mode,omitempty" json:"dev_mode,omitempty"`
	LogLevel             LogLevel `yaml:"log_level,omitempty" json:"log_level,omitempty"`
	DataDir              string   `yaml:"data_dir,omitempty" json:"data_dir,omitempty"`
	HttpPort             int      `yaml:"http_port,omitempty" json:"http_port,omitempty"`
	DnsPort              int      `yaml:"dns_port,omitempty" json:"dns_port,omitempty"`
	DotPort              int      `yaml:"dot_port,omitempty" json:"dot_port,omitempty"`
	RequireProxyProtocol bool     `yaml:"require_proxy_protocol,omitempty" json:"require_proxy_protocol,omitempty"`
	TrustedProxies       []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
	AllowedHosts         []string `yaml:"allowed_hosts,omitempty" json:"allowed_hosts,omitempty"`
	MetricsAuth          string   `yaml:"metrics_auth,omitempty" json:"metrics_auth,omitempty"`
}

type DNSConfig struct {
	Upstreams   []string        `yaml:"upstreams,omitempty" json:"upstreams,omitempty"`
	ECS         *ECSConfig      `yaml:"ecs,omitempty" json:"ecs,omitempty"`
	Cache       *CacheConfig    `yaml:"cache,omitempty" json:"cache,omitempty"`
	NoiseFilter *NoiseFilter    `yaml:"noise_filter,omitempty" json:"noise_filter,omitempty"`
	Timeouts    *TimeoutsConfig `yaml:"timeouts,omitempty" json:"timeouts,omitempty"`
}

type ECSConfig struct {
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

type CacheConfig struct {
	MaxSize      int           `yaml:"max_size,omitempty" json:"max_size,omitempty"`
	TtlFloor     time.Duration `yaml:"ttl_floor,omitempty" json:"ttl_floor,omitempty"`
	CronSchedule string        `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty"`
}

type NoiseFilter struct {
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
}

type TimeoutsConfig struct {
	Read  time.Duration `yaml:"read,omitempty" json:"read,omitempty"`
	Write time.Duration `yaml:"write,omitempty" json:"write,omitempty"`
	Dial  time.Duration `yaml:"dial,omitempty" json:"dial,omitempty"`
}

type BlocklistsConfig struct {
	URLs         []string `yaml:"urls,omitempty" json:"urls,omitempty"`
	CronSchedule string   `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty"`
}

type GeoblockConfig struct {
	Ipinfo *IpinfoConfig `yaml:"ipinfo,omitempty" json:"ipinfo,omitempty"`
}

type IpinfoConfig struct {
	Enabled      bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	CronSchedule string `yaml:"cron_schedule,omitempty" json:"cron_schedule,omitempty"`
}
