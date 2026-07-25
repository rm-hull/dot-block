package config

import (
	"time"

	"github.com/alecthomas/jsonschema"
)

type Config struct {
	Server     ServerConfig     `yaml:"server" json:"server"`
	DNS        DNSConfig        `yaml:"dns" json:"dns"`
	Blocklists BlocklistsConfig `yaml:"blocklists" json:"blocklists"`
	Geoblock   GeoblockConfig   `yaml:"geoblock" json:"geoblock"`
}

type LogLevel string

func (LogLevel) JSONSchema() *jsonschema.Type {
	return &jsonschema.Type{
		Type:  "string",
		Enum:  []interface{}{"DEBUG", "INFO", "WARN", "ERROR"},
	}
}

type ServerConfig struct {
	DevMode              bool     `yaml:"dev_mode" json:"dev_mode"`
	LogLevel             LogLevel `yaml:"log_level" json:"log_level"`
	DataDir              string   `yaml:"data_dir" json:"data_dir"`
	HttpPort             int      `yaml:"http_port" json:"http_port"`
	DnsPort              int      `yaml:"dns_port" json:"dns_port"`
	DotPort              int      `yaml:"dot_port" json:"dot_port"`
	RequireProxyProtocol bool     `yaml:"require_proxy_protocol" json:"require_proxy_protocol"`
	TrustedProxies       []string `yaml:"trusted_proxies,omitempty" json:"trusted_proxies,omitempty"`
	AllowedHosts         []string `yaml:"allowed_hosts,omitempty" json:"allowed_hosts,omitempty"`
	MetricsAuth          string   `yaml:"metrics_auth,omitempty" json:"metrics_auth,omitempty"`
}

type DNSConfig struct {
	Upstreams   []string       `yaml:"upstreams" json:"upstreams"`
	ECS         ECSConfig      `yaml:"ecs" json:"ecs"`
	Cache       CacheConfig    `yaml:"cache" json:"cache"`
	NoiseFilter NoiseFilter    `yaml:"noise_filter" json:"noise_filter"`
	Timeouts    TimeoutsConfig `yaml:"timeouts" json:"timeouts"`
}

type ECSConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

type CacheConfig struct {
	MaxSize      int           `yaml:"max_size" json:"max_size"`
	TtlFloor     time.Duration `yaml:"ttl_floor" json:"ttl_floor"`
	CronSchedule string        `yaml:"cron_schedule" json:"cron_schedule"`
}

type NoiseFilter struct {
	URL string `yaml:"url" json:"url"`
}

type TimeoutsConfig struct {
	Read  time.Duration `yaml:"read" json:"read"`
	Write time.Duration `yaml:"write" json:"write"`
	Dial  time.Duration `yaml:"dial" json:"dial"`
}

type BlocklistsConfig struct {
	URLs         []string `yaml:"urls" json:"urls"`
	CronSchedule string   `yaml:"cron_schedule" json:"cron_schedule"`
}

type GeoblockConfig struct {
	Ipinfo IpinfoConfig `yaml:"ipinfo" json:"ipinfo"`
}

type IpinfoConfig struct {
	Enabled      bool   `yaml:"enabled" json:"enabled"`
	CronSchedule string `yaml:"cron_schedule" json:"cron_schedule"`
}
