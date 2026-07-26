package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/drone/envsubst/v2"
	"gopkg.in/yaml.v3"
)

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: &ServerConfig{
			DevMode:  false,
			LogLevel: "INFO",
			DataDir:  "./data",
			HttpPort: 80,
			DnsPort:  0,
			DotPort:  853,
			ProxyProtocol: &ProxyProtocolConfig{
				Enabled:        false,
				TrustedProxies: []string{},
			},
			LetsEncrypt: &LetsEncryptConfig{
				Enabled:            false,
				Email:              "",
				CloudflareApiToken: "",
				AllowedHosts:       []string{},
			},
		},
		DNS: &DNSConfig{
			Upstreams: []string{
				"8.8.8.8",
				"8.8.4.4",
				"1.1.1.1",
				"1.0.0.1",
			},
			ECS: &ECSConfig{
				Enabled: false,
			},
			Cache: &CacheConfig{
				MaxSize:      1_000_000,
				TtlFloor:     3600 * time.Second,
				CronSchedule: "0 3 * * *",
			},
			NoiseFilter: &NoiseFilter{
				URL:          "https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/noise-filter.csv",
				CronSchedule: "@every 19h",
			},
			Timeouts: &TimeoutsConfig{
				Read:  300 * time.Millisecond,
				Write: 100 * time.Millisecond,
				Dial:  300 * time.Millisecond,
			},
		},
		Blocklist: &BlocklistConfig{
			Sources: []BlocklistSource{
				{
					Name:         "hagezi-pro",
					URL:          "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.txt",
					CronSchedule: "@every 19h",
				},
				{
					Name:         "cebeerre-nrd",
					URL:          "https://raw.githubusercontent.com/Cebeerre/dnsblocklists/refs/heads/main/NRD/nrd7_asterisk.txt",
					CronSchedule: "@every 19h",
				},
				{
					Name:         "dot-block",
					URL:          "https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/blocklist.txt",
					CronSchedule: "@every 19h",
				},
			},
		},
		Geoblock: &GeoblockConfig{
			Ipinfo: &IpinfoConfig{
				Enabled:      true,
				CronSchedule: "5 7 4 * *",
			},
		},
		Telemetry: &TelemetryConfig{
			SentryDsn:         "",
			MetricsAuth:       "",
			OtelEndpoint:      "",
			OtelSamplingRatio: 0.01,
			TopK: &TopKConfig{
				NumDomains: 100,
				NumBlocked: 100,
				NumClients: 100,
			},
		},
	}
}

// Load loads configuration from a YAML file with environment variable substitution.
// Precedence: Defaults < config.yaml (with envsubst) < Environment Variables < CLI Flags
func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	if configPath == "" {
		// Search for config.yaml in default locations
		configPath = findConfigFile()
	}

	if configPath != "" {
		if err := loadFromFile(configPath, cfg); err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", configPath, err)
		}
	}

	// Environment variables are applied via ApplyEnvOverrides
	// CLI flags will be applied in main.go after this

	return cfg, nil
}

func loadFromFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Substitute environment variables
	substituted, err := envsubst.EvalEnv(string(data))
	if err != nil {
		return fmt.Errorf("envsubst failed: %w", err)
	}

	return yaml.Unmarshal([]byte(substituted), cfg)
}

func findConfigFile() string {
	var candidates []string

	// Current directory
	candidates = append(candidates, "config.yaml", "config.yml")

	// XDG config directories
	for _, dir := range xdg.ConfigDirs {
		candidates = append(candidates, filepath.Join(dir, "dot-block", "config.yaml"))
		candidates = append(candidates, filepath.Join(dir, "dot-block", "config.yml"))
	}

	// Also check XDG_CONFIG_HOME if set
	if xdg.ConfigHome != "" {
		candidates = append(candidates, filepath.Join(xdg.ConfigHome, "dot-block", "config.yaml"))
		candidates = append(candidates, filepath.Join(xdg.ConfigHome, "dot-block", "config.yml"))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// ApplyEnvOverrides applies environment variable overrides to the config.
// This mirrors the Cobra flag env var bindings.
func ApplyEnvOverrides(cfg *Config) {
	if v := os.Getenv("DEV_MODE"); v != "" {
		cfg.Server.DevMode = v == "true"
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.Server.LogLevel = LogLevel(strings.ToUpper(v))
	}
	if v := os.Getenv("DATA_DIR"); v != "" {
		cfg.Server.DataDir = v
	}
	if v := os.Getenv("HTTP_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Server.HttpPort = port
		}
	}
	if v := os.Getenv("DNS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Server.DnsPort = port
		}
	}
	if v := os.Getenv("DOT_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Server.DotPort = port
		}
	}
	if v := os.Getenv("REQUIRE_PROXY_PROTOCOL"); v != "" {
		if cfg.Server.ProxyProtocol == nil {
			cfg.Server.ProxyProtocol = &ProxyProtocolConfig{}
		}
		cfg.Server.ProxyProtocol.Enabled = v == "true"
	}
	if v := os.Getenv("METRICS_AUTH"); v != "" {
		cfg.Telemetry.MetricsAuth = v
	}
	if v := os.Getenv("ENABLE_ECS"); v != "" {
		if cfg.DNS.ECS == nil {
			cfg.DNS.ECS = &ECSConfig{}
		}
		cfg.DNS.ECS.Enabled = v == "true"
	}
	if v := os.Getenv("DISABLE_IPINFO"); v != "" {
		if cfg.Geoblock.Ipinfo == nil {
			cfg.Geoblock.Ipinfo = &IpinfoConfig{}
		}
		cfg.Geoblock.Ipinfo.Enabled = v != "true"
	}
	if v := os.Getenv("ACME_EMAIL"); v != "" {
		if cfg.Server.LetsEncrypt == nil {
			cfg.Server.LetsEncrypt = &LetsEncryptConfig{}
		}
		cfg.Server.LetsEncrypt.Email = v
	}
	if v := os.Getenv("CLOUDFLARE_API_TOKEN"); v != "" {
		if cfg.Server.LetsEncrypt == nil {
			cfg.Server.LetsEncrypt = &LetsEncryptConfig{}
		}
		cfg.Server.LetsEncrypt.CloudflareApiToken = v
	}
	if v := os.Getenv("IPINFO_TOKEN"); v != "" {
		if cfg.Geoblock.Ipinfo == nil {
			cfg.Geoblock.Ipinfo = &IpinfoConfig{}
		}
		cfg.Geoblock.Ipinfo.Token = v
	}
	if v := os.Getenv("SENTRY_DSN"); v != "" {
		cfg.Telemetry.SentryDsn = v
	}
	if v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); v != "" {
		cfg.Telemetry.OtelEndpoint = v
	}
	if v := os.Getenv("OTEL_SAMPLING_RATIO"); v != "" {
		if ratio, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Telemetry.OtelSamplingRatio = ratio
		}
	}
	// Upstreams, blocklists, etc. are handled via flags in main.go
}
