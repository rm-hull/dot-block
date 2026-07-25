package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/drone/envsubst/v2"
	"gopkg.in/yaml.v3"
)

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			DevMode:              false,
			LogLevel:             "INFO",
			DataDir:              "./data",
			HttpPort:             80,
			DnsPort:              0,
			DotPort:              853,
			RequireProxyProtocol: false,
			TrustedProxies:       []string{},
			AllowedHosts:         []string{},
			MetricsAuth:          "",
		},
		DNS: DNSConfig{
			Upstreams: []string{
				"8.8.8.8",
				"8.8.4.4",
				"1.1.1.1",
				"1.0.0.1",
			},
			ECS: ECSConfig{
				Enabled: false,
			},
			Cache: CacheConfig{
				MaxSize:      1_000_000,
				TtlFloor:     3600 * time.Second,
				CronSchedule: "0 3 * * *",
			},
			NoiseFilter: NoiseFilter{
				URL: "https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/noise-filter.csv",
			},
			Timeouts: TimeoutsConfig{
				Read:  300 * time.Millisecond,
				Write: 100 * time.Millisecond,
				Dial:  300 * time.Millisecond,
			},
		},
		Blocklists: BlocklistsConfig{
			URLs: []string{
				"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.txt",
				"https://raw.githubusercontent.com/Cebeerre/dnsblocklists/refs/heads/main/NRD/nrd7_asterisk.txt",
				"https://raw.githubusercontent.com/rm-hull/dot-block/refs/heads/main/data/blocklist.txt",
			},
			CronSchedule: "@every 19h",
		},
		Geoblock: GeoblockConfig{
			Ipinfo: IpinfoConfig{
				Enabled:      true,
				CronSchedule: "5 7 4 * *",
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

	// Environment variables are applied via Viper or similar in main.go
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
	candidates := []string{
		"config.yaml",
		"config.yml",
		"/etc/dot-block/config.yaml",
		"/etc/dot-block/config.yml",
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
		fmt.Sscanf(v, "%d", &cfg.Server.HttpPort)
	}
	if v := os.Getenv("DNS_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Server.DnsPort)
	}
	if v := os.Getenv("DOT_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Server.DotPort)
	}
	if v := os.Getenv("REQUIRE_PROXY_PROTOCOL"); v != "" {
		cfg.Server.RequireProxyProtocol = v == "true"
	}
	if v := os.Getenv("METRICS_AUTH"); v != "" {
		cfg.Server.MetricsAuth = v
	}
	if v := os.Getenv("ENABLE_ECS"); v != "" {
		cfg.DNS.ECS.Enabled = v == "true"
	}
	if v := os.Getenv("DISABLE_IPINFO"); v != "" {
		cfg.Geoblock.Ipinfo.Enabled = v != "true"
	}
	// Upstreams, blocklists, etc. are handled via flags in main.go
}