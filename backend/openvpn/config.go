package openvpn

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// Config is the OpenVPN backend configuration decoded from Backend.config
// (an opaque JSON string produced by the panel's OpenVPNConfig.to_str()).
type Config struct {
	InboundTag   string   `json:"inbound_tag"`
	Port         int      `json:"port"`
	Proto        string   `json:"proto"`
	Device       string   `json:"device"`
	ServerSubnet string   `json:"server_subnet"`
	DNS          []string `json:"dns"`
	Cipher       string   `json:"cipher"`
	DataCiphers  []string `json:"data_ciphers"`
	Auth         string   `json:"auth"`
	Keepalive    string   `json:"keepalive"`
	MaxClients   int      `json:"max_clients"`
	DuplicateCN  bool     `json:"duplicate_cn"`
	Push         []string `json:"push"`
	CACert       string   `json:"ca_cert"`
	ServerCert   string   `json:"server_cert"`
	ServerKey    string   `json:"server_key"`
	TLSCryptKey  string   `json:"tls_crypt_key"`

	workDir string
}

// NewConfig parses the config string and applies defaults.
func NewConfig(configStr string) (*Config, error) {
	cfg := &Config{}
	if strings.TrimSpace(configStr) == "" {
		return nil, fmt.Errorf("openvpn config string must not be empty")
	}
	if err := json.Unmarshal([]byte(configStr), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse openvpn config: %w", err)
	}

	if cfg.InboundTag == "" {
		return nil, fmt.Errorf("inbound_tag is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.Proto == "" {
		cfg.Proto = "udp"
	}
	if cfg.Device == "" {
		cfg.Device = "tun"
	}
	if cfg.ServerSubnet == "" {
		return nil, fmt.Errorf("server_subnet is required")
	}
	if cfg.Cipher == "" {
		cfg.Cipher = "AES-256-GCM"
	}
	if cfg.Auth == "" {
		cfg.Auth = "SHA256"
	}
	if cfg.Keepalive == "" {
		cfg.Keepalive = "10 60"
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = 1024
	}
	if cfg.CACert == "" || cfg.ServerCert == "" || cfg.ServerKey == "" {
		return nil, fmt.Errorf("ca_cert, server_cert and server_key are required")
	}

	return cfg, nil
}

func (c *Config) mgmtSocketPath() string {
	return filepath.Join(c.workDir, "mgmt.sock")
}
